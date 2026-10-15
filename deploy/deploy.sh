#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "Usage: $0 gear-engine|gear-ui vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
service=$1
version=$2
case "$service" in
  gear-engine) tag_key=ENGINE_TAG ;;
  gear-ui) tag_key=UI_TAG ;;
  *) echo "Unknown service: $service" >&2; exit 2 ;;
esac
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && ! $version =~ ^bootstrap-[0-9]{8}-[0-9]{6}$ ]]; then
  echo "Invalid release tag: $version" >&2
  exit 2
fi

cd -- "$(dirname -- "$(readlink -f -- "$0")")"
umask 077
# Both repositories share this server-side lock; Actions concurrency is per repository.
exec 9>.deploy.lock
flock -w 600 9
unset ENGINE_TAG UI_TAG

compose() {
  docker compose --project-name projects --env-file .env -f docker-compose.yml "$@"
}
candidate() {
  env "$tag_key=$version" docker compose --project-name projects --env-file .env -f docker-compose.yml "$@"
}
verify() {
  # Nginx resolves upstream container names on startup/reload.
  docker exec gear-ui nginx -t || return 1
  docker exec gear-ui nginx -s reload || return 1
  local ui_status api_status
  for ((attempt = 0; attempt < 20; attempt++)); do
    ui_status=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/ || true)
    api_status=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/v1/token || true)
    if [[ $ui_status == 200 && $api_status == 401 ]]; then
      return 0
    fi
    sleep 2
  done
  echo "Smoke check failed: UI=$ui_status API=$api_status (expected 200/401)" >&2
  return 1
}

test -s .env
test -s engine.env
test "$(docker exec gear-redis redis-cli ping)" = PONG
compose config --quiet
candidate config --quiet
previous=$(awk -F= -v key="$tag_key" '$1 == key {print substr($0, length(key) + 2)}' .env)
test -n "$previous"

# Prepare the state file before touching a container; publish it only after verification.
next_env=$(mktemp .env.next.XXXXXX)
trap 'rm -f -- "$next_env"' EXIT
awk -v key="$tag_key" -v value="$version" '
  index($0, key "=") == 1 {if (!seen++) print key "=" value; next}
  {print}
  END {if (!seen) print key "=" value}
' .env > "$next_env"

# Bootstrap tags are local snapshots, deliberately absent from GHCR.
if [[ $version != bootstrap-* ]]; then
  candidate pull "$service"
fi
if candidate up -d --no-deps --pull never --wait --wait-timeout 120 "$service" && verify; then
  mv -- "$next_env" .env
  compose ps "$service"
  echo "Deployed $service: $previous -> $version"
else
  echo "Deployment failed; restoring $service to $previous" >&2
  if ! compose up -d --no-deps --pull never --wait --wait-timeout 120 "$service" || ! verify; then
    echo "ROLLBACK FAILED: inspect $service manually; .env still records $previous" >&2
  fi
  exit 1
fi
