# Implementation Plan: RunServe (task 12.1)

## Context

`RunServe` lives in `internal/cli/serve.go` and must mirror the pattern of
`RunInit` in `internal/cli/init.go`. All heavy lifting (TLS validation,
master.key 0600 check, DB open/close, HTTP→HTTPS redirect, graceful shutdown)
is already done by `config.Load`, `server.New`, and `(*Server).Run`.
`RunServe` is intentionally thin: parse flags → optional env-var overrides →
load config → build server → run server.

---

## Implementation Steps

- [ ] 1. **Replace the stub in `internal/cli/serve.go` with the full implementation.**

  ### Imports required

  ```go
  import (
      "flag"
      "fmt"
      "os"

      "github.com/gear/engine/internal/config"
      "github.com/gear/engine/internal/server"
  )
  ```

  ### Flags to define

  Define two optional flags that mirror init.go's `--db` and `--master-key`,
  mapping onto the env vars that `config.Load` reads:

  | Flag           | Env var overridden         | Default      |
  |----------------|---------------------------|--------------|
  | `--db`         | `GEAR_DB_PATH`            | _(empty — let config.Load use its own default)_ |
  | `--master-key` | `GEAR_MASTER_KEY_PATH`    | _(same)_ |

  Flags for TLS (`--tls-cert`, `--tls-key`) are intentionally omitted: TLS
  values are sensitive paths that belong in env vars (`GEAR_TLS_CERT`,
  `GEAR_TLS_KEY`) and are already enforced as required by `config.Load`.
  Adding flags for them would not add usability in the Docker/container
  deployment context and would diverge from the minimal-flags style of
  init.go.

  ### Call sequence

  ```
  1. fs := flag.NewFlagSet("gear serve", flag.ContinueOnError)
  2. define --db and --master-key flags (pointer vars)
  3. if err := fs.Parse(args); err != nil { return err }
  4. if *db != ""        { os.Setenv("GEAR_DB_PATH", *db) }
  5. if *masterKey != "" { os.Setenv("GEAR_MASTER_KEY_PATH", *masterKey) }
  6. cfg, err := config.Load()
     if err != nil { return fmt.Errorf("serve: %w", err) }
  7. s, err := server.New(cfg)
     if err != nil { return fmt.Errorf("serve: %w", err) }
  8. if err := s.Run(); err != nil { return fmt.Errorf("serve: %w", err) }
  9. return nil
  ```

  ### Error-wrapping style

  Wrap all errors with `fmt.Errorf("serve: %w", err)` — matching the
  `fmt.Errorf("failed to ...: %w", err)` pattern seen throughout init.go and
  server.go. The prefix `"serve: "` makes the call site clear in error output.

  ### What RunServe must NOT do

  - Must NOT open the database itself (`database.Open`) — `server.New` owns
    the DB lifecycle and `server.Run` calls `database.Close`.
  - Must NOT validate TLS file paths — `server.New` calls
    `middleware.ValidateTLSCertFiles` already.
  - Must NOT enforce master.key permissions — `server.New` calls
    `checkMasterKeyPermission` (which does `log.Fatal` if wrong).
  - Must NOT add any plain-HTTP API routes — `server.Run` runs the HTTP
    listener as redirect-only via `middleware.HTTPSRedirectHandler`.
  - Must NOT duplicate graceful-shutdown logic — `server.Run` already handles
    `SIGINT`/`SIGTERM` with a 30-second drain.

  ### Security invariants (already enforced upstream — confirm not weakened)

  | Invariant | Enforced by | RunServe action |
  |-----------|------------|-----------------|
  | TLS cert+key required | `config.Load` → error if missing | surface error via `fmt.Errorf("serve: %w", err)` |
  | TLS files readable & valid | `server.New` → `middleware.ValidateTLSCertFiles` | none needed |
  | master.key perm == 0600 | `server.New` → `checkMasterKeyPermission` (log.Fatal) | none needed |
  | HTTP is redirect-only | `server.Run` → `middleware.HTTPSRedirectHandler` | none needed |
  | Graceful shutdown drains requests | `server.Run` → `httpsSrv.Shutdown(30s ctx)` | none needed |

  **Files to modify:**
  - `internal/cli/serve.go`

  **Verify:**
  ```
  cd /home/rocket/Projects/gear-engine && make build && make test
  ```
  Expected: binary compiles without errors, all existing tests pass.

---

## Final code shape

```go
package cli

import (
    "flag"
    "fmt"
    "os"

    "github.com/gear/engine/internal/config"
    "github.com/gear/engine/internal/server"
)

// RunServe executes the "gear serve" command.
// It starts the HTTPS API server with HTTP→HTTPS redirect.
//
// Configuration is loaded primarily from environment variables (see config.Load).
// The optional --db and --master-key flags, when provided, override the
// corresponding env vars (GEAR_DB_PATH, GEAR_MASTER_KEY_PATH) before Load is called.
// TLS cert/key must be supplied via GEAR_TLS_CERT and GEAR_TLS_KEY; config.Load
// returns a clear error if either is absent.
func RunServe(args []string) error {
    fs := flag.NewFlagSet("gear serve", flag.ContinueOnError)
    db := fs.String("db", "", "path to SQLite database file (overrides GEAR_DB_PATH)")
    masterKey := fs.String("master-key", "", "path to master key file (overrides GEAR_MASTER_KEY_PATH)")

    if err := fs.Parse(args); err != nil {
        return err
    }

    // Allow flag values to override env vars before config.Load reads them.
    if *db != "" {
        os.Setenv("GEAR_DB_PATH", *db)
    }
    if *masterKey != "" {
        os.Setenv("GEAR_MASTER_KEY_PATH", *masterKey)
    }

    cfg, err := config.Load()
    if err != nil {
        return fmt.Errorf("serve: %w", err)
    }

    s, err := server.New(cfg)
    if err != nil {
        return fmt.Errorf("serve: %w", err)
    }

    if err := s.Run(); err != nil {
        return fmt.Errorf("serve: %w", err)
    }

    return nil
}
```

---

## Verification commands

```bash
cd /home/rocket/Projects/gear-engine && make build && make test
```

- `make build` → `go build -o bin/gear ./cmd/gear/` must succeed with no errors.
- `make test` → `go test -count=1 ./...` must pass all existing tests.

---

## Verification result (task 12.1)

**Ran:** `cd /home/rocket/Projects/gear-engine && go build -o bin/gear ./cmd/gear/` and `go test -count=1 -timeout 300s ./... > /tmp/gear-test-output.txt 2>&1`

**Build:** PASS (exit 0)

**Tests:**
```
?   github.com/gear/engine/cmd/gear        [no test files]
ok  github.com/gear/engine/internal/cli    0.576s
?   github.com/gear/engine/internal/config [no test files]
ok  github.com/gear/engine/internal/crypto 4.498s
?   github.com/gear/engine/internal/database [no test files]
ok  github.com/gear/engine/internal/handler 0.004s
ok  github.com/gear/engine/internal/middleware 0.010s
?   github.com/gear/engine/internal/model  [no test files]
?   github.com/gear/engine/internal/server [no test files]
ok  github.com/gear/engine/internal/service 5.724s
ok  github.com/gear/engine/internal/validate 0.007s
exit:0
```

All 6 test packages: **PASS**. Binary compiled successfully.
