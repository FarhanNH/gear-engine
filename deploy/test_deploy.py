"""Exercise deployment state changes without Docker, SSH, or production access."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class DeployTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copy(Path(__file__).with_name("deploy.sh"), self.root / "deploy.sh")
        (self.root / "engine.env").write_text("GEAR_DB_PATH=/app/data/gear.db\n")
        (self.root / "docker-compose.yml").write_text("services: {}\n")
        self.original = "# keep comment\nENGINE_TAG=bootstrap-20261015-000000\nUI_TAG=v1.0.0\nEXTRA=keep\n"
        (self.root / ".env").write_text(self.original)
        mock = self.root / "bin"
        mock.mkdir()
        self.env = dict(os.environ, PATH=f"{mock}:{os.environ['PATH']}", LOG=str(self.root / "calls"))
        (mock / "docker").write_text('''#!/usr/bin/env bash
set -eu
echo "${ENGINE_TAG:-baseline}|${UI_TAG:-baseline}|$*" >> "$LOG"
if [[ "$*" == 'exec gear-redis redis-cli ping' ]]; then echo PONG; fi
if [[ "$*" == 'exec gear-ui nginx -t' && ${FAIL_VERIFY_ONCE:-0} == 1 && ! -f "$LOG.verify" ]]; then touch "$LOG.verify"; exit 1; fi
if [[ "$*" == *' pull '* && ${FAIL_PULL:-0} == 1 ]]; then exit 1; fi
if [[ "$*" == *' up '* && ${ENGINE_TAG:-${UI_TAG:-}} == v9.9.9 ]]; then exit 1; fi
''')
        (mock / "curl").write_text('''#!/usr/bin/env bash
if [[ "$*" == *'/v1/token' ]]; then printf 401; else printf 200; fi
''')
        for file in mock.iterdir():
            file.chmod(0o755)

    def run_deploy(self, service="gear-engine", version="v1.2.3"):
        return subprocess.run(["bash", str(self.root / "deploy.sh"), service, version],
                              env=self.env, capture_output=True, text=True)

    def test_engine_success_preserves_ui_and_extra_values(self):
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / ".env").read_text(), self.original.replace(
            "ENGINE_TAG=bootstrap-20261015-000000", "ENGINE_TAG=v1.2.3"))
        calls = (self.root / "calls").read_text()
        self.assertIn("pull gear-engine", calls)
        self.assertIn("--wait-timeout 120 gear-engine", calls)
        self.assertIn("exec gear-ui nginx -s reload", calls)
        self.assertNotIn("--wait-timeout 120 gear-ui", calls)

    def test_ui_success_preserves_engine(self):
        result = self.run_deploy("gear-ui")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / ".env").read_text(), self.original.replace(
            "UI_TAG=v1.0.0", "UI_TAG=v1.2.3"))

    def test_failure_restores_previous_image_without_publishing_state(self):
        result = self.run_deploy(version="v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / ".env").read_text(), self.original)
        calls = (self.root / "calls").read_text()
        self.assertIn("v9.9.9|baseline|compose", calls)
        self.assertIn("baseline|baseline|compose --project-name projects --env-file .env -f docker-compose.yml up", calls)
        self.assertEqual(list(self.root.glob(".env.next.*")), [])

    def test_pull_failure_does_not_replace_container_or_state(self):
        self.env["FAIL_PULL"] = "1"
        result = self.run_deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / ".env").read_text(), self.original)
        self.assertNotIn(" up ", (self.root / "calls").read_text())

    def test_smoke_failure_triggers_rollback(self):
        self.env["FAIL_VERIFY_ONCE"] = "1"
        result = self.run_deploy()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / ".env").read_text(), self.original)
        calls = (self.root / "calls").read_text()
        self.assertIn("baseline|baseline|compose --project-name projects --env-file .env -f docker-compose.yml up", calls)
        self.assertIn("exec gear-ui nginx -s reload", calls)

    def test_two_repositories_preserve_both_tag_updates(self):
        command = ["bash", str(self.root / "deploy.sh")]
        first = subprocess.Popen(command + ["gear-engine", "v2.0.0"], env=self.env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        second = subprocess.Popen(command + ["gear-ui", "v3.0.0"], env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for process in [first, second]:
            _, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
        state = (self.root / ".env").read_text()
        self.assertIn("ENGINE_TAG=v2.0.0", state)
        self.assertIn("UI_TAG=v3.0.0", state)
        self.assertIn("EXTRA=keep", state)

    def test_bootstrap_rollback_uses_local_image(self):
        result = self.run_deploy(version="bootstrap-20261015-000000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(" pull ", (self.root / "calls").read_text())

    def test_rejects_invalid_service_or_tag_before_docker(self):
        for service, version in [("redis", "v1.2.3"), ("gear-engine", "v1.2.3;id")]:
            with self.subTest(service=service, version=version):
                self.assertEqual(self.run_deploy(service, version).returncode, 2)
        self.assertFalse((self.root / "calls").exists())


if __name__ == "__main__":
    unittest.main()
