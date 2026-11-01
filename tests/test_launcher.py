"""Launcher tests: keyveil.sh with stub decrypt commands (no real keys, no network)."""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(shutil.which("bash"), "bash required")
class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.port = free_port()
        # Run a copy of the launcher from a temp dir (src/ symlinked) so the repo's own
        # keyveil.conf / routes.json / .env.age are never picked up by tests.
        self.launcher = Path(self.tmp, "keyveil.sh")
        shutil.copy(REPO / "keyveil.sh", self.launcher)
        Path(self.tmp, "src").symlink_to(REPO / "src")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(lambda: self.run_launcher("stop"))

    def run_launcher(self, cmd, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith("KEYVEIL_")}
        env.update(KEYVEIL_PORT=str(self.port), XDG_CACHE_HOME=self.tmp,
                   XDG_CONFIG_HOME=self.tmp, KEYVEIL_ROUTES=os.path.join(self.tmp, "none.json"))
        env.update(extra)
        return subprocess.run(["bash", str(self.launcher), cmd], env=env, capture_output=True,
                              text=True, timeout=30, stdin=subprocess.DEVNULL)

    def log(self):
        return (Path(self.tmp) / "keyveil.log").read_text()

    def status_code(self, path):
        try:
            return urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path)).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_custom_decrypt_cmd_start_status_stop(self):
        r = self.run_launcher("start", KEYVEIL_DECRYPT_CMD="printf 'DEEPSEEK_API_KEY=k\\n'")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("routes=deepseek", self.log())
        self.assertEqual(self.status_code("/nope/x"), 404)       # proxy is answering
        self.assertIn("running", self.run_launcher("status").stdout)
        self.run_launcher("stop")
        time.sleep(0.3)
        self.assertIn("not running", self.run_launcher("status").stdout)

    def test_default_age_path_still_works(self):
        fake = Path(self.tmp, "fakeage")
        fake.write_text('#!/bin/sh\nprintf "OPENAI_API_KEY=k\\n"\n')
        fake.chmod(0o755)
        Path(self.tmp, "id").touch()
        Path(self.tmp, "env.age").touch()
        r = self.run_launcher("start", KEYVEIL_AGE=str(fake), KEYVEIL_IDENTITY=str(Path(self.tmp, "id")),
                              KEYVEIL_ENV_FILE=str(Path(self.tmp, "env.age")))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("routes=openai", self.log())

    def test_failures_are_reported_and_nothing_starts(self):
        for cmd in ("false", "true"):                            # fails / prints nothing
            r = self.run_launcher("start", KEYVEIL_DECRYPT_CMD=cmd)
            self.assertNotEqual(r.returncode, 0, cmd)
            self.assertIn("not running", self.run_launcher("status").stdout)
        r = self.run_launcher("start")                           # nothing configured at all
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("KEYVEIL_DECRYPT_CMD", r.stderr)


if __name__ == "__main__":
    unittest.main()
