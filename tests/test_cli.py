"""CLI tests: run `python -m keyveil` in an isolated sandbox (own HOME/XDG dirs, free port,
stub decrypt commands). No YubiKey, no network, no real keys; never touches port 8787."""
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
import urllib.error
import urllib.request
from pathlib import Path

SECRET = "sk-test-SECRET-0123456789"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


@unittest.skipUnless(sys.platform.startswith("linux"), "keyveil supports Linux only")
class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.port = free_port()
        for d in ("home", "run"):
            (self.tmp / d).mkdir(mode=0o700)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("KEYVEIL_", "XDG_"))}
        self.env.update(HOME=str(self.tmp / "home"),
                        XDG_CONFIG_HOME=str(self.tmp / "config"),
                        XDG_STATE_HOME=str(self.tmp / "state"),
                        XDG_RUNTIME_DIR=str(self.tmp / "run"))
        self.secret_file = self.write("plain.env", "DEEPSEEK_API_KEY=%s\n" % SECRET)
        self.pidfile = self.tmp / "run" / "keyveil" / ("%d.pid" % self.port)
        self.addCleanup(self.kill_proxy)

    # -- helpers
    def write(self, name, text, mode=None):
        path = self.tmp / name
        path.write_text(text)
        if mode:
            path.chmod(mode)
        return path

    def keyveil(self, *args):
        return subprocess.run([sys.executable, "-m", "keyveil", *args], env=self.env,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=30)

    def config(self, command=None, top=""):
        """Write the default-location config with a [decrypt] command (default: cat the stub)."""
        command = command or "cat %s" % self.secret_file
        return self.config_text('port = %d\n%s\n[decrypt]\ncommand = \'%s\'\n'
                                % (self.port, top, command))

    def config_text(self, text):
        path = self.tmp / "config" / "keyveil" / "config.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def kill_proxy(self):
        self.keyveil("stop")
        try:
            os.kill(int(self.pidfile.read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass

    def status_code(self, path):
        try:
            return urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path)).status
        except urllib.error.HTTPError as e:
            return e.code

    def assert_no_secret(self, *results):
        for r in results:
            self.assertNotIn(SECRET, r.stdout + r.stderr)


class LifecycleTests(CliTestCase):
    def test_start_status_stop(self):
        # A shell feature in the command proves it runs through /bin/sh.
        self.config(command='printf "DEEPSEEK_API_KEY=%%s\\n" "$(cat %s | cut -d= -f2)"'
                    % self.secret_file)
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)
        s = self.keyveil("status")
        self.assertEqual((s.returncode, "running" in s.stdout), (0, True), s.stdout)
        self.assertEqual(self.status_code("/nope/x"), 404)            # the proxy answers
        again = self.keyveil("start")
        self.assertEqual(again.returncode, 0)
        self.assertIn("already running", again.stdout)
        stop = self.keyveil("stop")
        self.assertEqual((stop.returncode, stop.stdout.strip()), (0, "stopped"))
        self.assertFalse(port_open(self.port))
        self.assertEqual(self.keyveil("status").returncode, 3)
        again = self.keyveil("stop")
        self.assertEqual((again.returncode, again.stdout.strip()), (0, "not running"))

    def test_decrypt_cmd_flag_overrides_the_config(self):
        self.config(command="false")
        r = self.keyveil("start", "--decrypt-cmd", "cat %s" % self.secret_file)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_init_writes_a_valid_template_and_never_overwrites(self):
        r = self.keyveil("init")
        path = self.tmp / "config" / "keyveil" / "config.toml"
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(tomllib.loads(path.read_text()), {"port": 8787})
        path.write_text("port = 1234\n")
        r = self.keyveil("init")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already exists", r.stderr)
        self.assertEqual(path.read_text(), "port = 1234\n")


class FailureTests(CliTestCase):
    def test_decrypt_failures_start_nothing_and_leak_nothing(self):
        cases = {
            "false": "decryption failed",
            "exit 3": "exit status 3",
            "true": "printed nothing",
            "/nonexistent/cmd": "decryption failed",
            "cat %s; exit 1" % self.secret_file: "decryption failed",   # prints secret, then fails
        }
        for command, message in cases.items():
            self.config(command=command)
            r = self.keyveil("start")
            self.assertEqual(r.returncode, 1, command)
            self.assertIn(message, r.stderr, command)
            self.assertFalse(port_open(self.port), command)
            self.assert_no_secret(r)

    def test_age_mode_problems_are_explained(self):
        enc = self.write("keys.age", "x")
        ident = self.write("id.txt", "x")
        self.config_text('port = %d\n[age]\nbinary = "/nonexistent/age"\nfile = "%s"\n'
                         % (self.port, enc))
        self.assertIn("no key source configured", self.keyveil("start").stderr)
        self.config_text('port = %d\n[age]\nidentity = "%s"\nfile = "%s"\nbinary = "/nonexistent/age"\n'
                         % (self.port, ident, enc))
        self.assertIn("cannot run", self.keyveil("start").stderr)
        self.config_text('port = %d\n[age]\nidentity = "%s"\nfile = "%s"\n'
                         % (self.port, ident, self.tmp / "missing.age"))
        self.assertIn("encrypted file not found", self.keyveil("start").stderr)

    def test_proxy_that_exits_early_is_reported_by_variable_names_only(self):
        other = self.write("other.env", "OTHER=whatever-value\n")
        self.config(command="cat %s" % other)
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no usable keys", r.stderr)
        self.assertIn("OTHER", r.stderr)
        self.assertNotIn("whatever-value", r.stdout + r.stderr)

    def test_bad_routes_file_is_reported_and_nothing_starts(self):
        routes = self.write("routes.json",
                            '{"routes": {"x": {"upstream": "http://evil.example.com", "env": "K"}}}')
        self.config(top='routes_file = "%s"' % routes)
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 1)
        self.assertIn("bad routes file", r.stderr)
        self.assertFalse(port_open(self.port))

    def test_port_in_use_by_another_process_is_refused(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", self.port))
        sock.listen()
        self.addCleanup(sock.close)
        self.config()
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already in use", r.stderr)
        self.assertEqual(self.keyveil("status").returncode, 3)         # not ours

    def test_bad_config_is_a_clean_error(self):
        self.config_text("port = = 1\n")
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 1)
        self.assertIn("invalid TOML", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


class PidFileTests(CliTestCase):
    def test_stale_pid_file_is_cleaned_up(self):
        dead = subprocess.Popen(["true"])
        dead.wait()
        self.pidfile.parent.mkdir(parents=True, exist_ok=True)
        self.pidfile.write_text("%d\n" % dead.pid)
        self.config()
        r = self.keyveil("stop")
        self.assertEqual(r.returncode, 0)
        self.assertIn("stale", r.stdout)
        self.assertFalse(self.pidfile.exists())

    def test_stop_never_signals_an_unrelated_process(self):
        other = subprocess.Popen(["sleep", "60"])
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        self.pidfile.parent.mkdir(parents=True, exist_ok=True)
        self.pidfile.write_text("%d\n" % other.pid)
        self.config()
        r = self.keyveil("stop")
        self.assertEqual(r.returncode, 0)
        self.assertIn("stale", r.stdout)
        time.sleep(0.2)
        self.assertIsNone(other.poll(), "stop killed a process that is not keyveil")


class SecretHygieneTests(CliTestCase):
    def test_the_key_is_only_in_the_proxy_process_memory(self):
        self.config()
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_no_secret(r)
        pid = int(self.pidfile.read_text())
        self.assertRegex(self.pidfile.read_text(), r"^\d+\n?$")        # a pid, nothing else
        cmdline = Path("/proc/%d/cmdline" % pid).read_bytes()
        self.assertIn(b"keyveil.proxy", cmdline)
        self.assertNotIn(SECRET.encode(), cmdline)
        with self.assertRaises(PermissionError):                         # dumpable=0
            Path("/proc/%d/environ" % pid).read_bytes()
        # The key must not be in any file the CLI or proxy wrote (only our own stub holds it).
        for path in self.tmp.rglob("*"):
            if path.is_file() and path != self.secret_file:
                self.assertNotIn(SECRET.encode(), path.read_bytes(), str(path))


class RunTests(CliTestCase):
    def test_run_stdin_serves_and_exits_cleanly_on_sigterm(self):
        proc = subprocess.Popen([sys.executable, "-m", "keyveil", "run", "--stdin",
                                 "--port", str(self.port)], env=self.env, text=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        self.addCleanup(proc.kill)
        self.addCleanup(lambda: [f.close() for f in (proc.stdin, proc.stdout, proc.stderr)])
        proc.stdin.write("DEEPSEEK_API_KEY=%s\n" % SECRET)
        proc.stdin.close()
        deadline = time.monotonic() + 5
        while not port_open(self.port) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.status_code("/nope/x"), 404)
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertNotIn(SECRET, proc.stdout.read() + proc.stderr.read())


class AgeStubTests(CliTestCase):
    def test_age_is_called_with_exactly_the_documented_arguments(self):
        enc, ident = self.write("keys.age", "x"), self.write("id.txt", "x")
        stub = self.write("fakeage", '#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/argv.txt"\n'
                          'printf "OPENAI_API_KEY=k\\n"\n', mode=0o755)
        self.config_text('port = %d\n[age]\nidentity = "%s"\nfile = "%s"\nbinary = "%s"\n'
                         % (self.port, ident, enc, stub))
        r = self.keyveil("start")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.tmp / "argv.txt").read_text().split("\n")[:-1],
                         ["-d", "-i", str(ident), str(enc)])
        log = (self.tmp / "state" / "keyveil" / "keyveil.log").read_text()
        self.assertIn("routes=openai", log)


if __name__ == "__main__":
    unittest.main()
