"""`keyveil sandbox` tests. Unit tests inspect the bwrap command line; live tests run a probe
script inside a real sandbox with a throwaway HOME (created inside the repo, not under /tmp,
because the sandbox replaces /tmp and that would make "hidden" checks pass trivially)."""

import dataclasses
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from keyveil import config, proxy, sandbox

REPO = Path(__file__).resolve().parent.parent


def bwrap_works():
    if not shutil.which("bwrap"):
        return False
    return (
        subprocess.run(
            ["bwrap", "--ro-bind", "/", "/", "--", "true"], capture_output=True
        ).returncode
        == 0
    )


class SandboxCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix=".sandbox-test-", dir=REPO))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / "home"
        self.project = self.home / "proj"
        (self.project / ".git" / "hooks").mkdir(parents=True)
        (self.project / ".git" / "config").write_text("[core]\n")
        for rel, text in {
            ".bashrc": "original\n",
            ".ssh/id_ed25519": "PRIVATE-KEY\n",
            "keys/env.age": "ENCRYPTED\n",
            "id.txt": "IDENTITY\n",
            ".claude/settings.json": "{}\n",
            ".config/keyveil/config.toml": "\n",
            ".local/bin/tool": "#!/bin/sh\n",
        }.items():
            (self.home / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.home / rel).write_text(text)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("XDG_", "KEYVEIL_"))}
        self.env.update(
            HOME=str(self.home),
            XDG_CONFIG_HOME=str(self.home / ".config"),
            XDG_STATE_HOME=str(self.home / ".local/state"),
        )
        self.cfg = config.Config(
            age_file=self.home / "keys/env.age", age_identity=self.home / "id.txt"
        )

    def build(self, command=("true",), **kw):
        kw.setdefault("project", self.project)
        kw.setdefault("cfg", self.cfg)
        kw.setdefault("home", self.home)
        kw.setdefault("environ", {})
        kw.setdefault("prefix", "/usr")
        return sandbox.build(list(command), **kw)


class BuildTests(SandboxCase):
    def test_refuses_dangerous_project_directories(self):
        for bad in (self.home, self.root, Path("/")):
            with self.assertRaises(sandbox.SandboxError, msg=bad):
                self.build(project=bad)
        with self.assertRaises(sandbox.SandboxError):
            self.build(project=self.home / "missing")
        with self.assertRaises(sandbox.SandboxError):
            self.build(command=())

    @mock.patch.dict(os.environ)
    def test_refuses_writable_paths_that_would_expose_protected_ones(self):
        os.environ["XDG_CONFIG_HOME"] = str(self.home / ".config")
        (self.home / ".config/git").mkdir(parents=True)
        (self.project / "keys").mkdir()
        for bad in (
            self.home,  # $HOME itself: ~/.bashrc, ~/.ssh, ...
            self.root,  # a parent of $HOME
            self.home / ".config",  # contains keyveil's config and ~/.config/git
            self.home / ".config/keyveil",  # keyveil's config itself (even if it existed)
            self.home / ".ssh/sub",  # inside a hidden directory
            self.home / ".local",  # contains ~/.local/bin (on PATH)
            self.home / "keys",  # contains the encrypted key file
        ):
            with self.assertRaises(sandbox.SandboxError, msg=bad):
                self.build(extra_rw=[str(bad)])
            with self.assertRaises(sandbox.SandboxError, msg=bad):
                self.build(cfg=dataclasses.replace(self.cfg, sandbox_rw=(bad,)))
        # The key file inside the project would make the project unsafe too.
        cfg = dataclasses.replace(self.cfg, age_file=self.project / "keys/env.age")
        with self.assertRaises(sandbox.SandboxError):
            self.build(cfg=cfg)
        # A harmless sibling is fine.
        (self.home / "cache-dir").mkdir()
        self.build(extra_rw=[str(self.home / "cache-dir")])

    def test_every_hide_comes_after_every_writable_bind(self):
        (self.home / "cache-dir").mkdir()
        argv, _, _ = self.build(extra_rw=[str(self.home / "cache-dir")], extra_hide=["/etc"])
        binds = [i for i, a in enumerate(argv) if a == "--bind"]
        hides = [
            i
            for i, a in enumerate(argv)
            if (a == "--tmpfs" and argv[i + 1] not in ("/run", "/tmp", str(self.home / ".cache")))
            or (a == "--ro-bind" and argv[i + 1] == "/dev/null")
        ]
        self.assertTrue(binds and hides)
        self.assertLess(max(binds), min(hides))
        hidden = {argv[i + 1] if argv[i] == "--tmpfs" else argv[i + 2] for i in hides}
        for path in (self.home / ".ssh", self.home / "keys/env.age", self.home / "id.txt"):
            self.assertIn(str(path), hidden)

    def test_secret_environment_is_removed_and_reported(self):
        env = {
            "FOO_API_KEY": "1",
            "GITHUB_TOKEN": "2",
            "AWS_PROFILE": "x",
            "DB_PASSWORD": "3",
            "MY_SECRET": "4",
            "PATH": "/bin",
            "HOME": "/h",
            "TOKENIZERS_PARALLELISM": "1",
            proxy.ROUTES["deepseek"][1]: "5",
        }
        argv, removed, _ = self.build(environ=env)
        self.assertEqual(
            removed,
            sorted(
                [
                    "FOO_API_KEY",
                    "GITHUB_TOKEN",
                    "AWS_PROFILE",
                    "DB_PASSWORD",
                    "MY_SECRET",
                    "DEEPSEEK_API_KEY",
                ]
            ),
        )
        unset = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--unsetenv"]
        self.assertEqual(sorted(unset), removed)
        _, removed, _ = self.build(environ=env, keep_env=("GITHUB_TOKEN",))
        self.assertNotIn("GITHUB_TOKEN", removed)

    def test_ssh_agent_requires_a_socket(self):
        with self.assertRaises(sandbox.SandboxError):
            self.build(ssh_agent=True, environ={})

    def test_command_comes_last_and_unchanged(self):
        argv, _, _ = self.build(command=["sh", "-c", "echo 'a b'", "--", "-x"])
        self.assertEqual(argv[argv.index("--") + 1 :], ["sh", "-c", "echo 'a b'", "--", "-x"])
        self.assertEqual(argv[0], "bwrap")


@unittest.skipUnless(
    sys.platform.startswith("linux") and bwrap_works(),
    "bubblewrap with unprivileged user namespaces is required",
)
class LiveTests(SandboxCase):
    def run_inside(self, script, *extra, env=None):
        cfg_file = self.home / ".config/keyveil/config.toml"
        cfg_file.write_text(
            '[age]\nidentity = "%s"\nfile = "%s"\n'
            % (self.home / "id.txt", self.home / "keys/env.age")
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "keyveil",
                "sandbox",
                "--project",
                str(self.project),
                *extra,
                "--",
                "bash",
                "-c",
                script,
            ],  # bash: the probes use /dev/tcp
            env={**self.env, **(env or {})},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)

    def test_confinement(self):
        out = self.run_inside(r"""
            echo "nnp=$(grep NoNewPrivs /proc/self/status | cut -f2)"
            echo "docker=$([ -e /run/docker.sock ] && echo yes || echo no)"
            echo "bashrc=$( (echo pwned >> ~/.bashrc) 2>/dev/null && echo yes || echo no)"
            echo "localbin=$( (echo x > ~/.local/bin/tool) 2>/dev/null && echo yes || echo no)"
            echo "project=$( (echo ok > ./made-inside) 2>/dev/null && echo yes || echo no)"
            echo "hooks=$( (echo x > .git/hooks/pre-commit) 2>/dev/null && echo yes || echo no)"
            echo "gitconfig=$( (echo x >> .git/config) 2>/dev/null && echo yes || echo no)"
            echo "claude_state=$( (echo x > ~/.claude/new) 2>/dev/null && echo yes || echo no)"
            echo "ssh=$(cat ~/.ssh/id_ed25519 2>/dev/null)"
            echo "agefile=$(cat ~/keys/env.age 2>/dev/null)"
            echo "identity=$(cat ~/id.txt 2>/dev/null)"
            echo "kvconfig=$(ls -A ~/.config/keyveil | wc -l)"
            echo "pwd=$(pwd)"
        """)
        self.assertEqual(out["nnp"], "1")
        self.assertEqual(out["docker"], "no")
        for key in ("bashrc", "localbin", "hooks", "gitconfig"):
            self.assertEqual(out[key], "no", key)
        for key in ("project", "claude_state"):
            self.assertEqual(out[key], "yes", key)
        for key in ("ssh", "agefile", "identity"):
            self.assertEqual(out[key], "", key)
        self.assertEqual(out["kvconfig"], "0")
        self.assertEqual(out["pwd"], str(self.project))
        # Effects as seen from the host:
        self.assertEqual((self.home / ".bashrc").read_text(), "original\n")
        self.assertEqual((self.project / "made-inside").read_text(), "ok\n")
        self.assertFalse((self.project / ".git/hooks/pre-commit").exists())
        self.assertTrue((self.home / ".claude/new").exists())

    def test_refuses_a_writable_parent_of_keyveil_config(self):
        # Audit regression: --rw ~/.config used to re-expose ~/.config/keyveil read-write.
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "keyveil",
                "sandbox",
                "--project",
                str(self.project),
                "--rw",
                str(self.home / ".config"),
                "--",
                "true",
            ],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("refusing to make", result.stderr)

    def test_hide_works_for_a_file_inside_a_writable_directory(self):
        # e.g. `--hide ~/.claude/.credentials.json` while ~/.claude itself is writable.
        creds = self.home / ".claude" / ".credentials.json"
        creds.write_text("OAUTH-TOKEN\n")
        out = self.run_inside(
            r"""
            echo "creds=$(cat ~/.claude/.credentials.json 2>/dev/null)"
            s=~/.claude/settings.json
            echo "sibling=$( (echo x > "$s") 2>/dev/null && echo writable || echo no)"
        """,
            "--hide",
            str(creds),
        )
        self.assertEqual(out, {"creds": "", "sibling": "writable"})
        self.assertEqual(creds.read_text(), "OAUTH-TOKEN\n")  # untouched on the host

    def test_loopback_reachable_processes_invisible_env_stripped(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()
        marker = subprocess.Popen(["sleep", "30"])
        self.addCleanup(marker.wait)
        self.addCleanup(marker.kill)
        out = self.run_inside(
            'echo "loopback=$( (exec 3<>/dev/tcp/127.0.0.1/%d) 2>/dev/null && echo yes '
            '|| echo no)"\n'
            'echo "seen=$([ -d /proc/%d ] && echo yes || echo no)"\n'
            'echo "foo=${FOO_API_KEY-unset}"\necho "kept=${KEEP_TOKEN-unset}"\n'
            % (port, marker.pid),
            "--keep-env",
            "KEEP_TOKEN",
            env={"FOO_API_KEY": "secret", "KEEP_TOKEN": "fine"},
        )
        self.assertEqual(out, {"loopback": "yes", "seen": "no", "foo": "unset", "kept": "fine"})


if __name__ == "__main__":
    unittest.main()
