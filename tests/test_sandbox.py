"""`keyveil sandbox` tests. Unit tests inspect the bwrap command line; live tests run a probe
script inside a real sandbox with a throwaway HOME (created inside the repo, not under /tmp,
because the sandbox replaces /tmp and that would make "hidden" checks pass trivially)."""

import dataclasses
import os
import shlex
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


def slirp_works():
    return bool(shutil.which("slirp4netns")) and Path("/dev/net/tun").exists()


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
        ):
            with self.assertRaises(sandbox.SandboxError, msg=bad):
                self.build(extra_rw=[str(bad)])
            with self.assertRaises(sandbox.SandboxError, msg=bad):
                self.build(cfg=dataclasses.replace(self.cfg, sandbox_rw=(bad,)))
        # A key file that doesn't exist yet inside a writable folder: the agent could plant one.
        cfg = dataclasses.replace(self.cfg, age_file=self.project / "keys/missing.age")
        with self.assertRaises(sandbox.SandboxError):
            self.build(cfg=cfg)
        # An existing one is fine: hidden after the binds, its parent directories pinned.
        (self.project / "keys/env.age").write_text("ENCRYPTED\n")
        cfg = dataclasses.replace(self.cfg, age_file=self.project / "keys/env.age")
        argv, _, _ = self.build(cfg=cfg)
        pin = argv.index(str(self.project / "keys"))
        self.assertEqual(argv[pin - 1 : pin + 2], ["--bind", *[str(self.project / "keys")] * 2])
        self.build(extra_rw=[str(self.home / "keys")])  # contains the existing key file
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
        command = ["sh", "-c", "echo 'a b'", "--", "-x"]
        argv, _, _ = self.build(command=command, network="host")
        self.assertEqual(argv[argv.index("--") + 1 :], command)
        self.assertEqual(argv[0], "bwrap")
        # With its own network the command is started by the proxy relay, unchanged.
        argv, _, _ = self.build(command=command, port=9999)
        inner = argv[argv.index("--") + 1 :]
        self.assertEqual(
            inner[1:6], ["-I", "/run/keyveil/bridge.py", "9999", "/run/keyveil/proxy.sock", "--"]
        )
        self.assertEqual(inner[6:], command)

    def test_network_modes(self):
        bridge = self.root / "bridge"
        for mode in ("isolated", "none"):
            argv, _, warnings = self.build(network=mode, bridge_dir=bridge)
            self.assertIn("--unshare-net", argv)
            i = argv.index(str(bridge))
            self.assertEqual(argv[i - 1 : i + 2], ["--ro-bind", str(bridge), "/run/keyveil"])
            self.assertEqual(
                str(bridge / "resolv.conf") in argv, mode == "isolated", mode
            )  # slirp's DNS only where there is a network to use it
            self.assertFalse(any("--network host" in w for w in warnings))
        argv, _, warnings = self.build(network="host", bridge_dir=bridge)
        self.assertNotIn("--unshare-net", argv)
        self.assertNotIn(str(bridge), argv)
        self.assertTrue(any("X11" in w for w in warnings))
        with self.assertRaises(sandbox.SandboxError):
            self.build(network="bogus")

    def test_relay_interpreter_is_never_a_hidden_one(self):
        hidden = [Path(os.path.realpath(sys.executable)).parent]
        self.assertEqual(sandbox._bridge_python(hidden), "/usr/bin/python3")


@unittest.skipUnless(
    sys.platform.startswith("linux") and bwrap_works(),
    "bubblewrap with unprivileged user namespaces is required",
)
class LiveTests(SandboxCase):
    # "none" needs no slirp4netns or /dev/net/tun, so the general confinement tests run
    # anywhere bwrap does; IsolatedNetworkTests covers the default "isolated" mode.
    network = "none"

    def run_inside(self, script, *extra, env=None, port=8787):
        cfg_file = self.home / ".config/keyveil/config.toml"
        age_file = getattr(self, "age_file", self.home / "keys/env.age")
        cfg_file.write_text(
            'port = %d\n[age]\nidentity = "%s"\nfile = "%s"\n'
            % (port, self.home / "id.txt", age_file)
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "keyveil",
                "sandbox",
                "--project",
                str(self.project),
                "--network",
                self.network,
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

    def test_key_file_inside_the_project_cant_be_read_or_swapped(self):
        # e.g. ~/project/.env.age as the age file: hidden, and its folder pinned so that
        # `mv keys keys.old && mkdir keys` can't put a planted file at the configured path.
        key = self.project / "keys" / "env.age"
        key.parent.mkdir()
        key.write_text("ENCRYPTED\n")
        self.age_file = key
        out = self.run_inside(r"""
            echo "read=$(cat keys/env.age 2>/dev/null)"
            echo "rm=$( (rm -f keys/env.age) 2>/dev/null && echo yes || echo no)"
            echo "mvdir=$( (mv keys keys.old) 2>/dev/null && echo yes || echo no)"
            echo "mvfile=$( (mv keys/env.age x) 2>/dev/null && echo yes || echo no)"
        """)
        self.assertEqual(out, {"read": "", "rm": "no", "mvdir": "no", "mvfile": "no"})
        self.assertEqual(key.read_text(), "ENCRYPTED\n")

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

    def host_server(self, greeting=b""):
        """A TCP server on the host's 127.0.0.1 that sends ``greeting`` to each client."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        self.addCleanup(srv.close)

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                conn.sendall(greeting)
                conn.close()

        threading.Thread(target=loop, daemon=True).start()
        return srv.getsockname()[1]

    def test_network_only_the_proxy_on_loopback(self):
        # Audit regressions: the agent reached every host loopback service and the abstract
        # socket of the X server (keystroke injection), and could squat the proxy's port.
        proxy_port = self.host_server(b"proxy-hello")
        other_port = self.host_server(b"other")
        abstract = socket.socket(socket.AF_UNIX)
        abstract.bind("\0keyveil-test-%d" % os.getpid())
        abstract.listen()
        self.addCleanup(abstract.close)
        probe = (
            "import socket\n"
            "s = socket.socket(socket.AF_UNIX)\n"
            "try:\n    s.connect('\\0keyveil-test-%d'); print('abstract=yes')\n"
            "except OSError:\n    print('abstract=no')\n" % os.getpid()
        )
        out = self.run_inside(
            'echo "proxy=$( (exec 3<>/dev/tcp/127.0.0.1/%d; head -c 11 <&3) 2>/dev/null)"\n'
            'echo "other=$( (exec 3<>/dev/tcp/127.0.0.1/%d) 2>/dev/null && echo yes '
            '|| echo no)"\n'
            "python3 -c %s\n" % (proxy_port, other_port, shlex.quote(probe)),
            port=proxy_port,
        )
        self.assertEqual(out, {"proxy": "proxy-hello", "other": "no", "abstract": "no"})

    def test_processes_invisible_env_stripped(self):
        marker = subprocess.Popen(["sleep", "30"])
        self.addCleanup(marker.wait)
        self.addCleanup(marker.kill)
        out = self.run_inside(
            'echo "seen=$([ -d /proc/%d ] && echo yes || echo no)"\n'
            'echo "foo=${FOO_API_KEY-unset}"\necho "kept=${KEEP_TOKEN-unset}"\n' % marker.pid,
            "--keep-env",
            "KEEP_TOKEN",
            env={"FOO_API_KEY": "secret", "KEEP_TOKEN": "fine"},
        )
        self.assertEqual(out, {"seen": "no", "foo": "unset", "kept": "fine"})

    def test_exit_status_is_the_agents(self):
        cfg_file = self.home / ".config/keyveil/config.toml"
        cfg_file.write_text("")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "keyveil",
                "sandbox",
                "--project",
                str(self.project),
                "--network",
                self.network,
                "--",
                "sh",
                "-c",
                "exit 7",
            ],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 7, result.stderr)


@unittest.skipUnless(
    sys.platform.startswith("linux") and bwrap_works() and slirp_works(),
    "slirp4netns and /dev/net/tun are required for the isolated network mode",
)
class IsolatedNetworkTests(LiveTests):
    """The same live tests in the default mode, plus what only slirp4netns provides."""

    network = "isolated"

    def test_host_loopback_unreachable_through_slirp_gateway(self):
        port = self.host_server(b"x")
        out = self.run_inside(
            'echo "gw=$( (exec 3<>/dev/tcp/10.0.2.2/%d) 2>/dev/null && echo yes '
            '|| echo no)"\n'
            # /proc is this namespace's own; /sys is the host's sysfs, bound in with /.
            'echo "tap=$(grep -q "tap0:" /proc/net/dev && echo yes || echo no)"\n'
            'echo "dns=$(cat /etc/resolv.conf)"\n' % port
        )
        self.assertEqual(out, {"gw": "no", "tap": "yes", "dns": "nameserver 10.0.2.3"})


if __name__ == "__main__":
    unittest.main()
