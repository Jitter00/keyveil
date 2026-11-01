"""`keyveil sandbox -- <agent>`: run an AI agent under bubblewrap (bwrap).

The agent keeps using your real tools and can edit the project, and it can still reach the
keyveil proxy on 127.0.0.1. What it can no longer do:
  * become root: no_new_privs blocks sudo/su/pkexec and setuid binaries;
  * reach Docker / LXD / libvirt / ssh-agent / the desktop keyring: /run and /tmp are private;
  * tamper with what runs outside the sandbox: everything except the project and the agent's
    own state is read-only (~/.bashrc, PATH, keyveil's install and config, .git/hooks, ...);
  * read common secret stores (~/.ssh, ~/.gnupg, cloud CLI credentials, browser profiles...);
  * see or signal other processes (own PID namespace), including the keyveil proxy;
  * reach anything on the host's loopback or abstract Unix sockets (X11, D-Bus, ibus...):
    the agent gets its own network namespace. slirp4netns gives it the internet, and a
    relay gives it the keyveil proxy at the usual 127.0.0.1:<port>, and nothing else.
"""

import fnmatch
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from . import bridge, proxy
from . import config as cfgmod

# --network modes: own namespace with internet (slirp4netns), own namespace with only the
# proxy, or the host's network (no isolation from loopback services or abstract sockets).
NETWORK_MODES = cfgmod.SANDBOX_NETWORKS
BRIDGE_MOUNT = "/run/keyveil"  # where the relay's directory appears inside the sandbox
SLIRP_RESOLV = "nameserver 10.0.2.3\n"  # slirp4netns' built-in DNS forwarder

# Hidden from the agent if they exist (relative to $HOME). Directories get an empty tmpfs,
# files are replaced by /dev/null.
HIDDEN_IN_HOME = (
    ".ssh",
    ".gnupg",
    ".password-store",
    ".local/share/keyrings",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".lesshst",
)
# Writable for the agent if they exist (relative to $HOME): Claude Code's state.
AGENT_STATE = (".claude", ".claude.json")
# Run code later, outside the sandbox (relative to $HOME). Read-only like the rest of $HOME;
# listed so that no writable path (--rw, the project) can contain them.
RUNS_CODE_LATER = (
    ".bashrc",
    ".bash_profile",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".gitconfig",
    ".config/git",
    ".config/autostart",
    ".config/systemd",
    ".config/environment.d",
    ".local/bin",
)
# Environment variables removed before the agent starts (fnmatch, case-sensitive).
SECRET_ENV = (
    "*_API_KEY",
    "*_APIKEY",
    "*_TOKEN",
    "*_SECRET",
    "*_SECRET_*",
    "*SECRET_KEY*",
    "*_PASSWORD",
    "*_PASSWD",
    "AWS_*",
    "AZURE_*",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
)


class SandboxError(Exception):
    """A problem that prevents starting the sandbox; the message is shown to the user."""


def _secret_env_names(environ, route_env_names, keep):
    names = []
    for name in environ:
        if name in keep:
            continue
        if name in route_env_names or any(fnmatch.fnmatchcase(name, p) for p in SECRET_ENV):
            names.append(name)
    return sorted(names)


def _check_writable(path, home, hidden, runs_code, what):
    """Raise SandboxError unless ``path`` is safe to make writable for the agent.

    Refused: /, $HOME and its parents; anything that is or sits inside a hidden or
    code-running path; anything containing a code-running path, or a hidden path that
    doesn't exist yet (the agent could create it: a planted key file or keyveil config).
    An existing hidden path inside it is fine: it is mounted over after the writable binds
    and its parent directories are pinned (see build()), so it can't be read or replaced.
    """
    path = Path(path).resolve()
    if path == home or path in home.parents:
        raise SandboxError(
            "refusing to make %s writable: pick a directory below your home directory" % path
        )
    for p, is_hidden in [*((p, True) for p in hidden), *((p, False) for p in runs_code)]:
        p = Path(p).expanduser().resolve()
        if path == p or p in path.parents:
            relation = "it is" if path == p else "it is inside"
        elif path in p.parents and not (is_hidden and p.exists()):
            relation = "it contains"
        else:
            continue
        missing = (
            " (which doesn't exist yet, so the agent could create it)" if not p.exists() else ""
        )
        raise SandboxError(
            "refusing to make %s writable (%s): %s %s%s, which must stay protected. "
            "Pick a narrower directory." % (path, what, relation, p, missing)
        )


def _pins(hides, roots):
    """Directories to bind onto themselves so no hidden path can be moved aside.

    A mount point can't be renamed or removed, so pinning every directory between a
    writable root and a hidden path stops `mv dir dir.old && mkdir dir` from swapping the
    hidden file for one the agent wrote.
    """
    pins = []
    for hide in hides:
        for root in roots:
            if root in hide.parents:
                d = hide.parent
                while d != root:
                    pins.append(d)
                    d = d.parent
    return sorted(set(pins), key=lambda d: len(d.parts))  # parents first


def _tiocsti_possible():
    """True unless the kernel blocks terminal keystroke injection (dev.tty.legacy_tiocsti=0)."""
    try:
        return Path("/proc/sys/dev/tty/legacy_tiocsti").read_text().strip() != "0"
    except OSError:
        return True  # kernels before 6.2 have no switch: injection is possible


def build(
    command,
    *,
    project,
    cfg,
    home=None,
    environ=None,
    extra_rw=(),
    extra_hide=(),
    keep_env=(),
    ssh_agent=False,
    prefix=None,
    network="isolated",
    port=cfgmod.DEFAULT_PORT,
    bridge_dir=None,
):
    """Return (bwrap argv, removed env var names, warnings). Pure: inspects but never runs.

    Unless ``network`` is "host", the argv expects ``run()`` to have prepared
    ``bridge_dir`` (the proxy relay socket, bridge.py and resolv.conf).
    """
    if not command:
        raise SandboxError("no command given. Usage: keyveil sandbox [options] -- COMMAND [ARGS]")
    if network not in NETWORK_MODES:
        raise SandboxError("unknown network mode %r (use %s)" % (network, ", ".join(NETWORK_MODES)))
    bridge_dir = Path(bridge_dir or default_bridge_dir())
    home = Path(home or Path.home()).resolve()
    environ = os.environ if environ is None else environ
    project = Path(project).resolve()
    if not project.is_dir():
        raise SandboxError("project directory not found: %s" % project)
    warnings = []
    argv = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/tmp",  # noqa: S108 - a mount point inside the sandbox, not a temp file
    ]
    resolv = Path("/etc/resolv.conf").resolve()
    if network == "host":
        # /etc/resolv.conf is often a symlink into /run (systemd-resolved); give back just
        # that file, read-only, so DNS keeps working. The resolver's socket stays hidden.
        if Path("/run") in resolv.parents and resolv.is_file():
            argv += ["--ro-bind", str(resolv), str(resolv)]
        warnings.append(
            "--network host: the agent shares your network namespace, so it can reach every "
            "service on 127.0.0.1 and abstract Unix sockets such as your X11 display (which "
            "lets it type into other windows). Use it only if isolated/none can't work"
        )
    else:
        argv += ["--unshare-net", "--ro-bind", str(bridge_dir), BRIDGE_MOUNT]
        if network == "isolated":  # DNS through slirp4netns
            argv += ["--ro-bind", str(bridge_dir / "resolv.conf"), str(resolv)]
    runtime = environ.get("XDG_RUNTIME_DIR")
    if runtime and Path("/run") in Path(runtime).parents:  # recreate it, empty, on the new /run
        argv += ["--dir", runtime, "--chmod", "0700", runtime]
    if _tiocsti_possible():
        argv.append("--new-session")
        warnings.append(
            "this kernel allows terminal keystroke injection; running the agent "
            "in a new session (some terminal features may not work)"
        )

    # What gets hidden: common secret stores, then keyveil itself (config, log/state, the
    # installed environment, and the key files).
    hidden = [home / rel for rel in HIDDEN_IN_HOME]
    hidden += [cfgmod.config_dir(), cfgmod.state_dir()]
    prefix = Path(prefix or sys.prefix).resolve()
    if home in prefix.parents and prefix != project and project not in prefix.parents:
        hidden.append(prefix)  # e.g. ~/.local/share/uv/tools/keyveil
    hidden += [p for p in (cfg.age_file, cfg.age_identity) if p]

    # Nothing writable may expose a hidden path or a file that runs code later outside the
    # sandbox (see _check_writable).
    runs_code = [home / rel for rel in RUNS_CODE_LATER]
    _check_writable(project, home, hidden, runs_code, what="project directory")
    user_rw = [Path(p).expanduser() for p in (*cfg.sandbox_rw, *extra_rw)]
    for path in user_rw:
        _check_writable(path, home, hidden, runs_code, what="writable path")

    if (home / ".cache").is_dir():
        argv += ["--tmpfs", str(home / ".cache")]  # private scratch; nothing persists

    for path in (*(home / rel for rel in AGENT_STATE), *user_rw):
        if path.exists():
            argv += ["--bind", str(path), str(path)]
        elif path in user_rw:
            warnings.append("writable path does not exist, skipped: %s" % path)

    argv += ["--bind", str(project), str(project)]
    git = project / ".git"
    if git.is_dir():  # these run code later, outside the sandbox
        for rel in ("hooks", "config"):
            if (git / rel).exists():
                argv += ["--ro-bind", str(git / rel), str(git / rel)]

    # Every hide goes after every bind: a later mount covers an earlier one, so this is what
    # keeps a hidden path hidden even inside a writable directory (including user hides of a
    # single file such as ~/.claude/.credentials.json). Pin the directories in between.
    hides = [Path(p) for p in hidden]
    hides += [Path(p).expanduser() for p in (*cfg.sandbox_hide, *extra_hide)]
    roots = [project, *(home / rel for rel in AGENT_STATE), *(p.resolve() for p in user_rw)]
    for d in _pins([p.resolve() for p in hides if p.exists()], [r for r in roots if r.exists()]):
        argv += ["--bind", str(d), str(d)]
    for path in hides:
        if path.is_dir() and not path.is_symlink():
            argv.extend(["--tmpfs", str(path)])
        elif path.exists():
            argv.extend(["--ro-bind", "/dev/null", str(path)])

    if ssh_agent:
        sock = environ.get("SSH_AUTH_SOCK")
        if not sock or not Path(sock).exists():
            raise SandboxError("--ssh-agent: SSH_AUTH_SOCK is not set or the socket is missing")
        argv += ["--bind", sock, sock]
        keep_env = (*keep_env, "SSH_AUTH_SOCK")

    route_env = {env for _, env, _ in proxy.ROUTES.values()}
    removed = _secret_env_names(environ, route_env, set(keep_env))
    for name in removed:
        argv += ["--unsetenv", name]

    if network != "host":  # start the proxy relay inside, then the command
        command = [
            _bridge_python(hidden),
            "-I",
            BRIDGE_MOUNT + "/bridge.py",
            str(port),
            BRIDGE_MOUNT + "/proxy.sock",
            "--",
            *command,
        ]
    argv += ["--chdir", str(project), "--", *command]
    return argv, removed, warnings


def _bridge_python(hidden):
    """An interpreter for bridge.py that is visible inside the sandbox."""
    for candidate in (os.path.realpath(sys.executable), "/usr/bin/python3"):
        path = Path(candidate)
        if path.is_file() and not any(h == path or h in path.parents for h in hidden):
            return str(path)
    raise SandboxError("no python3 interpreter visible inside the sandbox for the proxy relay")


def default_bridge_dir():
    """Host directory for this session's proxy relay (private; removed when it ends)."""
    return cfgmod.runtime_dir() / ("sandbox-%d" % os.getpid())


# ---------------------------------------------------------------- running it


def run(argv, *, network, port, bridge_dir=None):
    """Run the bwrap ``argv`` from ``build()`` and return its exit status.

    Unless ``network`` is "host": serves the proxy relay socket for the sandbox and, for
    "isolated", attaches slirp4netns to the sandbox's network namespace before the command
    starts. Ctrl-C goes to the agent (we ignore it); SIGTERM/SIGHUP are forwarded.
    """
    bridge_dir = Path(bridge_dir or default_bridge_dir())
    relay = None
    try:
        if network != "host":
            relay = _start_relay(bridge_dir, port)
        return _supervise(argv, network)
    finally:
        if relay is not None:
            relay.close()
            shutil.rmtree(bridge_dir, ignore_errors=True)


def _start_relay(bridge_dir, port):
    """Prepare ``bridge_dir`` and relay its proxy.sock to the proxy on 127.0.0.1:port."""
    bridge_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.rmtree(bridge_dir, ignore_errors=True)  # stale, from a crashed run with our pid
    bridge_dir.mkdir(mode=0o700)
    (bridge_dir / "bridge.py").write_text(Path(bridge.__file__).read_text())
    (bridge_dir / "resolv.conf").write_text(SLIRP_RESOLV)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(bridge_dir / "proxy.sock"))
    srv.listen(64)

    def connect():
        conn = socket.create_connection(("127.0.0.1", port), timeout=10)
        conn.settimeout(None)  # long, quiet streamed responses must not time out
        return conn

    bridge.serve([srv], connect)
    return srv


def _read_child_pid(fd):
    """Read bwrap's --info-fd JSON (it may arrive in pieces); None if bwrap failed first."""
    buf = b""
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            return None
        buf += chunk
        try:
            return json.loads(buf)["child-pid"]
        except ValueError:
            continue


def _start_slirp(pid):
    """Attach slirp4netns to ``pid``'s network namespace; return (process, exit fd)."""
    ready_r, ready_w = os.pipe()
    exit_r, exit_w = os.pipe()  # slirp4netns exits when we close exit_w (or die)
    errors = tempfile.TemporaryFile()
    slirp = subprocess.Popen(  # noqa: S603 - fixed argv
        [  # noqa: S607 - slirp4netns from PATH, like bwrap
            "slirp4netns",
            "--configure",
            "--mtu=65520",
            "--disable-host-loopback",
            "--ready-fd=%d" % ready_w,
            "--exit-fd=%d" % exit_r,
            "--userns-path=/proc/%d/ns/user" % pid,
            str(pid),
            "tap0",
        ],
        pass_fds=(ready_w, exit_r),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=errors,
    )
    os.close(ready_w)
    os.close(exit_r)
    ready = os.read(ready_r, 1)
    os.close(ready_r)
    if ready != b"1":
        os.close(exit_w)
        slirp.wait()
        errors.seek(0)
        detail = errors.read().decode("utf-8", "replace").strip().splitlines()
        raise SandboxError(
            "slirp4netns could not set up the sandbox network (%s)"
            % (detail[-1] if detail else "exit %s" % slirp.returncode)
        )
    errors.close()
    return slirp, exit_w


def _supervise(argv, network):
    fds = []
    if network == "isolated":
        info_r, info_w = os.pipe()
        block_r, block_w = os.pipe()
        argv = [argv[0], "--info-fd", str(info_w), "--block-fd", str(block_r), *argv[1:]]
        fds = [info_w, block_r]
    handled = (signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGHUP)
    saved = {s: signal.getsignal(s) for s in handled}
    proc = slirp = None
    try:
        proc = subprocess.Popen(argv, pass_fds=fds)  # noqa: S603 - argv built by build()
        # After Popen: an ignored signal would be inherited by the agent.
        for s in (signal.SIGINT, signal.SIGQUIT):  # the terminal sends these to the agent too
            signal.signal(s, signal.SIG_IGN)
        for s in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(s, lambda signum, _frame: proc.send_signal(signum))
        if network == "isolated":
            for fd in fds:
                os.close(fd)
            fds = [info_r, block_w]
            pid = _read_child_pid(info_r)
            if pid is None:
                return proc.wait()  # bwrap failed before starting; it said why
            slirp = _start_slirp(pid)
            os.write(block_w, b"1")  # network ready: let the command start
        return proc.wait()
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        if slirp is not None:
            process, exit_w = slirp
            os.close(exit_w)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for s, handler in saved.items():
            signal.signal(s, handler)


def preflight(network="host"):
    """Fail early with a helpful message if bwrap (or slirp4netns) can't run here."""
    if network == "isolated":
        if not shutil.which("slirp4netns"):
            raise SandboxError(
                "slirp4netns is not installed (Ubuntu/Debian: sudo apt install slirp4netns). "
                "It gives the sandbox internet access without sharing your network. "
                "Alternatives: --network none (only the keyveil proxy, no internet)"
            )
        if not Path("/dev/net/tun").exists():
            raise SandboxError(
                "/dev/net/tun is missing, so slirp4netns can't work here (are you inside a "
                "container or another sandbox?). Use --network none (only the keyveil proxy)"
            )
    if not shutil.which("bwrap"):
        raise SandboxError(
            "bubblewrap is not installed (Ubuntu/Debian: sudo apt install bubblewrap)"
        )
    probe = subprocess.run(  # noqa: S603 - fixed argv
        ["bwrap", "--ro-bind", "/", "/", "--", "true"],  # noqa: S607 - bwrap from PATH
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        raise SandboxError(
            "bubblewrap cannot create a sandbox here (%s). Unprivileged user "
            "namespaces may be disabled; on Ubuntu 24.04+ see "
            "kernel.apparmor_restrict_unprivileged_userns"
            % (probe.stderr.strip() or "exit %d" % probe.returncode)
        )


def describe(argv, network="host"):
    text = shlex.join(argv)
    if network != "host":
        text += "\n# plus: a relay from %s/proxy.sock to the proxy on 127.0.0.1" % BRIDGE_MOUNT
    if network == "isolated":
        text += (
            "\n# plus: slirp4netns --configure --mtu=65520 --disable-host-loopback, attached "
            "to the sandbox's network namespace before the command starts"
        )
    return text
