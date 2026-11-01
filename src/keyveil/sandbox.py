"""`keyveil sandbox -- <agent>`: run an AI agent under bubblewrap (bwrap).

The agent keeps using your real tools and can edit the project, and it can still reach the
keyveil proxy on 127.0.0.1. What it can no longer do:
  * become root: no_new_privs blocks sudo/su/pkexec and setuid binaries;
  * reach Docker / LXD / libvirt / ssh-agent / the desktop keyring: /run and /tmp are private;
  * tamper with what runs outside the sandbox: everything except the project and the agent's
    own state is read-only (~/.bashrc, PATH, keyveil's install and config, .git/hooks, ...);
  * read common secret stores (~/.ssh, ~/.gnupg, cloud CLI credentials, browser profiles...);
  * see or signal other processes (own PID namespace), including the keyveil proxy.
Network access is shared with the host (the agent needs the proxy and usually the internet).
"""
import fnmatch
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from . import config as cfgmod
from . import proxy

# Hidden from the agent if they exist (relative to $HOME). Directories get an empty tmpfs,
# files are replaced by /dev/null.
HIDDEN_IN_HOME = (
    ".ssh", ".gnupg", ".password-store", ".local/share/keyrings", ".aws", ".azure",
    ".config/gcloud", ".kube", ".docker", ".netrc", ".git-credentials", ".pgpass",
    ".mozilla", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
    ".bash_history", ".zsh_history", ".python_history", ".lesshst",
)
# Writable for the agent if they exist (relative to $HOME): Claude Code's state.
AGENT_STATE = (".claude", ".claude.json")
# Environment variables removed before the agent starts (fnmatch, case-sensitive).
SECRET_ENV = ("*_API_KEY", "*_APIKEY", "*_TOKEN", "*_SECRET", "*_SECRET_*", "*SECRET_KEY*",
              "*_PASSWORD", "*_PASSWD", "AWS_*", "AZURE_*", "GOOGLE_APPLICATION_CREDENTIALS",
              "SSH_AUTH_SOCK", "GPG_AGENT_INFO")


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


def _tiocsti_possible():
    """True unless the kernel blocks terminal keystroke injection (dev.tty.legacy_tiocsti=0)."""
    try:
        return Path("/proc/sys/dev/tty/legacy_tiocsti").read_text().strip() != "0"
    except OSError:
        return True  # kernels before 6.2 have no switch: injection is possible


def build(command, *, project, cfg, home=None, environ=None, extra_rw=(), extra_hide=(),
          keep_env=(), ssh_agent=False, prefix=None):
    """Return (bwrap argv, removed env var names, warnings). Pure: inspects but never runs."""
    if not command:
        raise SandboxError("no command given. Usage: keyveil sandbox [options] -- COMMAND [ARGS]")
    home = Path(home or Path.home()).resolve()
    environ = os.environ if environ is None else environ
    project = Path(project).resolve()
    if not project.is_dir():
        raise SandboxError("project directory not found: %s" % project)
    if project == home or project in home.parents or project == Path("/"):
        raise SandboxError("refusing to make %s writable: pick a project directory below your "
                           "home directory" % project)

    warnings = []
    argv = ["bwrap", "--die-with-parent", "--unshare-pid", "--unshare-ipc",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
            "--tmpfs", "/run", "--tmpfs", "/tmp"]
    # /etc/resolv.conf is often a symlink into /run (systemd-resolved); give back just that
    # file, read-only, so DNS keeps working. The resolver's control socket stays hidden.
    resolv = Path("/etc/resolv.conf").resolve()
    if Path("/run") in resolv.parents and resolv.is_file():
        argv += ["--ro-bind", str(resolv), str(resolv)]
    runtime = environ.get("XDG_RUNTIME_DIR")
    if runtime and Path("/run") in Path(runtime).parents:  # recreate it, empty, on the new /run
        argv += ["--dir", runtime, "--chmod", "0700", runtime]
    if _tiocsti_possible():
        argv.append("--new-session")
        warnings.append("this kernel allows terminal keystroke injection; running the agent "
                        "in a new session (some terminal features may not work)")

    def hide(path):
        path = Path(path)
        if path.is_dir() and not path.is_symlink():
            argv.extend(["--tmpfs", str(path)])
        elif path.exists():
            argv.extend(["--ro-bind", "/dev/null", str(path)])

    if (home / ".cache").is_dir():
        argv += ["--tmpfs", str(home / ".cache")]   # private scratch; nothing persists
    for rel in HIDDEN_IN_HOME:
        hide(home / rel)
    # keyveil itself: config, log/state, the installed environment, and the key files.
    for path in (cfgmod.config_dir(), cfgmod.state_dir()):
        hide(path)
    prefix = Path(prefix or sys.prefix).resolve()
    if home in prefix.parents and prefix != project and project not in prefix.parents:
        hide(prefix)                                # e.g. ~/.local/share/uv/tools/keyveil
    for path in (cfg.age_file, cfg.age_identity):
        if path:
            hide(path)

    for path in (*(home / rel for rel in AGENT_STATE), *cfg.sandbox_rw, *extra_rw):
        path = Path(path).expanduser()
        if path.exists():
            argv += ["--bind", str(path), str(path)]
        elif path in cfg.sandbox_rw or path in [Path(p).expanduser() for p in extra_rw]:
            warnings.append("writable path does not exist, skipped: %s" % path)

    argv += ["--bind", str(project), str(project)]
    git = project / ".git"
    if git.is_dir():                                # these run code later, outside the sandbox
        for rel in ("hooks", "config"):
            if (git / rel).exists():
                argv += ["--ro-bind", str(git / rel), str(git / rel)]

    # User-requested hides go last: a later mount covers an earlier one, so hiding a file
    # inside a writable path (e.g. ~/.claude/.credentials.json) only works after the binds.
    for path in (*cfg.sandbox_hide, *extra_hide):
        hide(Path(path).expanduser())

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

    argv += ["--chdir", str(project), "--", *command]
    return argv, removed, warnings


def preflight():
    """Fail early with a helpful message if bwrap can't run here."""
    if not shutil.which("bwrap"):
        raise SandboxError("bubblewrap is not installed (Ubuntu/Debian: sudo apt install bubblewrap)")
    probe = subprocess.run(["bwrap", "--ro-bind", "/", "/", "--", "true"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        raise SandboxError("bubblewrap cannot create a sandbox here (%s). Unprivileged user "
                           "namespaces may be disabled; on Ubuntu 24.04+ see "
                           "kernel.apparmor_restrict_unprivileged_userns"
                           % (probe.stderr.strip() or "exit %d" % probe.returncode))


def describe(argv):
    return shlex.join(argv)
