"""`keyveil sandbox -- <agent>`: run an AI agent under bubblewrap (bwrap).

The agent keeps using your real tools and can edit the project, and it can still reach the
keyveil proxy on 127.0.0.1. What it can no longer do:
  * become root: no_new_privs blocks sudo/su/pkexec and setuid binaries;
  * reach Docker / LXD / libvirt / ssh-agent / the desktop keyring: /run and /tmp are private;
  * tamper with what runs outside the sandbox: everything except the project and the agent's
    own state (Claude Code, Codex CLI, Gemini CLI) is read-only (~/.bashrc, PATH, keyveil's
    install and config, ...). In the project's git repositories the hooks, config and git
    dirs can't be changed or swapped, and they are checked again after the agent exits;
  * read common secret stores (~/.ssh, ~/.gnupg, cloud CLI credentials, browser profiles...);
  * see or signal other processes (own PID namespace), including the keyveil proxy;
  * create user namespaces (bwrap 0.8+, unless --allow-userns), the usual first step of a
    namespace-escape exploit;
  * reach anything on the host's loopback or abstract Unix sockets (X11, D-Bus, ibus...):
    the agent gets its own network namespace. slirp4netns gives it the internet, and a
    relay gives it the keyveil proxy at the usual 127.0.0.1:<port>, and nothing else.
"""

import dataclasses
import fcntl
import fnmatch
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import agentstate, bridge, proxy
from . import config as cfgmod

# --network modes: own namespace with internet (slirp4netns), own namespace with only the
# proxy, or the host's network (no isolation from loopback services or abstract sockets).
NETWORK_MODES = cfgmod.SANDBOX_NETWORKS
BRIDGE_MOUNT = "/run/keyveil"  # where the relay's directory appears inside the sandbox
SLIRP_RESOLV = "nameserver 10.0.2.3\n"  # slirp4netns' built-in DNS forwarder
# With its own network namespace the agent can't reach your display or session bus, so these
# would only make programs try and fail. --network host keeps them: they still work there.
DESKTOP_ENV = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS")

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
    ".config/gh",
    ".config/hub",
    ".config/rclone",
    ".config/doctl",
    ".config/op",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
    ".terraform.d",
    ".m2/settings.xml",
    ".gradle/gradle.properties",
    ".kaggle",
    ".thunderbird",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".lesshst",
    ".local/share/fish/fish_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
    ".sqlite_history",
    ".irb_history",
    ".local/share/zsh/history",
    ".config/fish/fish_variables",  # `set -U` variables, often tokens
    ".viminfo",  # command and search history, registers
    ".local/share/nvim/shada",
    ".ipython/profile_default/history.sqlite",
    ".config/git/credentials",  # git-credential-store's XDG location
    ".config/containers/auth.json",  # podman / skopeo registry logins
    ".config/github-copilot",  # editor extension's OAuth tokens (hosts.json)
    ".cline",  # editor extension; data/secrets.json holds API keys in clear
    ".continue/.env",  # editor extension's API keys
    ".config/configstore",  # npm-style token stores of many CLIs
    ".fly",
    ".config/hcloud",
)
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
# Environment variables removed before the agent starts (fnmatch on the upper-cased name).
SECRET_ENV = (
    "*_KEY",
    "*_API_KEY",
    "*_APIKEY",
    "*_PAT",
    "*_CREDENTIALS",
    "*_PASSPHRASE",
    "DATABASE_URL",
    "*_DATABASE_URL",
    "*_DSN",
    "*_TOKEN",
    "*_SECRET",
    "*_SECRET_*",
    "*SECRET_KEY*",
    "*_PASSWORD",
    "*PASSWORD*",
    "*_PASSWD",
    "*_PWD",
    "PGPASSWORD",
    "MYSQL_PWD",
    "*_AUTH",
    "*_PRIVATE_KEY*",
    "*_ACCESS_KEY*",
    "*_WEBHOOK_URL",
    "AWS_*",
    "AZURE_*",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
)


# Not searched for nested git repositories: big, and not where you run git.
GIT_SCAN_SKIP = frozenset(
    {"node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
)
# Files in a git dir that git reads config or hooks through. Read-only while the agent runs.
GIT_READ_ONLY = ("config", "config.worktree", "commondir", "gitdir")
# Of those, the ones that send git somewhere else when they appear in an existing git dir.
# They can't be made read-only before they exist, so a new one is moved aside after exit.
GIT_REDIRECTS = ("commondir", "config.worktree")
# Config keys (fnmatch on the lowercased name) that make git run a program or read more
# config. Reported for git repositories the agent created. alias.* is checked separately.
DANGEROUS_GIT_KEYS = (
    "core.hookspath",
    "core.fsmonitor",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.askpass",
    "core.gitproxy",
    "sequence.editor",
    "pager.*",
    "diff.external",
    "diff.*.textconv",
    "diff.*.command",
    "merge.*.driver",
    "filter.*",
    "credential.helper",
    "credential.*.helper",
    "gpg.program",
    "gpg.*.program",
    "include.path",
    "includeif.*.path",
    "uploadpack.packobjectshook",
    "remote.*.uploadpack",
    "remote.*.receivepack",
    "url.*.insteadof",
    "url.*.pushinsteadof",
)


class SandboxError(Exception):
    """A problem that prevents starting the sandbox; the message is shown to the user."""


_BWRAP_VERSION = None


def bwrap_version():
    """bubblewrap's version as a tuple, (0, 0, 0) if it can't be found. Cached."""
    global _BWRAP_VERSION
    if _BWRAP_VERSION is None:
        _BWRAP_VERSION = (0, 0, 0)
        try:
            out = subprocess.run(  # noqa: S603 - fixed argv
                ["bwrap", "--version"],  # noqa: S607 - bwrap from PATH
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
            found = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
            if found:
                _BWRAP_VERSION = tuple(int(n) for n in found.groups())
        except (OSError, subprocess.SubprocessError):
            pass
    return _BWRAP_VERSION


DISABLE_USERNS_SINCE = (0, 8, 0)  # bwrap --disable-userns


def _secret_env_names(environ, route_env_names, keep):
    names = []
    for name in environ:
        if name in keep:
            continue
        upper = name.upper()
        if name in route_env_names or any(fnmatch.fnmatchcase(upper, p) for p in SECRET_ENV):
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


# ---------------------------------------------------------------- git repositories


def _inside(path, roots):
    return any(path == r or r in path.parents for r in roots)


def _git_entries(root):
    """Every `.git` directory or file below ``root`` (symlinks not followed)."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames or ".git" in filenames:
            found.append(Path(dirpath) / ".git")
        dirnames[:] = [d for d in dirnames if d != ".git" and d not in GIT_SCAN_SKIP]
    return found


def _gitdir_of(entry):
    """The git dir a `.git` entry stands for: itself, or where its `gitdir:` line points."""
    if entry.is_dir():
        return entry.resolve()
    try:
        with open(entry, encoding="utf-8", errors="replace") as f:
            line = f.readline(4096).strip()
    except OSError:
        return None
    if not line.startswith("gitdir:"):
        return None
    return (entry.parent / line[len("gitdir:") :].strip()).resolve()


def _commondir(gitdir):
    """Where a git dir's shared config, hooks and objects live (itself, unless a worktree)."""
    try:
        text = (gitdir / "commondir").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return gitdir
    return (gitdir / text).resolve() if text else gitdir


def _git_layout(roots):
    """(`.git` entries below ``roots``, every git dir they use).

    The git dirs include each one's common dir and the git dirs of its submodules
    (modules/**) and linked worktrees (worktrees/*), wherever those are.
    """
    entries = sorted({e for root in roots for e in _git_entries(root)})
    todo = [g for g in map(_gitdir_of, entries) if g is not None]
    gitdirs = set()
    while todo:
        g = todo.pop()
        if g in gitdirs or not g.is_dir():
            continue
        gitdirs.add(g)
        todo.append(_commondir(g))
        if (g / "worktrees").is_dir():
            todo += [d.resolve() for d in (g / "worktrees").iterdir() if d.is_dir()]
        for dirpath, dirnames, filenames in os.walk(g / "modules"):
            if "HEAD" in filenames:  # a submodule's git dir; its own modules come via todo
                todo.append(Path(dirpath).resolve())
                dirnames[:] = []
    return entries, sorted(gitdirs)


def _git_env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git_config(args, cwd):
    """[(origin path or None, lowercased key, value)] from `git config --list -z`, or None."""
    git = shutil.which("git")
    if not git:
        return None
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv; only reads config, runs nothing
            [git, *args, "config", "--list", "--show-origin", "-z"],
            cwd=cwd,
            env=_git_env(),
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    items = out.stdout.split(b"\0")
    result = []
    for origin, item in zip(items[0::2], items[1::2], strict=False):  # last item: b""
        origin = origin.decode("utf-8", "replace")
        key, _, value = item.decode("utf-8", "replace").partition("\n")
        path = None
        if origin.startswith("file:"):
            path = Path(cwd) / Path(origin[len("file:") :]).expanduser()
        result.append((path, key.lower(), value))
    return result


def _git_protections(roots, writable):
    """What keeps the agent from planting code that git runs later, outside the sandbox.

    Returns (paths to mount read-only, missing hook dirs to create read-only, paths whose
    folders must be pinned, warnings). ``roots`` are searched for repositories; only what
    lies in ``writable`` needs protecting (everything else is read-only anyway).
    """
    entries, gitdirs = _git_layout(roots)
    read_only, create, pin, warnings = set(), set(), [], []
    for entry in entries:
        if entry.is_file() and not entry.is_symlink():  # a worktree's or submodule's link
            read_only.add(entry)
    for path in [*entries, *(g / name for g in gitdirs for name in ("hooks", *GIT_READ_ONLY))]:
        if path.is_symlink() and _inside(path.parent.resolve(), writable):
            warnings.append(
                "%s is a symbolic link, which keyveil can't make read-only (the agent could "
                "replace it): make it a real file or folder for sandboxed sessions" % path
            )
    for g in gitdirs:
        if not _inside(g, writable):
            continue
        pin.append(g / "hooks")  # pins g itself and everything above it
        for name in GIT_READ_ONLY:
            if (g / name).exists():
                read_only.add(g / name)
        if (g / "hooks").exists():
            read_only.add(g / "hooks")
        elif not (g / "commondir").exists():  # an empty one, so the agent can't add one
            create.add(g / "hooks")
    for entry in entries:  # config files (includes) and hook dirs set in config
        g = _gitdir_of(entry)
        if g is None:
            continue
        for origin, key, value in _git_config(["--git-dir", str(g)], entry.parent) or ():
            if origin is not None and origin.exists() and _inside(origin.resolve(), writable):
                read_only.add(origin.resolve())
            if key == "core.hookspath":
                base = entry.parent
            elif key == "include.path" or fnmatch.fnmatchcase(key, "includeif.*.path"):
                base = origin.parent if origin is not None else entry.parent
            else:
                continue
            target = (base / Path(value).expanduser()).resolve()
            if not _inside(target, writable):
                continue
            if target.exists():
                read_only.add(target)
            else:
                warnings.append(
                    "%s is set in git config but doesn't exist, so the agent could create "
                    "it and git would use it outside the sandbox: create it or remove that "
                    "setting first" % target
                )
    pin += sorted(read_only | create)
    return sorted(read_only), sorted(create), pin, warnings


@dataclasses.dataclass
class GitSnapshot:
    roots: list
    entries: set
    redirects: dict  # git dir -> names from GIT_REDIRECTS present before


def snapshot_git(roots):
    """Record the git repositories below ``roots`` before the agent runs (see audit_git)."""
    roots = [p for p in (Path(r).expanduser().resolve() for r in roots) if p.is_dir()]
    entries, gitdirs = _git_layout(roots)
    redirects = {g: {n for n in GIT_REDIRECTS if os.path.lexists(g / n)} for g in gitdirs}
    return GitSnapshot(roots, set(entries), redirects)


def _printable(text):
    """Text safe to show in a terminal (agent-chosen names may carry escape sequences)."""
    return "".join(c if c.isprintable() else "\\x%02x" % ord(c) for c in str(text))


def _git_risks(gitdir):
    """What in a git dir would run a program when you use git there."""
    risks = []
    common = _commondir(gitdir)
    if common != gitdir:
        risks.append("shares hooks and config with %s" % _printable(common))
    hooks = common / "hooks"
    if hooks.is_dir():
        names = sorted(
            h.name
            for h in hooks.iterdir()
            if h.is_file() and os.access(h, os.X_OK) and not h.name.endswith(".sample")
        )
        if names:
            risks.append("hooks: %s" % ", ".join(map(_printable, names)))
    for path in (common / "config", gitdir / "config.worktree"):
        if not path.is_file():
            continue
        items = _git_config_file(path)
        if items is None:
            risks.append("couldn't check %s (is git installed?)" % _printable(path))
            continue
        keys = sorted(
            {
                key
                for key, value in items
                if any(fnmatch.fnmatchcase(key, p) for p in DANGEROUS_GIT_KEYS)
                or (key.startswith("alias.") and value.lstrip().startswith("!"))
            }
        )
        if keys:
            risks.append("config sets %s" % ", ".join(map(_printable, keys)))
    return risks


def _git_config_file(path):
    """[(lowercased key, value)] in one config file (includes not followed), or None."""
    git = shutil.which("git")
    if not git:
        return None
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv; only reads the file
            [git, "config", "--file", str(path), "--list", "-z"],
            env=_git_env(),
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    pairs = []
    for item in out.stdout.split(b"\0"):
        if item:
            key, _, value = item.decode("utf-8", "replace").partition("\n")
            pairs.append((key.lower(), value))
    return pairs


def audit_git(before):
    """Check the repositories below ``before.roots`` after the agent exited.

    Moves aside redirect files (GIT_REDIRECTS) that appeared in existing git dirs, and
    reports git repositories, submodules and worktrees the agent created, with anything in
    them that would run a program. Returns the findings as lines of text.
    """
    findings = []
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for g, present in sorted(before.redirects.items()):
        for name in GIT_REDIRECTS:
            path = g / name
            if name in present or not os.path.lexists(path):
                continue
            dest = g / ("keyveil-quarantine-" + stamp)
            try:
                dest.mkdir(mode=0o700, exist_ok=True)
                path.rename(dest / name)
            except OSError as e:
                findings.append(
                    "%s was created inside the sandbox and could NOT be moved aside (%s): "
                    "delete it before you run git there" % (_printable(path), e.strerror)
                )
            else:
                findings.append(
                    "%s was created inside the sandbox (it redirects git's config or "
                    "hooks); moved it to %s" % (_printable(path), _printable(dest / name))
                )
    entries, gitdirs = _git_layout(before.roots)
    reported = set()
    for entry in entries:
        if entry in before.entries:
            continue
        g = _gitdir_of(entry)
        reported.add(g)
        what = "new git repository %s" % _printable(entry.parent)
        if g is not None and g != entry.resolve():
            what += " (git dir %s)" % _printable(g)
        risks = _git_risks(g) if g is not None else []
        findings.append(what + (": " + "; ".join(risks) if risks else ""))
    for g in gitdirs:
        if g in before.redirects or g in reported:
            continue
        risks = _git_risks(g)
        findings.append(
            "new git dir %s (a submodule or worktree)" % _printable(g)
            + (": " + "; ".join(risks) if risks else "")
        )
    return findings


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
    userns=None,
):
    """Return (bwrap argv, removed env var names, warnings). Inspects (and reads git config)
    but changes nothing. ``userns`` (default: ``cfg.sandbox_userns``) allows the agent to
    create user namespaces inside the sandbox.

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
    if userns is None:
        userns = cfg.sandbox_userns
    argv = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ]
    # Nested user namespaces are the usual first step of a namespace-escape exploit, and
    # the agent doesn't need them, unless it drives a Chromium browser or rootless podman.
    if userns:
        warnings.append(
            "nested user namespaces allowed (--allow-userns): needed by Chromium/Playwright "
            "and rootless podman, but it widens the kernel attack surface"
        )
    elif bwrap_version() >= DISABLE_USERNS_SINCE:
        argv += ["--unshare-user", "--disable-userns"]  # bwrap refuses the second alone
    else:
        warnings.append(
            "bubblewrap %s can't block nested user namespaces (needs 0.8+)"
            % ".".join(map(str, bwrap_version()))
        )
    argv += [
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
    if network != "host":
        hidden.append(home / ".Xauthority")  # the display's login cookie; no display to use it on
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

    # Each agent's own state (login, sessions, caches) is writable; see agentstate.
    agent_state = agentstate.state_paths(home, environ)
    for path in (*agent_state, *user_rw):
        if path.exists():
            argv += ["--bind", str(path), str(path)]
        elif path in user_rw:
            warnings.append("writable path does not exist, skipped: %s" % path)

    argv += ["--bind", str(project), str(project)]
    roots = [project, *agent_state, *(p.resolve() for p in user_rw)]
    roots = [r for r in roots if r.exists()]

    # Git runs hooks and config-named programs outside the sandbox later, so in every
    # repository in a writable directory: hooks, config (and the files it includes) and the
    # files that point git elsewhere are read-only, and the git dirs themselves are pinned
    # (a mount point can't be renamed), so `mv .git .git.old && mkdir .git` fails.
    git_ro, git_create, git_pin, git_warnings = _git_protections(
        [project, *(p.resolve() for p in user_rw if p.is_dir())], roots
    )
    warnings += git_warnings

    # Every hide goes after every bind: a later mount covers an earlier one, so this is what
    # keeps a hidden path hidden even inside a writable directory (including user hides of a
    # single file such as ~/.claude/.credentials.json). Pin the directories in between.
    hides = [Path(p) for p in hidden]
    hides += [Path(p).expanduser() for p in (*cfg.sandbox_hide, *extra_hide)]
    for d in _pins([*(p.resolve() for p in hides if p.exists()), *git_pin], roots):
        argv += ["--bind", str(d), str(d)]
    for path in git_ro:
        argv += ["--ro-bind", str(path), str(path)]
    for path in git_create:
        argv += ["--tmpfs", str(path), "--remount-ro", str(path)]

    # The agents' files that make a later, unsandboxed session run something (settings
    # with hooks, plugins, commands, ...) are read-only; directories other sessions read
    # from (shell snapshots, ~/.claude.json backups, ...) are private. See agentstate.
    agent_ro, agent_create = agentstate.read_only_paths(home, environ)
    for path in agent_ro:
        argv += ["--ro-bind", str(path), str(path)]
    for path in agent_create:
        argv += ["--tmpfs", str(path), "--remount-ro", str(path)]
    for path in agentstate.private_paths(home, environ):
        argv += ["--tmpfs", str(path)]
    # --dev-bind, because the other binds are nodev: the agent would get "Permission denied"
    # each time it saves a prompt, instead of an empty file that discards what it writes.
    for path in agentstate.prompt_history_paths(home, environ):
        argv += ["--dev-bind", "/dev/null", str(path)]
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
    if network != "host":
        for name in DESKTOP_ENV:
            if name in environ and name not in keep_env:
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


NS_GET_USERNS = 0xB701  # ioctl on a namespace fd: the user namespace that owns it


def _netns_owner(pid):
    """An fd for the user namespace that owns ``pid``'s network namespace.

    Not necessarily ``/proc/PID/ns/user``: newer bwrap (0.9) moves its child into another
    user namespace after creating the network namespace, and from there slirp4netns isn't
    allowed to enter the network namespace (setns(CLONE_NEWNET): EPERM).
    """
    net = os.open("/proc/%d/ns/net" % pid, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return fcntl.ioctl(net, NS_GET_USERNS)
    finally:
        os.close(net)


def _start_slirp(pid, attempts=3):
    """Attach slirp4netns to ``pid``'s network namespace; return (process, exit fd)."""
    try:
        userns = _netns_owner(pid)
    except OSError as e:
        raise SandboxError("can't find the sandbox's network namespace (%s)" % e) from e
    try:
        for attempt in range(attempts):
            try:
                return _try_slirp(pid, userns)
            except SandboxError:
                if attempt == attempts - 1:
                    raise
                time.sleep(0.1 * (attempt + 1))
    finally:
        os.close(userns)


def _try_slirp(pid, userns):
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
            "--userns-path=/proc/self/fd/%d" % userns,
            str(pid),
            "tap0",
        ],
        pass_fds=(ready_w, exit_r, userns),
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
        errors.close()
        raise SandboxError(
            "slirp4netns could not set up the sandbox network (%s)"
            % ("; ".join(detail[-3:]) if detail else "exit %s" % slirp.returncode)
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
        # Kill bwrap before closing the block fd: closing it lets the command start.
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
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
