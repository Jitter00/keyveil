"""Coding agents' own files under `keyveil sandbox` (Claude Code, Codex CLI, Gemini CLI).

An agent needs its state directory writable (its login, sessions, caches), but some of what
lives there makes a later, unsandboxed run execute a program or trust something: hooks, MCP
servers, plugins, custom commands, a status line command. Each AgentProfile says which of
its files the sandbox makes read-only, which directories get a private empty copy (other
sessions read from them), and which JSON files that must stay writable are checked for
changed security settings after exit (snapshot() before, changes() and restore() after).
"""

import copy
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# One coding agent's files in the home directory. ``state`` is bind-mounted read-write;
# inside the state directory ``read_only_files`` (created with that content if missing) and
# ``read_only_dirs`` (created empty if missing) are read-only, ``private`` directories are
# empty tmpfs copies, ``login`` names the credential files (readable by default, like the
# rest of the state: the agent can't work without them; hide them with --hide when the agent
# goes through keyveil), ``watched`` are home-relative JSON files whose security settings
# are compared after exit, and ``home_env`` can move the state directory (e.g. CODEX_HOME).
@dataclass(frozen=True)
class AgentProfile:
    name: str
    state: tuple  # home-relative paths bind-mounted read-write; the first is the state dir
    read_only_files: dict = field(default_factory=dict)
    read_only_dirs: tuple = ()
    private: tuple = ()
    login: tuple = ()
    watched: tuple = ()
    home_env: str | None = None


PROFILES = (
    AgentProfile(
        "claude",
        state=(".claude", ".claude.json"),
        # settings.local.json applies when Claude Code is started in the home directory
        read_only_files={"settings.json": "{}\n", "settings.local.json": "{}\n", "CLAUDE.md": ""},
        read_only_dirs=(
            "plugins",
            "commands",
            "agents",
            "skills",
            "workflows",
            "hooks",
            "output-styles",
            "rules",
        ),
        # Other Claude Code sessions source shell snapshots and session environments, and
        # restore ~/.claude.json from backups; the agent's own copies go away when it exits.
        private=("backups", "shell-snapshots", "session-env", "downloads"),
        login=(".credentials.json",),
        watched=(".claude.json",),
    ),
    AgentProfile(
        "codex",
        state=(".codex",),
        # config.toml: mcp_servers.*.command, notify, hooks, model_providers.*.auth.command;
        # hooks.json and *.config.toml profiles likewise. AGENTS.md: instructions.
        read_only_files={"config.toml": "", "hooks.json": "{}\n", "AGENTS.md": ""},
        read_only_dirs=("memories", "skills", "prompts", "plugins", "agents", "rules", "hooks"),
        login=("auth.json",),
        home_env="CODEX_HOME",
    ),
    AgentProfile(
        "gemini",
        state=(".gemini",),
        # settings.json: mcpServers, hooks; commands/*.toml run shell commands; extensions
        # hold hooks and MCP servers; trustedFolders.json grants trust; .env holds keys.
        read_only_files={
            "settings.json": "{}\n",
            "GEMINI.md": "",
            "trustedFolders.json": "{}\n",
            ".env": "",
        },
        read_only_dirs=("commands", "extensions", "skills", "agents", "hooks", "policies"),
        login=("oauth_creds.json", "google_accounts.json", "mcp-oauth-tokens.json"),
    ),
)
# Relative to the project: files and folders that can run commands when used (skills and
# commands with !`cmd`, agents with hooks in their frontmatter, workflow scripts, MCP
# servers and hooks in an agent's project config). The agent may legitimately edit them,
# so changes are only reported after exit.
PROJECT_CODE_DIRS = (
    ".claude/skills",
    ".claude/commands",
    ".claude/agents",
    ".claude/workflows",
    ".claude/hooks",
    ".codex/config.toml",
    ".codex/hooks.json",
    ".gemini/settings.json",
    ".gemini/commands",
)
# Script files directly in a state dir (often a status line or hook command): read-only.
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl")


def state_dir(profile, home, environ=None):
    """The profile's state directory: ``home_env`` if set and inside ``home``, else default."""
    environ = os.environ if environ is None else environ
    home = Path(home)
    if profile.home_env and environ.get(profile.home_env):
        custom = Path(environ[profile.home_env]).expanduser()
        if home in custom.resolve().parents:
            return custom
    return home / profile.state[0]


def agents(home, environ=None):
    """[(profile, state dir)] for every agent that has a state directory under ``home``."""
    found = []
    for profile in PROFILES:
        d = state_dir(profile, home, environ)
        if d.is_dir():
            found.append((profile, d))
    return found


def state_paths(home, environ=None):
    """Existing paths to bind read-write: every agent's state directory and extra files."""
    paths = []
    for profile, d in agents(home, environ):
        paths.append(d)
        extra = [Path(home) / rel for rel in profile.state[1:]]
        paths += [path for path in extra if os.path.lexists(path)]
    return paths


# Keys whose values decide what Claude Code runs or trusts, wherever they appear in a
# watched file (top level, per project in ~/.claude.json, ...).
SECURITY_KEYS = frozenset(
    {
        "mcpServers",
        "enabledMcpServers",
        "disabledMcpServers",
        "enabledMcpjsonServers",
        "disabledMcpjsonServers",
        "enableAllProjectMcpServers",
        "hooks",
        "disableAllHooks",
        "permissions",
        "allowedTools",
        "hasTrustDialogAccepted",
        "hasClaudeMdExternalIncludesApproved",
        "env",
        "apiKeyHelper",
        "awsAuthRefresh",
        "awsCredentialExport",
        "otelHeadersHelper",
        "statusLine",
        "fileSuggestion",
        "enabledPlugins",
        "extraKnownMarketplaces",
    }
)


def read_only_paths(home, environ=None):
    """(existing paths to bind read-only, missing directories to create read-only)."""
    existing, missing = [], []
    for profile, d in agents(home, environ):
        for rel in (*profile.read_only_files, *profile.read_only_dirs):
            path = d / rel
            if os.path.lexists(path):
                existing.append(path)
            elif rel in profile.read_only_dirs:
                missing.append(path)
        for path in sorted(d.iterdir()):
            if not path.is_file():
                continue
            if path.suffix in SCRIPT_SUFFIXES or os.access(path, os.X_OK):
                existing.append(path)
            elif profile.name == "codex" and path.name.endswith(".config.toml"):
                existing.append(path)  # a profile config, selected with --profile
    return existing, missing


def private_paths(home, environ=None):
    return [d / rel for profile, d in agents(home, environ) for rel in profile.private]


def prepare(home, environ=None):
    """Create the missing read-only files (so the agent can't create them). Returns them."""
    made = []
    for profile, d in agents(home, environ):
        for rel, text in profile.read_only_files.items():
            path = d / rel
            if not os.path.lexists(path):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(text)
                made.append(path)
    return made


def login_files(home, environ=None):
    """{profile name: [credential files that exist]}, for messages and the README."""
    return {
        profile.name: [d / rel for rel in profile.login if os.path.lexists(d / rel)]
        for profile, d in agents(home, environ)
    }


def watched_files(home, project):
    """JSON files the agent may write whose security settings are checked after it exits."""
    project = Path(project)
    return [
        *(Path(home) / rel for profile in PROFILES for rel in profile.watched),
        project / ".claude" / "settings.json",
        project / ".claude" / "settings.local.json",
        project / ".mcp.json",
    ]


# ---------------------------------------------------------------- before and after


def snapshot_files(project):
    """{path: sha256} of the files in the project's PROJECT_CODE_DIRS."""
    found = {}
    for rel in PROJECT_CODE_DIRS:
        root = Path(project) / rel
        files = [root] if root.is_file() else []
        for dirpath, _, filenames in os.walk(root):
            files += [Path(dirpath) / name for name in filenames]
        for path in files:
            try:
                found[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
    return found


def file_changes(before, project):
    """Lines naming the files in PROJECT_CODE_DIRS that were added or changed."""
    after = snapshot_files(project)
    return [
        "%s %s" % (_printable(path), "added" if path not in before else "changed")
        for path, digest in sorted(after.items())
        if before.get(path) != digest
    ]


def _security_values(obj, path=()):
    """{json path: value} for every SECURITY_KEYS entry in nested objects."""
    found = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in SECURITY_KEYS:
                found[(*path, key)] = value
            else:
                found.update(_security_values(value, (*path, key)))
    return found


_MISSING = object()


def _load(path):
    """(text, parsed) of a JSON file; (None, None) if missing; (text, _MISSING) if invalid."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, None
    except (OSError, UnicodeDecodeError):
        return None, _MISSING
    try:
        return text, json.loads(text)
    except ValueError:
        return text, _MISSING


@dataclass
class Watched:
    path: Path
    text: str | None  # the file before the session (None: didn't exist)
    values: dict = field(default_factory=dict)  # its security settings then


def snapshot(paths):
    out = []
    for path in paths:
        text, data = _load(path)
        values = _security_values(data) if data not in (None, _MISSING) else {}
        out.append(Watched(Path(path), text if data is not _MISSING else None, values))
    return out


@dataclass
class Change:
    watched: Watched
    keys: list  # json paths whose values differ (empty if the file is no longer valid JSON)
    broken: bool = False  # not valid JSON any more


def changes(snapshots):
    """The watched files whose security settings changed during the session."""
    result = []
    for w in snapshots:
        _, data = _load(w.path)
        if data is _MISSING:
            if w.text is not None:
                result.append(Change(w, [], broken=True))
            continue
        after = _security_values(data) if data is not None else {}
        keys = sorted(k for k in w.values.keys() | after.keys() if w.values.get(k) != after.get(k))
        if keys:
            result.append(Change(w, keys))
    return result


def describe(change, limit=200):
    """Lines describing a change for the terminal (agent-written text made printable)."""
    if change.broken:
        return ["%s is no longer valid JSON" % _printable(change.watched.path)]
    _, data = _load(change.watched.path)
    after = _security_values(data or {})
    lines = []
    for key in change.keys:
        name = ".".join(_printable(k) for k in key)
        if key not in change.watched.values:
            what = "added: %s" % _short(after[key], limit)
        elif key not in after:
            what = "removed"
        else:
            what = "changed to: %s" % _short(after[key], limit)
        lines.append("%s: %s %s" % (_printable(change.watched.path), name, what))
    return lines


def restore(change):
    """Put back the security settings from before the session, keeping everything else."""
    w = change.watched
    if change.broken:
        _atomic_write(w.path, w.text)
        return
    _, data = _load(w.path)
    data = copy.deepcopy(data) if isinstance(data, dict) else {}
    for key in change.keys:
        parent = data
        for part in key[:-1]:
            if not isinstance(parent.get(part), dict):
                parent[part] = {}
            parent = parent[part]
        if key in w.values:
            parent[key[-1]] = w.values[key]
        else:
            parent.pop(key[-1], None)
    _atomic_write(w.path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _atomic_write(path, text):
    path = Path(path)
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = 0o600
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".%s." % path.name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _printable(text):
    return "".join(c if c.isprintable() else "\\x%02x" % ord(c) for c in str(text))


def _short(value, limit):
    text = _printable(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return text if len(text) <= limit else text[: limit - 1] + "…"
