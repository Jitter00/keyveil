"""Claude Code's own files under `keyveil sandbox`.

The agent needs ~/.claude and ~/.claude.json writable (its login, sessions, caches), but some
of what lives there makes a later, unsandboxed Claude Code run a program or trust something:
hooks, MCP servers, plugins, a status line command. The sandbox makes those files read-only
(READ_ONLY), gives the agent private copies of directories another Claude Code session reads
from (PRIVATE), and checks the security settings in the JSON files that must stay writable
(snapshot() before, changes() and restore() after).
"""

import copy
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Relative to ~/.claude: read-only inside the sandbox. Missing directories are created empty
# (and read-only) so the agent can't add one; missing files are created by prepare().
# (settings.local.json applies when Claude Code is started in the home directory itself.)
READ_ONLY_FILES = {"settings.json": "{}\n", "settings.local.json": "{}\n", "CLAUDE.md": ""}
READ_ONLY_DIRS = (
    "plugins",
    "commands",
    "agents",
    "skills",
    "workflows",
    "hooks",
    "output-styles",
    "rules",
)
# Relative to the project: folders whose files can run commands when used (skills and
# commands with !`cmd`, agents with hooks in their frontmatter, workflow scripts). The
# agent may legitimately edit them, so changes are only reported after exit.
PROJECT_CODE_DIRS = (
    ".claude/skills",
    ".claude/commands",
    ".claude/agents",
    ".claude/workflows",
    ".claude/hooks",
)
# Relative to ~/.claude: an empty, private directory inside the sandbox. Other Claude Code
# sessions source shell snapshots and session environments, and restore ~/.claude.json from
# backups; the agent's own copies go away when it exits.
PRIVATE = ("backups", "shell-snapshots", "session-env", "downloads")
# Script files directly in ~/.claude (often a status line or hook command): read-only.
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl")

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


def read_only_paths(home):
    """(existing paths to bind read-only, missing directories to create read-only)."""
    claude = Path(home) / ".claude"
    if not claude.is_dir():
        return [], []
    existing, missing = [], []
    for rel in (*READ_ONLY_FILES, *READ_ONLY_DIRS):
        path = claude / rel
        if os.path.lexists(path):
            existing.append(path)
        elif rel in READ_ONLY_DIRS:
            missing.append(path)
    for path in sorted(claude.iterdir()):
        if path.is_file() and (path.suffix in SCRIPT_SUFFIXES or os.access(path, os.X_OK)):
            existing.append(path)
    return existing, missing


def private_paths(home):
    claude = Path(home) / ".claude"
    return [claude / rel for rel in PRIVATE] if claude.is_dir() else []


def prepare(home):
    """Create the missing READ_ONLY_FILES (so the agent can't create them). Returns them."""
    claude = Path(home) / ".claude"
    made = []
    if not claude.is_dir():
        return made
    for rel, text in READ_ONLY_FILES.items():
        path = claude / rel
        if not os.path.lexists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            made.append(path)
    return made


def watched_files(home, project):
    """JSON files the agent may write whose security settings are checked after it exits."""
    project = Path(project)
    return [
        Path(home) / ".claude.json",
        project / ".claude" / "settings.json",
        project / ".claude" / "settings.local.json",
        project / ".mcp.json",
    ]


# ---------------------------------------------------------------- before and after


def snapshot_files(project):
    """{path: sha256} of the files in the project's PROJECT_CODE_DIRS."""
    found = {}
    for rel in PROJECT_CODE_DIRS:
        for dirpath, _, filenames in os.walk(Path(project) / rel):
            for name in filenames:
                path = Path(dirpath) / name
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
