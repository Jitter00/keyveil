#!/usr/bin/env python3
"""Claude Code PreToolUse hook: refuse tool calls that touch Claude Code's own config.

An early warning, not a boundary: it sees the agent's Edit/Write/NotebookEdit targets and
Bash command lines, but not what a script or program started by the agent does later, nor
an obfuscated command. `keyveil sandbox` is the boundary; this tells the agent (and you)
early that it tried.

Refused: writing to, or naming in a shell command, the files that make Claude Code run
something or trust something later:
  ~/.claude.json, .mcp.json, and in any .claude folder: settings.json, settings.local.json,
  CLAUDE.md, plugins/, commands/, agents/, skills/, workflows/, hooks/, output-styles/, rules/.

Install it where the agent can't change it, and register it in managed settings, e.g.
  sudo install -D -m 755 -o root contrib/claude-guard-hook.py \
      /usr/local/lib/keyveil/claude-guard-hook.py
then in /etc/claude-code/managed-settings.json:
  {"hooks": {"PreToolUse": [{"matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
     "hooks": [{"type": "command",
                "command": "/usr/bin/python3 -I /usr/local/lib/keyveil/claude-guard-hook.py"}]}]}}
Standard library only; reads the hook input as JSON on stdin; exit 2 refuses the call.
"""

import json
import os
import re
import sys

PROTECTED = re.compile(
    r"\.claude\.json"
    r"|\.mcp\.json"
    r"|\.claude/+(settings(\.local)?\.json|CLAUDE\.md"
    r"|(plugins|commands|agents|skills|workflows|hooks|output-styles|rules)(/|\b|$))"
)
FILE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}


def _target(tool_name, tool_input, cwd):
    if tool_name in FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if not path:
            return None
        path = os.path.join(cwd or "/", os.path.expanduser(path))
        return os.path.realpath(path) + "\n" + os.path.normpath(path)  # link and target
    if tool_name == "Bash":
        return tool_input.get("command") or ""
    return None


def check(payload):
    """The reason to refuse this tool call, or None."""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    tool_name = payload.get("tool_name", "")
    text = _target(tool_name, tool_input, payload.get("cwd"))
    if not text:
        return None
    match = PROTECTED.search(text.replace("\\", "/"))
    if not match:
        return None
    return (
        "refused by keyveil's guard hook: %s would touch Claude Code's configuration (%s), "
        "which can make Claude Code run programs later. Ask the user to make this change "
        "themselves, outside the agent." % (tool_name, match.group(0))
    )


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # not a hook call we understand: don't break Claude Code
    if not isinstance(payload, dict):
        return 0
    reason = check(payload)
    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
