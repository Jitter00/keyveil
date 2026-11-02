"""contrib/claude-guard-hook.py: the PreToolUse hook that refuses edits to Claude Code's
config."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "contrib" / "claude-guard-hook.py"


def run_hook(payload):
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        [sys.executable, "-I", str(HOOK)], input=data, capture_output=True, text=True, timeout=10
    )


def call(tool_name, cwd="/home/u/proj", **tool_input):
    return run_hook(
        {
            "hook_event_name": "PreToolUse",
            "cwd": cwd,
            "tool_name": tool_name,
            "tool_input": tool_input,
        }
    )


class GuardHookTests(unittest.TestCase):
    def assertRefused(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("refused by keyveil's guard hook", result.stderr)

    def assertAllowed(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_file_tools(self):
        for path in (
            "/home/u/.claude/settings.json",
            "/home/u/.claude.json",
            "/home/u/.claude/plugins/x/hooks.json",
            "/home/u/.claude/skills/s/SKILL.md",
            ".claude/settings.local.json",  # relative to cwd
            ".mcp.json",
            "/home/u/proj/sub/../.claude/commands/x.md",
        ):
            self.assertRefused(call("Write", file_path=path, content="x"))
            self.assertRefused(call("Edit", file_path=path, old_string="a", new_string="b"))
        self.assertRefused(call("NotebookEdit", notebook_path="/h/.claude/hooks/x.ipynb"))
        for path in (
            "/home/u/proj/src/app.py",
            "/home/u/.claude/projects/p/memory/note.md",  # Claude Code's own memory
            "/home/u/proj/docs/claude.md",
            "/home/u/proj/.claude-skills-notes.md",
        ):
            self.assertAllowed(call("Write", file_path=path, content="x"))

    def test_bash(self):
        for command in (
            "echo '{}' > ~/.claude/settings.json",
            "cp x ~/.claude.json",
            'python3 -c \'open(".mcp.json","w")\'',
            "mkdir -p .claude/hooks && cp evil.sh .claude/hooks/",
            "sed -i s/a/b/ $HOME/.claude//CLAUDE.md",
        ):
            self.assertRefused(call("Bash", command=command))
        for command in ("git status", "ls ~/.claude/projects", "cat README.md"):
            self.assertAllowed(call("Bash", command=command))

    def test_other_tools_and_bad_input_pass(self):
        self.assertAllowed(call("Read", file_path="/home/u/.claude/settings.json"))
        self.assertAllowed(run_hook("not json"))
        self.assertAllowed(run_hook("[]"))
        self.assertAllowed(run_hook({"tool_name": "Write", "tool_input": "x"}))


if __name__ == "__main__":
    unittest.main()
