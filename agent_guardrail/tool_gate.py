"""ToolGate: drop the guardrail into ANY function-calling agent loop, no MCP required.

Most agents are not MCP -- they run an OpenAI / Anthropic "tool calling" loop: the model emits a tool
name + a JSON arguments object, the app executes it, and feeds the result back. That shape is identical
across providers, so this adapter needs no SDK. Wrap your tool dispatch in one call:

    gate = ToolGate(workspace="/path/to/repo", control_plane=ControlPlane("agent", Policy("prod")))
    ...
    for call in response.tool_calls:                 # OpenAI: call.function.name / .arguments
        result = gate.handle(call.name, json.loads(call.arguments))
        # ... append result as the tool message ...
    receipt = gate.receipt()                          # signed, independently verifiable

Every call is gated (a force-push to main, an rm -rf of the repo, a secret exfiltration is blocked
before it runs) and recorded into the Control Plane receipt. Register the tools with the model using
`openai_tools()` or `anthropic_tools()` so the schemas match what `handle` accepts.
"""
from __future__ import annotations

from .control_plane import ControlPlane
from .executor import Executor
from .guardrail import Guardrail

# One definition of the gated toolset; formatted per provider below. These mirror the Executor tools.
_TOOLS = [
    {
        "name": "run_shell",
        "description": "Run a shell command in the working directory. Destructive commands "
                       "(repo/home deletion, secret exfiltration, protected-branch force-push) are blocked.",
        "properties": {"cmd": {"type": "string", "description": "the shell command to run"}},
        "required": ["cmd"],
    },
    {
        "name": "write_file",
        "description": "Write a file in the working directory. Writing a secret or emptying a CI "
                       "config is blocked.",
        "properties": {
            "path": {"type": "string", "description": "path relative to the working directory"},
            "content": {"type": "string", "description": "file contents"},
        },
        "required": ["path", "content"],
    },
    {
        "name": "git",
        "description": "Run a git command, e.g. 'add -A' or 'commit -m fix'. A force-push, hard-reset, "
                       "or rebase of a protected branch is blocked.",
        "properties": {"args": {"type": "string", "description": "git arguments, without the leading 'git'"}},
        "required": ["args"],
    },
]


def _schema(t: dict) -> dict:
    return {"type": "object", "properties": t["properties"], "required": t["required"]}


def openai_tools() -> list[dict]:
    """The gated tools in OpenAI `tools` format (for chat.completions / responses)."""
    return [{"type": "function",
             "function": {"name": t["name"], "description": t["description"], "parameters": _schema(t)}}
            for t in _TOOLS]


def anthropic_tools() -> list[dict]:
    """The gated tools in Anthropic `tools` format (for the Messages API)."""
    return [{"name": t["name"], "description": t["description"], "input_schema": _schema(t)}
            for t in _TOOLS]


class ToolGate:
    """Routes a function-calling tool invocation through the gated Executor and records it. A control
    plane is optional; attach one to get a signed receipt for the session."""

    def __init__(self, workspace: str, guard: Guardrail | None = None,
                 control_plane: ControlPlane | None = None):
        self._exec = Executor(workspace, guard or Guardrail(), control_plane=control_plane)

    @property
    def blocked(self) -> list[str]:
        return self._exec.blocked

    @property
    def executed(self) -> list[str]:
        return self._exec.executed

    def handle(self, name: str, arguments: dict) -> str:
        """Execute one tool call after gating it. Returns the tool result string (a blocked call returns
        a ⛔ message the model can read). Unknown tools and malformed arguments are refused fail-closed,
        never raised, so a hijacked or confused model cannot crash the loop or slip past the gate."""
        args = arguments if isinstance(arguments, dict) else {}
        try:
            if name == "run_shell":
                return self._exec.run_shell(str(args["cmd"]))
            if name == "write_file":
                return self._exec.write_file(str(args["path"]), str(args["content"]))
            if name == "git":
                return self._exec.git(str(args["args"]))
        except KeyError as e:
            return f"⛔ REFUSED: tool '{name}' is missing required argument {e}."
        return f"⛔ REFUSED: '{name}' is not in the gated toolset {[t['name'] for t in _TOOLS]}."

    def receipt(self):
        """The signed, independently-verifiable receipt for this session (None if no control plane)."""
        return self._exec.receipt()
