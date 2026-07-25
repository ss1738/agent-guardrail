"""agent-guardrail as an MCP server.

MCP (Model Context Protocol) is the tool-call surface that Claude Desktop, Cursor,
Copilot, Windsurf and other agents speak. This server exposes the usual coding-agent
tools (run_shell, write_file, git) but routes every call through the guardrail before
executing it, so the tool call is gated in the actual protocol path, not by trusting
the agent. Any MCP client that points at this server gets the gate for free.

Add to an MCP client config (e.g. Claude Desktop / Cursor):

    "agent-guardrail": {
      "command": "python3",
      "args": ["/path/to/agent-guardrail/integrations/mcp_server.py"],
      "env": {"GUARDRAIL_WORKSPACE": "/path/to/your/repo"}
    }
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
from agent_guardrail.guardrail import Guardrail
from agent_guardrail.executor import Executor

WORKSPACE = os.environ.get("GUARDRAIL_WORKSPACE", os.path.join(os.getcwd(), "workspace"))
os.makedirs(WORKSPACE, exist_ok=True)

GUARD = Guardrail()
EXEC = Executor(WORKSPACE, GUARD)
mcp = FastMCP("agent-guardrail")


@mcp.tool()
def run_shell(cmd: str) -> str:
    """Run a shell command in the workspace. Blocked if it is a destructive action
    (rm -rf the repo, secret exfiltration, force-push); otherwise executed."""
    return EXEC.run_shell(cmd)


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write a file in the workspace. Blocked if it writes a secret or empties a CI
    config; otherwise executed."""
    return EXEC.write_file(path, content)


@mcp.tool()
def git(args: str) -> str:
    """Run a git command, e.g. 'add -A', 'commit -m fix'. A force-push, hard-reset,
    or rebase of a protected branch is blocked; normal git is executed."""
    return EXEC.git(args)


@mcp.tool()
def audit_log() -> str:
    """Return the tamper-evident audit chain of every guardrail decision so far."""
    return json.dumps({"chain_verifies": GUARD.verify_chain(),
                       "blocked": EXEC.blocked, "executed": EXEC.executed,
                       "log": GUARD.log}, indent=2)


if __name__ == "__main__":
    mcp.run()
