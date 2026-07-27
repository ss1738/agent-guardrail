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
from agent_guardrail.control_plane import ControlPlane, Policy

WORKSPACE = os.environ.get("GUARDRAIL_WORKSPACE", os.path.join(os.getcwd(), "workspace"))
os.makedirs(WORKSPACE, exist_ok=True)


def _signing_key():
    """Ed25519 key for the session receipt. Persist it via GUARDRAIL_SIGNING_KEY (hex 32-byte seed) so
    a relying party can pin one identity across runs; otherwise ephemeral (public key is in the receipt)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = os.environ.get("GUARDRAIL_SIGNING_KEY", "")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) if seed else Ed25519PrivateKey.generate()


AGENT_ID = os.environ.get("GUARDRAIL_AGENT_ID", "agent")
# GUARDRAIL_ZK=1 turns on zero-knowledge receipts: git-branch actions carry a ZK proof, so the
# session receipt can be redacted yet stay provably in-policy (see docs/ZK_ROADMAP.md, experimental).
ZK = os.environ.get("GUARDRAIL_ZK", "").lower() in ("1", "true", "yes")
GUARD = Guardrail()
POLICY = Policy(os.environ.get("GUARDRAIL_POLICY_ID", "default-policy"))
CONTROL = ControlPlane(AGENT_ID, POLICY, signing_key=_signing_key(), zk=ZK)
EXEC = Executor(WORKSPACE, GUARD, control_plane=CONTROL)
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


@mcp.tool()
def session_receipt(redact: bool = False) -> str:
    """Export a signed, independently-verifiable RECEIPT for this session: the agent id, the committed
    policy, every gated action with its verdict, and an Ed25519 signature over the tamper-evident chain
    head. A third party (an auditor, a bank, an insurer) can verify it with the PUBLIC KEY ALONE via
    agent_guardrail.control_plane.verify_receipt -- proving the agent stayed within policy, without
    trusting this server or its operator, and catching any forged ALLOW.

    redact=True strips every raw action (commands, file contents, branches) before returning. In
    zk-mode (GUARDRAIL_ZK=1) git-branch actions stay provably in-policy via their zero-knowledge proof
    even when redacted; other actions keep integrity + authenticity only."""
    r = EXEC.receipt()
    if r is None:
        return json.dumps({"error": "no control plane attached"})
    if redact:
        r, _ = r.redact(reveal=())
    return r.to_json()


if __name__ == "__main__":
    mcp.run()
