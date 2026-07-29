"""qedra as an MCP server (package entry point).

MCP (Model Context Protocol) is the tool-call surface that Claude Desktop, Cursor,
Copilot, Windsurf and other agents speak. This server exposes the usual coding-agent
tools (run_shell, write_file, git) but routes every call through the guardrail before
executing it, so the tool call is gated in the actual protocol path, not by trusting
the agent. Any MCP client that points at this server gets the gate for free.

Install and run:

    pip install 'qedra[mcp]'
    qedra-mcp

Point an MCP client at it (e.g. Claude Desktop / Cursor):

    "qedra": {
      "command": "qedra-mcp",
      "env": {"GUARDRAIL_WORKSPACE": "/path/to/your/repo"}
    }

Configuration is entirely by environment variable, so one install serves every repo:
  GUARDRAIL_WORKSPACE   repo the agent operates on (default: ./workspace)
  GUARDRAIL_AGENT_ID    agent identity bound into the receipt (default: agent)
  GUARDRAIL_POLICY_ID   committed policy name (default: default-policy)
  GUARDRAIL_PRESET      comma-separated opt-in presets, e.g. 'devops' (cloud/DB kill-commands)
  GUARDRAIL_POLICY_SPEC path to a PolicySpec JSON (protected branches, extra patterns)
  GUARDRAIL_SIGNING_KEY hex 32-byte Ed25519 seed to pin one identity across runs
  GUARDRAIL_AUDIT_LOG   path to stream every gated action to disk (survives a crash)
  GUARDRAIL_ALERT_URL   Slack-compatible webhook fired on every block
  GUARDRAIL_ZK          1|modp|ec to attach zero-knowledge proofs to git actions
"""
import json
import os


def _signing_key():
    """Ed25519 key for the session receipt. Persist it via GUARDRAIL_SIGNING_KEY (hex 32-byte seed) so
    a relying party can pin one identity across runs; otherwise ephemeral (public key is in the receipt)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = os.environ.get("GUARDRAIL_SIGNING_KEY", "")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) if seed else Ed25519PrivateKey.generate()


def build_server():
    """Construct the FastMCP server from the environment and register the gated tools.

    The `mcp` import is deferred so the base package installs and imports without the
    optional `mcp` extra; it is only required when the server is actually run."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise SystemExit(
            "The MCP server needs the 'mcp' extra. Install it with:\n"
            "    pip install 'qedra[mcp]'"
        ) from exc

    from qedra.guardrail import Guardrail
    from qedra.executor import Executor
    from qedra.control_plane import ControlPlane, Policy
    from qedra.audit_log import AuditLog
    from qedra.alerts import webhook_alert

    workspace = os.environ.get("GUARDRAIL_WORKSPACE", os.path.join(os.getcwd(), "workspace"))
    os.makedirs(workspace, exist_ok=True)

    agent_id = os.environ.get("GUARDRAIL_AGENT_ID", "agent")
    zk_env = os.environ.get("GUARDRAIL_ZK", "").lower()
    zk = zk_env if zk_env in ("modp", "ec") else (zk_env in ("1", "true", "yes"))

    # One spec from the environment (default threat model + optional PolicySpec file + opt-in presets),
    # used for BOTH the enforcing gate and the receipt's committed policy, so what is blocked and what the
    # receipt commits to are the same ruleset. Reuses the hook's loader so the two integrations agree.
    from qedra.claude_code_hook import _load_policy_spec
    spec = _load_policy_spec()
    guard = Guardrail(spec)
    policy = Policy(os.environ.get("GUARDRAIL_POLICY_ID", "default-policy"), spec=spec)
    audit = AuditLog(os.environ["GUARDRAIL_AUDIT_LOG"]) if os.environ.get("GUARDRAIL_AUDIT_LOG") else None
    alert = webhook_alert(os.environ["GUARDRAIL_ALERT_URL"]) if os.environ.get("GUARDRAIL_ALERT_URL") else None
    control = ControlPlane(agent_id, policy, signing_key=_signing_key(), zk=zk, audit_log=audit, on_block=alert)
    ex = Executor(workspace, guard, control_plane=control)

    mcp = FastMCP("qedra")

    @mcp.tool()
    def run_shell(cmd: str) -> str:
        """Run a shell command in the workspace. Blocked if it is a destructive action
        (rm -rf the repo, secret exfiltration, force-push); otherwise executed."""
        return ex.run_shell(cmd)

    @mcp.tool()
    def write_file(path: str, content: str) -> str:
        """Write a file in the workspace. Blocked if it writes a secret or empties a CI
        config; otherwise executed."""
        return ex.write_file(path, content)

    @mcp.tool()
    def git(args: str) -> str:
        """Run a git command, e.g. 'add -A', 'commit -m fix'. A force-push, hard-reset,
        or rebase of a protected branch is blocked; normal git is executed."""
        return ex.git(args)

    @mcp.tool()
    def audit_log() -> str:
        """Return the tamper-evident audit chain of every guardrail decision so far."""
        return json.dumps({"chain_verifies": guard.verify_chain(),
                           "blocked": ex.blocked, "executed": ex.executed,
                           "log": guard.log}, indent=2)

    @mcp.tool()
    def policy_info() -> str:
        """Report the exact ruleset being enforced: the committed policy id and root (content hash), the
        protected branches, and any opt-in presets/extra patterns. A relying party can hold the same spec
        and confirm the receipt's policy root matches, so 'the gate enforces this policy' is checkable,
        not a promise."""
        return json.dumps({
            "policy_id": policy.policy_id, "version": policy.version, "policy_root": policy.root(),
            "protected_branches": list(spec.protected_branches),
            "presets": [p for p in os.environ.get("GUARDRAIL_PRESET", "").split(",") if p.strip()],
            "extra_shell_denylist": len(spec.extra_shell_denylist),
            "extra_secret_patterns": len(spec.extra_secret_patterns),
        }, indent=2)

    @mcp.tool()
    def session_receipt(redact: bool = False) -> str:
        """Export a signed, independently-verifiable RECEIPT for this session: the agent id, the committed
        policy, every gated action with its verdict, and an Ed25519 signature over the tamper-evident chain
        head. A third party (an auditor, a bank, an insurer) can verify it with the PUBLIC KEY ALONE via
        qedra.control_plane.verify_receipt, proving the agent stayed within policy, without
        trusting this server or its operator, and catching any forged ALLOW.

        redact=True strips every raw action (commands, file contents, branches) before returning. In
        zk-mode (GUARDRAIL_ZK=1) git-branch actions stay provably in-policy via their zero-knowledge proof
        even when redacted; other actions keep integrity + authenticity only."""
        r = ex.receipt()
        if r is None:
            return json.dumps({"error": "no control plane attached"})
        if redact:
            r, _ = r.redact(reveal=())
        return r.to_json()

    return mcp


def main():
    """Console entry point: build the server from the environment and serve over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
