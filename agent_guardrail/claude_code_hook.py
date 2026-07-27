"""`agent-guardrail-hook` -- a Claude Code PreToolUse hook.

Claude Code is the ICP: a coding agent that runs shell commands on your machine. It has a native
`PreToolUse` hook that hands every tool call to an external command as JSON on stdin and lets that
command block it. This wires the guardrail into that seam, so the same gate that the receipts prove
runs on real tool calls with no framework code:

    agent-guardrail-hook --print-config      # prints the .claude/settings.json block to paste

Registered as a `command` hook matching `Bash` (and, if you widen the matcher, `Write`/`Edit`), every
tool call is classified by the same `Guardrail`:
  - BLOCK   -> the call is denied and Claude is told why (permissionDecision "deny")
  - ESCALATE -> Claude Code prompts the human (permissionDecision "ask")
  - ALLOW   -> nothing printed; the call proceeds normally

Policy comes from the environment so one installed hook serves any repo:
  GUARDRAIL_PRESET       comma-separated opt-in presets, e.g. "devops"
  GUARDRAIL_POLICY_SPEC  path to a PolicySpec JSON (protected branches, extra patterns)
  GUARDRAIL_AUDIT_LOG    if set, every gated call is appended to a durable, hash-chained trail, so a
                         real Claude Code session leaves a verifiable receipt (agent-guardrail-verify)
  GUARDRAIL_ALERT_URL    if set, a Slack-compatible webhook is posted on every BLOCK

Fail-open by design: any internal error in the hook prints a note to stderr and lets the call proceed.
A buggy security hook that bricks the agent gets uninstalled; the gate's remit is high-precision blocks
on a defined threat model, not being a single point of failure for the whole session. Stdlib only.
"""
from __future__ import annotations

import json
import os
import sys

from .guardrail import Action, DEFAULT_SPEC, Guardrail

HOOK_EVENT = "PreToolUse"


def _load_policy_spec():
    """Build the PolicySpec from the environment (spec file first, then presets layered on)."""
    spec = DEFAULT_SPEC
    path = os.environ.get("GUARDRAIL_POLICY_SPEC")
    if path:
        from .guardrail import PolicySpec
        spec = PolicySpec.from_json(open(path).read())
    presets = [p.strip() for p in os.environ.get("GUARDRAIL_PRESET", "").split(",") if p.strip()]
    if presets:
        from .presets import preset_spec
        spec = preset_spec(*presets, base=spec)
    return spec


def action_from_tool_call(tool_name: str, tool_input: dict) -> Action | None:
    """Map a Claude Code tool call to a guardrail Action, or None if the tool is out of scope.

    Bash -> shell (covers destruction, secret exfiltration, protected-branch history rewrite, and any
    opt-in preset denylist). Write/Edit -> write (covers writing a secret to a file, emptying CI)."""
    if tool_name == "Bash":
        cmd = (tool_input or {}).get("command", "")
        return Action("shell", cmd=cmd) if cmd else None
    if tool_name == "Write":
        ti = tool_input or {}
        return Action("write", path=ti.get("file_path", ""), content=ti.get("content", ""))
    if tool_name in ("Edit", "MultiEdit"):
        ti = tool_input or {}
        # the new content is what could introduce a secret; approximate with new_string(s)
        if tool_name == "Edit":
            content = ti.get("new_string", "")
        else:
            content = "\n".join(e.get("new_string", "") for e in ti.get("edits", []) or [])
        return Action("write", path=ti.get("file_path", ""), content=content)
    return None


def decide(payload: dict, guard: Guardrail):
    """Pure decision function (no I/O): return (hook_output_dict_or_None, action, decision).

    hook_output is None when the call should proceed with no interference (ALLOW / out of scope).
    For BLOCK -> permissionDecision "deny"; for ESCALATE -> "ask" (defer to the human)."""
    tool_name = payload.get("tool_name", "")
    action = action_from_tool_call(tool_name, payload.get("tool_input") or {})
    if action is None:
        return None, None, None
    decision = guard.check(action)
    if decision.verdict == "BLOCK":
        out = _hook_output("deny", f"agent-guardrail blocked this: {decision.reason}")
    elif decision.verdict == "ESCALATE":
        out = _hook_output("ask", f"agent-guardrail wants a human to confirm: {decision.reason}")
    else:
        out = None
    return out, action, decision


def _hook_output(permission_decision: str, reason: str) -> dict:
    return {"hookSpecificOutput": {
        "hookEventName": HOOK_EVENT,
        "permissionDecision": permission_decision,
        "permissionDecisionReason": reason,
    }}


def _maybe_record(payload: dict, action: Action, decision) -> None:
    """Best-effort: append the gated call to the durable trail and fire a block alert. Never raises."""
    path = os.environ.get("GUARDRAIL_AUDIT_LOG")
    if not path or action is None:
        return
    try:
        from .audit_log import AuditLog
        from .control_plane import ControlPlane, Policy

        spec = _load_policy_spec()
        policy = Policy(os.environ.get("GUARDRAIL_POLICY_ID", "claude-code"),
                        os.environ.get("GUARDRAIL_POLICY_VERSION", "1"), spec)
        on_block = None
        url = os.environ.get("GUARDRAIL_ALERT_URL")
        if url:
            from .alerts import webhook_alert
            on_block = webhook_alert(url)
        cp = ControlPlane(payload.get("session_id", "claude-code"), policy,
                          audit_log=AuditLog(path), on_block=on_block)
        cp.resume(AuditLog.load(path))          # continue the file's hash-chain across processes
        cp.record(action, decision.verdict, decision.reason, executed=(decision.verdict == "ALLOW"))
    except Exception as e:                       # logging must never break the hook
        print(f"agent-guardrail-hook: audit logging skipped ({e})", file=sys.stderr)


CONFIG_SNIPPET = """{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "agent-guardrail-hook" }
        ]
      }
    ]
  }
}"""


def main(argv: list[str] | None = None, stdin=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--print-config" in argv:
        print("# Paste into .claude/settings.json (merge with any existing \"hooks\"):")
        print(CONFIG_SNIPPET)
        print("\n# Widen coverage to file writes with:  \"matcher\": \"Bash|Write|Edit\"")
        print("# Env: GUARDRAIL_PRESET=devops  GUARDRAIL_AUDIT_LOG=~/.agent-guardrail/session.jsonl")
        return 0

    stdin = stdin or sys.stdin
    try:
        payload = json.load(stdin)
    except Exception as e:
        # cannot parse the hook input -> fail open (let the call proceed), but say why on stderr
        print(f"agent-guardrail-hook: could not read hook input ({e}); allowing", file=sys.stderr)
        return 0

    try:
        guard = Guardrail(_load_policy_spec())
        out, action, decision = decide(payload, guard)
        if decision is not None:
            _maybe_record(payload, action, decision)
        if out is not None:
            print(json.dumps(out))
    except Exception as e:
        print(f"agent-guardrail-hook: internal error ({e}); allowing", file=sys.stderr)
    return 0   # always 0: block is expressed via the JSON body, never a nonzero exit


if __name__ == "__main__":
    sys.exit(main())
