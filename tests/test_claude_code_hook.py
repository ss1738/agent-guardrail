"""The Claude Code PreToolUse hook: it maps real tool-call payloads to guardrail decisions, emits the
exact deny/ask JSON Claude Code expects, never blocks via a nonzero exit, fails open on bad input, and
(when GUARDRAIL_AUDIT_LOG is set) leaves a durable hash-chained trail across separate hook processes."""
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent_guardrail.claude_code_hook import action_from_tool_call, decide, main
from agent_guardrail.guardrail import Guardrail, PolicySpec


def _bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "hook_event_name": "PreToolUse"}


def _decision(payload, spec=None):
    return decide(payload, Guardrail(spec) if spec else Guardrail())


def test_blocks_force_push_to_protected_branch():
    out, _, dec = _decision(_bash("git push origin main --force"))
    assert dec.verdict == "BLOCK"
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "agent-guardrail blocked" in hso["permissionDecisionReason"]


def test_blocks_catastrophic_rm():
    out, _, dec = _decision(_bash("rm -rf ~"))
    assert dec.verdict == "BLOCK" and out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_allows_ordinary_command_emits_nothing():
    out, _, dec = _decision(_bash("pytest -q && npm run build"))
    assert dec.verdict == "ALLOW"
    assert out is None                     # nothing printed -> the call proceeds untouched


def test_escalate_maps_to_ask():
    # a history rewrite naming no branch -> ESCALATE -> Claude Code asks the human
    out, _, dec = _decision(_bash("git rebase -i HEAD~3"))
    assert dec.verdict == "ESCALATE"
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_preset_opt_in_blocks_terraform_destroy():
    from agent_guardrail.presets import preset_spec
    out, _, dec = _decision(_bash("terraform destroy -auto-approve"), spec=preset_spec("devops"))
    assert dec.verdict == "BLOCK" and out["hookSpecificOutput"]["permissionDecision"] == "deny"
    # ...and without the preset the same command is out of scope (default is unchanged)
    _, _, dec2 = _decision(_bash("terraform destroy -auto-approve"))
    assert dec2.verdict == "ALLOW"


def test_write_tool_secret_is_blocked():
    # built at runtime so no literal AWS key sits in the source (the AWS docs EXAMPLE key)
    secret = "AKIA" + "IOSFODNN7EXAMPLE"
    payload = {"tool_name": "Write",
               "tool_input": {"file_path": "cfg.py", "content": f"AWS_KEY = '{secret}'"}}
    _, action, dec = decide(payload, Guardrail())
    assert action.kind == "write" and dec.verdict == "BLOCK"


def test_unknown_tool_is_out_of_scope():
    assert action_from_tool_call("WebFetch", {"url": "https://x"}) is None
    out, action, dec = decide({"tool_name": "WebFetch", "tool_input": {}}, Guardrail())
    assert (out, action, dec) == (None, None, None)


def test_main_emits_deny_json_and_exit_zero():
    stdin = io.StringIO(json.dumps(_bash("git push origin main --force")))
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        rc = main([], stdin=stdin)
    finally:
        sys.stdout = old
    assert rc == 0                                  # NEVER a nonzero exit; block is in the body
    assert json.loads(buf.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_fails_open_on_bad_input():
    rc = main([], stdin=io.StringIO("not json {{{"))
    assert rc == 0                                  # unreadable input -> allow, do not brick the agent


def test_main_allow_prints_nothing():
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        rc = main([], stdin=io.StringIO(json.dumps(_bash("ls -la"))))
    finally:
        sys.stdout = old
    assert rc == 0 and buf.getvalue().strip() == ""


def test_audit_log_chains_across_separate_processes():
    """Each hook call is a fresh process; the durable trail must still form ONE verifiable chain."""
    from agent_guardrail.audit_log import verify_log
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as fh:
        path = fh.name
    os.remove(path)
    os.environ["GUARDRAIL_AUDIT_LOG"] = path
    try:
        for cmd in ["ls -la", "git push origin main --force", "npm test", "rm -rf ~"]:
            # simulate independent invocations: a new stdin + (conceptually) a new process each time
            main([], stdin=io.StringIO(json.dumps(_bash(cmd))))
        ok, msg = verify_log(path)
        assert ok, msg
        assert "4 entries" in msg
    finally:
        os.environ.pop("GUARDRAIL_AUDIT_LOG", None)
        os.path.exists(path) and os.remove(path)


def test_print_config():
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        rc = main(["--print-config"])
    finally:
        sys.stdout = old
    assert rc == 0 and '"PreToolUse"' in buf.getvalue() and "agent-guardrail-hook" in buf.getvalue()


if __name__ == "__main__":
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    passed = 0
    for f in fns:
        try:
            f()
            print(f"  ✓ {f.__name__}")
            passed += 1
        except AssertionError as ex:
            print(f"  ✗ {f.__name__}  {ex}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
