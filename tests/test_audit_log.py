"""Durable audit log + block alerts. A crashed agent still leaves a tamper-evident trail on disk that
verifies without a key and reconstructs into a signed receipt; a tampered trail is rejected; and an
audit-sink or alert failure never breaks the gate."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_guardrail.audit_log import AuditLog, receipt_from_log, verify_log
from agent_guardrail.control_plane import ControlPlane, Policy, Receipt, verify_receipt
from agent_guardrail.guardrail import Action

POLICY = Policy("audit-test", "1")


def _session(path, key=None, on_block=None):
    cp = ControlPlane("acme/agent", POLICY, signing_key=key, audit_log=AuditLog(path), on_block=on_block)
    cp.gate(Action("git", op="commit", branch="dev"))               # ALLOW
    cp.gate(Action("git", op="push", branch="main", force=True))    # BLOCK
    cp.gate(Action("shell", cmd="rm -rf .git"))                     # BLOCK
    cp.gate(Action("shell", cmd="cargo test --all"))                # ALLOW
    return cp


def test_log_written_and_loads():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    cp = _session(p)
    entries = AuditLog.load(p)
    assert len(entries) == 4
    assert [e.verdict for e in entries] == [e.verdict for e in cp._entries]


def test_log_integrity_verifies_without_a_key():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    _session(p)
    ok, why = verify_log(p)
    assert ok and "4 entries" in why


def test_receipt_reconstructed_from_log_verifies():
    key = Ed25519PrivateKey.generate()
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    cp = _session(p, key)
    reconstructed = receipt_from_log(p, "acme/agent", POLICY, key)
    v = verify_receipt(Receipt.from_json(reconstructed.to_json()), POLICY)
    assert v.ok, v.reason
    # same head as the live in-memory receipt (the log is a faithful mirror)
    assert reconstructed.final_head == cp.receipt().final_head


def test_crash_leaves_a_valid_partial_trail():
    key = Ed25519PrivateKey.generate()
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    cp = ControlPlane("acme/agent", POLICY, signing_key=key, audit_log=AuditLog(p))
    cp.gate(Action("git", op="commit", branch="dev"))
    cp.gate(Action("git", op="push", branch="main", force=True))    # then the process "dies"
    del cp
    ok, _ = verify_log(p)
    assert ok
    r = receipt_from_log(p, "acme/agent", POLICY, key)
    assert len(r.entries) == 2
    assert verify_receipt(Receipt.from_json(r.to_json()), POLICY).ok


def test_tampered_log_is_rejected():
    key = Ed25519PrivateKey.generate()
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    _session(p, key)
    lines = open(p).read().splitlines()
    lines[1] = lines[1].replace('"BLOCK"', '"ALLOW"')   # flip the force-push from BLOCK to ALLOW
    open(p, "w").write("\n".join(lines) + "\n")
    ok, why = verify_log(p)
    assert not ok and "altered" in why
    try:
        receipt_from_log(p, "acme/agent", POLICY, key)
        assert False, "a tampered log must not reconstruct into a receipt"
    except ValueError:
        pass


def test_on_block_fires_only_on_blocks():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    hits = []
    _session(p, on_block=lambda action, reason: hits.append((action.kind, reason)))
    assert len(hits) == 2                                  # exactly the two BLOCKed actions
    assert all(isinstance(r, str) and r for _, r in hits)


def test_on_block_failure_never_breaks_the_gate():
    p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    def boom(action, reason):
        raise RuntimeError("webhook is down")
    cp = _session(p, on_block=boom)                        # must not raise
    assert len(cp._entries) == 4


def test_audit_sink_failure_never_breaks_the_gate():
    class BadSink:
        def append(self, e):
            raise IOError("disk full")
    cp = ControlPlane("a/b", POLICY, audit_log=BadSink())
    cp.gate(Action("git", op="push", branch="main", force=True))   # must not raise
    assert len(cp._entries) == 1 and cp._entries[0].verdict == "BLOCK"


def test_webhook_alert_posts_the_block():
    import http.server
    import json as _json
    import threading
    from agent_guardrail.alerts import webhook_alert
    received = {}
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received["body"] = self.rfile.read(n).decode()
            self.send_response(200); self.end_headers()
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.handle_request, daemon=True); th.start()
    webhook_alert(f"http://127.0.0.1:{port}")(
        Action("git", op="push", branch="main", force=True), "force-push to protected branch 'main'")
    th.join(timeout=3); srv.server_close()
    d = _json.loads(received["body"])
    assert d["verdict"] == "BLOCK" and "push main" in d["action"] and "force-push" in d["reason"]


def test_webhook_alert_survives_a_dead_endpoint():
    from agent_guardrail.alerts import webhook_alert
    # nothing is listening; the alert must swallow the failure and not raise
    webhook_alert("http://127.0.0.1:1", timeout=0.5)(Action("shell", cmd="rm -rf .git"), "repo delete")


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
