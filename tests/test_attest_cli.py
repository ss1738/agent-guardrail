"""`qedra-attest` turns a persisted audit log into a signed, third-party-verifiable receipt, refuses to
sign a tampered log, and writes the signing key at mode 600."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qedra.attest_cli import main
from qedra.audit_log import AuditLog
from qedra.control_plane import ControlPlane, Policy, Receipt, verify_receipt
from qedra.guardrail import Action


def _make_log(path):
    cp = ControlPlane("agent-1", Policy("qedra"), audit_log=AuditLog(path))
    cp.record(Action("shell", cmd="cargo test"), "ALLOW", "build/test", executed=True)
    cp.record(Action("shell", cmd="git push --force origin main"), "BLOCK", "protected rewrite", executed=False)
    cp.record(Action("shell", cmd="npm run build"), "ALLOW", "build/test", executed=True)


def test_attest_produces_a_verifiable_receipt():
    d = tempfile.mkdtemp()
    log, key, out = f"{d}/s.jsonl", f"{d}/key", f"{d}/r.json"
    _make_log(log)
    assert main([log, "--agent-id", "agent-1", "--key", key, "--out", out, "-q"]) == 0
    receipt = Receipt.from_json(open(out).read())
    assert receipt.agent_id == "agent-1"
    assert len(receipt.entries) == 3
    assert verify_receipt(receipt, Policy("qedra")).ok


def test_signing_key_is_created_mode_600():
    d = tempfile.mkdtemp()
    log, key = f"{d}/s.jsonl", f"{d}/key"
    _make_log(log)
    assert main([log, "--key", key, "--out", f"{d}/r.json", "-q"]) == 0
    assert os.path.exists(key)
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"


def test_refuses_to_sign_a_tampered_log():
    d = tempfile.mkdtemp()
    log = f"{d}/s.jsonl"
    _make_log(log)
    lines = open(log).read().splitlines()
    e = json.loads(lines[1]); e["verdict"] = "ALLOW"; e["executed"] = True  # flip a BLOCK
    lines[1] = json.dumps(e)
    open(log, "w").write("\n".join(lines) + "\n")
    assert main([log, "--key", f"{d}/key", "--out", f"{d}/r.json", "-q"]) == 1  # integrity check fails


def test_missing_log_returns_1():
    assert main(["/no/such/log.jsonl", "-q"]) == 1


if __name__ == "__main__":
    fns = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    ok = 0
    for f in fns:
        try:
            f(); print(f"  ok {f.__name__}"); ok += 1
        except Exception as e:
            print(f"  XX {f.__name__}: {e}")
    print(f"{ok}/{len(fns)} passed")
    sys.exit(0 if ok == len(fns) else 1)
