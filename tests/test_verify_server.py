"""The HTTP verify service. A relying party POSTs a receipt and gets a yes/no under the policy the
server holds: an honest receipt verifies, a forged one is caught, a receipt under a different policy is
rejected, and an unregistered agent is refused. Same trust model as the CLI, over HTTP."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_guardrail.control_plane import (
    GENESIS, ControlPlane, Policy, Receipt, _chain_step, _commit, _signing_payload,
)
from agent_guardrail.guardrail import Action
from agent_guardrail.registry import Registry
from agent_guardrail.verify_server import build_server

POLICY = Policy("serve-test", "1")


def _receipt(key):
    cp = ControlPlane("acme/agent", POLICY, signing_key=key)
    cp.gate(Action("git", op="commit", branch="dev"))
    cp.gate(Action("git", op="push", branch="main", force=True))   # BLOCK
    cp.gate(Action("shell", cmd="cargo test"))
    return cp.receipt()


def _forge(receipt, key):
    for e in receipt.entries:
        if e.verdict == "BLOCK":
            e.verdict, e.executed, e.reason = "ALLOW", True, "nothing to see"
    head = GENESIS
    for i, e in enumerate(receipt.entries):
        if e.action is not None:
            e.commit = _commit(e.action, e.salt)
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        e.head = head
    receipt.final_head = head
    receipt.signature = key.sign(_signing_payload(receipt.agent_id, receipt.policy_root, head, len(receipt.entries))).hex()
    return receipt


class _Server:
    def __init__(self, policy=POLICY, pinned=None, registry=None):
        self.srv = build_server(policy, "127.0.0.1", 0, pinned=pinned, registry=registry)
        self.port = self.srv.server_address[1]
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True); self.th.start()
    def post(self, obj):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/verify",
                                     data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.status, json.load(r)
    def close(self):
        self.srv.shutdown(); self.srv.server_close(); self.th.join(timeout=2)


def test_honest_receipt_verifies_over_http():
    s = _Server()
    try:
        code, body = s.post({"receipt": json.loads(_receipt(Ed25519PrivateKey.generate()).to_json())})
        assert code == 200 and body["ok"] is True, body
        assert body["actions"] == 3 and body["blocked"] == 1
    finally:
        s.close()


def test_receipt_accepted_at_top_level_too():
    s = _Server()
    try:
        code, body = s.post(json.loads(_receipt(Ed25519PrivateKey.generate()).to_json()))
        assert body["ok"] is True, body
    finally:
        s.close()


def test_forged_receipt_is_caught_over_http():
    key = Ed25519PrivateKey.generate()
    forged = _forge(_receipt(key), key)
    s = _Server()
    try:
        code, body = s.post({"receipt": json.loads(forged.to_json())})
        assert body["ok"] is False and "unsound" in body["reason"], body
    finally:
        s.close()


def test_wrong_policy_is_rejected():
    r = _receipt(Ed25519PrivateKey.generate())
    s = _Server(policy=Policy("a-different-policy", "1"))
    try:
        code, body = s.post({"receipt": json.loads(r.to_json())})
        assert body["ok"] is False and "policy" in body["reason"].lower(), body
    finally:
        s.close()


def test_registry_refuses_unregistered_agent():
    r = _receipt(Ed25519PrivateKey.generate())
    reg = Registry()  # empty
    s = _Server(registry=reg)
    try:
        code, body = s.post({"receipt": json.loads(r.to_json())})
        assert body["ok"] is False and "not registered" in body["reason"], body
    finally:
        s.close()


def test_health_and_malformed():
    s = _Server()
    try:
        assert s.get("/health")[1]["status"] == "ok"
        code, body = s.post("not-a-dict-or-receipt")   # valid JSON string, but not a receipt
        assert code == 400, (code, body)
    finally:
        s.close()


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
