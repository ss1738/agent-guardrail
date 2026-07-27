"""demo_zk_receipt.py: the Agent Control Plane with zero-knowledge receipts (ZK_ROADMAP milestone 2).

demo_receipt.py showed the trade-off: to prove a verdict sound, you disclose the action. This removes
it for the git-branch policy. The operator runs a gated session in zk-mode, then REDACTS every action
so that no commands, no branches, or file contents leave the box, and a third party can STILL verify that
each git action was correctly classified, and still catch a forged "it was allowed".

    python3 demo_zk_receipt.py
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_guardrail import zk as _zk
from agent_guardrail.control_plane import (
    GENESIS,
    ControlPlane,
    Policy,
    Receipt,
    _chain_step,
    _signing_payload,
    verify_receipt,
)
from agent_guardrail.guardrail import Action

POLICY = Policy("acme-prod-agent-policy", "1")


def line(c="-"):
    print(c * 72)


def forge(receipt, key):
    """Operator lies: flip every zk BLOCK to an executed ALLOW, swap in a witness-free ALLOW proof over
    the same commitment, recompute the chain, re-sign with their own key."""
    for e in receipt.entries:
        if e.zk is not None and e.verdict == "BLOCK":
            e.verdict, e.executed, e.reason = "ALLOW", True, "git-branch policy: ALLOW"
            e.zk = _zk.simulate_all(int(e.commit), "ALLOW").to_dict()
    head = GENESIS
    for i, e in enumerate(receipt.entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        e.head = head
    receipt.final_head = head
    receipt.signature = key.sign(
        _signing_payload(receipt.agent_id, receipt.policy_root, head, len(receipt.entries))
    ).hex()
    return receipt


def main():
    key = Ed25519PrivateKey.generate()
    cp = ControlPlane("acme/deploy-agent", POLICY, signing_key=key, zk=True)

    print("\nAGENT SESSION (zk-mode; git actions get an eager zero-knowledge proof)\n")
    cp.gate(Action("git", op="commit", branch="dev"))              # ALLOW
    cp.gate(Action("git", op="push", branch="main", force=True))   # BLOCK
    cp.gate(Action("git", op="rebase", branch="release"))          # BLOCK
    cp.gate(Action("git", op="push", branch="feature", force=True))  # ALLOW
    for e in cp._entries:
        print(f"  {e.reason:<28} verdict={e.verdict:<6} zk={'yes' if e.zk else 'no'}")

    receipt = cp.receipt()
    line()
    print("REDACT EVERYTHING (no command, branch, or op leaves the operator's box):")
    red, _ = receipt.redact(reveal=())
    leaked = [e.action for e in red.entries if e.action is not None]
    print(f"  actions disclosed : {len(leaked)}   (each entry keeps only: commitment, verdict, zk proof)")

    line()
    print("INDEPENDENT VERIFICATION (third party holds only the redacted receipt + the public policy):")
    v = verify_receipt(Receipt.from_json(red.to_json()), POLICY)
    print(f"  -> {'VERIFIED' if v.ok else 'REJECTED'}: {v.reason}")

    line()
    print("OPERATOR LIES: flip the blocked actions to ALLOW, forge proofs, re-chain, re-sign...")
    forged = forge(Receipt.from_json(red.to_json()), key)
    v2 = verify_receipt(forged, POLICY)
    print(f"  -> {'VERIFIED' if v2.ok else 'CAUGHT'}: {v2.reason}")

    line("=")
    print("Every action hidden, yet each git verdict provably correct, and the forgery still caught.")
    print("(Prototype crypto, Fiat-Shamir in ROM; external review required before it is a guarantee.)\n")


if __name__ == "__main__":
    main()
