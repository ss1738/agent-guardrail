"""demo_zk.py: zero-knowledge receipt for the git-branch policy (ZK_ROADMAP milestone 1).

The plaintext receipt forces a choice: disclose an action (leaks the command) or redact it (lose the
soundness proof). This removes the choice. The operator commits to an action and attaches a ZK proof
that the committed action is one the policy classifies as the recorded verdict, the verifier learns
the verdict is correct WITHOUT ever seeing the action, and a forged verdict is still caught.

    python3 demo_zk.py
"""
from agent_guardrail.guardrail import Action
from agent_guardrail import zk


def line(c="-"):
    print(c * 72)


def main():
    print("\nGROUP self-check (2048-bit safe prime, order-Q QR subgroup):",
          "OK" if zk._group_ok() else "FAILED")

    # The operator's agent tried a force-push to main. The gate BLOCKED it. The operator wants to
    # prove to an auditor "the agent's action was correctly blocked" WITHOUT revealing what it was.
    secret_action = Action("git", op="push", branch="main", force=True)
    verdict, _ = zk.action_verdict(secret_action)
    C, proof, r = zk.prove_action(secret_action)

    line()
    print("WHAT THE OPERATOR SHIPS (the entire disclosure):")
    print(f"  commitment C : {str(C)[:40]}...   (hides the action; perfectly hiding Pedersen)")
    print(f"  claimed verdict : {verdict}")
    print(f"  zk proof : {len(proof.t)} clauses over S_{verdict}  (the raw action is NEVER sent)")

    line()
    print("INDEPENDENT VERIFICATION (auditor holds only C + verdict + the public policy):")
    ok = zk.verify(C, proof)
    print(f"  -> {'VERIFIED' if ok else 'REJECTED'}: the committed action is provably one the policy "
          f"classifies as {verdict}")
    print("  the auditor learns the verdict is sound, and learns NOTHING about which action it was")

    line()
    print("NOW THE OPERATOR LIES: same commitment, claim it was ALLOW (a benign op), forge a proof...")
    forged = zk.simulate_all(C, "ALLOW")  # simulate every clause; no valid witness exists
    caught = not zk.verify(C, forged)
    print(f"  -> {'CAUGHT' if caught else 'VERIFIED'}: a false verdict cannot produce an accepting proof")

    line("=")
    print("Fully private AND provably in-policy. A forged verdict is caught with zero disclosure.")
    print("(Prototype crypto, Fiat-Shamir in ROM; external review required before it is a guarantee.)\n")


if __name__ == "__main__":
    main()
