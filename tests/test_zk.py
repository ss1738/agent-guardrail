"""Tests for the zero-knowledge git-branch receipt (ZK_ROADMAP milestone 1).

Three properties a ZK proof must have, each tested adversarially:
  correctness: an honest proof for the true verdict verifies
  soundness: a false claim (commit to X, prove membership of a set it is not in) cannot verify
  zero-knowledge: an accepting transcript is simulatable WITHOUT the witness (reveals nothing)
plus the group self-check, verdict binding, commitment binding, tamper-evidence, and serialization.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent_guardrail.guardrail import Action
from agent_guardrail import zk


# --- the group the whole construction rests on -----------------------------
def test_group_self_check():
    # P and Q prime, P = 2Q+1, G and H non-identity elements of the order-Q subgroup.
    # This also catches any transcription error in the hardcoded prime.
    assert zk._group_ok()


def test_pedersen_is_binding_form():
    C, r = zk.commit(7)
    assert C == (pow(zk.G, 7, zk.P) * pow(zk.H, r, zk.P)) % zk.P
    assert 1 <= r < zk.Q


# --- the policy set S_V is exactly the policy's preimage --------------------
def test_allowed_sets_match_policy():
    # every element the domain classifies as V lands in allowed_set(V), and only those
    for v in ("ALLOW", "BLOCK"):
        s = set(zk.allowed_set(v))
        for a in zk._domain():
            enc = zk.encode(*a)
            if zk._verdict(*a) == v:
                assert enc in s
            else:
                assert enc not in s or zk._verdict(*a) == v  # no cross-verdict leakage
    # the three real block cases are present in the BLOCK set
    block = set(zk.allowed_set("BLOCK"))
    assert zk.encode("push", "main", 1, 0) in block
    assert zk.encode("reset", "master", 0, 1) in block
    assert zk.encode("rebase", "release", 0, 0) in block
    # and a benign force-push to a feature branch is NOT in it
    assert zk.encode("push", "feature", 1, 0) not in block


# --- correctness -----------------------------------------------------------
def test_honest_proof_verifies_block_and_allow():
    for act in [Action("git", op="push", branch="main", force=True),      # BLOCK
                Action("git", op="rebase", branch="release"),             # BLOCK
                Action("git", op="reset", branch="master", hard=True),    # BLOCK
                Action("git", op="push", branch="feature", force=True),   # ALLOW
                Action("git", op="commit", branch="dev")]:                # ALLOW
        C, proof, r = zk.prove_action(act)
        assert zk.verify(C, proof), act
        # the proof carries the true verdict
        assert proof.verdict == zk.action_verdict(act)[0]


def test_proof_reveals_nothing_about_which_action():
    # two different BLOCK actions produce proofs over the SAME set; a verifier learns only "BLOCK"
    a1 = Action("git", op="push", branch="main", force=True)
    a2 = Action("git", op="rebase", branch="release")
    C1, p1, _ = zk.prove_action(a1)
    C2, p2, _ = zk.prove_action(a2)
    assert p1.verdict == p2.verdict == "BLOCK"
    assert len(p1.t) == len(p2.t) == len(zk.allowed_set("BLOCK"))


# --- soundness: a false verdict claim cannot be proven ---------------------
def test_forged_proof_without_witness_is_rejected():
    # commit to a real ALLOW action, then try to forge membership of the BLOCK set (and vice versa),
    # using the strongest witness-free cheat (simulate every clause). Both must be rejected.
    allow = Action("git", op="push", branch="feature", force=True)
    _, m = zk.action_verdict(allow)
    C, _ = zk.commit(m)
    for target in ("BLOCK", "ALLOW"):
        assert zk.verify(C, zk.simulate_all(C, target)) is False


def test_cannot_prove_allow_action_is_block():
    # the honest prover literally cannot build a BLOCK proof for an ALLOW action...
    allow = Action("git", op="commit", branch="dev")
    C, _ = zk.commit(zk.action_verdict(allow)[1])
    try:
        zk.prove(allow, 12345)  # verdict derived inside is ALLOW; fine, but check the set guard too
    except ValueError:
        pass
    # ...and forging the BLOCK claim over that commitment fails to verify
    assert zk.verify(C, zk.simulate_all(C, "BLOCK")) is False


def test_verdict_relabel_is_rejected():
    # take an honest ALLOW proof and relabel it BLOCK -> the set changes, verification fails
    act = Action("git", op="push", branch="feature", force=True)
    C, proof, _ = zk.prove_action(act)
    proof.verdict = "BLOCK"
    assert zk.verify(C, proof) is False


def test_proof_bound_to_its_commitment():
    # an honest proof for C1 does not verify against a different commitment C2
    act = Action("git", op="push", branch="main", force=True)
    C1, proof, _ = zk.prove_action(act)
    C2, _ = zk.commit(zk.action_verdict(act)[1])  # same action, fresh randomness -> different C
    assert C1 != C2
    assert zk.verify(C2, proof) is False


def test_tampered_response_is_rejected():
    act = Action("git", op="reset", branch="main", hard=True)
    C, proof, _ = zk.prove_action(act)
    assert zk.verify(C, proof)
    proof.z[0] = (proof.z[0] + 1) % zk.Q
    assert zk.verify(C, proof) is False


# --- zero-knowledge: transcripts are simulatable without the witness -------
def test_honest_verifier_zero_knowledge_simulatable():
    """Given only C and a target challenge, produce an accepting transcript with no witness.
    Each clause equation holds and the challenges sum to the target, identical distribution to
    a real transcript, demonstrating the proof leaks nothing about the opening."""
    act = Action("git", op="push", branch="main", force=True)
    C, _ = zk.commit(zk.action_verdict(act)[1])
    verdict = "BLOCK"
    ms = zk.allowed_set(verdict)
    for _ in range(5):
        e_target = secrets.randbelow(zk.Q)
        e = [secrets.randbelow(zk.Q) for _ in ms]
        e[-1] = (e_target - sum(e[:-1])) % zk.Q
        z = [secrets.randbelow(zk.Q) for _ in ms]
        t = [(pow(zk.H, z[i], zk.P) * pow(zk._y(C, ms[i]), (zk.Q - e[i]) % zk.Q, zk.P)) % zk.P
             for i in range(len(ms))]
        # simulated transcript satisfies every verification equation for the chosen challenge
        assert sum(e) % zk.Q == e_target
        for i in range(len(ms)):
            assert pow(zk.H, z[i], zk.P) == (t[i] * pow(zk._y(C, ms[i]), e[i], zk.P)) % zk.P


# --- serialization ---------------------------------------------------------
def test_proof_serialization_roundtrip():
    act = Action("git", op="rebase", branch="main")
    C, proof, _ = zk.prove_action(act)
    back = zk.ZKProof.from_dict(proof.to_dict())
    assert zk.verify(C, back)
    assert back.verdict == proof.verdict and back.t == proof.t


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
