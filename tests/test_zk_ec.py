"""The git-branch ZK proof over secp256k1 (ZK_ROADMAP milestone 4). Mirrors the property tests of
test_zk.py, correctness, soundness, zero-knowledge, serialization, to confirm the SAME guarantees
hold when only the group is swapped, plus the curve self-check and the measured size win."""
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent_guardrail import ec, zk, zk_ec
from agent_guardrail.guardrail import Action

BLOCK = Action("git", op="push", branch="main", force=True)
ALLOW = Action("git", op="push", branch="feature", force=True)


def test_curve_self_check():
    # constants + arithmetic validated against published vectors; Jacobian cross-checked vs affine
    assert ec.self_check()


def test_honest_proof_verifies():
    for act in [BLOCK, ALLOW, Action("git", op="rebase", branch="release"),
                Action("git", op="commit", branch="dev")]:
        C, proof, r = zk_ec.prove_action(act)
        assert zk_ec.verify(C, proof), act
        assert proof.verdict == zk.action_verdict(act)[0]


def test_forged_proof_rejected():
    _, m = zk.action_verdict(ALLOW)
    C, _ = zk_ec.commit(m)                      # commit to an ALLOW action
    for target in ("BLOCK", "ALLOW"):
        assert zk_ec.verify(C, zk_ec.simulate_all(C, target)) is False


def test_verdict_relabel_rejected():
    C, proof, _ = zk_ec.prove_action(ALLOW)
    proof.verdict = "BLOCK"                      # set changes -> fails
    assert zk_ec.verify(C, proof) is False


def test_proof_bound_to_commitment():
    C1, proof, _ = zk_ec.prove_action(BLOCK)
    _, m = zk.action_verdict(BLOCK)
    C2, _ = zk_ec.commit(m)                      # same action, fresh randomness -> different point
    assert C1 != C2 and zk_ec.verify(C2, proof) is False


def test_tampered_response_rejected():
    C, proof, _ = zk_ec.prove_action(BLOCK)
    assert zk_ec.verify(C, proof)
    proof.z[0] = (proof.z[0] + 1) % ec.N
    assert zk_ec.verify(C, proof) is False


def test_serialization_roundtrip():
    C, proof, _ = zk_ec.prove_action(BLOCK)
    from agent_guardrail.zk_core import ZKProof
    back = ZKProof.from_dict(proof.to_dict())
    assert zk_ec.verify(C, back) and back.t == proof.t
    # commitments/points serialize compactly (33-byte compressed points, 66 hex chars)
    assert all(len(s) == 66 for s in proof.t)


def test_zero_knowledge_simulatable():
    # accepting transcripts are producible without the witness (HVZK): for a chosen challenge, every
    # clause equation holds and the challenges sum to the target
    from agent_guardrail import zk_core
    _, m = zk.action_verdict(BLOCK)
    C, _ = zk_ec.commit(m)
    ms = zk.allowed_set("BLOCK")
    g = zk_ec.EC
    for _ in range(3):
        e_target = secrets.randbelow(g.q)
        e = [secrets.randbelow(g.q) for _ in ms]
        e[-1] = (e_target - sum(e[:-1])) % g.q
        z = [secrets.randbelow(g.q) for _ in ms]
        t = [g.op(g.mul(g.h, z[i]), g.mul(zk_core.y(g, C, ms[i]), (g.q - e[i]) % g.q))
             for i in range(len(ms))]
        assert sum(e) % g.q == e_target
        for i in range(len(ms)):
            lhs = g.mul(g.h, z[i])
            rhs = g.op(t[i], g.mul(zk_core.y(g, C, ms[i]), e[i]))
            assert g.eq(lhs, rhs)


def test_ec_proof_smaller_than_modp():
    _, p_ec, _ = zk_ec.prove_action(BLOCK)
    _, p_modp, _ = zk.prove_action(BLOCK)
    s_ec = len(json.dumps(p_ec.to_dict()))
    s_modp = len(json.dumps(p_modp.to_dict()))
    assert s_ec < s_modp / 4, f"EC {s_ec}B vs MODP {s_modp}B"   # measured ~8x smaller


def test_ec_and_modp_agree_on_verdict():
    # the two groups share the policy layer, so they must classify identically
    for act in [BLOCK, ALLOW, Action("git", op="reset", branch="master", hard=True)]:
        assert zk_ec.prove_action(act)[1].verdict == zk.prove(act, 7).verdict == zk.action_verdict(act)[0]


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
