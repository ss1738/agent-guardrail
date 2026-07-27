"""ZK receipts end-to-end (ZK_ROADMAP milestone 2): a git-branch entry can be REDACTED yet remain
provably in-policy, because it carries a zero-knowledge proof over the same Pedersen commitment that
is in the hash-chain. The load-bearing test: a chained BLOCK cannot be relabelled ALLOW, even by an
operator who recomputes the chain and re-signs with their own key."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_guardrail import ec
from agent_guardrail import zk as _zk
from agent_guardrail import zk_ec as _zk_ec
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

POLICY = Policy("zk-test-policy", "1")


def _session(key=None):
    cp = ControlPlane("acme/zk-agent", POLICY, signing_key=key, zk=True)
    cp.gate(Action("git", op="push", branch="main", force=True))    # BLOCK (zk)
    cp.gate(Action("git", op="commit", branch="dev"))               # ALLOW (zk)
    cp.gate(Action("git", op="rebase", branch="release"))           # BLOCK (zk)
    cp.gate(Action("shell", cmd="cargo test"))                      # ALLOW (sha, not zk)
    return cp


def _roundtrip(r):
    return Receipt.from_json(r.to_json())


def test_zk_entries_carry_proofs_and_verify():
    r = _session().receipt()
    git = [e for e in r.entries if e.zk is not None]
    assert len(git) == 3 and all(e.zk["verdict"] == e.verdict for e in git)
    v = verify_receipt(_roundtrip(r), POLICY)
    assert v.ok and "zk" in v.reason, v.reason


def test_zk_reason_is_generic_no_leak():
    # a zk git entry's reason must not name the branch/op (it survives into a redacted receipt)
    r = _session().receipt()
    for e in r.entries:
        if e.zk is not None:
            assert "main" not in e.reason and "release" not in e.reason
            assert e.reason.startswith("git-branch policy:")


def test_redacted_git_entries_stay_sound():
    # THE WIN: redact every git action; the receipt is still VERIFIED and sound via zk proofs
    r = _session().receipt()
    git_idx = [i for i, e in enumerate(r.entries) if e.zk is not None]
    shell_idx = [i for i, e in enumerate(r.entries) if e.zk is None]
    red, witness = r.redact(reveal=shell_idx)  # hide all git entries, keep the shell one
    for i in git_idx:
        assert red.entries[i].action is None and red.entries[i].salt == ""
        assert red.entries[i].zk is not None                # proof survives redaction
    v = verify_receipt(_roundtrip(red), POLICY)
    # 3 git entries redacted-but-zk-proven + 1 shell disclosed = all 4 sound despite the redaction
    assert v.ok and "3 via zk proof" in v.reason, v.reason


def test_fully_redacted_all_sound():
    r = _session().receipt()
    # redact the shell entry via witness disclosure omitted -> it becomes integrity-only; git stay zk-sound
    red, _ = r.redact(reveal=())
    v = verify_receipt(_roundtrip(red), POLICY)
    # 3 git zk-proven, 1 shell redacted-unprovable
    assert v.ok and "3 zk-proven" in v.reason and "1 redacted" in v.reason, v.reason


def test_relabel_verdict_keeping_block_proof_is_caught():
    # flip BLOCK->ALLOW but KEEP the (BLOCK) zk proof, then re-chain + re-sign so integrity and the
    # signature both pass -- the only thing left to catch it is the zk proof/verdict mismatch
    key = Ed25519PrivateKey.generate()
    r = _roundtrip(_session(key).receipt())
    for e in r.entries:
        if e.zk is not None and e.verdict == "BLOCK":
            e.verdict, e.executed = "ALLOW", True          # proof NOT swapped
    head = GENESIS
    for i, e in enumerate(r.entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        e.head = head
    r.final_head = head
    r.signature = key.sign(_signing_payload(r.agent_id, r.policy_root, head, len(r.entries))).hex()
    v = verify_receipt(r, POLICY)
    assert not v.ok and "verdict does not match" in v.reason, v.reason


def _resign_zk_forgery(r, key):
    """Strongest forgery: flip every zk BLOCK to an executed ALLOW, swap in a witness-free ALLOW proof
    over the SAME commitment, recompute the chain, and re-sign with the operator's own key."""
    for e in r.entries:
        if e.zk is not None and e.verdict == "BLOCK":
            e.verdict, e.executed, e.reason = "ALLOW", True, "git-branch policy: ALLOW"
            e.zk = _zk.simulate_all(int(e.commit), "ALLOW").to_dict()   # no valid witness exists
    head = GENESIS
    for i, e in enumerate(r.entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        e.head = head
    r.final_head = head
    r.signature = key.sign(_signing_payload(r.agent_id, r.policy_root, head, len(r.entries))).hex()
    return r


def test_resigned_block_to_allow_forgery_is_caught():
    key = Ed25519PrivateKey.generate()
    r = _roundtrip(_session(key).receipt())
    assert verify_receipt(_roundtrip(r), POLICY).ok            # honest receipt verifies first
    forged = _resign_zk_forgery(r, key)
    v = verify_receipt(forged, POLICY)
    # chain + signature are internally consistent, but the ALLOW proof over a BLOCK commitment fails
    assert not v.ok and ("invalid zk proof" in v.reason), v.reason


def test_disclosed_zk_action_binding_enforced():
    # reveal a git action, then tamper the revealed action -> commitment binding rejects it
    r = _session().receipt()
    git_idx = next(i for i, e in enumerate(r.entries) if e.zk is not None)
    r2 = _roundtrip(r)
    r2.entries[git_idx].action["branch"] = "feature"   # was a protected-branch action
    v = verify_receipt(r2, POLICY)
    assert not v.ok and "does not match its zk commitment" in v.reason, v.reason


def test_unmodeled_git_op_falls_back_to_sha_not_dropped():
    # in zk-mode, a git op outside the modeled set (add/status/fetch...) must still be RECORDED,
    # via the sha-256 commitment, never dropped or crashing the session
    cp = ControlPlane("a/b", POLICY, zk=True)
    cp.gate(Action("git", op="add", branch=""))                     # ALLOW, not zk-modeled -> sha
    cp.gate(Action("git", op="push", branch="main", force=True))    # BLOCK, zk-modeled -> zk
    cp.gate(Action("git", op="status", branch=""))                  # ALLOW, not zk-modeled -> sha
    r = cp.receipt()
    assert len(r.entries) == 3                                      # nothing dropped
    assert r.entries[0].zk is None and len(r.entries[0].commit) == 64   # add -> sha
    assert r.entries[1].zk is not None                                  # push -> zk
    assert r.entries[2].zk is None and len(r.entries[2].commit) == 64   # status -> sha
    assert verify_receipt(_roundtrip(r), POLICY).ok


def _session_ec(key=None):
    cp = ControlPlane("acme/zk-agent", POLICY, signing_key=key, zk="ec")
    cp.gate(Action("git", op="push", branch="main", force=True))    # BLOCK (ec zk)
    cp.gate(Action("git", op="commit", branch="dev"))               # ALLOW (ec zk)
    cp.gate(Action("git", op="rebase", branch="release"))           # BLOCK (ec zk)
    cp.gate(Action("shell", cmd="cargo test"))                      # ALLOW (sha)
    return cp


def test_ec_mode_entries_tagged_and_verify():
    r = _session_ec().receipt()
    git = [e for e in r.entries if e.zk is not None]
    assert git and all(e.zk_group == "ec" for e in git)
    # ec commitments are 33-byte compressed points (66 hex chars), not decimal integers
    assert all(len(e.commit) == 66 for e in git)
    assert verify_receipt(_roundtrip(r), POLICY).ok


def test_ec_mode_redacted_stays_sound():
    r = _session_ec().receipt()
    shell_idx = [i for i, e in enumerate(r.entries) if e.zk is None]
    red, _ = r.redact(reveal=shell_idx)          # hide all git, keep shell
    v = verify_receipt(_roundtrip(red), POLICY)
    assert v.ok and "3 via zk proof" in v.reason, v.reason


def _resign_ec_forgery(r, key):
    for e in r.entries:
        if e.zk is not None and e.verdict == "BLOCK":
            e.verdict, e.executed, e.reason = "ALLOW", True, "git-branch policy: ALLOW"
            e.zk = _zk_ec.simulate_all(ec.decompress(e.commit), "ALLOW").to_dict()
    head = GENESIS
    for i, e in enumerate(r.entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        e.head = head
    r.final_head = head
    r.signature = key.sign(_signing_payload(r.agent_id, r.policy_root, head, len(r.entries))).hex()
    return r


def test_ec_mode_resigned_forgery_caught():
    key = Ed25519PrivateKey.generate()
    r = _roundtrip(_session_ec(key).receipt())
    assert verify_receipt(_roundtrip(r), POLICY).ok
    v = verify_receipt(_resign_ec_forgery(r, key), POLICY)
    assert not v.ok and "invalid zk proof" in v.reason, v.reason


def test_ec_receipt_smaller_than_modp():
    ec_len = len(_session_ec().receipt().to_json())
    modp_len = len(_session().receipt().to_json())
    assert ec_len < modp_len / 3, f"ec {ec_len} vs modp {modp_len}"


def test_group_swap_and_unknown_group_fail_closed():
    # zk_group is a verification hint (not chained). Swapping it to another/unknown group must fail,
    # because the commitment cannot be deserialized under the wrong group.
    for bad in ("modp", "bogus"):
        r = _roundtrip(_session_ec().receipt())
        for e in r.entries:
            if e.zk is not None:
                e.zk_group = bad
        v = verify_receipt(r, POLICY)
        assert not v.ok, f"{bad}: {v.reason}"


def test_default_mode_unchanged_no_zk():
    # zk=False (default): git entries use sha commitments, no zk field -> existing behaviour intact
    cp = ControlPlane("a/b", POLICY)  # no zk
    cp.gate(Action("git", op="push", branch="main", force=True))
    r = cp.receipt()
    assert r.entries[0].zk is None
    assert len(r.entries[0].commit) == 64  # sha-256 hex, not a decimal Pedersen C
    assert verify_receipt(_roundtrip(r), POLICY).ok


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
