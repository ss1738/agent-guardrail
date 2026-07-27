"""The git-branch ZK OR-proof over secp256k1 (ZK_ROADMAP milestone 4 groundwork).

Same construction and guarantees as zk.py, but on a 256-bit curve instead of a 2048-bit MODP group,
so proofs are far smaller. It reuses the *entire* proof core (zk_core) and the *entire* policy layer
(encode / allowed_set / action_verdict / supports from zk.py), only the group differs. That reuse is
the point of the milestone: swapping the group is a drop-in, and the delicate crypto is not duplicated.

Elements here are curve points, so a commitment serializes via `ec.compress` (33-byte hex) rather than
as a decimal integer. This is standalone groundwork: control_plane still defaults to the MODP group
(zk.py). Prototype crypto, external review required before it is relied on (ZK_ROADMAP milestone 3).
"""
from __future__ import annotations

from . import ec, zk_core
from .guardrail import PROTECTED, Action
from .zk import action_verdict, allowed_set  # policy layer, shared with the MODP scheme
from .zk_core import ZKProof  # re-exported

EC = ec.ECGroup()
_TAG = "secp256k1"


def group_ok() -> bool:
    return ec.self_check()


def commit(m: int, r: int | None = None):
    """Return (C, r) with C = m*G + r*H on secp256k1."""
    r = EC.rand_scalar() if r is None else r % ec.N
    return zk_core.pedersen(EC, m, r), r


def prove(action: Action, r: int, protected: tuple[str, ...] = PROTECTED) -> ZKProof:
    protected = tuple(protected)
    verdict, m = action_verdict(action, protected)
    proof, _ = zk_core.prove(EC, allowed_set(verdict, protected), m, r, verdict, _TAG)
    return proof


def verify(C, proof: ZKProof, protected: tuple[str, ...] = PROTECTED) -> bool:
    return zk_core.verify(EC, allowed_set(proof.verdict, tuple(protected)), C, proof, _TAG)


def simulate_all(C, verdict: str, protected: tuple[str, ...] = PROTECTED) -> ZKProof:
    return zk_core.simulate_all(EC, allowed_set(verdict, tuple(protected)), C, verdict, _TAG)


def prove_action(action: Action, protected: tuple[str, ...] = PROTECTED):
    """Commit + prove. Returns (C, proof, r)."""
    protected = tuple(protected)
    verdict, m = action_verdict(action, protected)
    r = EC.rand_scalar()
    proof, C = zk_core.prove(EC, allowed_set(verdict, protected), m, r, verdict, _TAG)
    return C, proof, r
