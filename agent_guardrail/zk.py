"""Zero-knowledge receipts (milestone 1): prove a hidden action satisfied the committed git-branch
policy WITHOUT revealing the action.

The plaintext receipt (control_plane.py) gives soundness only for *disclosed* actions: a redacted
entry keeps integrity + authenticity but loses the "re-run the policy" check. This module removes that
trade-off for the git-branch sub-policy: the operator attaches a proof that the committed action is one
the policy classifies as the recorded verdict V, and a verifier checks it against (commitment, V) alone.

Why the git-branch policy first (see docs/ZK_ROADMAP.md): its decision depends only on
`(op, branch is protected?, force, hard)`, a small enumerable space, so "policy(A) == V" is set
membership over a handful of elements.

Construction: a Cramer-Damgard-Schoenmakers OR-proof (the group-agnostic core lives in zk_core.py) over
Pedersen commitments. This module supplies the DEFAULT group: the prime-order QR subgroup of a 2048-bit
safe-prime. zk_ec.py supplies a secp256k1 group with the same guarantees and ~1-2 orders of magnitude
smaller/faster proofs. Both are prototype crypto (Fiat-Shamir in ROM) and MUST get external review
before being presented as a guarantee (ZK_ROADMAP milestone 3).
"""
from __future__ import annotations

import hashlib
import secrets
from functools import lru_cache

from . import zk_core
from .guardrail import Action, PROTECTED
from .zk_core import ZKProof  # re-exported

_TAG = "modp/2048"

# ---------------------------------------------------------------------------
# Group: RFC 3526 2048-bit MODP safe prime; work in the order-q QR subgroup.
# g and h are nothing-up-my-sleeve generators (h derived by hashing, so its
# discrete log to base g is unknown, required for Pedersen binding).
# _group_ok() re-derives and re-checks these, so a transcription slip fails loudly.
# ---------------------------------------------------------------------------
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)
Q = (P - 1) // 2                      # prime order of the QR subgroup
G = pow(2, 2, P)                      # 4: a QR, generator of the order-Q subgroup
H = pow(int.from_bytes(hashlib.sha256(b"acp/zk/v1/pedersen-h").digest(), "big") % P, 2, P)


class _MODPGroup:
    """The order-Q QR subgroup of Z_P^*. Elements are ints in [1, P); scalars are ints in [0, Q)."""
    q = Q
    g = G
    h = H

    @staticmethod
    def op(a, b):
        return (a * b) % P

    @staticmethod
    def mul(base, k):
        return pow(base, k % Q, P)

    @staticmethod
    def eq(a, b):
        return a == b

    @staticmethod
    def ser(a) -> str:
        return str(a)

    @staticmethod
    def deser(s):
        x = int(s)
        # Bounds only: an off-subgroup element can never satisfy the verification equation
        # h^z == t * Y^e (LHS is a QR; a non-residue t would make the RHS a non-residue), so an
        # explicit (expensive) subgroup test on prover-supplied t is redundant for soundness.
        if not (1 <= x < P):
            raise ValueError("element out of range")
        return x

    @staticmethod
    def rand_scalar() -> int:
        return secrets.randbelow(Q)


MODP = _MODPGroup()


def _miller_rabin(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _group_ok() -> bool:
    """Self-check the hardcoded group. Catches any transcription error in P and confirms the subgroup
    structure the proof relies on."""
    if not _miller_rabin(P) or not _miller_rabin(Q):
        return False
    if P != 2 * Q + 1:
        return False
    for x in (G, H):
        if x <= 1 or pow(x, Q, P) != 1:   # in the order-Q subgroup, non-identity
            return False
    return G != H


# ---------------------------------------------------------------------------
# The git-branch policy's finite action domain, and its encoding to a group message.
# branch collapses to {each protected branch} + one "non-protected" token, because the
# policy decides only on protected-membership, so the domain is finite and the set S_V
# is exactly the policy's preimage of V. (Group-independent; shared by every backend.)
# ---------------------------------------------------------------------------
_OPS = ("push", "reset", "rebase", "commit", "branch")
_OTHER = "«other»"                      # single representative non-protected branch
_BRANCHES = tuple(PROTECTED) + (_OTHER,)
_NONPROTECTED_CONCRETE = "feature"               # a real non-protected name for classify()


def _domain():
    for op in _OPS:
        for br in _BRANCHES:
            for force in (0, 1):
                for hard in (0, 1):
                    yield (op, br, force, hard)


def encode(op: str, branch: str, force: int, hard: int) -> int:
    """Deterministic small-integer encoding of a git-branch action's policy-relevant projection."""
    br = _OTHER if branch not in PROTECTED else branch
    m = (((_OPS.index(op) * len(_BRANCHES)) + _BRANCHES.index(br)) * 2 + int(bool(force))) * 2 + int(bool(hard))
    return m


def _verdict(op: str, branch: str, force: int, hard: int) -> str:
    """The REAL policy verdict for a git-branch action, via the shared Guardrail classifier."""
    concrete = _NONPROTECTED_CONCRETE if branch == _OTHER else branch
    from .guardrail import Guardrail
    v, _ = Guardrail()._classify(
        Action("git", op=op, branch=concrete, force=bool(force), hard=bool(hard))
    )
    return v


@lru_cache(maxsize=None)
def allowed_set(verdict: str) -> tuple[int, ...]:
    """S_V: the sorted encodings of every git-branch action the policy classifies as `verdict`.
    The verifier recomputes this from the policy itself, so the proof is meaningful only relative
    to the real ruleset (exactly like the plaintext receipt's soundness re-run). Memoized: the
    domain and policy are fixed at import, so this is a pure function of `verdict`."""
    return tuple(sorted({encode(*a) for a in _domain() if _verdict(*a) == verdict}))


# ---------------------------------------------------------------------------
# Public API over the DEFAULT (MODP) group. Elements are ints, so C is an int and ser(C) == str(C),
# which keeps control_plane's commitment strings and the existing tests unchanged.
# ---------------------------------------------------------------------------
def commit(m: int, r: int | None = None) -> tuple[int, int]:
    """Return (C, r) with C = g^m * h^r. Perfectly hiding, computationally binding."""
    r = secrets.randbelow(Q - 1) + 1 if r is None else r % Q
    return zk_core.pedersen(MODP, m, r), r


def _y(C: int, mi: int) -> int:
    return zk_core.y(MODP, C, mi)


def supports(action: Action) -> bool:
    """Whether this action is inside the ZK-modeled git-branch domain. Only the history-relevant ops
    (push/reset/rebase/commit/branch) are covered; any other git op (add, status, fetch, ...) and every
    non-git action falls back to the sha-256 commitment. Callers use this to decide the commit scheme."""
    return action.kind == "git" and action.op in _OPS


def action_verdict(action: Action) -> tuple[str, int]:
    """(verdict, encoding) for a git Action under the real policy."""
    if not supports(action):
        raise ValueError(f"action is outside the zk-modeled git-branch domain (op={action.op!r}); "
                         "see ZK_ROADMAP")
    v = _verdict(action.op, action.branch, int(action.force), int(action.hard))
    return v, encode(action.op, action.branch, int(action.force), int(action.hard))


def prove(action: Action, r: int) -> ZKProof:
    """Prove that C = commit(encode(action), r) opens to an element of S_verdict, in zero knowledge."""
    verdict, m = action_verdict(action)
    proof, _ = zk_core.prove(MODP, allowed_set(verdict), m, r, verdict, _TAG)
    return proof


def verify(C: int, proof: ZKProof) -> bool:
    """Check a ZK proof that C commits to an element of S_{proof.verdict}. Public data only."""
    return zk_core.verify(MODP, allowed_set(proof.verdict), C, proof, _TAG)


def simulate_all(C: int, verdict: str) -> ZKProof:
    """The strongest witness-free cheat (see zk_core.simulate_all). Exposed so soundness is
    demonstrable (demo_zk.py) and testable, not something only the crypto author can check."""
    return zk_core.simulate_all(MODP, allowed_set(verdict), C, verdict, _TAG)


def prove_action(action: Action) -> tuple[int, ZKProof, int]:
    """Convenience: commit to `action`, prove policy-compliance in ZK. Returns (C, proof, r)."""
    verdict, m = action_verdict(action)
    r = secrets.randbelow(Q - 1) + 1
    proof, C = zk_core.prove(MODP, allowed_set(verdict), m, r, verdict, _TAG)
    return C, proof, r
