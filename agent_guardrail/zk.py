"""Zero-knowledge receipts (milestone 1): prove a hidden action satisfied the committed
git-branch policy WITHOUT revealing the action.

The plaintext receipt (control_plane.py) gives soundness only for *disclosed* actions: a redacted
entry keeps integrity + authenticity but loses the "re-run the policy" check, because the verifier
cannot re-run a policy on an action it cannot see. This module removes that trade-off for the
git-branch sub-policy: the operator attaches a proof that the committed action is one the policy
classifies as the recorded verdict V, and a verifier checks it against (commitment, V) alone.

Why the git-branch policy first (see docs/ZK_ROADMAP.md): its decision depends only on
`(op, branch is protected?, force, hard)`, a small enumerable space, so "policy(A) == V" is set
membership over a handful of elements. The shell/secret rules are regex over unbounded strings (a
SNARK-over-regex problem) and stay on commitment+witness selective disclosure for now.

Construction: a Cramer-Damgard-Schoenmakers OR-proof of Schnorr statements over Pedersen
commitments in the prime-order QR subgroup of a 2048-bit safe-prime group.

  C = g^m * h^r                       Pedersen commitment to m = encode(action), hiding via r
  S_V = { encode(A) : policy(A)=V }   the public allowed set for verdict V (verifier recomputes it)
  prove:  C commits to one of S_V     without revealing which -> ZK; a false claim cannot pass -> sound

Honest scope: this proves the action's *policy-relevant projection* (op, protected-vs-not, force,
hard) is in S_V. Fiat-Shamir soundness/ZK hold in the random-oracle model; the crypto is a prototype
and MUST get external review before it is presented as a guarantee (ZK_ROADMAP milestone 3).
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from functools import lru_cache

from .guardrail import Action, PROTECTED

# ---------------------------------------------------------------------------
# Group: RFC 3526 2048-bit MODP safe prime; work in the order-q QR subgroup.
# g and h are nothing-up-my-sleeve generators (h derived by hashing, so its
# discrete log to base g is unknown -- required for Pedersen binding).
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
    """Self-check the hardcoded group. Catches any transcription error in P and confirms
    the subgroup structure the proof relies on."""
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
# policy decides only on protected-membership -- so the domain is finite and the set S_V
# is exactly the policy's preimage of V.
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
# Pedersen commitment.
# ---------------------------------------------------------------------------
def commit(m: int, r: int | None = None) -> tuple[int, int]:
    """Return (C, r) with C = g^m * h^r mod P. Perfectly hiding, computationally binding."""
    r = secrets.randbelow(Q - 1) + 1 if r is None else r % Q
    C = (pow(G, m % Q, P) * pow(H, r, P)) % P
    return C, r


# ---------------------------------------------------------------------------
# CDS OR-proof: prove C commits to some element of S_V, without revealing which.
# Per clause i the statement is "I know x s.t. Y_i = h^x", where Y_i = C * g^{-ms[i]};
# for the true index Y_j = h^r so x = r. All other clauses are simulated.
# ---------------------------------------------------------------------------
@dataclass
class ZKProof:
    verdict: str
    t: list[int]
    e: list[int]
    z: list[int]

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "t": [str(x) for x in self.t],
                "e": [str(x) for x in self.e], "z": [str(x) for x in self.z]}

    @staticmethod
    def from_dict(d: dict) -> "ZKProof":
        return ZKProof(d["verdict"], [int(x) for x in d["t"]],
                       [int(x) for x in d["e"]], [int(x) for x in d["z"]])


def _y(C: int, mi: int) -> int:
    """Y_i = C * g^{-mi} mod P (so a valid opening C = g^{mi} h^r gives Y_i = h^r)."""
    return (C * pow(G, (Q - (mi % Q)) % Q, P)) % P


def _challenge(verdict: str, C: int, ms: list[int], ts: list[int]) -> int:
    h = hashlib.sha256()
    h.update(b"acp/zk/v1|")
    for part in (verdict, P, G, H, C, *ms, *ts):
        h.update(str(part).encode())
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % Q


def prove(action: Action, r: int) -> ZKProof:
    """Prove that Pedersen commitment C = commit(encode(action), r) opens to an element of S_verdict,
    where verdict = policy(action). Zero-knowledge: reveals nothing about which element."""
    verdict, _ = action_verdict(action)
    m = encode(action.op, action.branch, int(action.force), int(action.hard))
    ms = allowed_set(verdict)
    if m not in ms:
        raise ValueError("action is not in its own verdict set (policy/encoding mismatch)")
    j = ms.index(m)
    C = (pow(G, m % Q, P) * pow(H, r % Q, P)) % P

    t = [0] * len(ms)
    e = [0] * len(ms)
    z = [0] * len(ms)
    # simulate every clause except the real one
    for i in range(len(ms)):
        if i == j:
            continue
        e[i] = secrets.randbelow(Q)
        z[i] = secrets.randbelow(Q)
        Yi = _y(C, ms[i])
        t[i] = (pow(H, z[i], P) * pow(Yi, (Q - e[i]) % Q, P)) % P
    # real clause: commit first, derive challenge, then respond
    k = secrets.randbelow(Q)
    t[j] = pow(H, k, P)
    e_total = _challenge(verdict, C, ms, t)
    e[j] = (e_total - sum(e[i] for i in range(len(ms)) if i != j)) % Q
    z[j] = (k + e[j] * (r % Q)) % Q
    return ZKProof(verdict, t, e, z)


def verify(C: int, proof: ZKProof) -> bool:
    """Check a ZK proof that C commits to an element of S_{proof.verdict}. Needs only the public
    commitment, the verdict, and the policy (to recompute S_V). No witness, no operator secret."""
    ms = allowed_set(proof.verdict)
    if not (len(proof.t) == len(proof.e) == len(proof.z) == len(ms)) or not ms:
        return False
    if any(not (0 <= x < Q) for x in proof.e + proof.z):
        return False
    if any(not (1 <= x < P) for x in proof.t):
        return False
    # challenge must equal the sum of the per-clause challenges (this is what a cheat cannot satisfy)
    if sum(proof.e) % Q != _challenge(proof.verdict, C, ms, proof.t):
        return False
    # each clause's Schnorr equation must hold: h^{z_i} == t_i * Y_i^{e_i}
    for i, mi in enumerate(ms):
        Yi = _y(C, mi)
        if pow(H, proof.z[i], P) != (proof.t[i] * pow(Yi, proof.e[i], P)) % P:
            return False
    return True


def simulate_all(C: int, verdict: str) -> ZKProof:
    """The strongest cheat available to a prover with NO valid witness: simulate every clause
    (pick e_i, z_i, back out t_i). It does not verify, because the e_i are fixed before the
    Fiat-Shamir challenge, so their sum equals the challenge only with probability ~1/Q. Exposed so
    soundness is demonstrable (demo_zk.py) and testable, not something only the crypto author can check."""
    ms = allowed_set(verdict)
    e = [secrets.randbelow(Q) for _ in ms]
    z = [secrets.randbelow(Q) for _ in ms]
    t = [(pow(H, z[i], P) * pow(_y(C, ms[i]), (Q - e[i]) % Q, P)) % P for i in range(len(ms))]
    return ZKProof(verdict, t, e, z)


# ---------------------------------------------------------------------------
# Helpers bridging to the real Action / policy.
# ---------------------------------------------------------------------------
def action_verdict(action: Action) -> tuple[str, int]:
    """(verdict, encoding) for a git Action under the real policy."""
    if action.kind != "git":
        raise ValueError("zk covers git-branch actions only (see ZK_ROADMAP)")
    v = _verdict(action.op, action.branch, int(action.force), int(action.hard))
    return v, encode(action.op, action.branch, int(action.force), int(action.hard))


def prove_action(action: Action) -> tuple[int, ZKProof, int]:
    """Convenience: commit to `action`, prove policy-compliance in ZK. Returns (C, proof, r)."""
    _, m = action_verdict(action)
    C, r = commit(m)
    return C, prove(action, r), r
