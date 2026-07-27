"""Group-agnostic Cramer-Damgard-Schoenmakers OR-proof (the delicate crypto, written ONCE).

The proof is identical whether the group is a prime-order subgroup of Z_p^* (zk.py, MODP) or an
elliptic curve (zk_ec.py, secp256k1). Only the group operations differ, so they live behind a small
`Group` interface and the proof logic here never changes. Keeping this in one place avoids two
divergent copies of the part that is easy to get subtly wrong.

A `Group` must provide (duck-typed):
    q                      prime order (int)
    g, h                   two generators, unknown discrete-log relation (group elements)
    op(a, b)               the group operation            (a*b mod p  /  point add)
    mul(base, k)           scalar operation, k in Z_q     (base^k mod p / scalar mult); k=0 -> identity
    eq(a, b)               equality of elements
    ser(a) -> str          canonical serialization (also what the challenge hashes)
    deser(s) -> element    inverse of ser; raises ValueError on an invalid / off-subgroup element
    rand_scalar() -> int   uniform in [0, q)

Each proof clause i proves "I know x s.t. Y_i = h^x", where Y_i = C * g^{-ms[i]}. For the true index
the witness is the Pedersen randomness r; every other clause is simulated (CDS OR-composition). A
false claim cannot satisfy sum(e_i) == Fiat-Shamir challenge, and the transcript is simulatable
without the witness, soundness and honest-verifier zero-knowledge, in the random-oracle model.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass
class ZKProof:
    verdict: str
    t: list[str]   # serialized commitments t_i (group elements, as strings)
    e: list[int]   # per-clause challenges
    z: list[int]   # per-clause responses

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "t": list(self.t),
                "e": [str(x) for x in self.e], "z": [str(x) for x in self.z]}

    @staticmethod
    def from_dict(d: dict) -> "ZKProof":
        return ZKProof(d["verdict"], [str(x) for x in d["t"]],
                       [int(x) for x in d["e"]], [int(x) for x in d["z"]])


def pedersen(group, m: int, r: int):
    """C = g^m * h^r."""
    return group.op(group.mul(group.g, m % group.q), group.mul(group.h, r % group.q))


def y(group, C, mi: int):
    """Y_i = C * g^{-mi} (so a valid opening C = g^{mi} h^r gives Y_i = h^r). The negation is folded
    into the scalar (mul by q-mi) so no separate inverse op is needed."""
    return group.op(C, group.mul(group.g, (group.q - (mi % group.q)) % group.q))


def challenge(group, tag: str, C, ms, tser: list[str], verdict: str) -> int:
    h = hashlib.sha256()
    h.update(b"acp/zk-core/v1|")
    for part in (tag, verdict, group.ser(group.g), group.ser(group.h), group.q, group.ser(C), *ms):
        h.update(str(part).encode())
        h.update(b"|")
    for s in tser:
        h.update(s.encode())
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % group.q


def prove(group, ms, m: int, r: int, verdict: str, tag: str):
    """Prove C = pedersen(m, r) opens to an element of `ms`, in zero knowledge. Returns (proof, C)."""
    ms = tuple(ms)
    if m not in ms:
        raise ValueError("message is not in the claimed set")
    j = ms.index(m)
    C = pedersen(group, m, r)
    n = len(ms)
    t = [None] * n
    e = [0] * n
    z = [0] * n
    for i in range(n):                     # simulate every clause except the real one
        if i == j:
            continue
        e[i], z[i] = group.rand_scalar(), group.rand_scalar()
        Yi = y(group, C, ms[i])
        t[i] = group.op(group.mul(group.h, z[i]), group.mul(Yi, (group.q - e[i]) % group.q))
    k = group.rand_scalar()
    t[j] = group.mul(group.h, k)
    tser = [group.ser(x) for x in t]
    e_total = challenge(group, tag, C, ms, tser, verdict)
    e[j] = (e_total - sum(e[i] for i in range(n) if i != j)) % group.q
    z[j] = (k + e[j] * (r % group.q)) % group.q
    return ZKProof(verdict, tser, e, z), C


def verify(group, ms, C, proof: ZKProof, tag: str) -> bool:
    """Check a proof that C opens to an element of `ms`. Needs only public data (C, ms, the group)."""
    ms = tuple(ms)
    n = len(ms)
    if not (len(proof.t) == len(proof.e) == len(proof.z) == n) or not ms:
        return False
    q = group.q
    if any(not (0 <= x < q) for x in proof.e + proof.z):
        return False
    try:
        ts = [group.deser(s) for s in proof.t]
    except (ValueError, TypeError):
        return False
    if challenge(group, tag, C, ms, proof.t, proof.verdict) != sum(proof.e) % q:
        return False
    for i, mi in enumerate(ms):
        Yi = y(group, C, mi)
        lhs = group.mul(group.h, proof.z[i])
        rhs = group.op(ts[i], group.mul(Yi, proof.e[i]))
        if not group.eq(lhs, rhs):
            return False
    return True


def simulate_all(group, ms, C, verdict: str, tag: str) -> ZKProof:
    """Strongest witness-free cheat: simulate EVERY clause. It cannot verify, because the e_i are
    fixed before the Fiat-Shamir challenge, so their sum equals it only with probability ~1/q."""
    ms = tuple(ms)
    e = [group.rand_scalar() for _ in ms]
    z = [group.rand_scalar() for _ in ms]
    t = [group.op(group.mul(group.h, z[i]), group.mul(y(group, C, ms[i]), (group.q - e[i]) % group.q))
         for i in range(len(ms))]
    return ZKProof(verdict, [group.ser(x) for x in t], e, z)
