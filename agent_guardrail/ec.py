"""secp256k1 in pure Python -- a 256-bit prime-order group for the ZK OR-proof.

Rationale (ZK_ROADMAP milestone 4): the MODP group (zk.py) uses 2048-bit integers, so its group
elements serialize to ~600 decimal digits and every operation is a 2048-bit modexp. secp256k1 elements
compress to 33 bytes and its scalars are 256-bit, so proofs are far smaller. The curve has cofactor 1
(prime order n), so any on-curve point is a valid group element -- no subgroup checks needed.

This is affine arithmetic: correct and easy to audit, not speed-tuned (a production deployment would
bind a native curve library; a Jacobian-coordinate rewrite is the pure-Python speed path). `self_check`
validates the constants and the arithmetic against published test vectors, so a transcription error in
any constant fails loudly -- the same discipline as zk._group_ok.
"""
from __future__ import annotations

import hashlib
import secrets

# secp256k1 domain parameters (SEC 2). y^2 = x^3 + 7 over F_p.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141   # prime order

# Point = (x, y) affine, or None for the identity (point at infinity).
Point = tuple


def is_on_curve(pt) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (0 <= x < P) and (0 <= y < P) and (y * y - (x * x * x + B)) % P == 0


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None                                   # P + (-P) = identity
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _mul_affine(pt, k: int):
    """Reference scalar multiplication via affine double-and-add (slow: one inverse per step). Kept as
    the correctness oracle that `self_check` cross-validates the fast path against."""
    k %= N
    result = None
    addend = pt
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


# Jacobian coordinates (X, Y, Z), affine (X/Z^2, Y/Z^3); identity is Z == 0. Standard EFD formulas for
# a == 0 (secp256k1). One field inversion at the end instead of one per step -> the pure-Python speedup.
def _jac_dbl(pt):
    X1, Y1, Z1 = pt
    if Y1 == 0 or Z1 == 0:
        return (0, 1, 0)
    Aa = (X1 * X1) % P
    Bb = (Y1 * Y1) % P
    Cc = (Bb * Bb) % P
    Dd = (2 * (((X1 + Bb) ** 2) - Aa - Cc)) % P
    Ee = (3 * Aa) % P
    Ff = (Ee * Ee) % P
    X3 = (Ff - 2 * Dd) % P
    Y3 = (Ee * (Dd - X3) - 8 * Cc) % P
    Z3 = (2 * Y1 * Z1) % P
    return (X3, Y3, Z3)


def _jac_add(p1, p2):
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    if Z1 == 0:
        return p2
    if Z2 == 0:
        return p1
    Z1Z1 = (Z1 * Z1) % P
    Z2Z2 = (Z2 * Z2) % P
    U1 = (X1 * Z2Z2) % P
    U2 = (X2 * Z1Z1) % P
    S1 = (Y1 * Z2 * Z2Z2) % P
    S2 = (Y2 * Z1 * Z1Z1) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)                          # P + (-P) = identity
        return _jac_dbl(p1)
    Hh = (U2 - U1) % P
    HH = (Hh * Hh) % P
    HHH = (Hh * HH) % P
    Rr = (S2 - S1) % P
    Vv = (U1 * HH) % P
    X3 = (Rr * Rr - HHH - 2 * Vv) % P
    Y3 = (Rr * (Vv - X3) - S1 * HHH) % P
    Z3 = (Z1 * Z2 * Hh) % P
    return (X3, Y3, Z3)


def _to_affine(j):
    X, Y, Z = j
    if Z == 0:
        return None
    zi = pow(Z, P - 2, P)
    zi2 = (zi * zi) % P
    return ((X * zi2) % P, (Y * zi2 * zi) % P)


def mul(pt, k: int):
    """Scalar multiplication k*pt. Jacobian double-and-add: field mults throughout, a single inverse
    at the end. Cross-validated against `_mul_affine` in `self_check`."""
    k %= N
    if pt is None or k == 0:
        return None
    j = (pt[0], pt[1], 1)
    acc = (0, 1, 0)
    while k:
        if k & 1:
            acc = _jac_add(acc, j)
        j = _jac_dbl(j)
        k >>= 1
    return _to_affine(acc)


def compress(pt) -> str:
    """SEC1 compressed encoding as hex: 02/03 || x, or '00' for the identity."""
    if pt is None:
        return "00"
    x, y = pt
    return f"{(2 + (y & 1)):02x}{x:064x}"


def decompress(s: str):
    """Inverse of compress; raises ValueError if the encoding is malformed or the point is off-curve."""
    if s == "00":
        return None
    if len(s) != 66 or s[:2] not in ("02", "03"):
        raise ValueError("bad point encoding")
    prefix = int(s[:2], 16)
    x = int(s[2:], 16)
    if not (0 <= x < P):
        raise ValueError("x out of range")
    rhs = (x * x * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)                      # sqrt: p == 3 (mod 4)
    if (y * y) % P != rhs:
        raise ValueError("not a quadratic residue: point not on curve")
    if (y & 1) != (prefix & 1):
        y = P - y
    pt = (x, y)
    if not is_on_curve(pt):
        raise ValueError("point not on curve")
    return pt


def hash_to_point(seed: bytes):
    """A nothing-up-my-sleeve point (try-and-increment), for the second Pedersen generator H, whose
    discrete log to base G is unknown."""
    for i in range(10000):
        x = int.from_bytes(hashlib.sha256(seed + i.to_bytes(4, "big")).digest(), "big") % P
        rhs = (x * x * x + B) % P
        if pow(rhs, (P - 1) // 2, P) == 1:            # rhs is a quadratic residue
            y = pow(rhs, (P + 1) // 4, P)
            return (x, y)
    raise RuntimeError("hash_to_point failed")         # unreachable in practice


G = (GX, GY)
H = hash_to_point(b"acp/zk/secp256k1/pedersen-h")

# Known-answer vectors (published secp256k1 values) for the self-check.
_2G = (0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
       0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A)
_3G = (0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
       0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672)


def self_check() -> bool:
    """Validate constants + arithmetic against published vectors and identities. A typo in any
    constant, or a bug in add/mul, fails here rather than silently weakening the proof."""
    if not (is_on_curve(G) and is_on_curve(H) and G != H):
        return False
    if mul(G, 2) != _2G or mul(G, 3) != _3G:
        return False
    if mul(G, N) is not None:                         # n*G = identity (correct order)
        return False
    if add(G, None) != G or add(None, G) != G:
        return False
    # cross-check the Jacobian fast path against repeated affine addition on small scalars
    acc = None
    for k in range(1, 12):
        acc = add(acc, G)
        if mul(G, k) != acc:
            return False
    # cross-check Jacobian mul against the affine reference on random scalars and a second base point
    for _ in range(8):
        k = secrets.randbelow(N)
        if mul(G, k) != _mul_affine(G, k) or mul(H, k) != _mul_affine(H, k):
            return False
    # a compress/decompress round-trip
    return decompress(compress(_2G)) == _2G


class ECGroup:
    """Adapter exposing secp256k1 to zk_core's group interface. Elements are affine points."""
    q = N
    g = G
    h = H

    @staticmethod
    def op(a, b):
        return add(a, b)

    @staticmethod
    def mul(base, k):
        return mul(base, k)

    @staticmethod
    def eq(a, b):
        return a == b

    @staticmethod
    def ser(a) -> str:
        return compress(a)

    @staticmethod
    def deser(s):
        return decompress(s)

    @staticmethod
    def rand_scalar() -> int:
        return secrets.randbelow(N)
