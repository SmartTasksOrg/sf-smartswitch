"""Key hygiene for keys entering a fleet: refuse public keys that Ed25519 libraries treat differently.

A public key must be the canonical encoding (y < p, no "negative zero") of a point on the curve that is
not of small order. Small-order keys (the identity among them) let anyone forge that keyholder's
signatures with some libraries, and libraries disagree about non-canonical encodings. The fleet document
and every reinstatement are checked here by the command line (``fleet init``) and by the coordinator
(at start and before accepting a reinstatement); agents verify signatures with whatever their library
does, so these keys must never get that far.

Pure Python, only for these checks (a handful of keys, rarely): not used to verify signatures.
"""
from __future__ import annotations

P = 2 ** 255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _decode(b: bytes):
    if len(b) != 32:
        return None, 'not 32 bytes'
    y = int.from_bytes(b, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None, 'non-canonical encoding (y >= p)'
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None, 'non-canonical encoding (negative zero)'
        return (0, y), None
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None, 'not a point on the curve'
    if x & 1 != sign:
        x = P - x
    return (x, y), None


def _add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return x3, y3


def weakness(public_hex: str) -> str | None:
    """None for a good key, else why it is refused."""
    try:
        b = bytes.fromhex(public_hex)
    except (ValueError, TypeError):
        return 'not hex'
    pt, why = _decode(b)
    if pt is None:
        return why
    q = pt
    for _ in range(3):              # 8 * point
        q = _add(q, q)
    if q == (0, 1):
        return 'small-order point'
    return None
