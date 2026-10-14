"""Ed25519 signatures (RFC 8032) through the ``cryptography`` package (OpenSSL).

Keys and signatures travel as lower-case hex: a public key is 64 characters, a signature 128.
``verify`` is strict and identical in every SmartSwitch engine (spec/SEMANTICS.md, "Signatures"):
the hex must be lower-case and the right length, the scalar S (the second half of the signature, read
little-endian) must be below the group order L, and then the library check must pass. Checking S < L
ourselves makes every engine refuse the same malleable signatures, whatever its library does.
"""
from __future__ import annotations

import os
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

L = 2 ** 252 + 27742317777372353535851937790883648493
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_HEX128 = re.compile(r'[0-9a-f]{128}\Z')


def is_key_hex(s) -> bool:
    return isinstance(s, str) and bool(_HEX64.match(s))


def new_seed() -> bytes:
    return os.urandom(32)


def public_key(seed: bytes) -> str:
    """The public key (hex) of a 32-byte private seed."""
    k = Ed25519PrivateKey.from_private_bytes(seed)
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign(seed: bytes, message: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message).hex()


def verify(public_hex, message: bytes, sig_hex) -> bool:
    if not is_key_hex(public_hex) or not isinstance(sig_hex, str) or not _HEX128.match(sig_hex):
        return False
    sig = bytes.fromhex(sig_hex)
    if int.from_bytes(sig[32:], 'little') >= L:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False
