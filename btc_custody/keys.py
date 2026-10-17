"""Bitcoin key and address primitives, implemented from scratch (stdlib only).

Educational implementation: mathematically correct, but NOT audited and NOT
intended for real funds. Keys generated here are for demonstration/learning.

Public API:
    generate()                  -> random 32-byte private key (secrets module)
    privkey_to_pubkey(priv)     -> compressed (33-byte) or uncompressed pubkey
    privkey_to_address(priv)    -> P2PKH Base58Check address (mainnet)
    privkey_to_wif(priv)        -> Wallet Import Format string
    pubkey_to_p2pkh(pubkey)     -> P2PKH address from a raw public key
"""

from __future__ import annotations

import hashlib
import os
import secrets

# ---------------------------------------------------------------------------
# secp256k1 domain parameters (SEC 2)
# ---------------------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

__version__ = "0.1.0"


# ---------------------------------------------------------------------------
# Elliptic curve arithmetic
# ---------------------------------------------------------------------------
def _inv(a: int, p: int) -> int:
    """Modular inverse via Fermat's little theorem."""
    return pow(a % p, p - 2, p)


def _point_add(p1, p2):
    """Add two curve points; None represents the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2:
            return None  # p1 == -p2
        s = (3 * x1 * x1) * _inv(2 * y1, _P) % _P  # point doubling
    else:
        s = (y2 - y1) * _inv(x2 - x1, _P) % _P
    x3 = (s * s - x1 - x2) % _P
    y3 = (s * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k: int, point=(_GX, _GY)):
    """Double-and-add scalar multiplication: k * point."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# RIPEMD-160 (pure-Python fallback; preferred path is hashlib when available)
# ---------------------------------------------------------------------------
def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# Message word order, per round (5 rounds x 16), left and right lines
_ML = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
]
_MR = [
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
]
# Rotation amounts, per round, left and right lines
_SL = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
]
_SR = [
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
]
# Round constants, left and right lines
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _f(round_idx: int, x: int, y: int, z: int) -> int:
    """RIPEMD-160 round function (round_idx 0..4)."""
    if round_idx == 0:
        return (x ^ y ^ z) & 0xFFFFFFFF
    if round_idx == 1:
        return ((x & y) | (~x & z)) & 0xFFFFFFFF
    if round_idx == 2:
        return ((x | ~y) ^ z) & 0xFFFFFFFF
    if round_idx == 3:
        return ((x & z) | (y & ~z)) & 0xFFFFFFFF
    return (x ^ (y | ~z)) & 0xFFFFFFFF


def _ripemd160_pure(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160 per the specification."""
    # Padding: 0x80, zeros, then 64-bit little-endian bit length
    bit_len = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    data += bit_len.to_bytes(8, "little")

    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

    for off in range(0, len(data), 64):
        X = [int.from_bytes(data[off + 4 * i: off + 4 * i + 4], "little") for i in range(16)]

        # Left line: rounds use f0..f4. Step per the spec:
        #   T = rol(A + f(B,C,D) + X + K, s) + E ; then rotate registers.
        a1, b1, c1, d1, e1 = h0, h1, h2, h3, h4
        for j in range(80):
            r, i = divmod(j, 16)
            t = (_rol32((a1 + _f(r, b1, c1, d1) + X[_ML[r][i]] + _KL[r]) & 0xFFFFFFFF,
                        _SL[r][i]) + e1) & 0xFFFFFFFF
            a1, b1, c1, d1, e1 = e1, t, b1, _rol32(c1, 10), d1

        # Right line: rounds use f4..f0 (reversed)
        a2, b2, c2, d2, e2 = h0, h1, h2, h3, h4
        for j in range(80):
            r, i = divmod(j, 16)
            t = (_rol32((a2 + _f(4 - r, b2, c2, d2) + X[_MR[r][i]] + _KR[r]) & 0xFFFFFFFF,
                        _SR[r][i]) + e2) & 0xFFFFFFFF
            a2, b2, c2, d2, e2 = e2, t, b2, _rol32(c2, 10), d2

        t = (h1 + c1 + d2) & 0xFFFFFFFF
        h1 = (h2 + d1 + e2) & 0xFFFFFFFF
        h2 = (h3 + e1 + a2) & 0xFFFFFFFF
        h3 = (h4 + a1 + b2) & 0xFFFFFFFF
        h4 = (h0 + b1 + c2) & 0xFFFFFFFF
        h0 = t

    return b"".join(h.to_bytes(4, "little") for h in (h0, h1, h2, h3, h4))


def _ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 digest, preferring hashlib; pure-Python fallback otherwise."""
    if os.environ.get("BTC_CUSTODY_FORCE_PURE_RIPEMD") != "1":
        try:
            return hashlib.new("ripemd160", data).digest()
        except (ValueError, TypeError):
            pass
    return _ripemd160_pure(data)


# ---------------------------------------------------------------------------
# Hashing / encoding helpers
# ---------------------------------------------------------------------------
def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)): the 20-byte Bitcoin address payload."""
    return _ripemd160(_sha256(data))


def b58encode(raw: bytes) -> str:
    """Base58 encode (Bitcoin alphabet); leading zero bytes become '1'."""
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = 0
    for byte in raw:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def _b58check(payload: bytes) -> str:
    """Base58Check: payload + 4-byte double-SHA256 checksum, Base58 encoded."""
    checksum = _sha256(_sha256(payload))[:4]
    return b58encode(payload + checksum)


# ---------------------------------------------------------------------------
# Keys and addresses
# ---------------------------------------------------------------------------
def generate() -> bytes:
    """Generate a cryptographically random 32-byte private key."""
    while True:
        priv = secrets.token_bytes(32)
        if 1 <= int.from_bytes(priv, "big") < _N:
            return priv


def privkey_to_pubkey(priv: bytes, compressed: bool = True) -> bytes:
    """Private key -> secp256k1 public key (compressed 33B or uncompressed 65B)."""
    if len(priv) != 32:
        raise ValueError("private key must be 32 bytes")
    k = int.from_bytes(priv, "big")
    if not 1 <= k < _N:
        raise ValueError("private key out of range [1, n-1]")
    x, y = _scalar_mult(k, _G)
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def pubkey_to_p2pkh(pubkey: bytes) -> str:
    """Public key bytes -> P2PKH Base58Check address (mainnet, version 0x00)."""
    return _b58check(b"\x00" + hash160(pubkey))


def privkey_to_address(priv: bytes, compressed: bool = True) -> str:
    """Private key -> P2PKH address."""
    return pubkey_to_p2pkh(privkey_to_pubkey(priv, compressed))


def privkey_to_wif(priv: bytes, compressed: bool = True) -> str:
    """Private key -> Wallet Import Format (mainnet)."""
    payload = b"\x80" + priv + (b"\x01" if compressed else b"")
    return _b58check(payload)
