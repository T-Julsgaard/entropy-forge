"""Conditioning (plan §4 stage 5). Stdlib crypto only — RULE 3.

- ``condition``: public-mode output, SHA-256 in counter mode with a
  domain-separation tag.
- ``hkdf_sha256``: RFC 5869 extract-and-expand, used by wallet mode to
  combine the mandatory CSPRNG base with optional extra inputs. Extra
  inputs can only ADD security, never remove it.
"""
from __future__ import annotations

import hashlib
import hmac

PUBLIC_TAG = b"entropy-forge/public/v1"


def condition(pool_snapshot: bytes, n_bytes: int, tag: bytes = PUBLIC_TAG) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n_bytes:
        out += hashlib.sha256(
            tag + b"\x00" + pool_snapshot + counter.to_bytes(8, "big")
        ).digest()
        counter += 1
    return bytes(out[:n_bytes])


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-256 (extract then expand)."""
    if length > 255 * 32:
        raise ValueError("length too large for HKDF-SHA256")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]
