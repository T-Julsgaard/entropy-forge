"""Least-significant-digit extraction (plan §4 stage 1).

High-order digits of real-world measurements are predictable; the jitter
lives in the tail. We keep only trailing decimal digits and pack them
into bytes. Timestamps are extracted by AT MOST one designated source
(USGS) — everywhere else they are stripped before extraction (plan §3.4).
"""
from __future__ import annotations


def trailing_digits(value: float | int, n: int = 2) -> list[int]:
    """Last ``n`` decimal digits of the value's textual form (sign/dot removed)."""
    s = "".join(ch for ch in f"{value}" if ch.isdigit())
    if not s:
        return []
    return [int(ch) for ch in s[-n:]]


def digits_to_bytes(digits: list[int]) -> bytes:
    """Pack base-10 digits into bytes via a base-256 accumulator.

    Not entropy-preserving-optimal, but downstream SHA-256 conditioning
    makes optimality irrelevant; this just needs to be deterministic and
    injective enough to carry the jitter forward.
    """
    if not digits:
        return b""
    acc = 0
    for d in digits:
        acc = acc * 10 + d
    out = bytearray()
    while acc:
        out.append(acc & 0xFF)
        acc >>= 8
    return bytes(out) or b"\x00"


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> i) & 1 for byte in data for i in range(8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j, bit in enumerate(bits[i : i + 8]):
            byte |= bit << j
        out.append(byte)
    return bytes(out)
