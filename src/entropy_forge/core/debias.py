"""Von Neumann debiasing (plan §4 stage 3).

Pairs of bits: 01 -> 0, 10 -> 1, 00/11 -> discarded. Removes bias from a
stream of independent-but-biased bits. Partly pedagogical — SHA-256
conditioning downstream would suffice — kept as an inspectable stage.
"""
from __future__ import annotations


def von_neumann(bits: list[int]) -> list[int]:
    out: list[int] = []
    for i in range(0, len(bits) - 1, 2):
        a, b = bits[i], bits[i + 1]
        if a != b:
            out.append(a)
    return out
