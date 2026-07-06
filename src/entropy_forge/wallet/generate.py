"""Wallet-mode seed generation (plan §5, RULE 1).

The OS CSPRNG contribution is UNCONDITIONAL. There is deliberately no
argument, flag, environment variable, or config option that can skip it.
Extra inputs (harvested pool bytes, dice rolls) are combined via HKDF and
can only add security. If you want pure-API seeds you must fork the code
— that is a feature, not a limitation.
"""
from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence

from ..core.whitener import hkdf_sha256
from .bip39 import entropy_to_mnemonic

_INFO = b"entropy-forge/bip39/v1"


def generate_seed_phrase(extra_inputs: Sequence[bytes] = ()) -> str:
    """Return a 24-word BIP39 mnemonic. CSPRNG-backed, always."""
    base = secrets.token_bytes(32)  # RULE 1: unconditional, not configurable.
    salt = hashlib.sha256(b"\x00".join(extra_inputs) if extra_inputs else b"").digest()
    entropy = bytearray(hkdf_sha256(ikm=base, salt=salt, info=_INFO, length=32))
    try:
        return entropy_to_mnemonic(bytes(entropy))
    finally:
        # Best-effort hygiene; Python cannot guarantee no copies exist,
        # which is one reason docs point serious users to hardware wallets.
        for i in range(len(entropy)):
            entropy[i] = 0
