"""BIP39 implemented directly from the spec (plan §5).

Cross-verified in tests against the Trezor ``mnemonic`` reference library
and the official test vectors. The vendored wordlist is integrity-checked
at import time against its pinned SHA-256 (the well-known hash of the
official BIP-0039 english.txt).
"""
from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

_WORDLIST_PATH = Path(__file__).with_name("wordlist_english.txt")
# SHA-256 of the official bitcoin/bips bip-0039/english.txt
_WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def _load_wordlist() -> list[str]:
    raw = _WORDLIST_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != _WORDLIST_SHA256:
        raise RuntimeError(
            "BIP39 wordlist integrity check FAILED — refusing to continue. "
            f"expected {_WORDLIST_SHA256}, got {digest}"
        )
    words = raw.decode("utf-8").split()
    if len(words) != 2048:
        raise RuntimeError(f"wordlist must have 2048 words, has {len(words)}")
    return words


WORDLIST: list[str] = _load_wordlist()
_INDEX = {w: i for i, w in enumerate(WORDLIST)}


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 128/160/192/224/256 bits")
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = hashlib.sha256(entropy).digest()
    bits = int.from_bytes(entropy, "big") << cs_bits
    bits |= checksum[0] >> (8 - cs_bits) if cs_bits <= 8 else int.from_bytes(
        checksum, "big"
    ) >> (256 - cs_bits)
    total = ent_bits + cs_bits
    words = []
    for i in range(total // 11):
        idx = (bits >> (total - 11 * (i + 1))) & 0x7FF
        words.append(WORDLIST[idx])
    return " ".join(words)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    words = unicodedata.normalize("NFKD", mnemonic).split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must have 12/15/18/21/24 words")
    bits = 0
    for w in words:
        if w not in _INDEX:
            raise ValueError(f"word not in wordlist: {w!r}")
        bits = (bits << 11) | _INDEX[w]
    total = len(words) * 11
    cs_bits = total // 33
    ent_bits = total - cs_bits
    entropy_int = bits >> cs_bits
    checksum = bits & ((1 << cs_bits) - 1)
    entropy = entropy_int.to_bytes(ent_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if checksum != expected:
        raise ValueError("invalid mnemonic checksum")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt 'mnemonic'+passphrase."""
    m = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", m, salt, 2048)
