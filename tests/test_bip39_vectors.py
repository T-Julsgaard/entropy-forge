"""Official BIP39 vectors (Trezor repo). ALL must pass (plan §5)."""
from entropy_forge.wallet.bip39 import (
    entropy_to_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
)


def test_official_vectors_mnemonic_and_seed(vectors):
    for ent_hex, mnemonic, seed_hex, _xprv in vectors:
        entropy = bytes.fromhex(ent_hex)
        assert entropy_to_mnemonic(entropy) == mnemonic
        assert mnemonic_to_seed(mnemonic, "TREZOR").hex() == seed_hex


def test_round_trip(vectors):
    for ent_hex, mnemonic, _seed, _xprv in vectors:
        assert mnemonic_to_entropy(mnemonic) == bytes.fromhex(ent_hex)


def test_bad_checksum_rejected():
    words = entropy_to_mnemonic(b"\x00" * 32).split()
    words[-1] = "zoo" if words[-1] != "zoo" else "zone"
    import pytest

    with pytest.raises(ValueError):
        mnemonic_to_entropy(" ".join(words))
