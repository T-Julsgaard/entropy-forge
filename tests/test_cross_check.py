"""Our BIP39 vs the Trezor reference library on random inputs (plan §6.x).
If they ever disagree, the build fails."""
import secrets

from mnemonic import Mnemonic

from entropy_forge.wallet.bip39 import entropy_to_mnemonic, mnemonic_to_entropy

REF = Mnemonic("english")


def test_cross_check_1000_random_entropies():
    for _ in range(1000):
        ent = secrets.token_bytes(32)
        ours = entropy_to_mnemonic(ent)
        theirs = REF.to_mnemonic(ent)
        assert ours == theirs
        assert mnemonic_to_entropy(ours) == ent
