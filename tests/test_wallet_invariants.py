"""RULE 1 enforcement (plan §6.4): CSPRNG can never be bypassed."""
import inspect

import entropy_forge.wallet.generate as gen


def test_csprng_always_called_and_influences_output(monkeypatch):
    calls = []
    fixed = bytes(range(32))

    def spy(n):
        calls.append(n)
        return fixed

    monkeypatch.setattr(gen.secrets, "token_bytes", spy)
    words_a = gen.generate_seed_phrase()
    assert calls == [32], "secrets.token_bytes(32) must be called exactly once"

    def spy2(n):
        return bytes(reversed(fixed))

    monkeypatch.setattr(gen.secrets, "token_bytes", spy2)
    words_b = gen.generate_seed_phrase()
    assert words_a != words_b, "CSPRNG output must influence the mnemonic"


def test_identical_extra_inputs_still_produce_different_mnemonics():
    extras = [b"same-api-data", b"same-dice"]
    a = gen.generate_seed_phrase(extras)
    b = gen.generate_seed_phrase(extras)
    assert a != b, "regression toward API-only entropy detected"


def test_no_bypass_parameter_exists():
    sig = inspect.signature(gen.generate_seed_phrase)
    assert list(sig.parameters) == ["extra_inputs"], (
        "generate_seed_phrase must not grow flags that could skip the CSPRNG"
    )
    src = inspect.getsource(gen)
    for forbidden in ("os.environ", "getenv", "skip_csprng", "no_csprng"):
        assert forbidden not in src
