"""Extractor, debias, health, pool, whitener unit tests."""
import hashlib

from hypothesis import given
from hypothesis import strategies as st

from entropy_forge.core.debias import von_neumann
from entropy_forge.core.extractor import (
    bits_to_bytes,
    bytes_to_bits,
    digits_to_bytes,
    trailing_digits,
)
from entropy_forge.core.health import SourceHealth
from entropy_forge.core.pool import EntropyPool
from entropy_forge.core.whitener import condition, hkdf_sha256
from entropy_forge.sources.base import SourceSample


def _sample(name="s", domain="local", data=b"x", bits=10.0):
    return SourceSample(name, domain, 0.0, {}, data, bits)


def test_trailing_digits():
    assert trailing_digits(12.7, 2) == [2, 7]
    assert trailing_digits(-1002.45, 3) == [2, 4, 5]
    assert trailing_digits(0, 2) == [0]


def test_von_neumann_known_answers():
    assert von_neumann([0, 1, 1, 0, 0, 0, 1, 1]) == [0, 1]
    assert von_neumann([1, 1, 1, 1]) == []
    assert von_neumann([1, 0, 1, 0, 1, 0]) == [1, 1, 1]


@given(st.binary(min_size=1, max_size=64))
def test_bits_bytes_round_trip(data):
    assert bits_to_bytes(bytes_to_bits(data)) == data


@given(st.lists(st.integers(0, 9), min_size=1, max_size=40))
def test_digits_to_bytes_never_crashes(digits):
    assert isinstance(digits_to_bytes(digits), bytes)


def test_health_freshness_zero_credits_duplicates():
    h = SourceHealth()
    assert h.check(b"abc").ok
    v = h.check(b"abc")  # identical fetch => CDN cache hit
    assert not v.ok and v.reason == "stale_duplicate"
    assert h.check(b"abcd").ok


def test_pool_domain_minimum_and_margin():
    pool = EntropyPool(min_domains=2)
    pool.add(_sample("a", "local", b"1", 1000.0))
    ok, why = pool.ready(64)
    assert not ok and "domains" in why
    pool.add(_sample("b", "human", b"2", 1000.0))
    assert pool.ready(64)[0]


def test_pool_domain_haircut_caps_single_domain():
    pool = EntropyPool(domain_cap=0.40)
    pool.add(_sample("w1", "atmosphere", b"1", 900.0))
    pool.add(_sample("q1", "geophysics", b"2", 50.0))
    pool.add(_sample("h1", "human", b"3", 50.0))
    total_raw = 1000.0
    assert pool.credited_bits <= 0.40 * total_raw + 100.0 + 1e-6


def test_pool_zero_credits_unhealthy_but_still_absorbs():
    pool = EntropyPool(min_domains=1)
    pool.add(_sample("s", "local", b"same", 100.0))
    before = pool.credited_bits
    snap_before = pool.snapshot()
    pool.add(_sample("s", "local", b"same", 100.0))  # duplicate
    assert pool.credited_bits == before
    assert pool.snapshot() != snap_before  # bytes still absorbed


def test_condition_deterministic_and_tagged():
    a = condition(b"pool", 64)
    assert a == condition(b"pool", 64) and len(a) == 64
    assert a != condition(b"pool", 64, tag=b"other/v1")


def test_hkdf_rfc5869_case1():
    # RFC 5869 A.1 test vector
    okm = hkdf_sha256(
        ikm=bytes.fromhex("0b" * 22),
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
