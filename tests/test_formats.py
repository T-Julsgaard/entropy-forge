"""Format encodings: deterministic, in range, and web-parity on the stream."""
import hashlib
import re
import uuid

import pytest

from entropy_forge.cli import format_output

DATA = bytes((i * 7) & 255 for i in range(32))


def test_deterministic():
    for f in ("hex", "base64", "uuid", "int", "dice", "lotto"):
        assert format_output(DATA, f) == format_output(DATA, f)


def test_uuid_v4_bits():
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        format_output(DATA, "uuid"),
    )


@pytest.mark.parametrize("size", [0, 1, 6, 8, 15])
def test_uuid_rejects_short_emissions(size):
    with pytest.raises(ValueError, match="UUID output requires at least 16 bytes"):
        format_output(DATA[:size], "uuid")


def test_uuid_accepts_exactly_16_bytes():
    result = uuid.UUID(format_output(DATA[:16], "uuid"))
    assert result.version == 4
    assert result.variant == uuid.RFC_4122


def test_ranges():
    assert 0 <= int(format_output(DATA, "int")) <= 999_999
    dice = [int(x) for x in format_output(DATA, "dice").split()]
    assert len(dice) == 10 and all(1 <= d <= 6 for d in dice)
    lotto = [int(x) for x in format_output(DATA, "lotto").split()]
    assert len(set(lotto)) == 6 and all(1 <= n <= 49 for n in lotto)


def test_expand_stream_matches_web():
    # first expansion block must equal SHA-256(data || "fmt:0") — web parity
    from entropy_forge.cli import _expand

    g = _expand(DATA)
    first = bytes(next(g) for _ in range(32))
    assert first == hashlib.sha256(DATA + b"fmt:0").digest()
