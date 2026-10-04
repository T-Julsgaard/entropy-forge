"""Transcript verifier vs the web instrument's math, byte-for-byte."""
import hashlib
import json

import pytest

from entropy_forge.verify import verify_transcript


def _web_absorb_hash(name: str, payload: str) -> bytes:
    return hashlib.sha256((name + "\x00" + payload).encode()).digest()


def _make_transcript(tmp_path, tamper=None, n_bytes=32):
    samples = [("quakes", "231244483"), ("weather", "2447"), ("operator", "9912|14")]
    entries, buf = [], b""
    for i, (name, payload) in enumerate(samples):
        h = _web_absorb_hash(name, payload)
        buf += h
        entries.append({"n": i, "name": name, "domain": "d", "hash": h.hex(), "bits": 5})
    nonce = 3
    tag = b"entropy-forge/public/v1\x00web"
    out, c = b"", 0
    while len(out) < n_bytes:
        out += hashlib.sha256(tag + buf + f":{nonce}:{c}".encode()).digest()
        c += 1
    t = {"v": 1, "kind": "entropy-forge/transcript", "mode": "live",
         "tag": "entropy-forge/public/v1", "ctx": "web", "nonce": nonce,
         "fingerprint": hashlib.sha256(buf).hexdigest(),
         "output": out[:n_bytes].hex(), "entries": entries}
    if tamper:
        tamper(t)
    p = tmp_path / "t.json"
    p.write_text(json.dumps(t))
    return p


def test_valid_transcript_verifies(tmp_path):
    assert verify_transcript(_make_transcript(tmp_path)).ok


def test_tampered_output_fails(tmp_path):
    def flip(t): t["output"] = "00" + t["output"][2:]
    assert not verify_transcript(_make_transcript(tmp_path, flip)).ok


def test_tampered_entry_fails(tmp_path):
    def swap(t): t["entries"][0], t["entries"][1] = t["entries"][1], t["entries"][0]
    r = verify_transcript(_make_transcript(tmp_path, swap))
    assert not r.ok


def test_forged_fingerprint_fails(tmp_path):
    def forge(t): t["fingerprint"] = "ab" * 32
    assert not verify_transcript(_make_transcript(tmp_path, forge)).ok


@pytest.mark.parametrize("output", ["", " ", "not hex", "0", None, 0, [], {}])
def test_invalid_output_is_rejected_without_crashing(tmp_path, output):
    def tamper(t):
        t["output"] = output

    assert not verify_transcript(_make_transcript(tmp_path, tamper)).ok


def test_missing_output_is_rejected(tmp_path):
    def tamper(t):
        del t["output"]

    assert not verify_transcript(_make_transcript(tmp_path, tamper)).ok


@pytest.mark.parametrize("n_bytes", [1, 16, 64])
def test_valid_output_lengths_verify(tmp_path, n_bytes):
    assert verify_transcript(_make_transcript(tmp_path, n_bytes=n_bytes)).ok


@pytest.mark.parametrize("output", ["", "not hex"])
def test_verify_cli_reports_invalid_output(tmp_path, capsys, output):
    from entropy_forge.cli import main

    def tamper(t):
        t["output"] = output

    path = _make_transcript(tmp_path, tamper)
    assert main(["verify", str(path)]) == 1
    assert "TRANSCRIPT INVALID" in capsys.readouterr().out
