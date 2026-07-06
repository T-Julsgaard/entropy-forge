"""Transcript verifier vs the web instrument's math, byte-for-byte."""
import hashlib
import json

from entropy_forge.verify import verify_transcript


def _web_absorb_hash(name: str, payload: str) -> bytes:
    return hashlib.sha256((name + "\x00" + payload).encode()).digest()


def _make_transcript(tmp_path, tamper=None):
    samples = [("quakes", "231244483"), ("weather", "2447"), ("operator", "9912|14")]
    entries, buf = [], b""
    for i, (name, payload) in enumerate(samples):
        h = _web_absorb_hash(name, payload)
        buf += h
        entries.append({"n": i, "name": name, "domain": "d", "hash": h.hex(), "bits": 5})
    nonce = 3
    tag = b"entropy-forge/public/v1\x00web"
    out, c = b"", 0
    while len(out) < 32:
        out += hashlib.sha256(tag + buf + f":{nonce}:{c}".encode()).digest()
        c += 1
    t = {"v": 1, "kind": "entropy-forge/transcript", "mode": "live",
         "tag": "entropy-forge/public/v1", "ctx": "web", "nonce": nonce,
         "fingerprint": hashlib.sha256(buf).hexdigest(),
         "output": out[:32].hex(), "entries": entries}
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
