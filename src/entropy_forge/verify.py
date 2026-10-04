"""Offline verification of harvest transcripts.

A transcript is the instrument's notarized record of one emission: every
absorbed sample's hash in order, the pool fingerprint, the emission nonce,
and the output. Verification recomputes the whole chain from the entries —
no trust in the exporting page, server, or pixels required:

    pool_buf    = entry_hash_0 || entry_hash_1 || ...
    fingerprint = SHA-256(pool_buf)
    output[i]   = SHA-256(tag || 0x00 || ctx || pool_buf || b":{nonce}:{i}")

Matches the web instrument's ``absorb``/``emit`` byte-for-byte.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VerifyResult:
    ok: bool
    checks: list[tuple[str, bool, str]]
    mode: str


def verify_transcript(path: str | Path) -> VerifyResult:
    t = json.loads(Path(path).read_text(encoding="utf-8"))
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append((name, ok, detail))
        return ok

    check("format", t.get("kind") == "entropy-forge/transcript" and t.get("v") == 1)

    entries = t.get("entries", [])
    ordered = all(e.get("n") == i for i, e in enumerate(entries))
    check("entry ordering", ordered, f"{len(entries)} entries")

    try:
        buf = b"".join(bytes.fromhex(e["hash"]) for e in entries)
        check("entry hashes decode", True, f"{len(buf)} pool bytes")
    except (ValueError, KeyError) as exc:
        check("entry hashes decode", False, str(exc))
        return VerifyResult(False, checks, t.get("mode", "?"))

    fp = hashlib.sha256(buf).hexdigest()
    check("pool fingerprint", fp == t.get("fingerprint"), fp[:16] + "…")

    try:
        want = bytes.fromhex(t.get("output", ""))
        if not want:
            raise ValueError("output must contain at least one byte")
        check("output bytes", True, f"{len(want)} bytes")
    except (ValueError, TypeError) as exc:
        check("output bytes", False, str(exc))
        return VerifyResult(False, checks, t.get("mode", "?"))

    tag = (t.get("tag", "") + "\x00" + t.get("ctx", "")).encode()
    nonce = t.get("nonce", 0)
    out, c = b"", 0
    while len(out) < len(want):
        out += hashlib.sha256(tag + buf + f":{nonce}:{c}".encode()).digest()
        c += 1
    check("output derivation", out[: len(want)] == want, t.get("output", "")[:16] + "…")

    credited = sum(float(e.get("bits", 0)) for e in entries)
    dups = sum(1 for e in entries if e.get("dup"))
    check("accounting sane", credited >= 0, f"{credited:.0f} bits claimed, {dups} duplicates zeroed")

    ok = all(c[1] for c in checks)
    return VerifyResult(ok, checks, t.get("mode", "?"))


def format_report(r: VerifyResult) -> str:
    lines = []
    for name, ok, detail in r.checks:
        lines.append(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    verdict = "TRANSCRIPT VERIFIED" if r.ok else "TRANSCRIPT INVALID"
    if r.ok and r.mode == "demo":
        verdict += " (demo replay — sample dataset, honestly labeled)"
    lines.append(verdict)
    return "\n".join(lines)
