"""CLI. `entropy-forge random|seed|verify-vectors`. TUI theater is M4."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import uuid as uuidlib


def cmd_random(args) -> int:
    from .harvest import Harvester, default_sources
    from .sources.http import HttpClient

    client = None if args.offline else HttpClient()
    harvester = Harvester()
    if args.offline:
        # offline public mode: local domain only — relax the domain minimum
        # but SAY SO. Never silently weaken guarantees.
        harvester.pool.min_domains = 1
        print("[offline] local jitter only — domain-diversity guarantee OFF", file=sys.stderr)
    sources = default_sources(client, offline=args.offline)
    rounds = 0
    while True:
        harvester.round(sources)
        rounds += 1
        ok, why = harvester.pool.ready(args.bytes * 8)
        if ok or rounds >= args.max_rounds:
            break
        print(f"[round {rounds}] {why} — harvesting more…", file=sys.stderr)
    data = harvester.emit(args.bytes)
    print(f"[sources] ok: {', '.join(harvester.contributed) or '-'}", file=sys.stderr)
    if harvester.failed:
        print(f"[sources] failed: {', '.join(harvester.failed)}", file=sys.stderr)
    fmt = "base64" if args.base64 else args.format
    print(format_output(data, fmt))
    return 0


def _expand(data: bytes):
    """Deterministic byte stream from an emission, for rejection sampling.
    Mirrors the web instrument's expand() exactly."""
    ctr = 0
    while True:
        block = hashlib.sha256(data + f"fmt:{ctr}".encode()).digest()
        ctr += 1
        yield from block


def _draw(gen, limit: int, mod: int) -> int:
    for b in gen:
        if b < limit:
            return b % mod
    raise RuntimeError("unreachable")


def format_output(data: bytes, fmt: str) -> str:
    """Encode one emission. Formats are lenses, not new entropy — same bytes,
    same value, always. No key/password format by design: wrong output class."""
    if fmt == "hex":
        return data.hex()
    if fmt == "base64":
        return base64.b64encode(data).decode()
    if fmt == "uuid":
        if len(data) < 16:
            raise ValueError("UUID output requires at least 16 bytes")
        b = bytearray(data[:16])
        b[6] = (b[6] & 0x0F) | 0x40
        b[8] = (b[8] & 0x3F) | 0x80
        return str(uuidlib.UUID(bytes=bytes(b)))
    g = _expand(data)
    if fmt == "int":
        while True:
            v = 0
            for _ in range(3):
                v = (v << 8) | _draw(g, 256, 256)
            if v < 16_000_000:
                return f"{v % 1_000_000:06d}"
    if fmt == "dice":
        return " ".join(str(1 + _draw(g, 252, 6)) for _ in range(10))
    if fmt == "lotto":
        picks: list[int] = []
        while len(picks) < 6:
            n = 1 + _draw(g, 245, 49)
            if n not in picks:
                picks.append(n)
        return " ".join(map(str, picks))
    raise ValueError(f"unknown format: {fmt}")


def cmd_seed(args) -> int:
    from .wallet.generate import generate_seed_phrase

    print("=" * 62)
    print(" WALLET MODE — read docs/WALLET_MODE.md before using for value")
    print("  * generate on an OFFLINE machine for real funds")
    print("  * write the words on paper/steel; never photograph or type")
    print("    them into anything networked")
    print("  * security foundation: OS CSPRNG (APIs are optional mixing)")
    print("=" * 62)
    extra: list[bytes] = []
    if args.dice:
        rolls = input("enter dice rolls (e.g. 261435…): ").strip()
        if not rolls or any(c not in "123456" for c in rolls):
            print("invalid rolls — digits 1-6 only", file=sys.stderr)
            return 2
        extra.append(rolls.encode())
    words = generate_seed_phrase(extra)
    cols = words.split()
    for i in range(0, 24, 4):
        print("   " + "  ".join(f"{n+1:>2}.{w:<10}" for n, w in enumerate(cols[i:i+4], start=i)))
    if not args.yes_i_wrote_it_down:
        import random as _r
        picks = sorted(_r.sample(range(24), 3))
        for p in picks:
            got = input(f"verify — word #{p+1}: ").strip().lower()
            if got != cols[p]:
                print("MISMATCH — write the words down correctly and rerun.", file=sys.stderr)
                return 3
        print("verified ✓")
    print("\033[2J\033[H(screen cleared — beware terminal scrollback/tmux logs)")
    return 0


def cmd_verify_vectors(args) -> int:
    from .wallet.bip39 import entropy_to_mnemonic, mnemonic_to_seed

    from importlib import resources

    raw = resources.files("entropy_forge.wallet").joinpath("vectors.json").read_text(encoding="utf-8")
    vectors = json.loads(raw)["english"]
    bad = 0
    for ent_hex, mnemonic, seed_hex, _xprv in vectors:
        ours = entropy_to_mnemonic(bytes.fromhex(ent_hex))
        seed = mnemonic_to_seed(ours, "TREZOR").hex()
        ok = ours == mnemonic and seed == seed_hex
        bad += 0 if ok else 1
        print(("PASS " if ok else "FAIL ") + ent_hex[:16] + "…")
    print(f"{len(vectors) - bad}/{len(vectors)} official BIP39 vectors passed")
    return 1 if bad else 0


def cmd_verify(args) -> int:
    from .verify import format_report, verify_transcript

    r = verify_transcript(args.path)
    print(format_report(r))
    return 0 if r.ok else 1


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="entropy-forge")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("random", help="public-mode random bytes (NOT for keys/wallets)")
    r.add_argument("--bytes", type=_positive_int, default=32)
    r.add_argument("--base64", action="store_true", help="alias for --format base64")
    r.add_argument("--format", choices=["hex", "base64", "uuid", "int", "dice", "lotto"],
                   default="hex")
    r.add_argument("--offline", action="store_true", help="local jitter only")
    r.add_argument("--max-rounds", type=_positive_int, default=5)
    r.set_defaults(fn=cmd_random)
    s = sub.add_parser("seed", help="generate a 24-word BIP39 seed (CSPRNG-backed)")
    s.add_argument("--dice", action="store_true", help="mix in your own dice rolls")
    s.add_argument("--yes-i-wrote-it-down", action="store_true")
    s.set_defaults(fn=cmd_seed)
    v = sub.add_parser("verify-vectors", help="run official BIP39 test vectors")
    v.set_defaults(fn=cmd_verify_vectors)
    tv = sub.add_parser("verify", help="verify an exported harvest transcript offline")
    tv.add_argument("path")
    tv.set_defaults(fn=cmd_verify)
    args = p.parse_args(argv)
    if args.cmd == "random" and not args.base64 and args.format == "uuid" and args.bytes < 16:
        p.error("UUID output requires at least 16 bytes (--bytes 16 or greater)")
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
