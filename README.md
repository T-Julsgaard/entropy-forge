# entropy-forge


**Harvest chaos from the real world — earthquakes, weather, the Bitcoin mempool, solar wind — and forge it into randomness.** The API version of Cloudflare's lava-lamp wall.

Every emission is a **planetary checksum**: a 32-byte fingerprint of the state of the world at one instant — its quakes, its tides, its solar wind, its traffic, one human's hand on the pad. And every emission can prove itself: the instrument exports a **verifiable transcript** that `entropy-forge verify transcript.json` recomputes offline, so fairness is a proof, not a promise.

## Try it in the browser

No install needed — the **harvest theater** is a single-file live instrument, and the **field manual** explains every stage of the pipeline:

- **[Harvest theater](https://t-julsgaard.github.io/entropy-forge/web/harvest-theater.html)** — 13 live source lanes, credit ledger, operator pad, verifiable receipts
- **[Field manual](https://t-julsgaard.github.io/entropy-forge/web/harvest-manual.html)** — the theory, the threat model, and a live avalanche demo

## Install

```
git clone https://github.com/T-Julsgaard/entropy-forge.git
cd entropy-forge
pip install -e ".[test]"

entropy-forge random --bytes 32          # public-mode randomness from live APIs
entropy-forge seed                       # 24-word BIP39 seed (CSPRNG-backed)
entropy-forge verify-vectors             # prove the BIP39 math against official vectors
```

Requires Python ≥ 3.11.

## The one rule

> **Public API data is NEVER the sole entropy source for anything protecting real money.**

Every remote source here is public and observable. Public mode is for provably-fair draws, nonces, simulations. **Wallet mode always starts from the OS CSPRNG** (`secrets.token_bytes(32)`); harvested entropy and your dice rolls are *mixed in on top* via HKDF-SHA256, which can add security but mathematically cannot remove it. There is no flag to bypass this — `tests/test_wallet_invariants.py` fails the build if one ever appears.

## How it works

```
sources (8 domains) → LSB extraction → health tests → Von Neumann → pool → SHA-256
                                                                      │
wallet mode:  secrets.token_bytes(32) ──► HKDF-SHA256 ◄── (optional) ─┘ + dice
                                             │
                                     BIP39 → 24 words
```

- **Domain diversity**: the pool refuses to emit until ≥5 independent domains contribute, and no domain is credited >40% of the pool.
- **Health tests** (NIST SP 800-90B-inspired): stale/duplicate fetches (CDN cache hits) are credited **zero** entropy.
- **Failure isolation**: timeouts → retries → circuit breaker; a dead API just means fewer inputs, never a crash. Total network failure during wallet mode changes nothing — that's the point of the rule above.
- **Verified BIP39**: implemented from the spec, checked against all official Trezor vectors *and* cross-checked against the reference `mnemonic` library on 1000 random inputs in CI.

## Status

Milestones M1–M3, M5-core, and M9-web complete (sources, pipeline, wallet mode, web theater + manual, full test suite: 31 passing). Remaining per `PROJECT_PLAN.md`: TUI harvest theater (M4), statistical battery + charts (M6), Tier-2 sources + correlation heatmap (M8). The live browser instrument ships in `web/harvest-theater.html` alongside its technical manual, `web/harvest-manual.html`.

## Honest limitations

This is an educational tool. Entropy estimates for public sources are guesses — which is exactly why wallet mode never relies on them. For significant holdings, a hardware wallet's audited generation is the better choice. Not cryptographic advice.

## Privacy

Live harvesting reveals your IP address to each data provider; run over Tor or
a VPN if that matters to you. Set `ENTROPY_FORGE_CONTACT="you@example.org"` in
your environment before live harvesting — MET Norway's terms require an
identifiable contact in the User-Agent. The web instrument loads zero external
scripts, enforced by its Content-Security-Policy.

## Data credits

MET Norway (NLOD/CC-BY 4.0) · USGS · NOAA SWPC · wheretheiss.at · mempool.space · CoinGecko · Hacker News (Y Combinator). Be polite: keep the shipped rate limits.
