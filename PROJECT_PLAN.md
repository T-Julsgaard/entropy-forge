# Project Plan: `entropy-forge`
### An open-source, multi-API entropy harvester, randomness generator, and BIP39 seed phrase tool

**Document purpose:** This is the master execution plan. It is written to be handed to an AI coding agent (Claude Opus 4.8) or a human developer for implementation. Follow the milestones in order. Every architectural decision includes its rationale so the implementer never has to guess intent.

---

## 0. TL;DR of the whole project

We build a Python project that:

1. Harvests "chaotic" data from multiple public open APIs (weather, earthquakes, ISS position, crypto prices, etc.).
2. Extracts, debiases, and cryptographically whitens that data into a uniform random bitstream.
3. Provides a **public-entropy mode** (API entropy allowed as a source).
4. Provides a **wallet mode** that generates BIP39 24-word seed phrases — where the OS CSPRNG is **always** the security foundation and API entropy may only ever be *mixed in on top*, never used alone.
5. Proves its quality with statistical test suites (ent, Dieharder, NIST STS) and BIP39 official test vectors.
6. Is documented like a serious open-source project: README, SECURITY.md, threat model, architecture doc, CI.

---

## 1. The single most important design rule (read this twice)

> **RULE 1: Public API data must NEVER be the sole entropy source for anything that protects real money.**

Why: every entropy source in this project (weather, quakes, ISS, prices) is **public and observable**. An attacker who knows roughly *when* a seed was generated can re-fetch or reconstruct the same API responses and brute-force the remaining unknowns. This is not theoretical — weak-entropy wallets have been drained in the wild.

Therefore the architecture is:

```
Public mode:     API entropy ──► whitening ──► random output (games, art, dice, lotteries among friends)

Wallet mode:  OS CSPRNG (secrets.token_bytes / os.urandom)  ◄── ALWAYS PRESENT, 256 bits minimum
                    │
                    ├──(optional)── API entropy, user dice rolls, keyboard mashing
                    ▼
              HKDF-SHA256 combine ──► 256-bit entropy ──► BIP39 checksum ──► 24 words
```

Mixing extra inputs via a proper KDF can only *add* entropy, never subtract — as long as the CSPRNG contribution is unconditionally included. The code must make it **impossible** (not just "not default") to generate a wallet seed without the CSPRNG contribution. No flag, no env var, no config option may disable it. If someone wants pure-API seeds they must fork the code — that's a feature.

> **RULE 2: Wallet mode must support and recommend fully offline operation.** API mixing is optional; the tool must detect and warn when run on a networked machine, and the docs must recommend generating real seeds on an air-gapped device and never typing a seed into any online system afterward.

> **RULE 3: We never invent our own crypto primitives.** SHA-256, HKDF, and CSPRNG come from Python's `hashlib`, `hmac`, and `secrets` stdlib modules. BIP39 logic is implemented from the spec for educational value **and** cross-verified against the vetted `mnemonic` library (Trezor's reference implementation) in tests. If they ever disagree, the build fails.

---

## 2. Repository structure

```
entropy-forge/
├── README.md                  # Hero doc: what, why, demo GIF, quickstart, honest limitations
├── SECURITY.md                # Threat model, what this is/isn't safe for, reporting
├── docs/
│   ├── ARCHITECTURE.md        # Data flow diagrams, module responsibilities
│   ├── ENTROPY_SOURCES.md     # Each API: endpoint, fields used, why, rate limits, attribution
│   ├── WHITENING.md           # The math: LSB extraction, Von Neumann, hashing, health tests
│   └── WALLET_MODE.md         # BIP39 explainer, offline procedure, verification steps
├── src/entropy_forge/
│   ├── __init__.py
│   ├── sources/               # One module per API, all implementing a common interface
│   │   ├── base.py            # EntropySource ABC: name, fetch() -> SourceSample
│   │   ├── met_weather.py     # api.met.no — temp/pressure/wind decimals, multiple cities
│   │   ├── usgs_quakes.py     # USGS earthquake feed — magnitudes, depths, timestamps
│   │   ├── iss_position.py    # ISS lat/lon (wheretheiss.at)
│   │   ├── crypto_prices.py   # e.g. CoinGecko — last digits of prices
│   │   ├── system_jitter.py   # Local fallback: timing jitter between syscalls (always available)
│   │   └── user_input.py      # Dice rolls / keyboard mash for wallet mode extra entropy
│   ├── core/
│   │   ├── extractor.py       # Pull least-significant bits/digits from raw samples
│   │   ├── debias.py          # Von Neumann debiasing
│   │   ├── health.py          # NIST SP 800-90B style health tests (see §5.3)
│   │   ├── pool.py            # Entropy pool: accumulate, track estimated entropy per source
│   │   └── whitener.py        # SHA-256 conditioning; HKDF combine for multi-input mixing
│   ├── wallet/
│   │   ├── bip39.py           # entropy -> checksum -> mnemonic (from spec)
│   │   ├── wordlist_english.txt  # Official BIP39 wordlist (verify SHA-256 against known hash)
│   │   └── generate.py        # Wallet-mode orchestration: CSPRNG-always + optional mixing
│   ├── cli.py                 # `entropy-forge random`, `entropy-forge seed`, `entropy-forge dashboard`
│   └── api.py                 # Optional: small FastAPI /random endpoint (public mode ONLY)
├── tests/
│   ├── test_sources.py        # Mocked API responses; no network in unit tests
│   ├── test_extractor.py
│   ├── test_debias.py
│   ├── test_health.py
│   ├── test_bip39_vectors.py  # Official BIP39 test vectors (Trezor repo) MUST all pass
│   ├── test_cross_check.py    # Our BIP39 vs `mnemonic` library on 1000 random inputs
│   └── test_wallet_invariants.py  # Proves CSPRNG can't be bypassed (see §6.4)
├── analysis/
│   ├── run_ent.sh             # Generate N MB, run `ent`
│   ├── run_dieharder.sh       # Dieharder battery
│   ├── run_nist_sts.md        # Instructions for NIST STS (manual, it's fiddly)
│   └── results/               # Committed test result summaries + charts for README
├── .github/workflows/ci.yml   # lint (ruff), typecheck (mypy), pytest, cross-check
├── pyproject.toml
└── LICENSE                    # MIT
```

---

## 3. Entropy sources — specifications

Common interface (`sources/base.py`):

```python
@dataclass
class SourceSample:
    source_name: str
    fetched_at: float          # unix time
    raw_fields: dict           # what we pulled, for the dashboard/audit log
    entropy_bytes: bytes       # extracted candidate-entropy bytes
    est_min_entropy_bits: float  # conservative per-sample estimate (see §5.4)

class EntropySource(ABC):
    name: str
    def fetch(self) -> SourceSample: ...
```

### 3.1 Design principle: maximize *domain diversity*, not just source count

Ten weather APIs are one source wearing ten hats — their values are physically correlated. The project's headline claim ("an attacker must model the whole world to predict our pool") only holds if sources come from **independent physical/social domains**. Every source below is tagged with its domain; the pool must draw from **at least 5 distinct domains** before emitting public-mode output, and the dashboard must display domain coverage, not just source count.

### 3.2 Source catalog

**Tier 1 — launch set (implement in M2, all keyless and open):**

| Domain | Source | Endpoint | Fields to use | Notes |
|---|---|---|---|---|
| Atmosphere | MET Norway | `api.met.no/weatherapi/locationforecast/2.0/compact` | Decimals of temp, pressure, wind, humidity for ~10 globally scattered cities | **Must** send proper `User-Agent` with project URL + contact. Honor `Expires` header — cache, don't hammer. Credit MET/NLOD. |
| Geophysics | USGS earthquakes | `earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson` | Magnitude/depth/coord decimals, ms of timestamps | Can be empty in quiet hours → handle gracefully. |
| Orbital | ISS position | `api.wheretheiss.at/v1/satellites/25544` | lat/lon/velocity decimals | Computable from public TLEs → est. entropy near zero; kept for fun/diversity. |
| Markets | CoinGecko | simple price endpoint (keyless tier) | Last 2–3 digits of several coin prices | Respect rate limits; backoff on 429. |
| Blockchain | mempool.space | `/api/blocks` + `/api/mempool` | Latest block hash bytes, mempool tx-count/fee decimals | Block hashes are high-quality unpredictable bits (miners can bias slightly — fine for mixing). |
| Space weather | NOAA SWPC | JSON products (solar wind speed/density, Kp) | Measurement decimals | Genuinely chaotic plasma physics — great story. |
| Human/social | Hacker News | `hacker-news.firebaseio.com/v0/maxitem.json` + new item timestamps | Item-ID deltas, timestamp ms | Human posting behavior — uncorrelated with geophysics. |
| Local | System jitter | local | ns deltas between repeated `perf_counter_ns()` around small syscalls | Always available; keeps public mode working offline. |
| Local | User input | local | Dice rolls / keystroke content+timing | Wallet-mode optional extra. 100 honest d6 rolls ≈ 258 bits. |

**Tier 2 — expansion set (M7+, each its own small PR):**

| Domain | Source | What to pull | Notes |
|---|---|---|---|
| Aviation | OpenSky Network | Live aircraft positions/velocities over a bounding box | Free anonymous tier is rate-limited; thousands of jittering values per call. |
| Hydrology | USGS Water Services | River gauge heights/discharge decimals, many stations | Rainfall-driven chaos, independent of weather *forecasts*. |
| Tides/ocean | NOAA Tides & Currents | Water level + water temp decimals | Predictable component is fine — we take residual decimals. |
| Energy markets | hvakosterstrommen.no | Norwegian hourly spot power prices | Nice Norwegian tie-in with the Yr origin story; keyless. |
| FX | Frankfurter (ECB) | Exchange-rate decimals | Updates ~daily → low rate, tiny entropy cap. |
| Citizen sensors | openSenseMap | Random selection of public sensor boxes (PM2.5, temp, noise) | Thousands of independent hobbyist sensors worldwide. |
| Transit | Entur (Norway) real-time | Vehicle delays/positions | Human+traffic chaos; open API, requires ET-Client-Name header. |
| Knowledge graph | Wikipedia | Recent-changes feed: rev IDs, byte-size deltas, timestamps | Global human editing activity. |
| Code activity | GitHub public events | Event IDs/timestamps | Keyless at low rate; another human-activity domain. |
| Astronomy | NASA DONKI / NeoWs | Solar flare/CME timings, asteroid approach distances | DEMO_KEY works at low volume. |
| PKI/infra | Certstream (CT logs) | Live TLS certificate issuance events via websocket | The identity-defining source: entropy from the internet's own crypto infrastructure. Python tier (websocket). |
| Transit | KMB Hong Kong bus ETAs | Predicted arrival headways | Keyless government open data, second-level updates. Also in web instrument. |
| Citizen sensors | Sensor.Community | 15k+ hobbyist air sensors, random area query | Huge randomizable parameter space. Also in web instrument. |
| Urban micro | Swiss city sensors (St. Gallen pedestrians, Basel parking, Lucerne visitors) | Occupancy/count decimals | Tiny entropy, enormous charm; Tier 3. |
| Ocean deep | NOAA NDBC buoys | Wave height/period/wind decimals | Complements coastal tide stations. |
| Atmosphere fast | Singapore NEA | 1-minute station readings | Correlated domain but best-in-class freshness. |
| Randomness beacons | drand (League of Entropy), NIST beacon | Published beacon values | **Public and everyone sees the same values** → est. entropy = 0 for our threat model; include as mix-in only, and document that nuance — it's a great teaching point. |

**Explicitly rejected sources (document in ENTROPY_SOURCES.md so contributors don't re-propose them):** anything requiring paid keys or heavy auth (most AIS ship data, Twitter/X, Reddit), anything scraping HTML (fragile, often against ToS), random.org (ToS restricts this use; also a single trusted third party), and ANU QRNG (now keyed/metered).

### 3.3 Engineering requirements for all sources
- One module per source implementing `EntropySource`; adding a source must never touch core code (registry/entry-point pattern).
- Timeouts (5s), retries with jittered exponential backoff (max 3), per-source circuit breaker, and per-source rate-limit config honoring each provider's published limits.
- A failing source must **never** crash the pipeline — the pool just gets fewer inputs, and output metadata records which sources/domains contributed.
- All HTTP via one shared client with the project User-Agent; per-source attribution strings collected automatically into ENTROPY_SOURCES.md and the README credits section.
- Unit tests use recorded/mocked responses only; `pytest -m live` marker for optional real-network smoke tests.

### 3.4 Independence verification (this is what makes the project *sound*, not just cool)
- `analysis/correlation.py`: collect N hours of per-source extracted bitstreams, compute pairwise Pearson correlation and mutual-information estimates, and render a heatmap for the README.
- Sources within the same domain (e.g., two weather feeds) are *expected* to correlate — the heatmap should visually prove that cross-domain pairs don't. If a cross-domain pair shows correlation > threshold, investigate (shared timestamps are the usual culprit — see next point).
- **Timestamp de-duplication rule:** many APIs return "now"-ish timestamps; if we extract ms digits from every source, all sources secretly share one clock and the independence claim collapses. Extract timestamp entropy from at most ONE designated source; everywhere else, strip timestamps before extraction.
- The pool's entropy accounting must apply a **domain haircut**: total credited entropy from any single domain is capped (e.g., ≤ 40% of the pool) regardless of how many sources that domain has.

### 3.5 Randomized harvest scheduling (the "attacker can't even know what we sampled" layer)

Instead of querying a fixed set of sources on a fixed schedule, a **HarvestPlanner** uses local randomness (CSPRNG seeded, optionally jitter-mixed) to randomize *what*, *where*, and *when* we sample each round:

- **Which sources** participate this round (subject to the domain-coverage minimum in §3.1 — randomization must never drop below 5 domains).
- **Which parameters** within a source: which ~10 of a large city list for MET, which of thousands of openSenseMap boxes, which USGS river gauges, which bounding box for OpenSky. Parameter spaces should be large (hundreds+ options) so the attacker's search space multiplies combinatorially.
- **When**, with sub-second jitter on query timing. This matters most for fast-moving sources (mempool, HN, OpenSky, transit) where the exact millisecond changes the answer; it adds ~nothing for slow cached feeds (MET forecasts, FX) — document that asymmetry in WHITENING.md.

Two rules to keep this honest:
1. **No double counting.** The selection choices are derived from local randomness we already have; they add *attacker uncertainty about the harvest*, not new entropy in the information-theoretic sense. The pool credits entropy only from the fetched data itself. Frame it in docs as: randomized sampling **multiplies the attacker's search space** across all possible harvest plans, which is a defense-in-depth layer, not an entropy source.
2. **Auditability without predictability.** The audit log records a *hash* of the harvest plan per round (commit), with the full plan revealable on demand — so behavior is debuggable/provable after the fact without pre-announcing what we'll sample.

The planner must also respect per-provider rate budgets (a global politeness scheduler owns all outbound request quotas — no source module talks to the network directly).

---

## 4. The whitening pipeline (docs/WHITENING.md must explain all of this)

Stage by stage, each implemented and unit-tested independently:

1. **Extraction** (`extractor.py`): from each numeric field, keep only the least-significant digits/bits (e.g., temperature `12.7` → the `7`, timestamp `...483ms` → `483`). Concatenate across fields into candidate bytes. Rationale: high-order bits are predictable (Oslo in July is ~15–25°C); low-order bits jitter.
2. **Health tests** (`health.py`): before data enters the pool, run continuous tests inspired by NIST SP 800-90B:
   - **Repetition Count Test** — flag if the same sample value repeats implausibly (stuck/cached source).
   - **Adaptive Proportion Test** — flag if one value dominates a window.
   - **Freshness/duplicate test** — hash each raw sample; if a source returns bytes identical to its previous fetch (CDN cache hit, stale feed), credit it **zero** entropy for that round. This is the most common real-world failure mode and must be caught explicitly, not just statistically.
   - A source that fails is quarantined for a cooldown period and excluded from the pool; the event is logged and shown on the dashboard.
3. **Debiasing** (`debias.py`): Von Neumann extractor on the bitstream (pairs: `01→0`, `10→1`, `00`/`11`→ discard). This is partly pedagogical — the hash step would suffice — but it's a classic technique the README should teach. Keep it as an inspectable, optional pipeline stage.
4. **Pooling** (`pool.py`): accumulate whitened-candidate bytes with per-source accounting. The pool tracks a **conservative** running total of estimated min-entropy (see §5.4) and refuses to emit output until estimated input entropy ≥ 2× requested output bits (safety margin).
5. **Conditioning** (`whitener.py`):
   - Public mode output: `SHA-256(domain_tag || pool_snapshot || counter)` blocks, concatenated to requested length. Domain-separation tag prevents cross-protocol reuse.
   - Multi-input combining (wallet mode): **HKDF-SHA256** with the CSPRNG bytes as IKM, pool/user bytes as salt/info inputs. Never plain XOR for the final combine (XOR of correlated inputs can cancel; HKDF cannot be weakened by extra inputs).

### 5.4 Entropy estimation policy
Be deliberately pessimistic. Hard-code conservative per-sample caps (e.g., weather field ≤ 2 bits, quake field ≤ 3 bits, ISS ≤ 0.5 bits, price digit ≤ 2 bits) and document in ENTROPY_SOURCES.md *why* each cap was chosen. The README must state plainly: "our entropy estimates are guesses; that is exactly why wallet mode never relies on them."

---

## 5. Wallet mode (BIP39) — exact specification

`wallet/generate.py` flow:

1. `base = secrets.token_bytes(32)` — 256 bits from OS CSPRNG. **Unconditional. Not configurable.**
2. Optionally collect extra inputs (each clearly consented to in the CLI):
   - harvested API pool bytes (with a warning that this requires network),
   - user dice rolls / keyboard mash.
3. `entropy = HKDF-SHA256(ikm=base, salt=SHA256(extra_inputs or b""), info=b"entropy-forge/bip39/v1", length=32)`
4. BIP39: checksum = first `ENT/32 = 8` bits of `SHA256(entropy)`; append → 264 bits → 24 × 11-bit indices → words from the official English wordlist.
5. Display the 24 words **in the terminal only**. Never write them to disk, logs, shell history, or clipboard. Offer an interactive verification quiz (re-enter 3 random words) so the user proves they wrote it down.
6. **Memory & display hygiene:** overwrite entropy buffers after use (use `bytearray` and zero it; document honestly that Python cannot guarantee no copies exist — another reason the docs point serious users to hardware wallets). After display+quiz, print enough blank lines/clear-screen escape to push words out of view, and warn about terminal scrollback and tmux/screen logging.
7. **Trust-but-verify mode:** `entropy-forge seed --verify-vectors` runs the official BIP39 vectors live and prints the results, and `--from-entropy <hex>` lets a user feed known test entropy and confirm the words against an independent tool. A seed generator you can't independently verify shouldn't be trusted — make verification a first-class feature.
8. Print the offline-usage warning and a pointer to `docs/WALLET_MODE.md`.

`wallet/bip39.py` requirements:
- Implement from the BIP39 spec directly (educational).
- Wordlist file's SHA-256 must be checked at import against the known official hash.
- Must pass **all** official BIP39 English test vectors (from the Trezor `python-mnemonic` repo) in `test_bip39_vectors.py`.
- `test_cross_check.py`: for 1,000 random entropy inputs, our mnemonic == `mnemonic` library's mnemonic, and round-trip (mnemonic → entropy) is exact.

`docs/WALLET_MODE.md` must cover: what a seed phrase is, why entropy quality is life-or-death for it, the offline procedure (boot a live USB / air-gapped machine, generate, write on paper/steel, never photograph or type into a networked device), the optional BIP39 passphrase ("25th word") — what it protects against and its no-recovery-if-forgotten tradeoff — and an explicit statement that for large holdings a hardware wallet's built-in generation is the better-audited choice — this tool is for learning and for people who want to *understand* the process.

### 6.4 Wallet invariant tests (non-negotiable)
`test_wallet_invariants.py` must prove, via monkeypatching/inspection:
- Generating a seed **always** calls `secrets.token_bytes(32)` (patch it, assert called, assert its output influences the result).
- Two runs with **identical** API/extra inputs produce **different** mnemonics (because CSPRNG differs) — this is the test that catches any future regression toward API-only entropy.
- There is no code path, argument, or environment variable that skips step 1 (assert the function signature/config schema has no such option; grep-style CI check for forbidden flags is acceptable belt-and-braces).

---

## 6. Statistical validation (analysis/)

1. Generate ≥ 100 MB from public mode (system-jitter + cached API fixtures is fine for CI; real APIs for the headline run).
2. `ent`: report entropy/byte (want ≥ 7.9999), chi-square, arithmetic mean (~127.5), Monte Carlo π, serial correlation (~0).
3. **Dieharder**: `dieharder -a -g 201 -f output.bin`. Record pass/weak/fail table. A few WEAKs across the battery are statistically normal — say so in the docs rather than hiding it.
4. **NIST STS**: document the exact invocation in `run_nist_sts.md`; commit the summary.
5. Also run the battery on the **raw pre-whitening** stream and publish both side by side — the before/after comparison is the most instructive artifact in the whole repo and belongs in the README with charts (matplotlib PNG committed to `analysis/results/`).

---

## 7. Live visualization — make the harvest *visible* (docs/VISUALIZATION.md)

The pipeline is invisible by nature; the visualization is what makes people *feel* it. Requirement: a terminal UI (built with `textual`, falling back to `rich` Live) called the **harvest theater**, launched via `entropy-forge dashboard` and also shown inline during `entropy-forge random`.

### 7.1 The one rule that keeps it honest
**Every animation must be triggered by a real event.** No decorative fake progress bars. Architecture: the core pipeline emits structured events on an internal event bus — `FetchStarted(source, params)`, `FetchCompleted(source, raw_fields, latency)`, `SampleExtracted(source, bits)`, `HealthEvent(source, test, verdict)`, `PoolUpdated(est_bits, domains)` — and renderers subscribe. This decouples pipeline from presentation, and the same bus later feeds the plain-text logger, CI output, and the optional web dashboard.

### 7.2 Panels (top to bottom)
1. **World map** — a braille/ASCII world map with pulsing markers at real fetch coordinates: the cities being weather-sampled this round, quake epicenters as they arrive, the ISS's current position crawling along its track, the OpenSky bounding box. Markers flash on `FetchCompleted` and fade over ~3s. This is the panel that makes the randomized harvest plan (§3.5) *visible* — every round the constellation of dots is different.
2. **Source lanes** — one row per active source: status spinner while fetching → the **actual incoming values** rendered as a scrolling ticker (`Oslo 17.3°C · 1002.4 hPa · wind 4.7 m/s`, `M2.3 quake, 12.44 km deep`, `block 903f…e1a2, 14,203 tx`) → the extracted least-significant digits highlighted in a distinct color → a brief "absorbed into pool" sweep animation. Quarantined sources turn their lane red with the failing health test named.
3. **Pool panel** — a filling gauge of estimated bits vs. target, plus a **domain coverage meter** (e.g., 6/8 domain icons lit) so the §3.1 rule is visible at a glance.
4. **Bit-rain footer** — whitened output bytes streaming as hex "matrix rain" once the pool emits. Purely celebratory, but driven by real output bytes.

### 7.3 Engineering requirements
- Graceful degradation: if stdout isn't a TTY (CI, pipes), automatically switch to structured plain-text event logs; `--no-anim` and `NO_COLOR` respected; target ≤ 30 fps and negligible CPU when idle.
- The world map needs no heavy deps: ship a small packed coastline bitmap rendered to braille cells; lat/lon → cell math is ~20 lines.
- **Wallet-mode restriction:** in seed generation, the theater may show *metadata only* — source names, domains, sample counts, health status. Raw fields, extracted bits, and pool bytes must never be rendered, since anything displayed or logged during wallet mode is potential seed leakage. Enforce with a `redacted=True` event-bus mode and a test.
- Demo capture: a `make demo-gif` target records a short harvest with `vhs` or `asciinema` for the README hero GIF.

### 7.4 Stretch (backlog): web globe
The same event bus can feed a WebSocket endpoint on the optional FastAPI service, driving a rotating three.js/D3 globe with animated arcs from each fetch location to the user — the shareable showpiece. Strictly after the TUI is done; the TUI is the deliverable.

---

## 8. Documentation requirements

- **README.md**: badges, one-paragraph pitch, the Cloudflare-lava-lamp analogy, architecture diagram (mermaid), quickstart (`pipx install`, `entropy-forge random --bytes 32`, `entropy-forge seed --offline`), before/after randomness charts, honest **Limitations** section, attribution to MET Norway (NLOD/CC-BY-4.0), USGS, wheretheiss.at, CoinGecko.
- **SECURITY.md**: threat model table — attacker capabilities (observes public APIs; controls one API; controls network path; compromises the host) vs. what each mode guarantees. State plainly: public mode is NOT for keys, passwords, or anything adversarial; wallet mode's security reduces to the OS CSPRNG, by design. Include responsible-disclosure contact.
- Every module gets docstrings explaining *why*, not just *what*. Pipeline stages log to a structured audit log (source names, sample counts, health-test events — never the entropy bytes themselves in wallet mode).

---

## 9. Tooling & quality bar

- Python 3.11+, `pyproject.toml`, `ruff` (lint+format), `mypy --strict` on `core/` and `wallet/`, `pytest` + `pytest-cov` (≥ 90% on `core/` and `wallet/`).
- **Property-based testing** with `hypothesis` on all parsers and the extractor/debias/BIP39 round-trips — public APIs return malformed JSON constantly, and a security-adjacent tool must not crash or, worse, silently emit short output on garbage input.
- **Async fetching**: sources fetch concurrently via async `httpx` under the politeness scheduler; a harvest round across 15 sources should take seconds, not minutes.
- **Supply-chain hardening** (this repo *invites* scrutiny, so model good practice): hash-pinned lockfile, GitHub Actions pinned to commit SHAs, Dependabot, no post-install scripts, `pip install --require-hashes` in CI, and a documented dependency-review policy in CONTRIBUTING.md.
- CI (GitHub Actions): lint → typecheck → tests (no network) → BIP39 vectors → cross-check → a small `ent` smoke run on 1 MB of public-mode output with thresholds. Add a **chaos job** that runs the pipeline with every remote source mocked to fail/timeout/return garbage and asserts graceful degradation.
- Dependencies kept minimal: `httpx`, `mnemonic` (test-time cross-check), `fastapi`+`uvicorn` (optional extra), `rich` (CLI/dashboard), `matplotlib` (analysis only), `hypothesis` (test only). Pin with a lockfile.
- Conventional commits; one milestone per PR.

---

## 10. Milestones for the executing agent (do in order)

1. **M1 – Skeleton**: repo layout, pyproject, CI running an empty test, README stub. ✅ when CI is green.
2. **M2 – Sources (Tier 1)**: `base.py` + registry pattern, then all Tier 1 sources from §3.2 with mocked-response tests, shared HTTP client, backoff, circuit breaker, timestamp de-dup rule enforced.
3. **M3 – Core pipeline**: extractor → health tests (incl. freshness/dedup) → Von Neumann → pool → SHA-256 conditioning → **HarvestPlanner** (§3.5) with the politeness scheduler. Unit tests per stage, including known-answer tests for debiasing.
4. **M4 – Public mode CLI + harvest theater**: the event bus + `entropy-forge random --bytes N [--hex|--base64] [--sources ...]`, the full TUI dashboard per §7 (world map, source lanes with real incoming values, pool gauge, bit-rain), and `draw` — a **provably-fair raffle/dice command** using commit-reveal: it publishes `SHA256(pool_snapshot || nonce)` *before* the draw, then reveals the preimage so participants can verify the result wasn't cherry-picked. This is the killer demo feature: a concrete, legitimate use for public-entropy randomness.
5. **M5 – Wallet mode**: bip39.py + vectors + cross-check + invariant tests + generate.py + WALLET_MODE.md. **Nothing merges here with any test skipped.**
6. **M6 – Statistical analysis**: scripts, headline 100 MB run, charts, results committed.
7. **M7 – Docs polish + optional API**: full README/SECURITY/ARCHITECTURE/ENTROPY_SOURCES/WHITENING, FastAPI `/random` (public mode only, rate-limited, clearly labeled not-for-crypto).
8. **M8 – Tier 2 sources + independence analysis**: add Tier 2 sources from §3.2 one PR each; implement `analysis/correlation.py`; publish the cross-domain correlation heatmap and domain-coverage dashboard in the README.

9. **M9 – Verifiable transcripts (web ✅, Python)**: transcript export + `verify` CLI shipped for the web instrument; port transcript emission to the Python harvester so CLI emissions are equally auditable.
10. **M10 – Trust demos**: adversary drill (shipped lean in web demo mode) expanded with more attack classes; per-provider request-budget meter in the inspector; Geiger sonification polish; one-file source contract in CONTRIBUTING.md so a lane = one dropped file.

Acceptance for the whole project: CI green, Dieharder results published, all BIP39 vectors pass, invariant tests prove CSPRNG cannot be bypassed, and a stranger reading the README understands both how it works and what it must not be used for.

---

## 11. Explicit non-goals

- No custom hash functions, DRBG designs, or "clever" crypto.
- No key storage, wallet balance features, or transaction signing — this tool ends at the 24 words.
- No claim of "true randomness" in marketing copy; the honest claim is "well-conditioned entropy from diverse public sources, with CSPRNG-backed wallet generation."

---

## 12. Nice-to-have backlog (minor, post-M8, in rough priority order)

- **Dockerfile + devcontainer** for one-command reproducible setup; a `make demo` target that runs a full harvest → whiten → `ent` cycle in one go for first-time visitors.
- **Entropy timelapse**: record 24h of per-source contribution data and render an animated chart for the README — great for social sharing.
- **Cross-platform jitter audit**: verify `perf_counter_ns()` resolution on Linux/macOS/Windows and adjust the jitter source's entropy cap per platform (Windows timer resolution is coarser).
- **ADRs** (Architecture Decision Records) in `docs/adr/` — a few short records ("why HKDF not XOR", "why CSPRNG is mandatory", "why we rejected random.org") formalize the reasoning already in this plan and make great reading for contributors.
- **Prometheus metrics** on the optional FastAPI service (requests, pool level, source health) if anyone actually deploys it.
- **i18n wordlists**: BIP39 supports other languages; English-only at launch, but structure `bip39.py` so adding a wordlist is a data change, not a code change.
- **A short blog-post-style EXPLAINER.md** telling the story (lava lamps → APIs → why your wallet still needs a CSPRNG) — the narrative version of the README for people who want to read, not build.
