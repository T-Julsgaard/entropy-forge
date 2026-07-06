# Security

## Threat model

| Adversary capability | Public mode | Wallet mode |
|---|---|---|
| Observes all public API feeds | **Fully effective** — output is classified NON-SECRET for exactly this reason | No effect: CSPRNG base is never observable |
| Controls one or more API responses | Health tests + domain haircut limit credit; output remains NON-SECRET anyway | No effect: extras are HKDF-mixed, cannot subtract |
| Controls the network path (MITM) | Same as above | No effect; offline generation recommended regardless |
| Compromises the host OS | Game over | Game over — same as every software wallet; use a hardware wallet for serious holdings |

Wallet-mode security reduces to the operating system's CSPRNG **by design**.
`tests/test_wallet_invariants.py` fails the build if any code path could ever
skip the `secrets.token_bytes(32)` foundation.

## What this project is NOT

Not an audited cryptographic product, not a hardware RNG, and not a
recommendation to generate high-value seeds in software. It is an educational
instrument with honestly stated limits.

## Reporting

Open a GitHub security advisory on the repository, or a private report to the
maintainer contact listed in the repo profile. Please do not open public
issues for exploitable findings.
