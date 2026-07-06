# Wallet mode

A BIP39 seed phrase encodes the master key to every address derived from it. Entropy quality is the entire security of the wallet.

**Procedure for real funds:** use an air-gapped machine (live-USB Linux, network off) → `entropy-forge seed` → write the 24 words on paper or steel → verify via the built-in quiz → never photograph the words, never type them into anything networked. Consider a BIP39 passphrase ("25th word"): it protects the paper backup, but is unrecoverable if forgotten.

**Why the CSPRNG is mandatory:** all our API sources are public. An attacker who knows roughly when you generated could replay them. `secrets.token_bytes(32)` is therefore always the foundation; extras are HKDF-mixed on top and can only add security.

**Verify before trusting:** `entropy-forge verify-vectors` runs the official test vectors live. You can also cross-check any test mnemonic against an independent implementation (e.g. Ian Coleman's tool — offline copy only).

For large holdings, prefer a hardware wallet's audited generation. This tool exists so you *understand* the process.
