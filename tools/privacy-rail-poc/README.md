# StealthBridge Privacy Rail PoC (`tools/privacy-rail-poc`)

Standalone Cargo workspace (`soroban-sdk = 28.0.0`) built for **Milestone 4 — Privacy Rails Engineering**.

Why this crate is isolated from the repository root workspace (`Cargo.toml` at repo root uses `soroban-sdk = "=27.0.6"`):
- StealthBridge's deployed governance contracts (`corridor-registry`, `policy-registry`, `governance-gate`) target Soroban SDK `27.0.6`.
- Upstream privacy systems (`OpenZeppelin/stellar-contracts v0.8.0` Confidential Tokens and `NethermindEth/stellar-private-payments`) require Soroban SDK `28.0.0` (UltraHonk Keccak verifier, BN254 pairing host functions, Poseidon2 host support) and remain un-audited developer-preview software.
- Keeping this evaluation crate in its own workspace prevents third-party protocol dependencies from polluting or altering the production-locked governance workspace while enabling deterministic Soroban `Env` proof verification, Pedersen conservation checks, Merkle root-history eviction, and adversarial testing.

## Run tests

```bash
cargo test --locked
```

(If `Cargo.lock` is first generated on this host: `cargo test --offline`.)
