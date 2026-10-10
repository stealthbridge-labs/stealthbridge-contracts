# Rust-first Soroban implementation policy

**StealthBridge smart contracts are Rust compiled to Soroban WASM.** Python files in this repository are off-chain developer tooling and must never contain a substitute implementation of the protocol, financial settlement, proof verification, wallet custody or administrator authorizations.

## Why GitHub shows Python

The repository historically accumulated standalone scripts in `scripts/` for CLI artifact creation, isolated reproducible build checks, manifest consistency, Testnet preflight, bytecode inspection, benchmarking, and their negative tests. Counting source files makes Python unusually visible, despite **all on-chain methods living in the Rust crates under `contracts/`**.

A language chart can count tooling and fixtures; it is not an accurate diagram of the code that executes in Stellar validators. To keep code ownership unambiguous:

| Layer | Language | Where | Runtime |
| --- | --- | --- | --- |
| Soroban corridor registry | Rust / `#![no_std]` | `contracts/corridor-registry/src/` | Compiled to Stellar WASM |
| Soroban public policy registry | Rust / `#![no_std]` | `contracts/policy-registry/src/` | Compiled to Stellar WASM |
| Soroban cross-registry governance | Rust / `#![no_std]` | `contracts/governance-gate/src/` | Compiled to Stellar WASM |
| Contract integration/authentication tests | Rust / Soroban testutils | `contracts/**/src/tests.rs` | Native test host, not on-chain |
| Source security audit | **Native Rust** / std | `tools/source-audit.rs` | CI on Linux; not deployed |
| Build, local provenance and operator preflight | Python (temporary off-chain tooling) | `scripts/` | Maintainer workstation / CI; never on-chain |

## Current implemented Rust features

- Corridor registry: administrator-gated public flags; two-step admin transition; emergency stop; persistent storage TTL; invalid-identifier rejection.
- Policy registry: monotonically increasing public `PolicyRecord` revisions, opaque 32-byte **public** commitment, administrator auth and revocation. `is_effective_commitment(id, expected_revision, expected_commitment)` now rejects stale versions and substituted commitments.
- Governance gate: immutable references to approved registry addresses, fail-closed Soroban cross-contract reads, public `public_flags_allow`, stricter `public_flags_allow_commitment`, and `check_commitment_batch` limited to **eight public checks per call**.
- Adversarial Rust tests: missing registries, disabled/paused flags, bad identifiers, stale commitment/revision, admin handover, TTL, malformed inputs and oversized work requests.
- Rust CI source audit compiles directly with `rustc` using **no third-party packages**, and checks high-risk method signatures plus forbidden privilege drift.

None of these public governance reads proves an asset issuer, regulated corridor, private ZK witness, liquidity, fiat partner or permission to transfer. No deployed Testnet contract address is claimed.

## Tooling direction

We will keep **contract behavior and its security tests in Rust**, including authorization, state transitions, on-chain interactions, failures, fees and TTL. New smart-contract features belong in Rust crates, not `scripts/`.

Migration sequence for off-chain support:
1. Source-signature and privilege audit in native Rust (implemented in `tools/source-audit.rs`). Retain JSON structural parity checks until equally strict native replacement exists.
2. Move high-value artifact/ABI provenance and verification into a native Rust `xtask` or release tool with a pinned lockfile and parity tests. Do **not** weaken cryptographic digest validation merely to remove Python.
3. Move relevant benchmarks into Rust Soroban cost/testing harnesses so measurements include actual host and WASM behavior. Keep Python result formatting only when needed.
4. Preserve strictly operator-controlled, non-signing network preflight and independent on-chain attestation tooling; security correctness takes priority over language percentages.

This is a direction, not a claim that every Python helper was removed today. The reproducible WASM pipeline and hash checks must remain green during migration.

## Do not implement these prematurely

- Unverified privacy circuits, wallet seed custody or plaintext payment details on-chain.
- A settlement/transfer method merely to increase Rust code volume.
- Any automatic Testnet signing or deployment in GitHub Actions.
- A fake value-moving path inferred from `public_flags_allow_commitment=true`.

**Release evidence:** `cargo fmt --all -- --check`, `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, reproducible three-contract WASM/ABI build hashes, and independent deployment verification after operator-approved on-chain installation.

See [the full Soroban architecture](ARCHITECTURE-AND-DELIVERY.md), [operator Testnet deployment](../deployments/testnet/OPERATOR-DEPLOYMENT-RUNBOOK.md), and [source ABI](../integrations/public-soroban-interface.v1.json).
