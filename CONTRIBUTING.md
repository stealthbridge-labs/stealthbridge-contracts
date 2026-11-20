# Contributing to StealthBridge Contracts

Welcome to `stealthbridge-contracts`, the Stellar/Soroban smart-contract, Zero-Knowledge verifier, and Smart Account protocol repository for StealthBridge.

> **Testnet engineering policy:** Never commit operator secret keys, mnemonic phrases, shielded spend notes, ZK witness values, or live customer/KYC data. Never deploy to Mainnet or claim on-chain readiness without verifiable Testnet transaction and WASM-hash evidence.

---

## 1. Repository Responsibility & Architecture

Inspect these foundational references before modifying contracts:
- [Cross-Repository Integration Map](docs/CROSS-REPO-INTEGRATION-MAP.md)
- [Platform Architecture RFC](docs/RFC-0001-PLATFORM-ARCHITECTURE.md) & [ADR-0007: Protocol Execution & ZK Stack](docs/adr/0007-protocol-execution-and-zk-stack.md)
- [Threat Model](docs/THREAT-MODEL-v0.2.md) & [Privacy Feasibility Matrix](docs/PRIVACY-FEASIBILITY-MATRIX.md)
- [Verified Testnet Governance Release](deployments/testnet/VERIFIED-GOVERNANCE-RELEASE-2026-10-17.md)

Directory ownership:
- `contracts/corridor-registry`, `contracts/policy-registry`, `contracts/governance-gate` — non-fund-moving public governance control plane (`soroban-sdk = 27.0.6`). Protected by native Rust audits in `tools/source-audit.rs` and `tools/release-boundary-audit.rs`.
- `contracts/settlement-adapter`, `contracts/fee-vault` — governance-gated execution, fee vault, and replay-protection contracts.
- `tools/smart-account-preflight` — pinned Smart Account Kit inspection & recovery tooling.
- `tools/privacy-rail-poc` — reproducible privacy rail evaluation harness (`private-payments`, `confidential-token`).
- `scripts/` — deterministic WASM/ABI artifact checks, manifest checks, and Python unit tests.

---

## 2. Local Development Setup

### Prerequisites
- Rust toolchain (`rustup target add wasm32v1-none`, `rustfmt`, `clippy`)
- Node.js `>= 22` (for `tools/smart-account-preflight`)
- Python `>= 3.11`
- Stellar CLI (`v27.1.0` pinned for reproducible artifact checks)

### Verify Baseline Checks

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked --target wasm32v1-none --release

# Standalone contract workspaces
(cd contracts/settlement-adapter && cargo test --locked)
(cd tools/privacy-rail-poc && cargo test --locked)
(cd tools/smart-account-preflight && npm ci --ignore-scripts && npm test)

# Source audits and Python gates
rustc --edition=2021 -D warnings tools/source-audit.rs -o /tmp/sa && /tmp/sa
rustc --edition=2021 --test -D warnings tools/release-boundary-audit.rs -o /tmp/rba && /tmp/rba
python3 -m unittest discover -s scripts -p 'test_*.py'
```

---

## 3. Practical Contributor Walkthroughs

### How to Add or Extend a Soroban Protocol Contract
1. **Pick the right crate:** Keep the three governance contracts strictly non-financial (`release-boundary-audit.rs` enforces this). Add execution, verification, or account logic inside `contracts/settlement-adapter`, `contracts/fee-vault`, or a dedicated crate.
2. **Design fail-closed boundaries:** Enforce explicit `require_auth()`, TTL extension thresholds (`extend_ttl`), monotonic revisions, zero-digest checks, and reentrancy/replay guards.
3. **Write adversarial host tests:** Test invalid inputs, unauthorized callers, expired ledgers, replay attempts, and pause states under `soroban-sdk` `testutils`.
4. **Build `wasm32v1-none`:** Compile `--release --target wasm32v1-none` and record ABI/WASM SHA-256 checksums before submitting any Testnet deployment PR.

### How to Extend a Privacy Proof or Evaluator
1. Inspect [MILESTONE-4-PRIVACY-RAILS-EVALUATION.md](docs/MILESTONE-4-PRIVACY-RAILS-EVALUATION.md) and `tools/privacy-rail-poc/src/`.
2. Separate personal relationship privacy (`private-payments` commitments/nullifiers) from commercial amount confidentiality (`confidential-token` Pedersen/auditor scope).
3. Add deterministic negative vectors (tampered public inputs, duplicate nullifiers, wrong asset, expired root) alongside positive proof fixtures. Never reuse upstream third-party code without recording its license in `THIRD_PARTY_ATTRIBUTION.md`.

---

## 4. Security-Sensitive Review Rules

- Never label changes to ZK verifiers, smart-account signers/recovery, governance admin handover, or fund movement as `good first issue`.
- All cryptography, auth, and fund-release PRs require an ADR under `docs/adr/`, adversarial tests, and explicit maintainer security review.
- Coordinate API/contract ABI changes with [`stealthbridge-backend`](https://github.com/stealthbridge-labs/stealthbridge-backend) and [`stealthbridge-sdk`](https://github.com/stealthbridge-labs/stealthbridge-sdk). See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).
