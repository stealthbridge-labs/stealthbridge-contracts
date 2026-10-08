<div align="center"><img src="assets/stealthbridge-logo.svg" width="760" alt="StealthBridge — Confidential payments. Without borders." /></div>

# StealthBridge Protocol & Smart Contracts

**Engineering roadmap:** [View the repository-specific plan](ROADMAP.md).

**Confidential payments. Without borders.**

[Frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend) · [Backend](https://github.com/stealthbridge-labs/stealthbridge-backend) · [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk)

> **Status:** research-stage Stellar **testnet-only** protocol. One basic Soroban **corridor enablement registry** is present as source code; no contract deployments, proof-verification contracts, or fund-moving settlement primitives are verified.

## What is here?
- \`contracts/corridor-registry\`: minimal authorized corridor enablement example.
- \`docs/PROTOCOL-ARCHITECTURE.md\`: confidentiality vs anonymity, issuer-controlled stablecoins, planned boundaries.
- \`docs/TESTPLAN.md\`: formal verification milestones, no credentials required.
- \`deployments/testnet/manifest.json\`: truthfully empty deployment manifest.
- \`docs/PRIVACY-MODEL.md\`: initial threat model.
- \`docs/REFERENCES.md\`: official developer resources.

## Build & test
The repository pins Rust **1.91.0**, Soroban SDK **27.0.6**, Stellar CLI
**27.1.0**, and the `wasm32v1-none` target (protocol **27** baseline).
Install the CLI from its [official release](https://github.com/stellar/stellar-cli/releases/tag/v27.1.0).
Rustup reads `rust-toolchain.toml` automatically.

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked --target wasm32v1-none --release
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/artifacts.py
python3 scripts/validate_manifest.py
python3 scripts/benchmark.py
```

These commands run locally without signer credentials. CI publishes the WASM,
ABI snapshot, source/tool versions, checksums, and a quantitative resource table.
The artifact script compares two isolated release builds byte-for-byte.
[Verification and benchmark details](docs/REGISTRY-VERIFICATION.md) describe
what is measured and the local test limitations. The checked-in Testnet manifest
remains `not-deployed`: a local build is not evidence of deployment, settlement,
or verified network compatibility. Confirm the target network's protocol before
any separately authorized deployment.

Local verification on macOS ARM64 with the pinned toolchain: seven workspace
unit tests passed, the separate benchmark passed all 22 scenarios, and Clippy
passed with warnings denied. The two isolated corridor WASM builds matched
(6,549 bytes). The authorization/restoration tests use the local SDK host;
real signatures, network restoration fees and deployment remain unverified.

## Architecture
StealthBridge Business targets **confidential amounts with known parties**; StealthBridge Send targets **shielded relationships**. These require separate privacy primitives with different trust and metadata leakage characteristics. The initial registry is intentionally independent of both until testnet composability is proven.

## Prior-art and diligence
Tukar provides a compelling testnet reference for private remittances, proofs and compliance. StealthBridge's proposed differentiators are multi-provider tenancy, modular settlement adapters, B2B confidentiality, stablecoin issuer controls, and public SDK surfaces. These are planned capabilities, not shipped claims.

## Legacy scaffolding
This repo was renamed from the original monorepo. Historical \`apps/\`, \`services/\`, and \`packages/\` placeholders remain until reviewed; **implementation now belongs to the dedicated repositories above**. We preserve content rather than destroying it.

## Safety
No real funds; never commit credentials or witnesses. Review [SECURITY.md](SECURITY.md). License selection and contributor governance will be settled through open development.

## PolicyRegistry — separate governance prototype

The workspace now includes a second Soroban contract: [PolicyRegistry](contracts/policy-registry/README.md). It offers admin-authenticated policy commitment updates, strictly increasing revisions, and a fail-closed global pause. Both contracts are intentionally **public configuration registries**, not custody or ZK settlement solutions.

Refer to [the policy security model](docs/POLICY-REGISTRY.md) and [the comprehensive roadmap](ROADMAP.md). No contract ID or live asset integration is claimed until independently verifiable deployment evidence exists.

## Detailed implementation guide

[Contract implementation guide](docs/IMPLEMENTATION-GUIDE.md) documents both Soroban crates, authorization rules, verification procedures, TTL handling and deployment boundaries.
