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
Prerequisites: Rust 1.84+, \`wasm32v1-none\` target, Stellar CLI version matching testnet protocol.
\`\`\`sh
cargo test --workspace
stellar contract build
\`\`\`
Verify actual versions before relying on the current \`soroban-sdk = "27"\` workspace baseline.

## Architecture
StealthBridge Business targets **confidential amounts with known parties**; StealthBridge Send targets **shielded relationships**. These require separate privacy primitives with different trust and metadata leakage characteristics. The initial registry is intentionally independent of both until testnet composability is proven.

## Prior-art and diligence
Tukar provides a compelling testnet reference for private remittances, proofs and compliance. StealthBridge's proposed differentiators are multi-provider tenancy, modular settlement adapters, B2B confidentiality, stablecoin issuer controls, and public SDK surfaces. These are planned capabilities, not shipped claims.

## Legacy scaffolding
This repo was renamed from the original monorepo. Historical \`apps/\`, \`services/\`, and \`packages/\` placeholders remain until reviewed; **implementation now belongs to the dedicated repositories above**. We preserve content rather than destroying it.

## Safety
No real funds; never commit credentials or witnesses. Review [SECURITY.md](SECURITY.md). License selection and contributor governance will be settled through open development.
