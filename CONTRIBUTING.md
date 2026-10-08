# Contributing to StealthBridge Contracts

**Testnet-only, no real funds.** Read [protocol architecture](docs/RFC-0001-PLATFORM-ARCHITECTURE.md), [threat model](docs/THREAT-MODEL-v0.2.md), and the [privacy feasibility matrix](docs/PRIVACY-FEASIBILITY-MATRIX.md) before coding. Our contributors should not import Tukar's contracts or cryptographic materials without checking license, audits, and protocol security.

## Workflow
1. Select an issue with a bounded scope and state intended approach in a comment.
2. Work on a branch and submit a PR with tests, network/toolchain versions and reproducible observations.
3. Run `cargo test --workspace`; compile for `wasm32v1-none` when changing contracts.
4. Never add secrets, real KYC material, plaintext payment amounts or hidden-note witness to public storage/events.
5. Provide actual explorer evidence before calling a privacy/settlement feature verified.

Avoid contract deployments, issuer onboarding and external signing services without explicit maintainer permission. Legal licensing and mainnet restrictions will be finalized before accepting fund-moving modules.
