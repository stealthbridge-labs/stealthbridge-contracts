<div align="center"><img src="assets/stealthbridge-logo.svg" alt="StealthBridge — Confidential payments. Without borders." width="760" /></div>

# StealthBridge — Soroban Protocol & Smart Accounts

**Rust/Soroban governance and independently verified building blocks for a future privacy-conscious cross-border payment system.**

[Product](https://stealthbridge.vercel.app) · [Protocol architecture](docs/ARCHITECTURE-AND-DELIVERY.md) · [Privacy release gates](docs/PRIVACY-RELEASE-GATES.md) · [Roadmap](ROADMAP.md)

## Deployed versus implemented

Three **public governance contracts** were independently verified on **Stellar Testnet on October 17, 2026**:

| Governance contract | Responsibility |
| --- | --- |
| `CorridorRegistry` | Operator-controlled public corridor configuration, revocation and pause |
| `PolicyRegistry` | Revisioned public policy commitments and effective-state checks |
| `GovernanceGate` | Fail-closed, bounded cross-registry governance reads |

Their exact contract addresses, transaction receipts, hash evidence and administrator at deployment are in the [reviewed Testnet deployment record](deployments/testnet/VERIFIED-GOVERNANCE-RELEASE-2026-10-17.md) and [machine-readable evidence](deployments/testnet/governance-deployment-evidence.v2.json). Addresses and signing identities **belong in restricted operator/release documentation, not customer-facing product pages**.

**Critical version distinction:** the source workspace has since added public, digest-bound and batch governance methods. A source-level Rust test or rebuilt WASM is **not evidence those newer methods were deployed** to the historical instances. The legacy canonical `deployments/testnet/manifest.json` still records an older `not-deployed` integration format: it is **outdated as an integration manifest, not an assertion about the three observed governance instances**. Do not use it to authorize contract operations.

**The contracts do not custody funds, prove transaction confidentiality, execute transfers, collect platform fees, or provide bank payouts.**

## What the source repository contains

```text
contracts/
  corridor-registry/    public route governance and administrator controls
  policy-registry/      effective commitment/revision and pause controls
  governance-gate/      cross-contract gate checks; max-eight batch reads
  settlement-adapter/  placeholder, no deployed or enabled settlement path
integrations/
  confidential-tokens/         upstream issuer-privacy research, NO-GO
  stellar-private-payments/    relationship-privacy verification research
tools/
  smart-account-preflight/    read-only pinned Stellar Testnet WASM/policy checks
deployments/testnet/           governance release receipts and historical evidence
docs/                          threat models, ADRs, privacy and recovery gates
```

Other `apps/`, `services/` and `packages/` folders include **legacy scaffolding placeholders**. The active user-facing product, server, and SDK are maintained in **separate repositories**. Do not treat a placeholder folder as a production service.

Read the [Rust-first Soroban architecture](docs/RUST-FIRST-SOROBAN.md), [implementation guide](docs/IMPLEMENTATION-GUIDE.md), [public source ABI inventory](integrations/public-soroban-interface.v1.json), and [governance edge tests](docs/BATCH-GOVERNANCE-EDGE-TESTS.md).

## Build and verify the on-chain source

The repository pins Rust **1.91.0**, Soroban SDK **27.0.6**, Stellar CLI **27.1.0** and the `wasm32v1-none` target at a protocol-27 baseline. Check current Testnet protocol compatibility before any new deployment; upstream private-asset libraries may require newer toolchains and are **not automatically composable**.

```bash
rustup target add wasm32v1-none
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked --target wasm32v1-none --release
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/verify_artifacts.py
python3 scripts/validate_manifest.py
```

Source tests, deterministic builds and ABI manifests **do not prove deployed Testnet compatibility**. On-chain evidence must be independently refreshed for the exact contract ID, ledger, code hash, storage/TTL and administrator policy. Never sign transactions merely because preflight scripts pass.

## Smart accounts: reviewed read-only preflight

The Testnet Smart Account Kit/OpenZeppelin pinned-artifact verifier checks live public **account WASM bytes/hash**, **WebAuthn verifier**, **threshold policy**, **spending-limit policy**, Testnet identity, the authorization digest scheme and **remaining ledger TTL**. No customer smart account is currently deployed through StealthBridge by this tool.

```bash
cd tools/smart-account-preflight
npm ci
npm test
npm run verify:testnet
```

A green preflight can still report `ttlExtensionReviewRequired: true` and `canDeployCustomerWallet: false`. TTL readings change with the live ledger, so **do not trust a historic TTL amount**. The tool never reads the local operator signing identity, installs passkeys, extends TTL or broadcasts a transaction.

[Smart-account release plan](docs/CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md) · [Read-only preflight instructions](tools/smart-account-preflight/README.md) · [Wallet/privacy integration](docs/WALLET-SMART-ACCOUNT-AND-PRIVACY-INTEGRATION.md).

### Still unverified before a customer wallet

WebAuthn relying-party/domain binding; actual passkey enrollment and second-device recovery; signer/session limits; anti-replay; delegated authorization; relayer policies; key loss and custody model; authorized TTL restoration; real asset transfer simulation; independently reviewed on-chain deployment.

Do not extend storage TTL or deploy accounts automatically in CI. Both actions require an explicit reviewed on-chain operation.

## Confidentiality research

StealthBridge Business seeks **confidential commercial amounts with accountable counterparties**. StealthBridge Send seeks stronger **sender–recipient relationship privacy**. These are different threat models and cannot be promised from a public registry, network passphrase, or existence of a ZK library.

- [Confidential Tokens research](integrations/confidential-tokens/README.md): issuer controls, auditor disclosure and amount confidentiality; status **NO-GO** for deployment without proven compatibility and issuer relationship.
- [Stellar Private Payments verification](integrations/stellar-private-payments/VERIFICATION-GATES.md): independent proof/commitment/nullifier, address and metadata leakage, recovery and replay checks.
- [Independent privacy reproduction](docs/INDEPENDENT-PRIVACY-REPRODUCTION-29-31.md): negative/positive tests and on-chain evidence.
- [Privacy release gates](docs/PRIVACY-RELEASE-GATES.md): fail-closed requirements for any private financial execution.

There is no verified live privacy asset, no supported issuer/payout corridor and no reviewed platform fee collector. Operator or governance authority alone cannot enable these.

## Cross-repository product integration

```text
Next.js customer app ── same-origin API → Rust/Axum backend → Stellar RPC + Neon
   ├─ Personal / Send: real public route and recipient planning
   ├─ Business: real pending applications, memberships, invitations, local drafts
   └─ no signing / funding / payout execution
TypeScript SDK: reviewed, bounded API response validation
Three Soroban governance contracts: separately deployed public control plane
Future: audited issuer/settlement/privacy execution, with explicit release approval
```

The customer app's signed-message login is not a Soroban smart-account deployment or authorization for asset movement. The current backend profile and organization records are off-chain application data, **not cryptographically private ledger records**.

### Where to go next

1. Maintain reproducible source and deployed-code parity for the three governance contracts.
2. Validate full smart-account lifecycle on isolated Testnet accounts with explicit signing consent and secure recovery.
3. Independently reproduce privacy and regulated issuer/accountability requirements.
4. Implement verified, rate/fee-bounded and reconciled on-chain/provider execution only after external review.

[Frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend) · [Backend](https://github.com/stealthbridge-labs/stealthbridge-backend) · [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

**Public governance is deployed on Testnet. Private money movement is not.**
