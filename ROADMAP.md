# StealthBridge Protocol & Soroban — Comprehensive Roadmap

> **Engineering status: active, Testnet-first development.** This is a living implementation roadmap, not a feature announcement. No real funds, fabricated corridors, invented prices, alleged issuer partnerships or unsupported privacy guarantees. Work is complete only when code, tests, interface documentation and verifiable operational evidence exist.

**Cross-repository contract:** [Frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend/blob/main/ROADMAP.md) · [Backend](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/ROADMAP.md) · [Contracts](https://github.com/stealthbridge-labs/stealthbridge-contracts/blob/main/ROADMAP.md) · [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk/blob/main/ROADMAP.md)

## Protocol charter

Deliver a small set of independently validated Soroban contracts and adapters capable of supporting corridor eligibility, issuer-controlled confidential assets, selective disclosure and secure settlement interactions. Contract complexity is a liability: prefer vetted upstream primitives over copying or inventing cryptographic implementations. Contracts must never publish plaintext protected values or unintentionally link shielded parties through event topics.

## Current baseline

- Soroban Rust workspace and a privileged, Testnet-oriented public corridor registry prototype.
- Auth and TTL test foundation, WASM build CI, privacy feasibility matrix, threat model and empty testnet deployment manifest.
- No confidential token, private payment, issuer contract, custody contract or fund-moving settlement contract has been deployed by StealthBridge.

## Corridor and governance registry

Make the registry production-reviewable with admin rotation through proposal/acceptance, emergency pause, consistent TTL handling, getter APIs and robust authorization tests. Decide what a corridor identifier means (opaque ID vs public country/asset pair), minimum disclosure on-chain, storage lifetime and off-chain mapping ownership. Enforce authorization for *every* state mutation; design timelocked or multi-approval roles for later use. Reject permanent "root" assumptions and document contract upgrade authority, version rollout and protected data boundaries. An enabled corridor is a governance flag, **not** evidence of real payout eligibility or liquidity.

## Confidential Tokens feasibility and issuer controls

Pin the current supported OpenZeppelin/issuer-controlled confidential-token dependencies. On Stellar Testnet, verify deployments and actual transfers using disposable authorized test accounts only. Trace visible addresses, hidden balance/amount commitments, proof generation and verification costs, issuer restrictions and auditor disclosure capabilities. Analyze who can mint/burn, freeze/revoke, upgrade, reveal via viewing keys, and redeem underlying assets; express these as independent access-controlled contracts only if the upstream primitive permits safe composition. Do not assert real USDC compatibility or issuer endorsement merely because the chain supports stablecoins.

## Stellar Private Payments feasibility

Separately validate the supported alpha shield/deposit/private-transfer/withdraw flow using published testnet assets/pools, including user wallet signing, note encryption and recovery, nullifier uniqueness, merkle inclusion, proving latency, public edge correlations and witness leakage threats. Document the pool contract, prover, CLI, SDK version, asset precision, anonymity set and on-chain observability before writing an integration adapter. Establish proof-public-input binding to network, contract, asset, nullifier and authorized recipient. Test invalid proofs, double spends and reorg/retry handling. Keep relationship-private and amount-private designs distinct.

## Policy, compliance and selective disclosure

Define an enforceable policy model for account controls, issuer allow/block restrictions, per-operation limits where amounts are encrypted, protected allowlists, proof-of-eligibility, disclosure/auditor permissions and revocation without accidentally publishing sender/recipient identity. Evaluate whether policy attestations can be checked cryptographically on-chain or must remain governed off-chain with auditable commitments. Avoid describing policy checks as zero-knowledge unless the circuit and witness/statement relationship are independently verified.

## Settlement verification and asset accounting

Only after primitive compatibility is proven should the protocol expose settle/finalize/refund contracts. Define preconditions, replay domains, escrow trust and custody model, reentrancy/cross-contract calls, asset decimal conversion, expiration and fee accounting. A chain contract cannot guarantee a fiat payout. Verify invariant-preserving state transitions across Stellar RPC history limits, failed calls and refund paths. All proof verifier upgrades need explicit regression vectors and immutable test evidence.

## Deployment, versioning and ABI release engineering

Pin Rust toolchain, Stellar CLI, Soroban SDK matching network protocol, optimized WASM flags, security/lint rules, ABI/WASM checksums and reproducible artifact generation. Maintain canonical signed/declarative per-network manifests with real deployed contract IDs, asset issuers, transaction hashes, protocol version, code hash, operator approval and upgrade histories. No fabricated IDs, secret keys, automated mainnet deployments or unexplained ad-hoc storage changes. Generate SDK bindings against **actual released WASM** after testnet verification; use compatibility tags, interface-change ADRs and migration notes.

## Formal and adversarial assurance

Coverage includes negative admin auth, two-step ownership transfer, pause/unpause, storage TTL/restore, invariants after upgrade, malformed identifiers, contract-to-contract auth, token decimal edge cases, proof substitution, replay, nullifier reuse, multiple ledgers, storage exhaustion, resource fee bounds and attack-driven fuzz/property tests. Produce an auditor-oriented threat model and specify what third parties can infer from accounts, events, commitments and timing. Commission independent audit before mainnet consideration; never call a tested prototype audited.

## Stablecoin and cross-chain extensibility

Design issuer-controlled stablecoin interfaces with explicit mint/redeem reserve responsibility, sanctions/freeze governance, viewing authorities and eligibility. CCTP and other cross-chain paths are separate, later integrations requiring finality assumptions, attestation, decimal conversion and economic failure handling, not automatic extensions of Stellar settlement. Research DeFindex liquidity only if a real corridor business need exists; don't add a vault dependency as decorative infrastructure.

## Milestones, evidence and dependencies

Public deliverables: Rust tests and CI, reproducible Testnet transfer notebooks, field-level disclosure matrix, contracts/ABI manifest, wallet integration evidence, malicious-proof vectors, storage and rent cost reports, upgrade governance ADR and source-to-WASM reproducibility. Contracts depend on [backend](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/ROADMAP.md) policy APIs and [SDK](https://github.com/stealthbridge-labs/stealthbridge-sdk/blob/main/ROADMAP.md) artifact packaging; UI must not turn on real value flows before independent testnet verification. Contributor issues: [Registry hardening](https://github.com/stealthbridge-labs/stealthbridge-contracts/issues/1) and [Independent privacy verification](https://github.com/stealthbridge-labs/stealthbridge-contracts/issues/2).
