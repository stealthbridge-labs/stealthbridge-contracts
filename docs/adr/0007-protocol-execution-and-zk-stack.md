# ADR-0007: Operational Smart Accounts, ZK Verification, and Controlled Settlement Architecture

- **Status:** Accepted (Architecture Baseline for Phases 3–6)
- **Date:** 2026-11-20
- **Context:** Milestones 1–6 established public Soroban governance registries on Stellar Testnet, Protocol 30 CAP-84 `W...` compatibility across all repositories, isolated evaluations of *Stellar Private Payments* and *Confidential Tokens*, and a PostgreSQL-backed controlled Testnet settlement journal. Transitioning StealthBridge into a complete open-source protocol requires separating immutable governance contracts from operational protocol execution contracts.

---

## Decision

1. **Preserve Locked Governance Registries (`corridor-registry`, `policy-registry`, `governance-gate`):**
   - Keep the existing three governance contracts non-fund-moving and verified by `tools/source-audit.rs` and `tools/release-boundary-audit.rs`. They serve solely as the fail-closed administrative policy/corridor oracle.

2. **Protocol Execution Layer (`settlement-adapter`, `fee-vault`, `privacy-verifier`):**
   - Build deployable execution & verification crates alongside `contracts/governance-gate` without violating read-only governance guarantees:
     - **`settlement-adapter`:** Consumes exact `SettlementExecutionIntent` parameters, checks `GovernanceGate` commitment + revision + unpaused state, validates non-zero amounts/distinct parties/deadline ledgers, prevents reentrancy & receipt replay, and requires verified privacy proofs for shielded rails.
     - **`privacy-verifier` + `NullifierRegistry`:** Uses Soroban Protocol 25+ host cryptographic primitives (`soroban_sdk::crypto`) — specifically BN254 pairing / Poseidon2 hashing or deterministic circuit/VK-bound verification keys — rejecting modified public inputs, wrong circuit/VK versions, expired Merkle roots, and duplicate nullifiers.
     - **`fee-vault`:** Isolates transparent fee accounting behind explicit dual-step admin/beneficiary controls, emergency pause, and timelocked WASM upgrades.

3. **Smart Accounts (`smart-account` integration + P-256 WebAuthn + Recovery):**
   - Build around Soroban custom account authentication (`__check_auth`) + `env.crypto().secp256r1_verify` (passkey/WebAuthn secp256r1) and Ed25519 signers with RP-ID/challenge/domain separation, per-transaction/daily spending policies, session keys with explicit expiry ledgers, and time-locked guardian/second-device recovery.
   - Customer signing keys and WebAuthn private keys always remain user-controlled; the operator key (`operator_local`) is strictly isolated from ordinary customer smart accounts.

4. **Versioned Testnet Deployments & Manifests:**
   - Legacy `deployments/testnet/manifest.json` stays untouched for compatibility. Verified governance deployment uses `governance-deployment-evidence.v2.json`. New Testnet deployments of execution/verifier/smart-account contracts record full transaction hashes, contract IDs, WASM SHA-256 hashes, and RPC verification in a versioned `protocol-deployment.v3.json` manifest before backend/SDK wiring.

---

## Consequences

- Contributors can work independently on governance, settlement execution, ZK verifiers, and smart accounts with crystal-clear security boundaries.
- Production Mainnet and fiat payouts remain blocked behind explicit feature flags, external audits, and provider SLAs until Phase 9 sign-off.
