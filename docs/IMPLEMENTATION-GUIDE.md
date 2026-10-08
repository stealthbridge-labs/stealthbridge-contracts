# StealthBridge Soroban — Implementation Guide

## 1. What actually exists

Two separate Soroban governance prototypes live under `contracts/`:

| Contract | Purpose | Public methods |
|---|---|---|
| [CorridorRegistry](../contracts/corridor-registry/README.md) | Enable/disable opaque corridor flags; two-step administrator handover | constructor, get_admin, pending_admin, propose_admin, accept_admin, set_paused, is_paused, set_enabled, is_enabled |
| [PolicyRegistry](../contracts/policy-registry/README.md) | Admin-authenticated public policy commitments with monotonic revisions | constructor, admin, set_paused, is_paused, set_rule, get_rule, is_effective |

**Neither contract holds assets, executes transfers, confirms a bank payout, verifies ZK proofs or checks real-world eligibility.** Both store publicly observable administrative state. The rules should be understood as governance inputs, not confidential-compliance outcomes.

## 2. Local build

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --target wasm32v1-none --release
```

The workspace defines `soroban-sdk = "27"`; protocol/toolchain alignment must be reconfirmed against target network and official tooling before any approved deployment. GitHub Actions covers source tests and WASM compilation.

## 3. Threat boundaries and administrative controls

- Constructor requires initial administrator authorization.
- Corridor changes and policy records require the active administrator's authorization.
- Policy revision 0 is rejected, and updates must increase revision.
- Pause returns false from `is_enabled` or `is_effective` without fabricating eligibility.
- Instance and persistent storage TTLs are extended on relevant writes; storage expiration and restore strategies need operator tests.
- Public commitments may correlate activity. Never put wallets, customer identities, payment notes, decrypted amounts, FX quotes or regulated KYC payloads in contract storage or event topics.
- The CorridorRegistry supports a two-step admin transition; PolicyRegistry currently uses a simpler static administrator. This difference is intentional for a research prototype and must be addressed before broader governance.

## 4. Compatibility and deployments

The repository's [Testnet manifest](../deployments/testnet/manifest.json) intentionally declares no deployments. Contract addresses, issuer IDs, transaction hashes and proof verifications must come from actual approved chain activity and be independently reproduced. The SDK reads only validated manifest shapes and cannot create an address by guessing.

When introducing an ABI change, update this repository's contract docs and source, build checksum and actual deployment manifest (when available), backend capability checks, and SDK bindings together. No unaudited assumptions about composability of Confidential Tokens and Stellar Private Payments.

## 5. What remains

Zero-knowledge protocol feasibility, issuer-controlled token policy, real authorization, replay proofs, note storage/recovery, settlement/refund invariants, timelock/multisig governance, audit, upgrade policy, cost profiling, legitimate stablecoin and fiat partnerships. See [the roadmap](../ROADMAP.md), [threat model](THREAT-MODEL-v0.2.md), and [privacy feasibility matrix](PRIVACY-FEASIBILITY-MATRIX.md).

## Recent governance hardening

The PolicyRegistry now supports a **two-phase administrator transfer**, with `propose_admin(successor)`, `pending_admin()`, `cancel_admin_proposal()` and `accept_admin()`. The current administrator authorizes nomination/cancellation; the nominated account must authorize acceptance. Pending nominations confer no administration until accepted. Both registry contracts reject empty or overlong (more than 128-byte) opaque rule/corridor identifiers on writes and fail closed on invalid read identifiers. The policy's public commitment is **not** a verified user eligibility or ZK-proof check.
