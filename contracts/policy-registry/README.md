# StealthBridge Policy Registry

A small Soroban configuration contract that stores **public, opaque policy commitments** with monotonically increasing revisions, administrator authorization and an emergency pause.

## Operations

- `__constructor(admin)` — requires admin authorization.
- `admin()` — observes current admin.
- `set_rule(id, record)` — administrator writes an opaque 32-byte commitment, `enabled` flag and **strictly increasing** `revision` to persistent storage.
- `get_rule(id)` — reads the public record.
- `is_effective(id)` — returns false when missing, disabled or paused.
- `is_effective_commitment(id, expected_revision, expected_commitment)` — returns true only for the exact **current, enabled revision and public 32-byte commitment**. Missing, paused, revoked, stale or substituted policy versions fail closed. This compares public governance metadata only; it does not validate a privacy witness.

- `set_paused(bool)` and `is_paused()` — administrator-controlled emergency disable.

`true` means only that an administrator enabled a public flag. It is **not evidence of successful KYC, sanctions compliance, issuer authorization, confidential token proof, liquidity or real payouts**. This contract has no money-moving capabilities, no wallet-signing facility and no personal data; contract state and commitments are visible on-chain.

## Build and verify

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo build --target wasm32v1-none --release
```

The workspace builds corridor registry, policy registry and governance gate as distinct Rust/Soroban crates. CI runs unit, authorization and WASM checks. No deployed address or audited financial controls are claimed. Future protocol ADRs must define who produces commitments and how client/backend policies actually verify them before connecting any settlement logic.

## Recent governance hardening

The PolicyRegistry now supports a **two-phase administrator transfer**, with `propose_admin(successor)`, `pending_admin()`, `cancel_admin_proposal()` and `accept_admin()`. The current administrator authorizes nomination/cancellation; the nominated account must authorize acceptance. Pending nominations confer no administration until accepted. Both registry contracts reject empty or overlong (more than 128-byte) opaque rule/corridor identifiers on writes and fail closed on invalid read identifiers. The policy's public commitment is **not** a verified user eligibility or ZK-proof check.

## Revision and commitment test coverage

Native Soroban tests exercise wrong commitment bytes, zero/future/stale revisions, policy replacement, emergency pause, revocation and cross-registry reads. A public policy commitment must be generated from an independently reviewed policy statement; it is **not proof that anyone complied** with that statement.
