# StealthBridge Policy Registry

A small Soroban configuration contract that stores **public, opaque policy commitments** with monotonically increasing revisions, administrator authorization and an emergency pause.

## Operations

- `__constructor(admin)` — requires admin authorization.
- `admin()` — observes current admin.
- `set_rule(id, record)` — administrator writes an opaque 32-byte commitment, `enabled` flag and **strictly increasing** `revision` to persistent storage.
- `get_rule(id)` — reads the public record.
- `is_effective(id)` — returns false when missing, disabled or paused.
- `set_paused(bool)` and `is_paused()` — administrator-controlled emergency disable.

`true` means only that an administrator enabled a public flag. It is **not evidence of successful KYC, sanctions compliance, issuer authorization, confidential token proof, liquidity or real payouts**. This contract has no money-moving capabilities, no wallet-signing facility and no personal data; contract state and commitments are visible on-chain.

## Build and verify

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo build --target wasm32v1-none --release
```

Both corridor and policy registry crates are in the workspace. CI runs unit, authorization and WASM checks. No deployed address or audited financial controls are claimed. Future protocol ADRs must define who produces commitments and how client/backend policies actually verify them before connecting any settlement logic.
