# corridor-registry

Placeholder for Sprint 0 architecture and feasibility research. No production implementation exists yet.

## Registry methods and governance (v0.2)

- `__constructor(admin)`: initial admin must authorize, state stored on instance.
- `get_admin()`: current administrator.
- `pending_admin()`: proposed successor, if any.
- `propose_admin(new_admin)`: current admin authorizes nomination.
- `accept_admin()`: nominee authorizes final control handover.
- `set_paused(bool)` / `is_paused()`: emergency governance pause. The public `is_enabled` returns false while paused.
- `set_enabled(opaque_corridor_id, bool)` / `is_enabled(...)`: public governance-only enablement flag. Data is stored persistently with TTL renewal.

**Important:** registry enablement does not guarantee supported fiat corridors, liquidity, policy eligibility, stablecoin issuer acceptance or a working private payment integration. The current contract holds no financial amounts, payment identities or sensitive notes. Deployed contract IDs remain absent until an approved and verified Testnet deployment.

Tests cover authorized configuration, two-step admin rotation, emergency pause behavior and unauthenticated mutations. See the [protocol roadmap](../../ROADMAP.md) for upgrade governance, contract proof checks and audit gates.

Scoped authorization, TTL boundary/restoration-model tests, reproducible artifacts,
and resource benchmarks are documented in [registry verification](../../docs/REGISTRY-VERIFICATION.md).
No application events are emitted. Arguments and storage are public; never use
participant or private-payment identifiers as corridor IDs.

Opaque corridor IDs are constrained to 1–128 bytes. Invalid identifiers cannot be enabled; an invalid read is treated as disabled, never enabled.

## Emergency governance improvements

The corridor registry now permits the currently authorized administrator to cancel a pending successor nomination before acceptance with `cancel_admin_proposal()`. Cancellation never gives the nominee active privileges and is covered by scoped authorization tests. If the instance pause flag is missing or unavailable, `is_paused()` now defaults to **true**, so corridor status fails closed rather than implying eligibility. This is a safety invariant, not proof of real financial corridor availability.

## Time-bounded public configuration approval (Rust/Soroban)

The Rust registry now supports `approve_config(corridor, config_digest,
expires_at_ledger)` and `is_enabled_with_digest(corridor,
expected_digest)` in addition to its original enabled flag.

- An authorized administrator may approve an **already enabled** corridor
  by committing to a public `BytesN<32>` configuration digest and a
  ledger-sequence expiry. The expiry must be in the future and no more
  than 100,000 ledger sequences away at the time of approval.
- A strict read accepts only the active public flag, the exact digest,
  and an approval not past its ledger expiry. Missing records,
  mismatched hashes, disabled entries and paused registries return false.
- Disabling a corridor **deletes its digest approval**. Re-enabling
  it does not restore the old approval: a new admin-reviewed
  `approve_config` invocation is required.
- Approval writes require `require_auth()` through the existing
  administrator path; future ledger horizons, paused/disabled entries
  and malformed corridor identifiers are rejected.

This is a **configuration-fingerprint and freshness control** only.
A matching public digest does not verify a bank, fiat partner, asset
issuer, exchange quote, private witness or liquidity. Tests explicitly
cover revocation, ledger expiry, bad digest, excessive horizon,
pause and unauthorized access. Contracts are **not deployed** yet.
