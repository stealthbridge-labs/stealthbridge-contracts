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
