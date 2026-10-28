# Atomic, source-only business policy bundle observation

GovernanceGate now exposes all_configurations_current(checks), a pure read-only Soroban ABI. For one to eight business corridor/policy pairs, the gate checks exact approved corridor configuration digests together with current policy revisions and commitments. Every pair must pass in a single ledger invocation for the method to return true.

This avoids misinterpreting a partial batch of individually true/false results as full governance agreement. It fails closed on unknown contracts, paused registries, wrong hashes, expired config approvals, stale revisions and empty or oversized batches. The existing per-row check_config_batch API remains unchanged.

IMPORTANT: This is source-only code. The October 17 Testnet governance deployments do not contain the new method; no upgrade or new deployment has occurred. The method cannot authorize payment, settlement, privacy proofs, issuer controls, compliance checks, fee claiming or fiat payouts.
