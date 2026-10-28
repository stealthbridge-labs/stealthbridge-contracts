# Distinct and atomic business governance metadata reads

all_distinct_configs_current(checks) accepts 1–8 source-level GovernanceConfigCheck objects, rejects repeated corridor IDs, and checks all other exact config digests, policy revisions and commitments within one Soroban invocation. A single failed check returns false. Empty/overlimit batches return InvalidBatchSize.

This avoids treating duplicate routes as independent distinct business policy approvals. It does not inspect CSV, recipients, amounts, tokens, compliance, liquidity or privacy proofs; no transfers are authorized.

This is a source-only method. The October 2026 deployed governance gate does not contain it. There is no automatic WASM upgrade or contract interaction from the frontend batch planner.
