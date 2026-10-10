# Governance gate — Soroban read-only cross-registry adapter

The governance gate is an actual Rust/Soroban contract that **reads** the
`corridor-registry` and `policy-registry` sources using Soroban
cross-contract invocations. Its constructor immutably binds the admin and
registry addresses; the admin must authorize deployment.

`public_flags_allow(corridor, policy)` returns **true** only when the
bound corridor registry's `is_enabled` and policy registry's `is_effective`
both return `true`. Missing, paused, expired, incompatible or panicking
registry calls yield **false**. Empty IDs or IDs exceeding 128 bytes are
rejected as false. The contract exposes its recorded dependency addresses
for operator audit but has **no post-constructor writes**, wallet balances,
asset transfers, fiat instructions, account enrollment, proofs or admin
override of the combined result.

**Security limitation:** `true` means *public governance flags only*. It
does not verify any privacy proof, real asset issuer, settlement, compliance
eligibility, liquidity, wallet identity, payment signature or regulatory
permission. Backends and frontends must never infer financial capability
from this result.

Tests use the **actual two workspace registry implementations** with
multi-contract cross-calls. They verify both flags, emergency pauses,
revocation, unconfigured dependency failure and invalid identifiers.

The checked-in Testnet deployment manifest remains `not-deployed`. Before
deploying this contract, the two dependencies must be independently
deployed and verified, along with their addresses, source and WASM hashes.
The constructor's dependency addresses must then be attested. No wallet or
HTTP API may sign transactions based on this source-only method inventory.

## Revision-bound decisions in Rust

The gate also offers two strictly read-only methods:

```rust
// Soroban contract public interface (illustrative method calls only).
public_flags_allow_commitment(corridor, policy, expected_revision, expected_commitment)
check_commitment_batch(checks)  // 1 to 8 GovernanceCheck items
```

`public_flags_allow_commitment` requires the enabled corridor AND the
policy registry's exact current revision and public `BytesN<32>`
commitment. Upgrading the policy invalidates a previous commitment check:
callers must consciously re-evaluate the new revision and digest. A matching
digest is not a zero-knowledge proof, human approval or fiat settlement
permission.

`check_commitment_batch` performs at most eight independent,
ordered cross-registry decisions. An empty or oversized batch returns
`GateError::InvalidBatchSize` instead of silently trying unbounded work.
Individual missing, expired, disabled or paused entries yield `false`.
The method has **no write authority or signer requirement**. Tests exercise
stale/substituted hashes, disabling and pausing, mixed batch results and
unbounded-request rejection.

The source-only ABI is published for future independently attested deployments,
but the existing backend/frontend/SDK continue to use the last approved
read-only interface revision until an explicitly reviewed cross-repository
release updates the compatibility pin. Nothing here is deployed or enables funds.
