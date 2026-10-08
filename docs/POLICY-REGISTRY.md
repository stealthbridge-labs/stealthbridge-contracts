# Protocol policy registry — security and scope

## Why a separate contract?

Administrative policy *configuration* should not be confused with financial value movement, cryptographic validity, issuer controls or private beneficiary verification. The minimal Soroban PolicyRegistry stores only opaque public identifiers, public commitments and flags, and version-enforces updates.

## Security invariants

1. Every mutation requires an authorized administrator.
2. Revision 0 is invalid and every update must strictly increase revision, including re-enablement after a pause.
3. A paused registry returns false from `is_effective`.
4. Absent entries fail closed.
5. Public commitments may still correlate on-chain activity, so do not submit personal data, account links, KYC records, private witnesses or off-chain identity documents.

## Limitations

The contract does not validate the contents of a commitment or satisfy compliance requirements. There is no issuer-specific verifier, role delegation, proof check, rollback governor, Timelock, access recovery or audited upgrade model. These are future carefully reviewed tasks; no actual fund-moving pathways should reference the registry yet.

## Source

[contracts/policy-registry/src/lib.rs](../contracts/policy-registry/src/lib.rs)
