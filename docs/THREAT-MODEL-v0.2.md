# Threat Model v0.2 — Planning Stage

No adversarial testing or audit has been performed on StealthBridge payment code. This model is a list of properties requiring validation, **not evidence of protection**.

| Threat | Security objective | Proposed defense | Test to produce |
| --- | --- | --- | --- |
| Double spend of shielded note | No second spend accepted | Nullifier uniqueness bound into proof and contract state | Replay same note/proof |
| Proof/public data substitution | Proof cannot authorize different transfer | Contract derives inputs from typed committed data | Tamper recipient/asset/value/root |
| Wrong-network replay | Cross-chain replay fails | Domain separation by chain ID/contract/version | Reuse signed intent across networks |
| Cross-tenant disclosure | No tenant sees another tenant's settlements | Row-level tenant authorization and explicit data-scope checks | API negative tests |
| Compromised signing key | Operator loses minimal authority | Timelock, multisig, scoped roles, rotation | Simulated compromise and pause drill |
| Quote manipulation | No payment settled on invalid/stale quote | Authenticated issuer signature, expiry, min received | Expired/bad signature tests |
| Payout webhook replay | Duplicate callbacks cannot duplicate settlement | Signed webhook, inbox dedup, state machine | Replay callback and concurrency |
| FX rounding | Decimal conversion cannot create or lose value | Scaled integer arithmetic and precision tests | Boundary decimal fixtures |
| Privacy metadata linkage | Hide intended data against stated adversaries | Disclosure matrix, minimization, timing analysis | Observe explorers/RPC/logs |
| Note loss | Receiver can recover safely without central wallet custody | Verified backup/recovery mechanism | Recovery scenario test |
| Issuer censorship/control | Admin powers explicit, accountable and limited | Policy governance, scoped restrictions, audit | Admin permission tests |
| Denial of service | Failure isolation under pressure | Rate-limits, queues, timeout, circuit breakers | Load/fault-injection tests |

Privacy protocols require a specific anonymity set and threat model. Hidden sender/receiver does **not** imply anonymous fiat cash-out. Auditors/regulators may lawfully obtain financial-provider records.

## Sensitive material classification
**Never log:** private keys, spend keys, recovery seed, decrypted note, proof witness, raw KYC record.
**Restricted:** signed quotes, partner screening outcomes, internal payment identifiers, compliance case evidence.
**Public:** contract ID, network, version, explicit demo corridor identifier, published policy hash where safe.
**Unknown until inspected:** contract events, calldata, encrypted note metadata, observer timing in Confidential Tokens/SPP.

## Go/no-go
No mainnet value custody, issuer launch, real remittance, promotional privacy guarantee, or Drips financial distribution until tests, controls, and responsible maintenance contacts exist.
