# Product Requirements — Draft v0.1

## Vision
Enable businesses and individuals to move value across borders with confidential on-chain payment information while preserving auditable, policy-governed operations.

## Product lines
### Business
- User: authorized finance operator of a payment provider or enterprise.
- Job: settle a cross-border obligation without publicly disclosing the amount.
- Expected confidentiality: amount and balances; institutional counterparties may remain observable.
- MVP: register parties, configure a corridor, approve a quote, authorize and execute a testnet settlement, track finality, export a privacy-aware receipt.

### Send
- User: an individual sender and a designated recipient.
- Job: send funds across a corridor without exposing the transfer amount or a link between sender and recipient on-chain.
- Expected confidentiality: amount and payment relationship for the shielded leg; deposit/withdraw and fiat edges may remain public.
- MVP: testnet onboarding, shielding, transfer, receipt/claim, and simulated payout.

## Shared domain
- Corridor: country pair + source and destination asset + allowed payment rail + policy profile.
- Quote: expiring, uniquely identified pricing proposal with source, destination, fee, minimum received and issuer.
- Settlement: durable lifecycle with idempotent API initiation and reconciliation across chain and payout legs.
- Policy: permissions, limits, risk flags and documented compliance outcomes. No claim that on-chain privacy eliminates KYC/AML.

## First demonstrator
Nigeria → Kenya using **testnet-issued demo tokens** and mock NGN/KES cash-in/out providers. No real fiat settlement, no production USDC, no licensed-provider representation.

## Acceptance criteria
- Complete one B2B testnet transfer using the selected supported confidential protocol with evidence of what ledger observers can and cannot see.
- Complete one consumer testnet remittance using a separate relationship-hiding integration, if feasibility gate passes.
- Reject repeated idempotency keys with mismatched request payloads.
- Distinguish `onchain_finalized` and `payout_completed` in all status displays.
- Prove refunds and failures do not silently duplicate releases.
- No sensitive witness data in the server, logs or analytics unless explicitly justified in a documented threat model.

## Exclusions until subsequent phases
Real fiat ramps; real-value custody; live regulatory processing; custom cryptographic circuits; trustless cross-currency FX liquidity; permissionless anonymous withdrawals; assertions of audit completion.

## Open questions
1. Confidential Tokens composability with custom Soroban contracts.
2. SPP wallet/prover and receiving experience on current testnet.
3. Who holds custody and who bears FX, settlement, and payout failure risk?
4. Which claims can selectively be disclosed and to whom?
5. What are acceptable limits on metadata leakage and timing correlation?
