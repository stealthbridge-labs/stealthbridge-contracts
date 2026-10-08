# Privacy and Threat Model — Draft v0.1

## Desired disclosures

| Field | Business mode | Consumer mode |
|---|---|---|
| Transfer amount | Concealed on chain | Concealed on shielded leg |
| Balance | Concealed where implementation supports it | Protocol-dependent |
| Sender/recipient identities | May be visible on chain | Shielded relationship should not be directly linkable |
| Deposit and withdrawal events | Possibly visible | Often public at the pool edges |
| FX and payout records | Visible to involved providers | Visible to involved providers |
| Timing and network metadata | May leak | May leak |

*All of these are hypotheses until verified against current deployed implementations and specific transaction paths.*

## Adversaries
Passive blockchain observer; RPC/indexer operator; malicious API operator; compromised browser or wallet; corrupt FX/payout provider; malicious counterparty; network traffic analyst.

## Non-goals
Anonymity from legally authorized fiat partners; hiding fiat account identities from financial providers; censorship resistance guarantees; concealment of illegal activity.

## Validation
Produce a field-level disclosure matrix for both transfer variants. Confirm transaction events, method arguments, state changes, proof public inputs and wallet UX. Run timing-correlation and small-anonymity-set analyses for consumer mode. Consider selective disclosure and evidence retention only with access control and legal review.
