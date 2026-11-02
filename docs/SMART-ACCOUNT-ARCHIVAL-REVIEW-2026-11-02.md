# Smart-account archival review — November 2, 2026

**Review only / NO-GO. Testnet only. No signing, funding, restoration, TTL extension, or payment execution authorized.**

## Evidence at ledger 5,523,276

The pinned audit validated the Stellar Testnet passphrase and ledger context, then checked seven public entries. All recorded WASM hashes matched the pinned upstream Smart Account Kit/OpenZeppelin release. Five entries nevertheless reported the RPC zero-TTL sentinel and were correctly classified as **unavailable live entries**, with unknown remaining TTL.

| Entry | Pinned public identity | Observed status |
| --- | --- | --- |
| Account code | `c514d35ea67eaea9bfc1fb3327854c0c06111bc1ddebd4fe217c504c1004b9e1` | Unavailable live; zero TTL |
| WebAuthn verifier instance | `CC7EKIHQP3TN4CARQDND6CEOY2UXLWWC2X5GHTD5NLAT7BG5GPZIOM3F` | Healthy; live until 7,878,980 |
| WebAuthn verifier code | `e63a030d0f1a1481e36059a4837c433083b33e704c1f9625b7314795b6d72b76` | Healthy; live until 7,878,982 |
| Threshold instance | `CAZ2WFUDXGX265LOEARFEOYYUL6F4BYWXZLGUAWZNJY3MRFPNLSZVS4S` | Unavailable live; zero TTL |
| Threshold code | `f72a11de6e2d5d2495d98fe61e04cd13544e64156a5a3be83ef8c2e403d14a94` | Unavailable live; zero TTL |
| Spending-limit instance | `CC3CEYQAP6NPNFIYSWL5MVZRCPJZGWX4XO7WDEJOUVGO2FZX5OONYPA5` | Unavailable live; zero TTL |
| Spending-limit code | `9bc17db0a804d6c82231a268c43bac1413650ea92cac0022e0d0a3b66ddc8189` | Unavailable live; zero TTL |

A separate direct, public SDK read at approximately ledger 5,523,301 confirmed the zero-TTL result for account code and the threshold instance, and a live-until of 7,878,980 for WebAuthn. No private material was retrieved.

### Historical TTL corroboration

An earlier reading at ledger 5,487,598 gave these live-until calculations:

- Account code: 5,487,598 + 17,432 = **5,505,030**
- Threshold instance: 5,487,598 + 18,036 = **5,505,634**
- Spending-limit instance: 5,487,598 + 18,038 = **5,505,636**

The new observed ledger is beyond those three expiry points. The leading hypothesis is **archival after TTL expiry**, not new WASM code or a lost administrator. This remains a hypothesis until archival state is independently checked. Do not use a zero sentinel as a historical expiration date.

Stellar Core's state-aware `getledgerentry` interface can distinguish `live`, `archived`, and `not-found` when a node has the relevant archival data. The public SDK `getLedgerEntries` results above alone do not provide that definitive state classification.

## No-broadcast review checklist

1. Re-run `npm run --silent audit:testnet` from `tools/smart-account-preflight` and preserve both JSON and nonzero exit status. Verify all seven keys separately.
2. Obtain state-aware archive evidence (or independently verifiable archive/restore metadata) for **each** of the five unavailable keys. Label each `archived`, `live`, `not-found`, or `unknown`. Do not blindly restore keys that are actually `not-found`.
3. Confirm exact pinned WASM provenance, contract IDs, network, current Stellar protocol compatibility and recovery policy. Distinguish code archival from instance archival.
4. Prepare an independently reviewed **Testnet-only** restoration footprint for entries confirmed archived, or TTL extension plan **only for verified-live entries**. Itemize resource fees, maximum payer cost, validity ledger, rollback/incident plan and impact on shared account policies. No contract replacement without separate approval.
5. Obtain explicit authorization for the exact maintenance transaction, payer and fee cap **before** construction, signing, simulation or broadcast. Do not access `operator_local` signing credentials without that approval.
6. After separately approved maintenance, run the live audit and strict verifier again, followed by separate authorization, WebAuthn RP/origin, signer thresholds, recovery and adversarial tests. A successful code audit **does not enable customer wallets or money movement**.

**Current result:** seven code identities matched, two entries healthy, five unavailable live; `canDeployCustomerWallet=false`, `credentialRecoveryVerified=false`, `verifiedFinancialExecution=false`, zero transactions built or broadcast.

## Source references

- [Stellar Core state-aware ledger query](https://github.com/stellar/stellar-core/blob/master/docs/software/commands.md)
- [Stellar state archival model](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-12.md)
- [Official archived instance restoration explanation](https://developers.stellar.org/docs/tools/cli/cookbook/restore-contract-instance) — not authorization to run.
- [Pinned preflight and audit](../tools/smart-account-preflight/README.md)
- [Customer account release gates](CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md)

