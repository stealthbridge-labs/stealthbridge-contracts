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

## Read-only Core cross-check tooling (November 3 update)

The package now provides a state-aware cross-check without authorizing maintenance:

```bash
cd tools/smart-account-preflight
npm run --silent review:archival -- --core-url http://127.0.0.1:11627
```

This command requires a trustworthy **separately provisioned** local Stellar Core with its HTTP query server on `HTTP_QUERY_PORT=11627`, not its command server (`HTTP_PORT`, typically 11626). The tool never installs, configures or starts Core and never queries the command server. Operators must independently check Testnet network configuration, trusted history/quorum setup, sync health and that port 11627 is the query interface. Only literal loopback URLs on this explicit port are allowed (IPv6 `[::1]` is also supported); no inferred ports, arbitrary hosts, paths, credentials, query parameters or redirects.

It uses only POST `/getledgerentry` on Core, with exactly seven ordered repeated form `key` fields and no TTL keys. The current published Core commands response is positional: `entries` objects with `state`, optional `entry` LedgerEntry XDR and `liveUntilLedgerSeq`, plus top-level `ledgerSeq`. Earlier CAP draft JSON is rejected. Every returned code/instance entry must match its requested key and pinned identity. Code bytes are SHA-256 checked, account size is checked, and last-modified/TTL ranges are checked. Archived requires matching XDR and absent/zero TTL; live requires matching XDR and a positive TTL at least the Core ledger; not-found must omit entry and TTL. See [complete input, schema and exit rules](../tools/smart-account-preflight/README.md#archival-state-cross-check-testnet-read-only).

The official pinned Testnet RPC supplies `getNetwork` and fresh canonical `getLatestLedger` anchors around the Core query. Core must be within 12 ledgers of the public bracket. This detects stale or inconsistent ledger observations, but **the query response does not contain Core's network passphrase, a ledger hash or a consensus proof**. A node on another network or a dishonest operator can report a plausible ledger number. The report labels this an operator-owned source and keeps `coreNetworkVerified: false`; independent operator verification remains essential.

JSON actions are `review_restoration_of_confirmed_archived_entries`, `review_live_ttl_extension`, `investigate_not_found`, `investigate_mismatch` and `retry_or_verify_core_node`, according to each finding. Missing service or malformed data fails closed. Exit 0 requires all seven entries live **and** every live TTL strictly above 120,960 ledgers. Otherwise it exits 1 and reports any extension-review candidates. All-live is not permission for financial execution. `customerWalletReady`, `credentialRecoveryVerified` and `verifiedFinancialExecution` remain false, and transaction counts remain zero. **Restoration requires separately reviewed on-chain signing and explicit approval.** No execution commands or transaction payloads are emitted.

This update adds tooling and offline tests; it does not replace the historical ledger evidence above with a fresh Core observation or confirm that the five unavailable entries are archived.

## No-broadcast review checklist

1. Re-run `npm run --silent audit:testnet` from `tools/smart-account-preflight` and preserve both JSON and nonzero exit status. Verify all seven keys separately.
2. Run the read-only Core cross-check against the independently verified local query service, or obtain independently verifiable archive/restore metadata, for **each** of the five unavailable keys. Label each `archived`, `live`, `not-found`, or `unknown`. Do not blindly restore keys that are actually `not-found`.
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

