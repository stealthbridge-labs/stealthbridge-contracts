# StealthBridge — Smart Account Kit public Testnet preflight

This is a **read-only verification tool** for pinned Smart Account Kit v0.10.0 and OpenZeppelin stellar-accounts v0.8.0 **public** Stellar Testnet artifacts.

It checks the exact account WASM bytes and SHA-256, WebAuthn verifier instance, threshold and spending-limit policy contracts, the Testnet network passphrase, the account authorization digest scheme and **remaining live ledger TTL**.

## Run locally

Requires Node.js 22+ and access to Stellar Testnet RPC.

```bash
npm ci
npm test
npm run --silent audit:testnet
npm run verify:testnet
```

The offline tests cover pinned dependencies, synthetic SDK XDR entries, TTL boundaries, independent missing entries, mismatches, partial RPC failures, wrong networks, stale or inconsistent ledgers, malformed manifests, and import/script safety. A successful live response resembles `result: read-only-code-preflight-passed`; it also **must** report `canDeployCustomerWallet: false`, `credentialRecoveryVerified: false`, `verifiedFinancialExecution: false` and `broadcastTransactions: 0`.

**TTL is dynamic.** Historical snapshots near 20,000 remaining ledgers are NOT current expiry measurements; always run the live check. If `ttlExtensionReviewRequired` is true, an operator must separately review the extension and chain fee before any approved on-chain action.

## Operator lifecycle audit (Testnet only)

`npm run --silent audit:testnet` (or `node src/audit.mjs`) emits one JSON document on stdout. No admin wallet, operator key, environment credentials, local Stellar CLI identity or signing approval is needed. It uses only `getNetwork`, `getLatestLedger` and `getLedgerEntries` on the pinned official public Testnet RPC, through the existing pinned Stellar SDK. Importing the module performs no RPC requests.

The audit attempts **seven independent entries**: account code, WebAuthn verifier instance and code, threshold instance and code, spending-limit instance and code. Every code entry has its WASM SHA-256 independently recomputed and compared with both the embedded hash and the manifest pin; the account byte length is also checked. Instances must point to their pinned WASM hashes. Code and instance TTLs are separate: one live entry does not prove the other is live. A missing account code entry cannot suppress the other observations.

The source of public identities remains `src/manifest.mjs`. Manifest release pins, the declared dependency versions and installed Kit 0.10.0 / SDK 16.4.1 versions must match before any RPC request. The endpoint and Testnet passphrase cannot be overridden by CLI options. This audit does not verify customer accounts or governance contracts.

### Interpret JSON and exit status

`schema_version: 1` has a fixed entry order, no local timestamps, no raw RPC errors, no WASM bytes and no transaction material. The same observations produce the same JSON. Each entry contains its public identity, expected hash, observed ledger, expiration and remaining TTL, with `null` for unavailable measurements. Valid observed code hashes, computed SHA-256 and byte sizes are included. Remaining TTL is `liveUntilLedgerSeq - observedLedger`, measured in ledgers; it is not a wall-clock expiry estimate.

| Entry status | Meaning | Review action |
| --- | --- | --- |
| `healthy` | Matching identity and remaining TTL above 120,960 ledgers | None |
| `low_ttl` | Matching live entry with TTL at or below 120,960 ledgers (one-week review threshold) | `review_extension` |
| `unavailable_live_entry` | A live entry is absent, or returned matching data has zero/past TTL; no usable live state is verified | `investigate_restore_or_republish` |
| `mismatch` | Returned key, code bytes, embedded hash or instance identity differs | `investigate_mismatch` |
| `indeterminate` | RPC failure, invalid/missing TTL or untrusted observation context | `retry_observation` |

**No verified live entry is ambiguous:** `getLedgerEntries` alone cannot distinguish an archived entry from one that never existed / was never published. The RPC may still return identity-matching WASM/instance XDR with a **zero TTL sentinel**; this is classified `unavailable_live_entry`, not as a live artifact or as an expiry at ledger zero. The report keeps TTL and expiry `null` for zero sentinels; an explicitly positive but past expiry is retained as an observed historical value, never a positive remaining lifetime. Neither situation justifies restoration or republication without independent state-archival evidence and an approved operator review.

`summary.minimumTtlRemainingLedgers` covers only entries with observed valid TTL, and does not imply missing entries are safe. It is `null` when the network/ledger context cannot be verified. `summary.actions` lists review categories, never transaction instructions. Exit 0 requires every entry healthy and the context verified; **low TTL, unavailable entries, mismatches and indeterminate observations all exit 1**. Do not discard the JSON on nonzero exit. Inspect both `errors` and every entry before making an operational decision.

The audit brackets all entry reads with fresh latest-ledger observations. It validates positive uint32 ledger sequences, ledger-header SHA-256/sequence/close-time agreement, a maximum 12-ledger span, entry observations within that span and equal hashes when both anchors have the same sequence. Latest-ledger close times must be at most 120 seconds old and at most 30 seconds in the future relative to the local clock. Invalid context fails closed, marks non-mismatch findings indeterminate and withholds the summary TTL. Check local clock and retry observation as appropriate. This relies on the official RPC; it is not independent consensus verification.

The existing `verify:testnet` remains unchanged: it stops on the first failure and rejects any required pin missing or with **720 or fewer ledgers** left. Its older “missing or near expiry” error does not distinguish those conditions; use the audit JSON for diagnosis. The audit's larger operational review threshold is deliberate.

### Review process

1. Run the audit without a wallet and retain its JSON and exit status through your normal evidence process. Inspect each code/instance identity, observation ledger, TTL and reason.
2. For `review_extension`, separately review whether the identified **live** entries need extension. Code and instance entries need separate consideration.
3. For `investigate_restore_or_republish`, establish publication/history and archived state using separately reviewed evidence. Restoration applies to archived entries; live-only absence does not justify it or republishing.
4. Extension, restoration and republication are paid on-chain actions requiring a separately reviewed plan, fees and explicit signing authorization. This tool provides no execution commands and authorizes none of those actions. Re-run the read-only audit after any independently authorized maintenance.

All reports keep `canDeployCustomerWallet`, `customerWalletCreated`, `credentialRecoveryVerified` and `verifiedFinancialExecution` false, and `broadcastTransactions` / `transactionsBuilt` zero. No customer funds, Mainnet checks or customer-wallet-created claims are part of this audit.

Official RPC semantics: [getLedgerEntries](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgerEntries) (live state, found entries and optional expiration), [getLatestLedger](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLatestLedger) (ledger hash, sequence, close time and header).

## Archival state cross-check (Testnet, read-only)

With a trustworthy, separately provisioned local Stellar Core query service:

```bash
npm run --silent review:archival -- --core-url http://127.0.0.1:11627
```

The URL is required. Only the exact literal `http://127.0.0.1:11627` or `http://[::1]:11627` is accepted. Port 11627 is deliberately fixed for this review; no default, port discovery, hostname resolution, credentials, paths, trailing slash, query parameters or fragments are accepted. This tool never installs, configures or runs Core. If the service is unavailable, the JSON fails closed with `retry_or_verify_core_node` and exit 1.

Operators must independently verify the node's **Testnet network configuration, trusted history/quorum configuration and syncing**, and that **HTTP_QUERY_PORT=11627** belongs to the query server. This is separate provisioning guidance, not configuration performed by this package. Never point this review at Core's command interface (`HTTP_PORT`, typically 11626). The tool never requests that interface, `/info`, `/getledgerentryraw`, or other Core endpoints. See the [published Core query commands and response schema](https://github.com/stellar/stellar-core/blob/master/docs/software/commands.md#http-query-server) and [Core configuration reference](https://github.com/stellar/stellar-core/blob/master/docs/stellar-core_example.cfg).

One `POST /getledgerentry` sends `application/x-www-form-urlencoded` with exactly seven unique, repeated `key` fields containing base64 LedgerKey XDR, in pinned manifest order: account code; WebAuthn instance/code; threshold instance/code; spending-limit instance/code. No TTL keys or snapshot parameter are sent. Both Core and public RPC fetches reject redirects, have a 15-second timeout, and require JSON bounded to 4 MiB while streaming. Errors are fixed reason codes; no remote error text, raw XDR, credentials, execution commands or transaction payloads appear in the report.

The current response must contain exactly seven **positional** objects in `entries` and a positive uint32 `ledgerSeq`. Each object uses only `state`, optional `entry` (base64 **LedgerEntry** XDR) and optional `liveUntilLedgerSeq`. Unknown fields, missing/extra entries, CAP draft `e`/`ttl` fields and malformed envelopes fail closed. A returned entry's actual ledger key is reconstructed and compared to the exact requested key. Code requires both embedded hash and computed WASM SHA-256 to match the pin, plus the account byte size. Instances require the exact address, instance key, persistent durability and executable WASM hash. Last-modified must be positive and no later than the Core observation ledger.

Only `getNetwork` and two `getLatestLedger` reads use the pinned official public Testnet RPC. The passphrase must match Testnet. Both anchors must pass the existing canonical header/hash, close-time and 12-ledger span checks. Core must fall between the first RPC ledger minus 12 and the last RPC ledger plus 12. Invalid or stale context makes non-mismatch states indeterminate and withholds live TTL minima. **Core returns no network passphrase or consensus proof in this endpoint**: RPC Testnet identity and ledger proximity cannot authenticate Core's network or establish consensus trust. The report always includes the operator-owned source warning and `source.coreNetworkVerified: false`.

| Report state | Required evidence | Action |
| --- | --- | --- |
| `archived` | Matching LedgerEntry identity/SHA; TTL absent or zero | `review_restoration_of_confirmed_archived_entries` |
| `live` | Matching LedgerEntry identity/SHA; positive uint32 TTL at least Core ledger | `review_live_ttl_extension` when remaining TTL is at most 120,960 ledgers |
| `not_found` | Core `not-found`, with neither entry nor TTL present | `investigate_not_found` |
| `mismatch` | Wrong key/identity/code bytes, or contradictory state/TTL fields | `investigate_mismatch` |
| `indeterminate` | Invalid response/XDR/live TTL, unavailable service or invalid context | `retry_or_verify_core_node` |

Schema version 1 includes the Testnet passphrase, Core ledger, public RPC bracket, seven public key SHA-256 hashes, per-entry identity and code SHA validation, and `summary.minimumLiveTtlRemainingLedgers` over verified live entries only. Instance `sha256Verified` is `null` because instances reference code; their code bytes are checked separately. All matching archived findings are conditional on the operator's Core trust checks. Not-found is not proof of archival and never justifies restoration.

Exit 1 means any archived, not-found, mismatched, indeterminate or missing entry, pin failure, invalid network/ledger context, **or any live TTL at or below the 120,960-ledger review threshold**. Exit 0 requires all seven entries to be observed live with valid identity and **each live TTL above the review threshold**. The report separately exposes factual `allEntriesLive` and the stricter `noTtlReviewNeeded` exit gate. **All-live is never financial execution authorization.** Reports always keep `customerWalletReady`, `canDeployCustomerWallet`, `customerWalletCreated`, `credentialRecoveryVerified` and `verifiedFinancialExecution` false, with `broadcastTransactions: 0` and `transactionsBuilt: 0`.

Restoration requires a separately reviewed on-chain plan, signing and explicit approval. This tool constructs, simulates, signs and broadcasts nothing. Retain JSON and exit status for review; recheck live state after any separately authorized maintenance. The [archival review record](../../docs/SMART-ACCOUNT-ARCHIVAL-REVIEW-2026-11-02.md) preserves historical observations without treating them as current evidence.

The additional offline tests use injected RPC/fetch APIs and synthetic LedgerEntry XDR, including a mocked local HTTP request that checks method, path, ordered seven-key form, redirect policy, timeout signal and the absence of other network/API calls. Existing audit and verifier tests remain intact.

## Not a customer wallet deployment

This utility does **not** read `operator_local` credentials, create accounts, register passkeys, test cross-device recovery, extend TTL, sign authorization entries or broadcast transactions. It never establishes smart-account security, user key recovery, custody, issuer support, private transfers or real-money payment eligibility.

Before an independently reviewed account pilot, validate WebAuthn RP/origin binding, policy revocation, signer thresholds and spending limits, anti-replay and digest compatibility, relayer authority, device-change recovery and currently deployed Testnet protocol compatibility.

**Pinned upstream source:** [stellar/smart-account-kit](https://github.com/stellar/smart-account-kit) at `768ac041dad01b94a750b768fc650e67930afd28`, published October 2026. These are upstream public artifacts, not contracts deployed by StealthBridge.

[Customer smart-account release plan](../../docs/CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md) · [Root protocol README](../../README.md) · [Wallet integration](../../docs/WALLET-SMART-ACCOUNT-AND-PRIVACY-INTEGRATION.md).

**Testnet only. No deployment, custody, fee collection, or customer financial execution.**
