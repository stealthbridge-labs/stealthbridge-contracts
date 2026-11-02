# Customer-owned programmable accounts — release gates

StealthBridge aims to offer recoverable passkey smart accounts for Send and role-aware policies for Business. The October 2026 deployed contracts are governance contracts, not customer accounts. The source-only experiments/restricted-account Ed25519 example is not a passkey wallet and MUST NOT be deployed as a product account.

## Verified components required before a Create account UI

1. Pin an exact Stellar Smart Account Kit revision, matching Stellar JS SDK version and reviewed OpenZeppelin Stellar Smart Account source (including the selected __check_auth authorization-digest version). Independent audit status must cover the exact code actually used, not a similarly named upstream project.
2. Verify the contract account code hash, authenticated factory and deterministic deployment provenance on Testnet; resolve potential occupied/predicted-address confusion. Confirm verifier contract and WebAuthn signature verification using real challenge/credential vectors.
3. Bind passkey RP ID and expected origin, account address, network passphrase, authorization context and nonce/expiry. Test replay, altered signatures, wrong context, wrong contract and recovery race conditions.
4. Require a second-device recovery flow before first-value custody; explicit user-visible recovery policy, rotation and revocation. Never store user private keys or passkey credentials in app logs.
5. Business: independent approval roles, per-operation spending and recipient controls, maker-checker separation and emergency revocation. No administrator/deployer universal user signer.
6. Relayer must not have unlimited funds or permissions. Pin relayer origin, network, allowed functions, sponsorship limits and record all signed requests. Sponsor API keys remain strictly server-side.
7. Integrate only after isolated Testnet end-to-end tests across frontend, SDK, backend, real deployed account, smart-account kit, and recovery; independent security review and explicit financial release decision.

The immediate customer-facing interface must not contain an enabled Create passkey, Transfer or Withdraw action. Contract-instance presence alone is not proof of __check_auth, ownership, asset acceptance or recovery. The restricted-account tests here exercise source-only auth failure modes, not production readiness.

References: https://skills.stellar.org/skills/dapp/SKILL.md; https://github.com/stellar/smart-account-kit; https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account


## Read-only Testnet dependency preflight (31 October 2026)

A version-pinned, dependency-isolated preflight now lives at
tools/smart-account-preflight. It uses the official Kit v0.10.0 JS package,
Stellar SDK 16.4.1, and the audited-reference *identity* from the official
stellar-accounts v0.8.0 deployment notes. From that directory: npm ci, npm test,
npm run verify:testnet.

It fetches raw account WASM from Testnet RPC, recomputes its SHA-256, verifies
the expected digest scheme (preimage-v1), and checks deployed WebAuthn verifier,
threshold and spending-limit policy code identities against the public ledger,
including remaining ledger-entry lifetime. No signing, credential registration,
secret reading, deployment, account funding or transfer occurs.

### Operator lifecycle audit (2 November 2026)

A separate public read-only audit is now available from
`tools/smart-account-preflight`: run `npm run --silent audit:testnet`.
No admin wallet or operator key is needed. It neither reads credentials nor
builds transaction material. No extension, restoration, signing, deployment or
broadcast is approved by running it.

The strict `verify:testnet` behavior is unchanged: it rejects required pins
that are absent or have 720 or fewer remaining ledgers and stops at its first
failure. Its “Account WASM missing or near expiry” message cannot identify which
condition occurred. The audit observes all seven code/instance entries
independently, verifies the Testnet passphrase, checks pinned dependency versions,
recomputes every observed WASM SHA-256 and checks exact public identities.
Account code TTL, verifier code TTL and each verifier/policy **instance TTL**
are distinct measurements.

The previously reported snapshot at ledger 5,487,598 (account 17,432 remaining
ledgers, threshold instance 18,036, spending-limit instance 18,038) is historical
context supplied for this investigation, not current evidence. None of these
values establishes current presence or expiry. Use the new audit's observation
ledgers and per-entry measurements; never extrapolate a current TTL from that
snapshot or relabel an absent entry as near expiry.

Review each JSON entry and retain the document even on exit 1. `healthy`
requires matching identity and TTL above 120,960 ledgers. `low_ttl` maps to
`review_extension`; `unavailable_live_entry` maps to
`investigate_restore_or_republish`; `mismatch` maps to `investigate_mismatch`;
`indeterminate` maps to `retry_observation`. A live-only absent entry cannot
distinguish archive from nonexistent/never published: expiration and TTL remain
null. No restoration or republication decision follows from this result alone.
A zero-TTL sentinel returned with code/instance XDR is similarly a missing
verified-live state; preserve the observed identity but do not invent a
ledger-zero expiration. Investigate whether the entry is archived or absent
through an independently reviewed state-archival source before selecting any
paid maintenance operation.
The minimum TTL covers only observed valid TTLs, not unavailable entries.
Fresh ledger-header hashes, canonical uint32 ledger numbers and a bounded
12-ledger observation span are required. Unverified context withholds the summary
TTL. Exit 0 requires all entries healthy; operational review also exits 1.

For a live entry, review extension separately. For a confirmed archived entry,
review restoration separately. Either requires paid on-chain signing and an
explicitly approved plan identifying affected code/instances and fees. Any
republication likewise requires independent review and authorization. The audit
contains no execution path or automatic maintenance commands. After any
independently authorized maintenance, re-run observation. The operator has not
approved an on-chain transaction as part of this audit.

See the [operator runbook](../tools/smart-account-preflight/README.md#operator-lifecycle-audit-testnet-only)
for schema, status, clock/freshness policy and failure interpretation. JSON keeps
wallet readiness, customer-wallet-created and financial execution flags false;
transactions built and broadcast are zero. This is Testnet only, with no Mainnet,
customer funds or customer wallet deployment claims.

This does NOT satisfy the required full account deployment, WebAuthn origin,
recovery and signer-policy audits. The integration remains Testnet-only.
