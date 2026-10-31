# StealthBridge — Smart Account Kit public Testnet preflight

This is a **read-only verification tool** for pinned Smart Account Kit v0.10.0 and OpenZeppelin stellar-accounts v0.8.0 **public** Stellar Testnet artifacts.

It checks the exact account WASM bytes and SHA-256, WebAuthn verifier instance, threshold and spending-limit policy contracts, the Testnet network passphrase, the account authorization digest scheme and **remaining live ledger TTL**.

## Run locally

Requires Node.js 22+ and access to Stellar Testnet RPC.

```bash
npm ci
npm test
npm run verify:testnet
```

The local three tests cover source pins, rejection of missing/unsafe TTL and the absence of wallet deployment, signing or secret-extraction paths. A successful live response resembles `result: read-only-code-preflight-passed`; it also **must** report `canDeployCustomerWallet: false`, `credentialRecoveryVerified: false`, `verifiedFinancialExecution: false` and `broadcastTransactions: 0`.

**TTL is dynamic.** Historical snapshots near 20,000 remaining ledgers are NOT current expiry measurements; always run the live check. If `ttlExtensionReviewRequired` is true, an operator must separately review the extension and chain fee before any approved on-chain action.

## Not a customer wallet deployment

This utility does **not** read `operator_local` credentials, create accounts, register passkeys, test cross-device recovery, extend TTL, sign authorization entries or broadcast transactions. It never establishes smart-account security, user key recovery, custody, issuer support, private transfers or real-money payment eligibility.

Before an independently reviewed account pilot, validate WebAuthn RP/origin binding, policy revocation, signer thresholds and spending limits, anti-replay and digest compatibility, relayer authority, device-change recovery and currently deployed Testnet protocol compatibility.

**Pinned upstream source:** [stellar/smart-account-kit](https://github.com/stellar/smart-account-kit) at `768ac041dad01b94a750b768fc650e67930afd28`, published October 2026. These are upstream public artifacts, not contracts deployed by StealthBridge.

[Customer smart-account release plan](../../docs/CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md) · [Root protocol README](../../README.md) · [Wallet integration](../../docs/WALLET-SMART-ACCOUNT-AND-PRIVACY-INTEGRATION.md).

**Testnet only. No deployment, custody, fee collection, or customer financial execution.**
