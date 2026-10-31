StealthBridge Smart Account Testnet Preflight

A reproducible, read-only check for Smart Account Kit v0.10.0 and OpenZeppelin
stellar-accounts v0.8.0 Testnet artifacts: live account WASM hash/bytes,
WebAuthn verifier, threshold and spending-limit policy instance hashes, TTL,
network passphrase, and authorization digest scheme.

Commands from this directory:
  npm ci
  npm test
  npm run verify:testnet

The tool needs Node 22+ and public Stellar RPC connectivity. It does not read
operator_local secrets, register passkeys, deploy smart accounts, sign or pay.
A green result does not authorize customer custody or payments.

Source: stellar/smart-account-kit at commit
768ac041dad01b94a750b768fc650e67930afd28, published October 2026.
Use docs/CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md before attempting deployment.
The kit and integration remain unaudited as a complete system. Recovery,
origin/RP binding, relayer policy, and user account authorization are unverified.


Important: Smart-account account WASM and policy contracts are currently only
about 20,000 ledgers from expiry on Testnet (around one day at five seconds per
ledger), even when their hash matches. The tool explicitly flags a one-week
TTL-extension review. A successful public code preflight is not a substitute
for a properly authorized ledger TTL extension or a fresh deployment rehearsal.
Any extension would be an on-chain transaction and needs separate consent.
