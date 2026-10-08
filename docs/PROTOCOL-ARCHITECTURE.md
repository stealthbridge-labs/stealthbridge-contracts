# StealthBridge Protocol Architecture v0.2

## Rationale
The current repository began as an organization-wide monorepo scaffold and retains historical \`apps/\`, \`services/\`, \`packages/\` folders for now. The definitive implementation owners are:
- \`stealthbridge-contracts\`: contract ABI/security + testnet deployment evidence
- \`stealthbridge-backend\`: orchestration, FX, compliance and payout services
- \`stealthbridge-frontend\`: wallet UX and private proving where supported
- \`stealthbridge-sdk\`: versioned consumable bindings

No migration deletes or rewrites legacy history without review.

## Payments privacy levels
1. **Confidential Tokens:** hide transfer amounts and balances; counterparties generally observable. Evaluate composability of issuer-controlled confidential stablecoin contracts and Soroban policy hooks.
2. **Stellar Private Payments:** shield sender–receiver relationship and amounts for consumer remittance leg, while admission and withdrawal edges may reveal metadata.
3. **Transparent asset handling:** standard Stellar assets/SAC remain public by default. Depositing into a confidential protocol is a separate custody/mint/redeem event whose integration must be verified.

Do not infer that SPP, Confidential Tokens, and traditional SAC balances can be atomically swapped or settled by a generic router. Prove each flow on current testnet first.

## Contract boundaries
- Corridor Registry (implemented skeleton): public key/name -> enabled flag and admin authorization.
- Policy Registry (proposed): public policy commitments, limits/issuer rules, pausing and recovery governance, **only as compatible with privacy contracts**.
- Settlement Verifier/Adapter (proposed): validates public statements and issuance/settlement events **without revealing private witness data**; feasibility-gated.
- Escrow/custody (deferred): requires explicit trust model, integration feasibility, audit and regulated-provider partnership.

## Engineering invariants
- Authenticate every privileged mutation with \`require_auth()\` and document multisig/upgrade controls.
- TTL rent and restoration handling for every persistent key.
- No plaintext payment amount, payer/recipient relationship or KYC on-chain via StealthBridge metadata.
- Verify ZK public signals bind to asset, chain, scope, nullifier/replay domain, and claimed recipient where appropriate.
- Preserve independent evidence for chain execution vs external fiat settlement.
- Rust tests cover authorization errors, storage recovery, invalid proof, replay and parameter bounds.

## Issuer-controlled confidential stablecoins
The OpenZeppelin guest article on confidential stablecoins highlights balances/amounts as commitments, visible addresses, issuer-operated freeze/restrict controls and scoped auditor visibility. Treat issuer privilege, view access, policy upgrades, redemption/reserve proofs, and asset supply invariants as **core architecture**, not optional UI features.

Initial testnet use: only mock non-redeemable fiat-equivalent test assets. Never label demo asset as real Circle USDC without verifying issuer/asset code and trustlines.

## Testnet proof gate
- Exact versions and Stellar protocol recorded.
- Contract/asset addresses and tx hashes after actual deployment.
- Public disclosure matrix for observed events/arguments/ledgers.
- Negative authorization and replay test evidence.
- End-to-end client proof and recovery timing measured.
- Signed ADR before adding any fund-moving contract.
