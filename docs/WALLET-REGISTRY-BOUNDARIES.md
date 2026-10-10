# Wallets, Soroban registries and Testnet trust boundaries

This is an engineering integration contract, not a claim that StealthBridge
payments, proof circuits, custody, or fiat settlement work today.

## The three distinct identities

1. **Watched public address:** a pasted, checksum-valid Stellar `G...`
   public account identifier. It is not proof of ownership. No permission,
   wallet signature, money movement, storage or backend request is required
   to display a watched address.
2. **Connected wallet:** Freighter explicitly grants a webpage permission to
   read its public account, and reports the **Testnet** network passphrase
   `Test SDF Network ; September 2015`. This is connection state only, not
   authentication, transaction authorization or proof that an organization
   approves the account. The UI must recheck account/network changes.
3. **Authorized contract signer:** a Soroban transaction submitted under the
   exact Testnet passphrase, with the appropriate account authorizing the
   specific invocation. Contract `require_auth()` enforces the on-chain
   permission. A pasted or connected account identifier cannot bypass it.

## Current on-chain source (not deployed)

- `corridor-registry`: stores public admin, pending admin, emergency pause,
  and governance-only corridor flags. It never tracks balances, payment
  amounts, personal identifiers or private witnesses.
- `policy-registry`: stores versioned public commitments, admin handover and
  emergency pause. Its effective policy reads never constitute compliance,
  identity, proof or asset verification.
- `governance-gate`: immutable registry-address references, a single
  `public_flags_allow(corridor, policy)` read combining both registries, and
  fail-closed handling of invalid IDs and failed Soroban cross-contract calls.
  A true result still means *only* public governance flags, not permission
  to move assets, reveal private notes, or satisfy compliance.
- Both registries now reject **new enabled entries while paused**, while
  allowing authorized disabling/revocation. This prevents dormant policy
  activations that could unexpectedly take effect after a pause.
- `get_admin`, `is_enabled`, `is_paused`, `get_rule` and
  `is_effective` are public read APIs, not payout/transfer authorization.
- The canonical Testnet manifest remains `not-deployed`. Do **not**
  expose a hardcoded contract ID or report an on-chain verified registry
  until deterministic WASM, admin signatures, deployment transactions,
  RPC bytecode/hash checks, and manifest attestations agree.

## Future *approved* signing path

1. Backend reports a verified Testnet ledger, supported manifest revision
   and deployed contract IDs. Clients cross-check deployed contract bytecode
   against independently validated artifact hashes.
2. Wallet adapter reads the connected account/network and forms a restricted,
   typed **Soroban invocation**. Reject stale ledgers, unexpected simulation
   outputs, unsupported contract IDs, and any network other than Testnet.
3. Show the actual contract, method, authorization footprint, assets and
   fees before invoking any signer. Require explicit human approval for
   each transaction; never submit a generated transaction automatically.
4. Freighter signs only the reviewed payload after the user approves.
   The backend verifies signatures and transaction outcomes independently.
5. Governance/registry configuration and financial execution must be
   separate permission scopes. Registering a corridor never grants
   funds-transfer authorization. Fiat payout requires its own verified,
   lawful provider and reconciliation workflow.

The current frontend **does not implement steps 2–5** and must not claim
that wallet connection or registry flags make confidential payments available.

## Controls to preserve

- Never request or store seed phrases, secret keys, private proofs or
  unredacted transaction envelopes.
- Never treat a wallet-provided public address as identity verification,
  organization membership, or delegated custody rights.
- User-facing watch-only entry must stay local unless the user separately
  opts into a public blockchain lookup. Do not send addresses to analytics.
- Contract `require_auth()`, pause logic and admin-rotation tests must
  pass in CI. Avoid introducing automatic contract writes during deployments
  or app startup.
- Distinguish `on_chain_verified`, `payment_execution_enabled` and
  `fiat_payouts_enabled`. Registry existence never implies the latter two.

## Release gates

A protocol release requires audited privacy primitives, deterministic WASM
builds, independent on-chain deployment validation, reviewable wallet signing,
adversarial authorization tests, trusted issuer constraints and a verified
settlement lifecycle. None of these gates can be satisfied by a marketing
frontend build, a wallet-connect click or a database corridor row.
