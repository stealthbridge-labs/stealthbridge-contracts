# StealthBridge Cross-Repository Integration Map

Every customer-facing or operator-facing capability in StealthBridge must trace cleanly across owning repositories rather than duplicating validation rules, cryptography, or authorization checks.

```text
Next.js UI (stealthbridge-frontend/src/components/)
   │  uses typed client helpers & validators (@stealthbridge/sdk / src/lib/)
   ▼
Same-Origin Next.js BFF (stealthbridge-frontend/src/app/api/)
   │  verifies signed cookie session, CSRF Origin, payload byte limits,
   │  and signs requests with STEALTHBRIDGE_ACCOUNT_BRIDGE_SECRET (HMAC-SHA256)
   ▼
Rust / Axum Service (stealthbridge-backend/src/)
   │  enforces timestamp skew (<=30s), single-use UUID nonces, RBAC & idempotency
   ├──► Neon PostgreSQL (stealthbridge-backend/migrations/)
   └──► Stellar Testnet Horizon & Soroban RPC
           │
           ▼
Soroban Contracts (stealthbridge-contracts/contracts/)
   ├─ Public Governance (deployed Testnet): CorridorRegistry, PolicyRegistry, GovernanceGate
   └─ Protocol Extensions (source & upcoming Testnet deployments):
      SettlementAdapter, FeeVault, PrivacyVerifier / NullifierRegistry, Smart Accounts
```

---

## Feature-by-Feature Traceability

| Feature | Frontend UI | Frontend BFF / Client | SDK Module | Backend Module | DB Table(s) | Soroban Contract(s) | Failure & Security Behavior |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Wallet Authentication** | `wallet-sign-in.tsx`, `/login` | `/api/auth/{challenge,verify,session,logout}` | `parseStellarAddress`, `canonicalStellarAccountAddress` | `wallet.rs`, `server.rs` | Signed cookie / ephemeral challenges | — | Same-origin cookie, `httpOnly`, SEP-53-style signed message; login never grants transfer authority |
| **Account Profile** | `account-journey.tsx`, `customer-profile-settings.tsx` | `/api/account/profile`, `account-profile.ts` | `readCustomerProfile`, `saveCustomerPreferences` | `account_profile.rs` | `customer_profiles`, `customer_profile_update_receipts` | — | Replay-resistant via single-use nonce; self-reported only, not KYC |
| **Account Beneficiaries** | `customer-payment-workspace.tsx` | `/api/account/beneficiaries`, `account-beneficiaries.ts` | `listAccountBeneficiaries`, `saveAccountBeneficiary`, `removeAccountBeneficiary` | `account_beneficiaries.rs` | `account_beneficiaries`, `account_beneficiary_receipts` | — | Strict Protocol 30 `G/M/C/W` validation; 25-entry cap; `identity_verified: false` |
| **Encrypted Draft Vault & Instructions** | `customer-draft-vault.tsx`, `payment-instructions.tsx` | `/api/account/drafts`, `/api/account/instructions` | `private-draft-vault.ts`, `payment-instructions.ts` | `customer_ciphertext_vault.rs`, `payment_instructions.rs` | `customer_ciphertext_drafts`, `customer_payment_instructions` | — | Web Crypto AES-256-GCM + PBKDF2-HMAC-SHA256 client-side; server never receives plaintext |
| **Controlled Testnet Lifecycle** | `settlement-lifecycle-panel.tsx` | `/api/account/settlements`, `settlement-lifecycle.ts`, `settlement-reconciliation.ts` | `settlement-lifecycle.ts` | `settlement_lifecycle.rs` | `account_settlement_lifecycles`, `_events`, `_outbox`, `_receipts` | References `CorridorRegistry` / `GovernanceGate` / `SettlementAdapter` rules | Halts FX at `quote_unavailable`; Testnet finality kept separate from fiat payout (`fiat_payouts_enabled: false`) |
| **Business Onboarding, Team & Invites** | `business-onboarding.tsx`, `account-organizations.tsx`, `organization-team-workspace.tsx` | `/api/account/{business-onboarding,directory,organizations/[id]/team,team-invites}` | `business-onboarding.ts`, `account-directory.ts`, `organization-team.ts`, `team-invites.ts` | `business_onboarding.rs`, `account_directory.rs`, `organization_team.rs`, `team_invites.rs`, `org_auth.rs` | `organizations`, `organization_members`, `organization_invitations` | — | Pending businesses explicitly unverified; membership never authorizes transfers |
| **Privacy Rail Evaluation & Disclosures** | `customer-payment-workspace.tsx`, `settlement-lifecycle-panel.tsx`, `/platform` | `privacy-rails.ts` | `privacy-rails.ts` | `privacy_rails.rs`, `privacy_commitment.rs` | — | `tools/privacy-rail-poc`, `PrivacyVerifier` (Phase 4) | Fails closed (`productionReady: false`); separates encrypted drafts from on-chain ZK proofs |
| **Public Network, Corridors & Smart Account Kit** | `/routes`, `/explorer`, `/preview/*`, `account-access-security.tsx` | `/api/public/*`, `/api/bridge/[...parts]` | `client.ts`, `generated/api-wire.ts`, `smart-account-kit.ts`, `contract-observation.ts` | `server.rs`, `smart_account_kit.rs`, `ledger.rs`, `ledger_events.rs` | `corridors`, `ledger_checkpoints`, `stellar_contract_event_journal` | `CorridorRegistry`, `PolicyRegistry`, `GovernanceGate`, upstream Smart Account Kit pins | Strict Testnet passphrase, fresh ledger window, bounded payloads; degraded states never fabricate routes |

---

## Schema & ABI Synchronization Rules

1. **Public Backend OpenAPI ↔ SDK ↔ Frontend:**
   - Canonical public schema: `stealthbridge-backend/api/openapi.yaml`
   - SDK snapshot & generator: `stealthbridge-sdk/specs/backend-openapi.v0.3.yaml` → `npm run generate:api-types` (`src/generated/api-wire.ts`)
   - Frontend mirror: `stealthbridge-frontend/src/lib/sdk-api-wire.v0.2.ts`
   - Verified automatically by `stealthbridge-backend/scripts/verify_consumer_contracts.py` and `stealthbridge-frontend/scripts/verify-sdk-wire.mjs`.
2. **Database Migrations ↔ Backend Readiness:**
   - Every SQLx migration under `stealthbridge-backend/migrations/` must pass `scripts/validate_migrations.py` (`test_validate_migrations.py`) with additive-only DDL and required bounds.
3. **Soroban Source & ABI ↔ Manifest Parity:**
   - Reproducible WASM builds (`wasm32v1-none`) produce deterministic SHA-256 digests verified by `stealthbridge-contracts/scripts/verify_artifacts.py` and `stealthbridge-backend/scripts/verify_manifest.py`.
