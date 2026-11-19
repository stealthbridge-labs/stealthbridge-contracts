# StealthBridge Milestone 6 — Release Readiness Report

**Status:** Stellar Testnet Engineering Complete (Milestones 1–6) · **NO-GO for Mainnet / Customer Funds**  
**Repositories covered:** `stealthbridge-contracts`, `stealthbridge-backend`, `stealthbridge-sdk`, `stealthbridge-frontend`  
**Network scope:** Stellar Testnet only (`mainnet_enabled = false`, `payment_execution_enabled = false`, `live_fx_enabled = false`, `fiat_payouts_enabled = false`)

---

## 1. Executive Summary

Across Milestones 1 through 6, the StealthBridge engineering platform was reconciled from upstream `main` across all four repositories, stabilized on Stellar Testnet observer & Protocol 30 infrastructure, extended with reproducible privacy-rail evaluations and a controlled Postgres-backed Testnet settlement lifecycle, and refined into cohesive Personal and Business web workspaces with honest failure, empty, and unverified states.

StealthBridge **does not fabricate balances, FX quotes, customers, compliance approvals, privacy guarantees, or fiat payouts**. Real-money execution, Mainnet deployment, live FX/liquidity quotes, regulated asset issuance, and fiat off-ramping remain strictly disabled behind explicit server-side flags, contract boundary checks, and release gates.

---

## 2. What Is Working Today

### 2.1 Authentication, Protocol 30 & Smart-Account Inspection
- **Wallet-authenticated customer session:** Freighter / Stellar signed-message challenge-response flow with cookie-bound backend-for-frontend session proxy (`POST /api/auth/challenge`, `POST /api/auth/verify`) without requesting secret keys or granting transfer authority.
- **Protocol 30 & CAP-84 `W...` compatibility:** Strict StrKey validation and parsing across `@stellar/stellar-sdk` and backend validators accepting `G...`, `M...`, `C...`, and CAP-84 `W...` muxed contract addresses without permissive regex fallbacks.
- **Smart Account Kit read-only monitoring:** Backend `GET /v1/wallet/smart-account-kit` and `AccountAccessSecurity` verify 7 pinned upstream Testnet artifact hashes & TTLs alongside local device passkey availability checks (no enrollment or recovery claim made).

### 2.2 Public Observation & Corridor Catalog
- **Public Stellar Testnet observer (`stealthbridge-backend`):** Bounded streaming RPC/Horizon reads with strict Testnet passphrase verification, fresh-ledger checks, and cross-repo CI parity (`scripts/verify_observation_pipeline.py`).
- **Live PostgreSQL/SQLx corridor catalog:** Authenticated & public read paths returning real configured Testnet corridors with fail-closed `400`/`404`/`503` degradation when empty or unreachable.
- **Opt-in Testnet recipient existence checks:** Explicit user-triggered `GET /api/public/classic-recipient/...` (`G...`/`M...`) and `GET /api/public/recipient/...` (`C...`/`W...`) confirming ledger existence while explicitly marking ownership and asset acceptance as unverified.

### 2.3 Personal & Business Product Experiences (`stealthbridge-frontend`)
- **Personal workspace (`/app`, `/app/send`, `/app/instructions`, `/app/settings`):**
  - Account overview & optional profile preferences (`AccountJourney`, `CustomerProfileSettings`).
  - Route selection, plain-language privacy mode disclosures (`describePrivacyRailForCustomer`), browser-local saved recipients (`src/lib/local-beneficiaries.ts` stored only in `localStorage` keyed by connected wallet), randomized SHA-256 local review receipts (`createPrivateReviewReceipt`), and encrypted payment instructions stored on `/api/account/instructions` (`PaymentInstructions`, `CustomerDraftVault`).
  - Controlled Testnet lifecycle UI (`SettlementLifecyclePanel`) with 7-stage visual progression (`stageProgressForLifecycle`), expandable audit event logs, and CSV/JSON reconciliation downloads (`src/lib/settlement-reconciliation.ts`) exported directly from real loaded records with zero fabricated numbers.
  - Wallet identity disclosure, non-custodial passphrase recovery warnings, and local passkey device checks (`AccountAccessSecurity`).
- **Business workspace (`/app/business`, `/app/business/[id]`, `/app/business/payments`, `/app/business/batch`, `/preview/approvals`, `/preview/developers`):**
  - Pending organization onboarding (`BusinessOnboarding`, capped, clearly labeled *Pending onboarding — not legal-entity verification*).
  - Verified membership directory (`AccountOrganizations`), viewer team invitations & pagination (`OrganizationTeamWorkspace`, `TeamInvitations`).
  - Business payment workspace (`CustomerPaymentWorkspace flow="business"`), client-side CSV batch route validator (`BusinessBatchPlanner` — up to 50 rows / 8 corridors, CSV never leaves browser), unsigned SHA-256 business approval envelope hashing (`BusinessReviewWorkspace`), and live developer dependency readiness console (`DeveloperWorkspace`).

---

## 3. Testnet-Only Functionality & Recorded Evidence

- **Soroban Governance Control Plane:** Historical October 17, 2026 Testnet deployment records (`CorridorRegistry`, `PolicyRegistry`, `GovernanceGate`) paired with reproducible workspace builds and source parity checks (`stealthbridge-contracts`).
- **Controlled Testnet Settlement Lifecycle (`stealthbridge-backend/src/settlement_lifecycle.rs`, migration `202611190001`, `/api/account/settlements`):**
  - Full state machine verified end-to-end against PostgreSQL 16 (`settlement_lifecycle_e2e`) and recorded Stellar Testnet transaction finality (`tx_hash`: `f7bc8714748f7cd4a466e50d5784abc6d870269b0f8d18822eecf402e2d27cfb`, Testnet ledger `5818583`, disposable account `GCMNQ7HHWLT7YBAFGHJBVPEZEANTZTIAZXCDTYNWHLESDGRMBIITUMOW`).
  - Always halts FX quotes at `quote_unavailable` when no verified provider is configured, and enforces separate `payout_status = unavailable` even after `chain_finalized` and `reconciled`.
- **Privacy Rail PoCs (`stealthbridge-contracts/tools/privacy-rail-poc`):** Local/Testnet evaluation prototypes studying Nethermind *Stellar Private Payments* (shielded pool commitments & nullifiers) and OpenZeppelin *Confidential Tokens* (amount confidentiality + auditor viewing/issuer freeze controls).

---

## 4. Unverified Integrations & Explicit Non-Claims

The following components are **explicitly unverified and non-operational for live funds**:
1. **Live FX quotes, fee schedules & liquidity pools:** No pricing provider API or AMM/orderbook aggregator is connected; all quote UI fields display `Unavailable` / `Not quoted`.
2. **Fiat payout & banking rails:** No PSP, mobile-money partner, SEPA/ACH/NIP rail, or settlement bank ledger integration exists (`fiat_payouts_enabled = false`).
3. **Production zero-knowledge privacy:** No independent third-party cryptographic ceremony, Soroban on-chain ZK verifier contract deployment, ASP compliance server, or confidential token issuer is live.
4. **Organization KYB / customer KYC:** Registered pending businesses are application records only, not regulated financial onboarding.
5. **Customer smart-account custody & passkey recovery:** No production factory contract, WebAuthn RP-bound deployment, or independent lost-device recovery circuit is live for customer accounts.

---

## 5. External Provider Dependencies Required Before Production

To transition any corridor beyond Testnet evaluation, StealthBridge must contract and integrate:
- **Regulated Anchor / Fiat Payout Partners:** Signed SLAs, API settlement webhooks, dispute/reversal SLAs, and reconciliation feeds per destination corridor.
- **Audited Stablecoin / Confidential Asset Issuers:** Verified Stellar issuer accounts, clawback/freeze disclosure policies, and ASP list operators (if operating shielded pools).
- **FX / Liquidity Providers:** Deterministic quote APIs with signed short-lived quote commitments matching `quote_sha256`.
- **Managed Infrastructure & KMS/HSM:** Isolated production Neon PostgreSQL backups, key custody / hardware security modules for relayers & operators, and immutable audit logging.

---

## 6. Security Review Requirements & Mainnet Blockers

Before any Mainnet deployment or customer funds acceptance is permitted:

1. **External Smart Contract & Cryptography Audit:** Independent security review of `CorridorRegistry`, `PolicyRegistry`, `GovernanceGate`, `contracts/settlement-adapter`, any custom ZK circuits/verifiers, and smart-account recovery logic.
2. **Backend, Auth & BFF Penetration Test:** Independent review of WebAuthn/Freighter challenge binding, session cookies, CSRF origin enforcement, tenant RBAC (`owner`/`admin`/`operator`/`approver`/`viewer`), idempotency keys, and SQLx migrations under concurrency.
3. **End-to-End Privacy Leakage Audit:** Threat-model validation ensuring Testnet/Mainnet fee payers, RPC endpoints, metadata timings, note recovery blobs, and confidential asset auditors do not silently de-anonymize users against stated product promises.
4. **Incident Response, Reversal & Reconciliation Runbooks:** Automated ledger-to-payout reconciliation jobs, stalled-transaction recovery, circuit breakers on anomalous corridor volume, and customer support/dispute escalation tooling.
5. **Legal, Licensing & Sanctions/Compliance Controls:** Applicable money-transmitter / VASP authorizations, KYB/KYC verification flows, travel-rule / sanctions screening, and ASP governance policies per operating jurisdiction.

---

**Release Decision:** **READY for closed Stellar Testnet technical preview and engineering handoff** with all production financial flags locked to `false`. **BLOCKED for Mainnet or real customer value transfer** until Sections 4–6 are satisfied and signed off independently.
