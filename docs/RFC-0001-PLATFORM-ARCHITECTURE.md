# RFC-0001 — StealthBridge Multi-Product Settlement Architecture

Status: **Proposed** · Date: 2026-10-08 · Network: **Stellar Testnet only**

## 1. Architectural objective

Serve two payment experiences with shared corridor and settlement infrastructure but different privacy models:

- **Business**: institution-to-institution confidential transfer; payment amounts/balances shielded, parties may remain public.
- **Send**: consumer shielded remittance; private payer–receiver relationship inside the pool, with explicit public deposit/withdraw edges.
- **Protocol/SDK**: reusable developer interfaces allowing external PSPs to integrate without duplicating proving/payment logic.

**Not** a claim of a deployed confidential token, stablecoin issuance, remittance processor, AML compliance service, regulated off-ramp, or audited ZK system. Our objective is an integrable protocol stack which can eventually support those after validation.

## 2. System context

\`\`\`mermaid
flowchart LR
  B[Institutional operator] --> F[StealthBridge Business]
  C[Individual sender / receiver] --> S[StealthBridge Send]
  F --> SDK[Typed SDK, wallet adapters]
  S --> SDK
  SDK --> P[Privacy adapter - client owned proving]
  SDK --> A[StealthBridge API]
  A --> O[Settlement orchestrator]
  O --> DB[(Postgres transactional journal)]
  O --> X[FX quote + payout interfaces]
  O --> I[Stellar RPC/indexer reconciler]
  P --> CT[Confidential Token contracts]
  P --> SPP[SPP shielded pool]
  CT --> L[Stellar testnet]
  SPP --> L
  I --> L
  X --> MOCK[Mock fiat provider in initial prototype]
\`\`\`

Contract modules must be _minimal_: on-chain corridor enablement and policies only when genuinely enforceable within chosen privacy primitive; proof-binding and privacy-preserving events must be assessed before custom code is written. Avoid creating additional on-chain metadata linking sender and recipient.

## 3. Bounded contexts / owner repository

| Context | Owner | Canonical spec |
| --- | --- | --- |
| UX, wallet and local proof display | frontend | product flows and design system |
| Public API & settlement lifecycle | backend | api/openapi.yaml |
| Corridor registry, verifier, on-chain invariants | contracts | ABI, tests, testnet deployment manifest |
| Stable interface types & generated clients | sdk | specs/COMPATIBILITY.md |
| Network/asset identity & software versions | contracts | deployments/testnet/manifest.json |
| Fiat-provider protocol + callback handling | backend | per-provider integration documentation |
| Selective disclosure scope and access | contracts + backend | privacy model / threat model |

We deliberately **do not** run backend private proving or store user's spend keys by default. Any future managed wallet must be a separate security and custody ADR.

## 4. Four distinct flows (do not collapse)

### 4.1 B2B confidentiality
Funding/issuer eligibility → wallet authorization → confidential token transfer proof → verification on Stellar → chain receipt → off-chain business reconciliation. Sender and receiver addresses can remain visible. Issuer-controlled accounts need freezing, scoped audit and redemption mechanisms.

### 4.2 Consumer anonymity
Public deposit → encrypted note creation and sync → shielded transfer → receiver's proof/claim → public withdrawal → local payout provider. The existence, timing, endpoint addresses and amounts at the edges can still be observed. Small anonymity sets or correlated rates can materially reduce privacy.

### 4.3 FX / asset corridor
Asset at origin, quoted FX obligation, target asset/fiat settlement, provider liquidity and price freshness are **separate economic legs**. A single protected Stellar token transfer does not inherently exchange currencies or guarantee local fiat delivery.

### 4.4 Cross-chain (deferred)
CCTP and alternate bridges require signed attestation, precision normalization, refund strategy, separate chain finality, destination funding/trustlines and independently audited risk review. Never advertise cross-chain settlement from a Stellar-only test.

## 5. API and identity
Use stable \`tenant_id\`, \`corridor_id\`, \`quote_id\`, \`settlement_id\`, \`attempt_id\` and \`external_payout_id\` throughout. Support idempotency keys scoped to an authenticated tenant and payload digest; reject same key with different payload. Public endpoints must never expose other tenant's settlement or KYC. Track per-network asset ID + issuer + decimals, not symbolic label alone. Reserve wallet challenge signing and scoped capability tokens for a formal auth design.

## 6. Financial accounting and reconciliation
Treat amounts as fixed-decimal integers at every boundary (no JS float for real settlement). Separate: funded liability, on-chain proof submission, chain finalized receipt, payout committed, payout completed, refund outstanding, refunded. Persist immutable transitions and compensated retries using transactional inbox/outbox. On provider callbacks: verify signature, freshness, tenant, payout reference, deduplication, ordering and valid transition. Keep independently reconciled balances; confidential commitments require special proofs/view access, not naive ledger arithmetic.

## 7. Multi-tenancy and operational scale
Start with a modular monolith for API+orchestrator, not microservices by default. Enforce tenant boundary in SQL and domain layer; move high-volume indexing and proof-intensive jobs into separate workers when measured workloads justify it. Partition event history, index by tenant/settlement reference, rate-limit per tenant, use backpressure for RPC and quote providers, and retain per-corridor circuit breakers. Multi-corridor policy updates require versioned, reviewable transitions with a replay story.

## 8. Security and operational trust
- Role-based access to API operations, approvals and issuer controls with explicit authority source.
- Signing operations stay on user device or explicitly approved managed signer; no hardcoded keys.
- Key rotation, admin multi-approval and contract upgrade governance before production.
- Proof public inputs bound to actual context; nullifier and chain replay defenses.
- Metadata and logs redaction; no secrets or protected amounts in analytics by default.
- Security/privacy incident response; limited KYC retention.
- Off-ramp compliance and licensed partner due diligence are required outside cryptography.

## 9. Stablecoins and issuer-control roadmap
The new issuer-controlled confidential stablecoin work from OpenZeppelin makes this more than a generic USDC router. Candidate B2B solution: issuer-managed confidential stablecoin wrapper/token with _visible account identity, concealed values, issuer restriction capability, scoped disclosure_, and clear redemption/reserve semantics. This is a design candidate only: do not automatically describe an asset as real USDC or commit to an unaudited issuer token. Maintain separate \`testnet-demo-asset\` identifiers.

## 10. Test strategy and exit gates
G1. Pin toolchains and source commits; reproduce vanilla confidential token transfer on current Testnet.
G2. Reproduce SPP deposit/transfer/withdraw with publicly documented observed disclosure fields.
G3. Validate usable wallet and secure local note/witness recovery. Measure proving time and CPU/memory.
G4. Validate interoperability boundaries with our registry/policy contracts (or explicitly conclude unsupported).
G5. Simulate settlement concurrency, callback races, chain rejection and recipient recovery.
G6. End-to-end UI with honest loading/error states and accurate contract status.
G7. Independent review of compliance, legal and security posture before any real-value pilot.
G8. Only after verifiable artifacts: begin structured contributor issues, grant/funding preparation, Drips profile and licensing.

## 11. Benchmark against Tukar
Tukar already has real testnet shielded corridors, documented compliance proofs, FX gates and other integrations. We do not claim any of those as our differentiator. Our thesis is **a stronger reusable multi-provider interface**, stable issuer-controlled B2B asset paths and shared SDKs alongside a consumer product. Prove these in code and partner integrations before claiming to be an advancement.

## 12. Open architectural decisions
D1 managed custody versus exclusively self-custodial UX; D2 issuer token vs pool wrapper; D3 audit key access model; D4 quote signer and oracle acceptance; D5 refund authority; D6 network-specific proof version compatibility; D7 licensing + Drips distribution; D8 deployment and data residency.
