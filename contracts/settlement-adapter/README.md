# Settlement adapter — Source-only governance-gated adapter crate

Implements a source-only Soroban `27.0.6` contract (`stealthbridge-settlement-adapter`) connecting StealthBridge's cross-registry `GovernanceGate`, explicit customer authorization (`payer.require_auth()`), replay protection (`Receipt(payer, intent_sha256)`), expiry enforcement (`expires_at_ledger`), exact-transfer SEP-41 delta checks, fail-closed quote and privacy-proof gates, and emergency pause/admin controls.

**Deployment boundary:** Neither this crate nor the fee vault is deployed to Testnet (`deployments/testnet/manifest.json` remains `"status": "not-deployed"`). Existing October 2026 deployed contracts (`corridor-registry`, `policy-registry`, `governance-gate`) remain unchanged.
