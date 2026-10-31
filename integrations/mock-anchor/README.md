# Mock anchor — legacy test fixture placeholder

No live partner, fiat on/off-ramp, bank account, settlement or payout provider exists here. This folder is **not a supported payment connector**. Never market it or its outputs as a real corridor.

Any future mock must run strictly in isolated tests with explicit fake-data labels, and must not be wired into customer pages, production API responses or financial accounting. Real partner integration belongs behind reviewed credentials, compliance, idempotency, webhook verification and payout reconciliation in the [Rust backend](https://github.com/stealthbridge-labs/stealthbridge-backend).

Read [provider callback security](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/docs/PROVIDER-CALLBACK-SECURITY.md).
