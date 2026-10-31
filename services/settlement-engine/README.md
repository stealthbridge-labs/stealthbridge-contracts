# Settlement engine — legacy monorepo placeholder

This folder has **no deployed execution engine**. The Rust backend holds an internal settlement-state model and replay-protection foundations, but public money-moving operations and payout-provider integrations remain disabled.

A real engine requires issuer-verified assets, secure smart-account authorization, independently validated confidentiality, exact pricing, on-chain finality and separate payout reconciliation. Do not enable funds or fees from infrastructure readiness alone.

See [backend settlement journal](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/docs/SETTLEMENT-JOURNAL.md) and [root safety scope](../../README.md).
