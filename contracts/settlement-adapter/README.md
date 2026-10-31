# Settlement adapter — not implemented

A **future separately reviewed** Soroban settlement adapter could connect verified asset issuance, privacy verification, authorized signing, exact fees, on-chain finality and independent payout reconciliation. **There is no executable, audited or deployed StealthBridge settlement adapter in this directory.**

Three public governance contracts deployed in October 2026 are **not** custody or asset movement contracts. No customer funds, FX quote, fee transfer, payout or confidential settlement can be executed.

Before any implementation: choose a verified issuer/legal corridor, establish asset identity and redemption support, independently reproduce confidentiality, model idempotency/replay and smart-account policies, and complete an external security/operational review. See [privacy release gates](../../docs/PRIVACY-RELEASE-GATES.md) and [root implementation overview](../../README.md).
