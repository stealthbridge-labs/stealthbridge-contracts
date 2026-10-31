# Stellar Private Payments — verification research only

This integration is **not a deployed, accepted or operational private-payment corridor**. No user can currently send a shielded StealthBridge payment, and the public governance contracts do not protect sender/recipient relationships.

Read [pre-execution verification gates](VERIFICATION-GATES.md) and the [independent privacy evidence vectors](../privacy-evidence-vectors.v1.json). Tests must establish actual source/proof validity, nullifier/replay constraints, issuer identity, account recovery and on-chain event leakage before a Testnet pilot can be considered.

No private witness should be uploaded to a customer API or logged. Real remittances, FX, platform fee collection and fiat payouts are disabled. See the [privacy release requirements](../../docs/PRIVACY-RELEASE-GATES.md).
