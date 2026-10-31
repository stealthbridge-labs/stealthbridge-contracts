# Indexer service — legacy monorepo placeholder

No separately deployed production indexer or ledger worker is implemented in this directory. The Rust backend contains **opt-in** Testnet public ledger observations and event journal primitives; follow its operator and retention documentation before running any worker.

Do not confuse public ledger checkpoint presence with confidential settlement finality, user balances or fiat payout receipts. Durable chain backfill, idempotent workers and independent reconciliation remain required release work.

See [Rust backend observer documentation](https://github.com/stealthbridge-labs/stealthbridge-backend/blob/main/docs/TRANSACTION-OBSERVATION.md).
