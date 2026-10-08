# StealthBridge

**Confidential payments. Without borders.**

StealthBridge is an experimental, **testnet-only** cross-border payment platform on Stellar. It comprises:

- **StealthBridge Business** — confidential settlements between known payment providers and businesses (amount and balance confidentiality is the intended initial model).
- **StealthBridge Send** — private consumer remittance journeys (amount and payer–recipient relationship privacy are intended, subject to feasibility validation).
- **StealthBridge Protocol** — shared corridor configuration, orchestration, policy enforcement, privacy integrations, and developer interfaces.

## Status

**Sprint 0 / architecture proposal — no contracts deployed or privacy guarantees established.** Do not transfer real funds or use this as production financial infrastructure.

## Principles

1. Privacy properties must be demonstrated, not assumed.
2. Reuse reviewed Stellar privacy primitives rather than inventing cryptography.
3. Distinguish blockchain finality from fiat payout completion.
4. Never put plaintext confidential payment amounts or ZK witnesses in application logs.
5. Use only testnet assets and mocked fiat rails during initial engineering.
6. Compliance requirements must be designed with qualified partners before real-world rollout.

## Layout

- `apps/business` — planned B2B dashboard
- `apps/send` — planned consumer sender/receiver interface
- `services/api` — planned service API
- `services/settlement-engine` — planned settlement state machine and reconciliation
- `services/indexer` — planned Stellar ledger event ingestion
- `contracts` — potential Soroban modules; interfaces intentionally **not yet frozen**
- `packages/privacy-adapters` — separate Confidential Tokens and SPP adapters
- `integrations` — privacy, FX, and fiat connector implementations
- `docs` — foundational specs and decisions
- `tests` — future integration and end-to-end tests

## Begin here

1. Read [Product Requirements](docs/PRODUCT.md).
2. Read [System Architecture](docs/ARCHITECTURE.md) and [Privacy Model](docs/PRIVACY-MODEL.md).
3. Review [ADRs](docs/adr/) and [Sprint 0 Backlog](docs/SPRINT-0.md).
4. Confirm current Stellar library API compatibility and testnet deployability before writing payment contracts.

## Security

No production use. Do not commit seeds, mnemonic phrases, wallet private keys, API tokens, plaintext KYC data, payment witnesses, or other secrets. See [SECURITY.md](SECURITY.md).

## License

License decision pending. No open-source license is granted merely by publishing the repository.
