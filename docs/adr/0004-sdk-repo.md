# ADR-0004: Adopt four repositories including SDK

Status: Accepted as architecture organization; SDK implementation pending.

The current organization has four repositories:

- `stealthbridge-contracts`: Soroban contracts and on-chain verification/deployment artifacts, plus protocol security architecture.
- `stealthbridge-backend`: Rust API, settlement orchestration, indexing and mock fiat integrations.
- `stealthbridge-frontend`: Business and Send frontend applications.
- `stealthbridge-sdk`: client libraries, protocol bindings and version compatibility specifications.

This supersedes ADR-0003's three-repository target. Keep contract ABI artifacts and backend OpenAPI specs source-controlled at their origin; generate and publish SDK clients with pinned versions. Avoid moving legacy Sprint 0 files until the relevant target repository has reviewed copies. Changes across repositories require compatibility tests and independent releases.
