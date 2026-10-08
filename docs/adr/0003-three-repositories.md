# ADR-0003: Three connected repositories

Status: Accepted — target organization structure, implementation pending

## Decision
Use three independently versioned repositories:

1. `stealthbridge-frontend`: Business dashboard and consumer remittance interfaces (separate apps within this frontend repository).
2. `stealthbridge-backend`: API, settlement orchestrator, indexing, and integrations.
3. `stealthbridge-contracts`: Rust/Soroban contracts, cryptographic protocol adapters where on-chain, deployment manifests, ABI artifacts and tests.

## Interconnection
- Publish versioned contract bindings/ABIs and TypeScript client package from contracts with explicit compatibility tags.
- Backend exposes a documented OpenAPI specification and event model.
- Frontend consumes a generated API client and matching pinned contract client.
- Shared `network-config` schema defines Stellar network, passphrase, token IDs and deployed contracts; no private keys.
- Contract releases pin testnet deployments and ensure integration tests run across version pairs.
- Every release uses a compatibility matrix; avoid referencing unpinned main branches.

## Migration plan
Keep this repository intact as the Sprint 0 source of truth until the organization owner creates the two new repositories and renames this repository to `stealthbridge-contracts`, or creates three new repositories and explicitly keeps this as a documentation umbrella. Avoid deleting planning documents or moving files until destinations exist.

## Alternatives rejected
Single monorepo for all services and apps: simple to start, but less aligned with the team's desired independent service lifecycles.
One repository per app: duplicates shared infrastructure and contract integration.

## Consequences
More CI, cross-repository release coordination and dependency management. Prefer keeping the initial specs in the contracts/core repository while splitting app/service ownership once repository availability is confirmed.
