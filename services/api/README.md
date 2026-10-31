# API service — legacy monorepo placeholder

The running API is maintained in [stealthbridge-backend](https://github.com/stealthbridge-labs/stealthbridge-backend) (Rust/Axum, Neon PostgreSQL, Stellar Testnet RPC), not in this folder. The customer app and authenticated BFF are in [stealthbridge-frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend).

Use the backend's canonical OpenAPI and SQLx migrations; do **not** create a parallel payments API or store keys here. Infrastructure readiness is not permission for money movement.
