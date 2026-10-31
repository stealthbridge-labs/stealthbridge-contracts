# Shared types — legacy monorepo placeholder

This directory is not the current cross-repository type source. **Rust backend OpenAPI** owns HTTP wire contracts, the **Soroban repository** owns the source interface, and [stealthbridge-sdk](https://github.com/stealthbridge-labs/stealthbridge-sdk) generates and validates public TypeScript read models. The [frontend](https://github.com/stealthbridge-labs/stealthbridge-frontend) pins a reviewed SDK wire model.

Avoid maintaining a second incompatible schema here. CI must check exact source revisions, bounded response shapes, disabled-money flags and Testnet identity. No payment-signing or privacy witness types are public release capabilities.
