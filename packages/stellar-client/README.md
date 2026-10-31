# Stellar client — legacy monorepo placeholder

The supported **public, read-only TypeScript client** is in [stealthbridge-sdk](https://github.com/stealthbridge-labs/stealthbridge-sdk). Live Testnet RPC observation and account/recipient checks are implemented in the [Rust backend](https://github.com/stealthbridge-labs/stealthbridge-backend), with bounded frontend same-origin reads.

No signer, key custody, confidential transfer or financial transaction client is exposed from this placeholder. Smart-account published-code preflight is a separate read-only tool under [tools/smart-account-preflight](../../tools/smart-account-preflight/README.md).
