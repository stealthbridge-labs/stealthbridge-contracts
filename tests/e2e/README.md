# Protocol end-to-end tests — scope and limitations

This is a reserved location for protocol-level, independently reviewable on-chain Testnet acceptance. No test here should be mistaken for the full private-transfer or payout service.

The actual desktop/mobile **customer user-journey browser suite** lives in [stealthbridge-frontend/tests/browser](https://github.com/stealthbridge-labs/stealthbridge-frontend/tree/main/tests/browser). Rust/Soroban governance tests live in the contract crates, and the read-only smart-account code verifier lives under [tools/smart-account-preflight](../../tools/smart-account-preflight/README.md).

Future e2e tests must fail closed on wrong network, stale TTL, unverified issuer, replay, missing privacy proof, unexpected permissions and false payout claims.
