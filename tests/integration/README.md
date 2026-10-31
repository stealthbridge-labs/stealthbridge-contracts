# Protocol integration tests — evidence required

This reserved folder does not itself establish a tested confidential-payments service. Current source-level Soroban integration tests belong to their Rust crates; SDK↔backend compatibility tests run in their respective repositories.

Future integration evidence must bind exactly reviewed contract IDs and WASM hashes to independent Testnet readbacks, actual issuer and smart-account authorization, proof verification and settlement reconciliation. Never use production customer funds or operator secrets in tests.

See [protocol verification](../../docs/TESTPLAN.md) and [smart-account release plan](../../docs/CUSTOMER-SMART-ACCOUNT-RELEASE-PLAN.md).
