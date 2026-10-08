# Contract verification milestones

1. Build corridor-registry WASM on an approved Rust toolchain and protocol-matched \`soroban-sdk\`.
2. Unit-test disabled defaults, authorization, enable/disable, TTL extension/restore.
3. Deploy on Stellar Testnet with explicit approval for account/credential use.
4. Record compiler, CLI, protocol, dependencies, deployed WASM digest and transaction hashes.
5. Separately validate Confidential Tokens integration and SPP proving with representative ledger observations.
6. Design and test policy/verification bridges only if the real protocol supports them.
7. No mainnet work, real stablecoin issuance, or off-ramp integration without regulatory + security review.

Local check commands, after installing toolchains:
\`\`\`sh
cargo test --workspace
stellar contract build
\`\`\`
No deploy command is executed automatically.
