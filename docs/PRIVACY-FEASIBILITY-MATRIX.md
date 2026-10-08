# Privacy primitive feasibility matrix — Research checkpoint (2026-10-08)

Evidence labels:
- **Documented upstream** = source describes behavior; not yet reproduced by StealthBridge.
- **Implemented by StealthBridge** = local demo source exists, not a cryptographic proof.
- **Verified by StealthBridge** = actual testnet transaction hash and assertion artifacts required. **No payment rail meets this status yet.**

| Question | Confidential Tokens | Stellar Private Payments |
| --- | --- | --- |
| Intended privacy | Amount + balance commitments | Amount + counterparties of private transfer |
| Public relationship | Account A → B visible | Private hop unlinkability target, but deposits/withdrawals public |
| Primary fit | B2B known-institution stablecoin transfers | Consumer remittance/receiver note journey |
| Status | Developer preview; testnet research | Developer preview alpha; testnet research |
| Asset support | Issuer/token deployment dependent | Upstream preview documentation advertises XLM and EURC testnet pools; **not an assumed USDC pool** |
| User experience | Wallet signatures, ZK proofs and issuer controls need testing | Prebuilt WASM TypeScript SDK plus Freighter signing; note storage/sync and recovery testing needed |
| Composability | Evaluate issuer-managed policy and custom Soroban integration | Evaluate gateway/recipient/withdraw semantics; do not assume arbitrary cross-contract transfers |
| Auditability | Scope issuer restrictions, viewing authorization and disclosure keys | Pool admission and optional selective disclosure are separate integration concerns |
| Transaction evidence | None yet | None yet |
| Go/no-go | Demonstrate transfer and a truthful ledger observation matrix | Demonstrate deposit → transfer → withdrawal and record public endpoints/timing |

## Source observations
- Official SPP preview: https://stellar.org/blog/developers/developer-preview-stellar-private-payments — XLM/EURC preview pools and \`stellar-private-payments@alpha\` TS/JS package; deposits and withdrawals expose external amount while private transfer has ext_amount zero.
- Issuer-controlled confidentiality essay: https://stellar.org/blog/developers/practical-confidential-stablecoins-an-issuer-controlled-architecture — issuer permissions, restrictions, scoped disclosure and proofs; no claim that a particular issuer has integrated.
- OpenZeppelin Confidential Tokens official blog: https://stellar.org/blog/developers/developer-preview-confidential-tokens-on-stellar
- Stellar ZK skill: https://skills.stellar.org/skills/zk-proofs/SKILL.md

## First POC acceptance
1. Pin SDK/protocol versions and deployed source code reference.
2. Run transfer with fresh testnet-funded accounts, only after approval to create/fund keys.
3. Record exact asset IDs, contract addresses and transaction hashes.
4. Compare expected secrecy against observer ledger, contract events, RPC values, asset history, timing and wallet side channels.
5. Independently test double spend, revoked issuer participant, missing trustline, wallet rejection and device note recovery.
6. State honestly whether the primitive supports our multi-provider corridor contract without leaks or off-chain trust assumptions.
