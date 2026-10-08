# Primary technical references — assessed 2026-10-08

Read:
- Stellar official skill index https://skills.stellar.org
- Smart contracts https://skills.stellar.org/skills/smart-contracts/SKILL.md
- Frontend https://skills.stellar.org/skills/dapp/SKILL.md
- ZK proofs https://skills.stellar.org/skills/zk-proofs/SKILL.md
- Cross-chain https://skills.stellar.org/skills/cross-chain/SKILL.md
- OpenZeppelin setup https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-skills/main/skills/setup-stellar-contracts/SKILL.md
- Stellar official docs https://developers.stellar.org/docs
- Issuer-controlled stablecoins https://stellar.org/blog/developers/practical-confidential-stablecoins-an-issuer-controlled-architecture
- SPP testnet preview https://stellar.org/blog/developers/developer-preview-stellar-private-payments
- Tukar reference https://github.com/PugarHuda/tukar

Important skill notes:
- Soroban Rust SDK major tracks protocol (the consulted skill referenced 27); verify actual target network protocol before testnet deployment.
- SDK v16 JS expects Node 22+, wallet signing stays on client.
- ZK primitive availability (BN254, UltraHonk) does **not** guarantee custom protocol composition or audited correctness.
- Cross-chain CCTP bridge is a later milestone with 6-vs-7 decimal asset precision and asynchronous attestation concerns.
- OpenZeppelin setup skill is AGPL-3.0-only. We reference it, but **do not copy/redistribute its code** without a licensing decision.
- DeFindex is a vault SDK, not needed for core corridor settlement; no integration scheduled.
- OpenZeppelin Relayer requires future service/credential provision; not set up.
