# Security Policy — StealthBridge (contracts)

## Scope
This repository contains experimental **Stellar Testnet-only** smart contracts, Zero-Knowledge verifiers, and Smart Account primitives for StealthBridge. It is not audited financial software. Real funds, mainnet secrets, private payment spend notes, ZK witness secrets, operator signer keys, and actual bank/custody integration data must never be used.

## Responsible reporting
Do not disclose critical vulnerabilities or zero-day exploits in public GitHub issues or pull requests.

If the repository's GitHub private vulnerability reporting is enabled, please submit reports via **Security → Report a vulnerability**. Otherwise, contact the maintainers privately to coordinate a responsible disclosure and review process.

Please include:
- Impacted contract, function, or circuit ID
- Deterministic, non-destructive reproduction steps or test vector
- Expected vs. observed security property
- Assessment of impact (e.g., unauthorized auth bypass, replay attack, state corruption)

Do not include private keys, real customer data, or live network exploits.

## Cryptographic & Smart Contract Security Commitments
- **Zero-Knowledge Verifiers:** `PrivacyVerifier` implements pairing checks over the BN254 curve with single-use nullifiers and expiring Merkle roots. Replay protection is enforced on-chain.
- **Smart Accounts:** `StealthBridgeSmartAccount` validates WebAuthn secp256r1 passkey signatures and Ed25519 signatures with role-based policies, session key spending limits, and timelocked guardian recovery.
- **Governance & Execution Gates:** Emergency pause controls fail closed. Uninitialized, paused, or mismatched contracts reject all state transitions.

## Important
No guarantee of financial security or transaction finality is made until formal verification, independent cryptographic audit, and mainnet governance deployment are complete. All deployments remain restricted to Stellar Testnet.
