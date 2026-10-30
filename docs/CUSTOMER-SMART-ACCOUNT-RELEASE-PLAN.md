# Customer-owned programmable accounts — release gates

StealthBridge aims to offer recoverable passkey smart accounts for Send and role-aware policies for Business. The October 2026 deployed contracts are governance contracts, not customer accounts. The source-only experiments/restricted-account Ed25519 example is not a passkey wallet and MUST NOT be deployed as a product account.

## Verified components required before a Create account UI

1. Pin an exact Stellar Smart Account Kit revision, matching Stellar JS SDK version and reviewed OpenZeppelin Stellar Smart Account source (including the selected __check_auth authorization-digest version). Independent audit status must cover the exact code actually used, not a similarly named upstream project.
2. Verify the contract account code hash, authenticated factory and deterministic deployment provenance on Testnet; resolve potential occupied/predicted-address confusion. Confirm verifier contract and WebAuthn signature verification using real challenge/credential vectors.
3. Bind passkey RP ID and expected origin, account address, network passphrase, authorization context and nonce/expiry. Test replay, altered signatures, wrong context, wrong contract and recovery race conditions.
4. Require a second-device recovery flow before first-value custody; explicit user-visible recovery policy, rotation and revocation. Never store user private keys or passkey credentials in app logs.
5. Business: independent approval roles, per-operation spending and recipient controls, maker-checker separation and emergency revocation. No administrator/deployer universal user signer.
6. Relayer must not have unlimited funds or permissions. Pin relayer origin, network, allowed functions, sponsorship limits and record all signed requests. Sponsor API keys remain strictly server-side.
7. Integrate only after isolated Testnet end-to-end tests across frontend, SDK, backend, real deployed account, smart-account kit, and recovery; independent security review and explicit financial release decision.

The immediate customer-facing interface must not contain an enabled Create passkey, Transfer or Withdraw action. Contract-instance presence alone is not proof of __check_auth, ownership, asset acceptance or recovery. The restricted-account tests here exercise source-only auth failure modes, not production readiness.

References: https://skills.stellar.org/skills/dapp/SKILL.md; https://github.com/stellar/smart-account-kit; https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account
