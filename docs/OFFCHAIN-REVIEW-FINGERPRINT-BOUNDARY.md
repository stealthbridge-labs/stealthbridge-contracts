# Off-chain customer review fingerprints are not on-chain privacy proofs

StealthBridge Send and Business now have a **browser-owned**, random-salted
SHA-256 review fingerprint. It is intentionally *not* a Stellar transaction,
Soroban authorization invocation, privacy-pool commitment, confidential-token
commitment, Groth16/UltraHonk proof, wallet signature, policy declaration,
proof of funds, or operator approval.

## Exact boundary

- Domain: `StealthBridge private local review v1` with an explicit Stellar Testnet
  passphrase, route UUID, origin/destination, asset, issuer, privacy rail,
  sender/recipient public addresses, amount and optional business reference.
- A 32-byte browser-generated secret salt prevents a published digest from
  making it trivial to brute-force small-entropy values. **Do not publish the
  salt or original draft.** The public fingerprint alone has no execution value.
- The scheme is independently implemented by the TypeScript SDK and Rust
  backend and has a pinned cross-language SHA-256 test vector. No public API
  receives the draft/secret. No new contract is deployed.
- `PolicyRegistry.public_commitment` is an *operator-governed, public policy
  identifier* and is never a customer receipt or verification of a ZK witness.
  A pinned negative Soroban test proves the local review vector is rejected
  when the actual policy commitment differs, even if the policy is enabled.

## Mainnet/ZK gates still missing

A reviewed, audited confidentiality mechanism must bind the actual transaction
witness, network, asset/issuer, amount, authorization context and nullifiers to
the verified on-chain verifier and verifying key. It must implement replay and
front-running protection; enforce AML/provider duties when applicable; and be
independently reproduced on Testnet. Only after this and institutional payout
reconciliation will any financial execution or sponsor/relayer path be enabled.

Do **not** take this local review digest and send it to an on-chain contract as
though it were a cryptographic payment commitment. Its salt is not a ZK witness
and its hash alone proves nothing about valid confidential balances.
