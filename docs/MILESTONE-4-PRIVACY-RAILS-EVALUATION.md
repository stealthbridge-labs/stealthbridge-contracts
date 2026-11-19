# Milestone 4 — StealthBridge Privacy Rails Engineering Evaluation

**Decision status:** `NO_GO` for customer execution and Mainnet (`paymentExecutionEnabled: false`, `privacy_verified: false`). Both evaluated Stellar privacy systems are **unaudited developer-preview protocols** requiring `soroban-sdk = 28.x` and cannot compose directly with StealthBridge's `soroban-sdk = "=27.0.6"` governance baseline without an isolated protocol-boundary upgrade and external audits.

Encrypted drafts (`customer_ciphertext_vault`) and SHA-256 review fingerprints (`privacy_commitment` / `private-review-commitment`) protect off-chain draft records only. They do **not** provide confidential on-chain settlement.

---

## 1. Pinned Upstream Sources & Licensing Assessment

| Component | Upstream Repository | Pinned Version / Commit | License Profile & Distribution Constraints | Soroban / Prover Runtime |
|---|---|---|---|---|
| **StealthBridge Governance** | Local workspace (`corridor-registry`, `policy-registry`, `governance-gate`) | Workspace HEAD | **MIT** | `soroban-sdk = "=27.0.6"`, `rust-toolchain 1.91.0` |
| **Confidential Tokens (System B)** | [`OpenZeppelin/stellar-contracts`](https://github.com/OpenZeppelin/stellar-contracts) *(Note: `stellar/stellar-contracts` returns Repository Not Found; canonical upstream is `OpenZeppelin/stellar-contracts`)* | Tag `v0.8.0` (`ddc327eb92d63709436da3a8455f641c2d5476c5`) | **MIT** (contracts & `packages/confidential/circuits/vks/*.vk.bin`) | `soroban-sdk = 28.0.0`, `soroban-poseidon = 28.0.0`, `ultrahonk-soroban-verifier = 0.1.0` (`rustc >= 1.92`), `nargo 1.0.0-beta.11`, `bb 0.87.0` (`--oracle_hash keccak` non-zk `ultra_flavor`) |
| **Stellar Private Payments (System A)** | [`NethermindEth/stellar-private-payments`](https://github.com/NethermindEth/stellar-private-payments) | `main` `cebb972b5872cba3a1cc40bcdfab297168ccc1d7` (`2026-11-18T11:20:06Z`) | **Mixed copyleft hazard:** root workspace **Apache-2.0**, workspace crates `edition = "2024"` / `rust-version = "1.95.0"`, `sdk/native` uses git dep `circom-compat#wasm-no-parallel` + `sqlite3mc-src = 205.1.0`; **`circuits/*.circom` statically link `circomlib` (`LGPL-3.0`)** into compiled `.wasm`/`.r1cs`/`.zkey` artifacts (`circuits/LICENSE`), and `tools/circuit-compiler` is **`GPL-3.0`** | `soroban-sdk = 28`, native BN254 pairing precompile + Poseidon2, Groth16 / Circom / snarkjs; browser OPFS SQLite3MC WASM (`address.len() == 56` validation in `wallet_vault.rs`) |

**Licensing isolation rule:** No LGPL-3.0 or GPL-3.0 `stellar-private-payments` circuit or compiler artifacts are vendored into StealthBridge repositories. Our isolated Soroban 28 verification harness in `tools/privacy-rail-poc/` includes only MIT-licensed `.vk.bin` files from OpenZeppelin `v0.8.0` (with explicit attribution in `tools/privacy-rail-poc/THIRD_PARTY_ATTRIBUTION.md`) plus clean-room Rust/Soroban BN254 Groth16 + Poseidon2 test fixtures.

---

## 2. Architecture & Product Fit Evaluation

These two systems solve fundamentally different confidentiality problems and are **not interchangeable**:

### A. Stellar Private Payments — Evaluated for **Personal** (`private-payments`)
- **Mechanism:** Shielded UTXO commitment pool using Poseidon2 binary Merkle tree (`ROOT_HISTORY_SIZE = 90` ring buffer in `MerkleTreeWithHistory`), BN254 Groth16 (`circom-groth16-verifier` with compile-time embedded VK), nullifier mapping, and Keccak-256 domain-bound `ExtDataDomain` (`pool`, `token`, `recipient`, `ext_amount`, `encrypted_output0`, `encrypted_output1`).
- **Compliance / ASP:** Supports optional allowlist (`asp-membership`, 90-root history, verified wasm hash check `TreeCodeMismatch`) and blocklist (`asp-non-membership`, sparse Merkle tree up to **31 levels** in circuits and **single current root only — no root history** in `pool.rs`). An in-flight user proof fails with `InvalidProof` if the ASP blocklist root advances before inclusion. `pool-gvk` adds an immutable admin BabyJubJub Global View Key `D` (`GvkMode`).
- **State, Notes & Recovery:** Clients persist private notes and Merkle paths locally (native/browser SQLite3MC WASM sealed via wallet-derived XSalsa20Poly1305 secret). Device loss or OPFS wipe destroys spending capability unless the recovery seed is exported **and** every historical `NewCommitmentEvent` can be scanned via a durable indexer beyond RPC ledger pruning.
- **Protocol 30 compatibility note:** `sdk/native/src/state/wallet_vault.rs` currently enforces `context.address.len() == 56`, blocking Protocol 30 M/W muxed addresses.

### B. Confidential Tokens — Evaluated for **Business** (`confidential-token`)
- **Mechanism:** Account-based Grumpkin Pedersen commitments split across `spendable_commitment`, homomorphic `receiving_commitment`, and per-spender `SpenderDelegation` (`allowance_commitment`, expiring after `live_until_ledger`), proved with Noir circuits + `bb` Keccak UltraHonk (`ultra_flavor`, explicitly non-zk). Replay across transactions is prevented by commitment chaining (`C_spend -> C_spend_new`), and across contracts by `addr_f = Poseidon2(delta_addr, lo, hi)` on register/transfer/withdraw.
- **Compliance & SAC Hazards:** `ComplianceHooks` supports `freeze`, `unfreeze`, external `Policy::is_authorized`, optional `sac_passthrough` (`sac.authorized()`), and `clawback`. Two critical operational hazards are documented in `packages/confidential/src/lib.rs` and `docs/compliance.md`:
  1. Freezing the wrapper contract's own address on the underlying SAC halts **all** deposits and withdrawals (`PoolSacFreezeDeadlock`).
  2. Calling underlying SAC `clawback` against the pool reserve directly before confidential `clawback()` creates a **socialized reserve shortfall** across holders.
  3. Fee-on-transfer and rebasing SEP-41 tokens break `deposit`/`withdraw` supply conservation because amounts are credited/debited without re-measuring delta balance.
- **Recovery & Indexer Dependency:** Seed recovery requires total ordering `(ledger_seq, tx_application_order, event_index)` across all `Transfer`, `Withdraw`, `Merge`, `SetSpender`, and `RevokeSpender` events indefinitely. Wallet seed recovery fails once RPC ledgers prune past account creation without a durable archival indexer.

---

## 3. On-Chain Observer Visibility Matrix

| Action | Passive Chain / RPC Observer Sees | Hidden from Public Chain | Operator / Auditor / ASP Visibility |
|---|---|---|---|
| **Encrypted Draft / Review Fingerprint (StealthBridge)** | Nothing (off-chain DB ciphertext or SHA-256 hash only) | Vault ciphertext payload if DB/browser-protected | Operator stores ciphertext blob (metadata/account binding visible to backend DB); **not on-chain settlement** |
| **SPP Deposit / Withdrawal** | Outer sender/fee-payer, pool & token IDs, edge `recipient`, exact `ext_amount`, `fee`, encrypted output blobs, nullifiers | Which shielded note was funded/spent inside pool (except timing/amount correlation) | ASP sees allowlist/blocklist state; under `pool-gvk`, admin `D` decrypts GVK ciphertexts |
| **SPP In-Pool Transfer** | Outer tx fee-payer / relayer, nullifiers, two new commitments, encrypted note payloads | Internal sender/recipient shielded keys and net transfer amount | Same as above; GVK admin `D` sees internal amounts if `pool-gvk` deployed |
| **Confidential Token Register / Merge / Revoke** | Public `account` (`from`), `auditor_id`, commitments `y`/`pvk` | Opening `(balance, blinding)` | Bound auditor holds `K_aud` |
| **Confidential Token Deposit / Withdraw** | Public `from`, `to`, **exact plaintext `i128` amount**, commitment updates | Remaining spendable balance scalar `b` (unless auditor decrypts) | Bound auditor decrypts sender balance checkpoint `(b_tilde_aud_s, r_tilde_aud_s)` |
| **Confidential Token Internal Transfer** | Public `from` and `to` addresses (full B2B counterparty graph!), commitments & ciphertexts | Internal transfer amount `v` and updated spendable balance `b'` | **Sender's AND recipient's registered auditors (`K_aud_s`, `K_aud_r`) decrypt transfer/balance values**; compromised viewing key `vk` opens deterministic `r_e` ciphertexts retroactively |

---

## 4. Evidence Stratification Matrix

| Evidence Tier | Exact Scope Verified in Milestone 4 | What Remains Unverified / Blocked |
|---|---|---|
| **1. Direct Upstream Source Inspection** | Audited OZ `stellar-contracts v0.8.0` (`packages/confidential`, `examples/confidential`, `docs/compliance.md`, `circuits/vks`) & Nethermind SPP (`cebb972b`: `pool`, `pool-core`, `pool-gvk`, `asp-membership`, `asp-non-membership`, `circom-groth16-verifier`, `wallet_vault.rs`, `circuits/LICENSE`). | Future unreleased upstream commits after `v0.8.0` / `cebb972b`. |
| **2. Local Cryptographic & Contract Execution** | Ran OZ `v0.8.0` tests locally (**115 passed** in `stellar-confidential`; **22 passed** in `compliant-token`; **7 passed** in `factory`; **5 passed** in `verifier` parsing all six `1760 B` `.vk.bin` files). Built isolated Soroban 28 crate [`tools/privacy-rail-poc`](../tools/privacy-rail-poc/README.md) (**15/15 adversarial tests passed offline `--locked`**) exercising real Soroban `env.crypto().bn254()` Groth16 pairing, real MIT OZ `ultrahonk_soroban_verifier` rejection on `.vk.bin` files, `soroban-poseidon` pairs, and elliptic-curve Pedersen conservation. Verified SDK (`295/295`), Backend (`privacy_rails` + `clippy` + OpenAPI guard), and Frontend (`typecheck`, `lint`, tests). | Full proof **generation** (`nargo 1.0.0-beta.11`, `bb 0.87.0`, `circom`, `snarkjs`) is NOT installed on this host, so positive full UltraHonk `.proof` generation and Circom `.wasm`/`.zkey` witness proving were not run locally. |
| **3. Read-Only Testnet RPC Observation** | Queried `soroban-testnet.stellar.org` (`getHealth` & `getNetwork`): `protocolVersion: 30`, `passphrase: "Test SDF Network ; September 2015"`, `latestLedger: 5817799`, `oldestLedger: 5696840`, **`ledgerRetentionWindow: 120960`** (~7.0 days). | Live Testnet transaction submission, live pool/confidential-token deployment, fee sponsorship, and browser OPFS persistence under load. |
| **4. Architectural & Security Sign-Off** | Adapter isolation implemented across Contracts PoC, Backend [`privacy_rails.rs`](../../stealthbridge-backend/src/privacy_rails.rs), SDK [`privacy-rails.ts`](../../stealthbridge-sdk/src/privacy-rails.ts), and Frontend [`privacy-rails.ts`](../../stealthbridge-frontend/src/lib/privacy-rails.ts). | External cryptographic audits, Soroban 27 -> 28 migration review for governance contracts, legal sign-off on ASP/auditor custody & LGPL-3.0 compliance. |

---

## 5. Complete 15-Vector Adversarial Test Coverage

Executed in [`tools/privacy-rail-poc/tests/adversarial_vectors.rs`](../tools/privacy-rail-poc/tests/adversarial_vectors.rs) (`cargo test --offline --locked`, 15 passed, 0 failed):

| # | Vector | Attack / Failure Mechanism Tested | Observed Verification Result |
|---|---|---|---|
| 0 | Isolation Guard (`adapter_prevents_draft_confusion_and_rail_interchange`) | Submitting `EncryptedDraftArtifact` for settlement or routing `ConfidentialSep41Token` through `PrivatePaymentsAdapter` | Rejected (`DraftNotSettleableOnChain`, `RailMismatch`) |
| 1 | Invalid proofs | Tampered BN254 Groth16 curve point `C` checked via `env.crypto().bn254().pairing_check`; forged proof bytes checked against OZ MIT `register/transfer/withdraw.vk.bin` in `UltraHonkVerifier` | Rejected (`InvalidProof`) |
| 2 | Modified recipient data | Swapping withdrawal `ext_data.recipient` while retaining valid proof for old `ext_data_hash` | Rejected (`RecipientMismatch`) |
| 3 | Modified amounts | Changing `ext_amount` with matching `ext_data_hash` vs committed `public_amount`; changing transfer scalar vs Pedersen commitment difference `C_old - C_new` | Rejected (`AmountMismatch`) |
| 4 | Replayed authorization | Re-submitting identical signed confidential transfer payload after `spendable_commitment` chained to `c_spend_new` | Rejected (`ReplayedAuthorization`) |
| 5 | Duplicate nullifiers | Supplying `nullifiers[0] == nullifiers[1]` in one pool `transact` call | Rejected (`DuplicateNullifier`) |
| 6 | Double spends | Reusing an already recorded nullifier in a second pool transaction | Rejected (`DoubleSpend`) |
| 7 | Expired commitments / allowances | Advancing SPP `MerkleTreeWithHistory` past `ROOT_HISTORY_SIZE = 90` evicting `initial_root`; advancing `ledger_seq > live_until_ledger` on `SpenderDelegation` | Rejected (`ExpiredCommitmentRoot`, `ExpiredDelegationAllowance`) |
| 8 | Wrong-network / contract binding | Replaying proof across `Public Global Stellar Network ; September 2015` vs Testnet or mismatched `contract_addr` domain | Rejected (`WrongNetworkOrContractDomain`) |
| 9 | Invalid asset identities & SAC hazards | `FeeOnTransfer` SEP-41 semantic rejection, observed reserve delta `< ext_amount`, `sac_passthrough` pool reserve freeze deadlock, underlying SAC clawback shortfall | Rejected (`AssetNotExactTransfer`, `ReserveShortfallDetected`, `PoolSacFreezeDeadlock`) |
| 10 | Missing note data / opening | Clearing client opening `(v, r)` for an existing on-chain commitment blocks transfer generation | Rejected (`MissingLocalOpeningOrNotes`) |
| 11 | Failed recovery | Seed present, corrupt XSalsa20Poly1305 / SQLite3MC backup fails decryption (`BackupCorruptOrDecryptionFailed`); healthy seed succeeds (`Ok(1)`) | Verified exact fail/recover split |
| 12 | Device loss | Lost local OPFS/SQLite state without backed-up seed fails cold recovery (`DeviceLossWithoutRecoverySeed`) | Rejected (`DeviceLossWithoutRecoverySeed`) |
| 13 | Malicious or unavailable ASP | ASP offline (`AspUnavailableOrStaleRoot`), ASP censoring (`AspUnilateralCensorship`), and mid-flight non-membership root drift (`pool.rs` single current SMT root without history) | Rejected cleanly |
| 14 | Event-retention & indexing gaps | Account created at ledger `5_500_000` vs observed Testnet RPC `oldestLedger = 5_696_840` without durable indexer fails recovery; durable archival indexer restores (`Ok(())`) | Verified (`LedgerHistoryPruned` vs recovered) |
| 15 | Metadata correlation & disclosure boundaries | Asserts `PrivatePaymentsAdapter` exposes outer sender/edges while hiding internal graph vs `ConfidentialTokenAdapter` exposing counterparty graph and auditor keys while hiding amounts | Verified exact disclosure flags |
