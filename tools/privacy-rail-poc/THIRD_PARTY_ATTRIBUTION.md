# Third-Party Attribution & Licensing Boundaries

## 1. OpenZeppelin Stellar Contracts (`v0.8.0`, MIT)
- Upstream repository: `https://github.com/OpenZeppelin/stellar-contracts` (moved from `stellar/stellar-contracts`)
- Pinned release tag / commit: `v0.8.0` (`ddc327eb92d63709436da3a8455f641c2d5476c5`)
- License: **MIT**
- Included binary test fixtures in `fixtures/`:
  - `register.vk.bin`
  - `transfer.vk.bin`
  - `withdraw.vk.bin`
  sourced verbatim from `packages/confidential/circuits/vks/` under the MIT License for local offline `ultrahonk-soroban-verifier` verification testing.
- Upstream dependency note: full Noir prover reproduction additionally requires external `nargo 1.0.0-beta.11` and `bb 0.87.0` (`--oracle_hash keccak` non-zk `ultra_flavor`, not installed on this evaluation host).

## 2. Nethermind Stellar Private Payments (`main`, Apache-2.0 with LGPL-3.0 / GPL-3.0 circuit constraints)
- Upstream repository: `https://github.com/NethermindEth/stellar-private-payments`
- Evaluated commit: `cebb972b5872cba3a1cc40bcdfab297168ccc1d7` (`2026-11-18T11:20:06Z`)
- Root workspace license: **Apache-2.0**
- Copyleft exclusions (intentionally **NOT** vendored here):
  - `circuits/*.circom` statically link `circomlib` (**LGPL-3.0**) into `.wasm`/`.r1cs` artifacts.
  - `tools/circuit-compiler` is **GPL-3.0**.
  - Compiled `.zkey` / `.wasm` circuit artifacts from `deployments/` and `sdk/web/dist/circuits/` trigger LGPL-3.0 notice and linked-source obligations under `circuits/LICENSE`.
- Because those copyleft circuit build artifacts are excluded, `src/private_pool.rs` implements a clean-room Soroban BN254 Groth16 + Poseidon2 adapter testbench using Soroban's native `env.crypto().bn254()` pairing check, `soroban-poseidon`, and synthetic BN254 Groth16 keys/proofs constructed in-process for adversarial testing.
