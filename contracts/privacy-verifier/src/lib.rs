#![no_std]
#![allow(clippy::too_many_arguments)]
//! StealthBridge BN254 Groth16 PrivacyVerifier and NullifierRegistry contract.
//!
//! Uses Soroban Protocol 25+ native `env.crypto().bn254().pairing_check` host
//! functions to verify zero-knowledge proofs against administrator-pinned
//! circuit verification keys, bounded Merkle root expiry ledgers, domain scope
//! digests, and single-use persistent nullifier records.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec as svec, Address, BytesN, Env, Vec,
};

const TTL_THRESHOLD: u32 = 17_280;
const TTL_EXTEND: u32 = 30 * TTL_THRESHOLD;
const MAX_PUBLIC_INPUTS: u32 = 15;
const MAX_ROOT_WINDOW_LEDGERS: u32 = 500_000;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Vk {
    pub alpha_g1: BytesN<64>,
    pub beta_g2: BytesN<128>,
    pub gamma_g2: BytesN<128>,
    pub delta_g2: BytesN<128>,
    pub ic_g1: Vec<BytesN<64>>,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Proof {
    pub a_g1: BytesN<64>,
    pub b_g2: BytesN<128>,
    pub c_g1: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofAttestation {
    pub circuit_id: u32,
    pub circuit_version: u32,
    pub root: BytesN<32>,
    pub nullifier: BytesN<32>,
    pub scope_digest: BytesN<32>,
    pub verified_ledger: u32,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    PendingAdmin,
    Paused,
    VerificationKey(u32, u32),
    RootExpiry(BytesN<32>),
    NullifierSpent(BytesN<32>),
}

#[contractevent(topics = ["privacy", "verified"])]
#[derive(Clone)]
pub struct ProofVerified {
    pub circuit_id: u32,
    pub circuit_version: u32,
    pub nullifier: BytesN<32>,
    pub root: BytesN<32>,
    pub verified_ledger: u32,
}

#[contractevent(topics = ["privacy", "vk_updated"])]
#[derive(Clone)]
pub struct VerificationKeyUpdated {
    pub circuit_id: u32,
    pub circuit_version: u32,
    pub active: bool,
}

#[contractevent(topics = ["privacy", "root_added"])]
#[derive(Clone)]
pub struct RootRegistered {
    pub root: BytesN<32>,
    pub expires_at_ledger: u32,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Paused = 3,
    InvalidVerificationKey = 4,
    VerificationKeyInactive = 5,
    InvalidRoot = 6,
    UnknownOrExpiredRoot = 7,
    InvalidNullifier = 8,
    NullifierAlreadySpent = 9,
    PublicInputMismatch = 10,
    InvalidProof = 11,
    NoPendingAdmin = 12,
    InvalidExpiry = 13,
}

fn is_zero_32(val: &BytesN<32>) -> bool {
    val.to_array() == [0u8; 32]
}

fn extend_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

fn require_admin(env: &Env) -> Result<Address, VerifierError> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(VerifierError::NotInitialized)?;
    admin.require_auth();
    extend_instance(env);
    Ok(admin)
}

#[contract]
pub struct PrivacyVerifier;

#[contractimpl]
impl PrivacyVerifier {
    pub fn initialize(env: Env, admin: Address) -> Result<(), VerifierError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(VerifierError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        extend_instance(&env);
        Ok(())
    }

    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(true)
    }

    pub fn set_paused(env: Env, paused: bool) -> Result<(), VerifierError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &paused);
        Ok(())
    }

    pub fn propose_admin(env: Env, candidate: Address) -> Result<(), VerifierError> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &candidate);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), VerifierError> {
        let candidate: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(VerifierError::NoPendingAdmin)?;
        candidate.require_auth();
        env.storage().instance().set(&DataKey::Admin, &candidate);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        extend_instance(&env);
        Ok(())
    }

    pub fn register_verification_key(
        env: Env,
        circuit_id: u32,
        circuit_version: u32,
        mut vk: Groth16Vk,
    ) -> Result<(), VerifierError> {
        require_admin(&env)?;
        // Requires at least root, nullifier, scope_digest => ic_g1 >= 4 elements.
        if vk.ic_g1.len() < 4 || vk.ic_g1.len() > MAX_PUBLIC_INPUTS + 1 {
            return Err(VerifierError::InvalidVerificationKey);
        }
        vk.active = true;
        env.storage()
            .persistent()
            .set(&DataKey::VerificationKey(circuit_id, circuit_version), &vk);
        env.storage().persistent().extend_ttl(
            &DataKey::VerificationKey(circuit_id, circuit_version),
            TTL_THRESHOLD,
            TTL_EXTEND,
        );
        VerificationKeyUpdated {
            circuit_id,
            circuit_version,
            active: true,
        }
        .publish(&env);
        Ok(())
    }

    pub fn revoke_verification_key(
        env: Env,
        circuit_id: u32,
        circuit_version: u32,
    ) -> Result<(), VerifierError> {
        require_admin(&env)?;
        let key = DataKey::VerificationKey(circuit_id, circuit_version);
        let mut vk: Groth16Vk = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(VerifierError::InvalidVerificationKey)?;
        vk.active = false;
        env.storage().persistent().set(&key, &vk);
        VerificationKeyUpdated {
            circuit_id,
            circuit_version,
            active: false,
        }
        .publish(&env);
        Ok(())
    }

    pub fn register_root(
        env: Env,
        root: BytesN<32>,
        expires_at_ledger: u32,
    ) -> Result<(), VerifierError> {
        require_admin(&env)?;
        if is_zero_32(&root) {
            return Err(VerifierError::InvalidRoot);
        }
        let current = env.ledger().sequence();
        let span = expires_at_ledger
            .checked_sub(current)
            .ok_or(VerifierError::InvalidExpiry)?;
        if span == 0 || span > MAX_ROOT_WINDOW_LEDGERS {
            return Err(VerifierError::InvalidExpiry);
        }
        let key = DataKey::RootExpiry(root.clone());
        env.storage().persistent().set(&key, &expires_at_ledger);
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
        RootRegistered {
            root,
            expires_at_ledger,
        }
        .publish(&env);
        Ok(())
    }

    pub fn is_root_valid(env: Env, root: BytesN<32>) -> bool {
        if is_zero_32(&root) {
            return false;
        }
        match env
            .storage()
            .persistent()
            .get::<DataKey, u32>(&DataKey::RootExpiry(root))
        {
            Some(expiry) => env.ledger().sequence() <= expiry,
            None => false,
        }
    }

    pub fn is_nullifier_spent(env: Env, nullifier: BytesN<32>) -> bool {
        if is_zero_32(&nullifier) {
            return false;
        }
        env.storage()
            .persistent()
            .has(&DataKey::NullifierSpent(nullifier))
    }

    /// Verifies a BN254 Groth16 proof on-chain via `env.crypto().bn254().pairing_check`,
    /// binding `public_inputs[0..3]` directly to `[root, nullifier, scope_digest]`,
    /// checks root expiry, and atomically records `nullifier` in `NullifierSpent`.
    pub fn verify_and_spend(
        env: Env,
        circuit_id: u32,
        circuit_version: u32,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        scope_digest: BytesN<32>,
        public_inputs: Vec<BytesN<32>>,
        proof: Groth16Proof,
    ) -> Result<ProofAttestation, VerifierError> {
        if Self::is_paused(env.clone()) {
            return Err(VerifierError::Paused);
        }
        if is_zero_32(&root) {
            return Err(VerifierError::InvalidRoot);
        }
        if is_zero_32(&nullifier) || is_zero_32(&scope_digest) {
            return Err(VerifierError::InvalidNullifier);
        }
        if !Self::is_root_valid(env.clone(), root.clone()) {
            return Err(VerifierError::UnknownOrExpiredRoot);
        }
        let nullifier_key = DataKey::NullifierSpent(nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(VerifierError::NullifierAlreadySpent);
        }

        let vk_key = DataKey::VerificationKey(circuit_id, circuit_version);
        let vk: Groth16Vk = env
            .storage()
            .persistent()
            .get(&vk_key)
            .ok_or(VerifierError::VerificationKeyInactive)?;
        if !vk.active {
            return Err(VerifierError::VerificationKeyInactive);
        }
        if public_inputs.len() < 3 || public_inputs.len() + 1 != vk.ic_g1.len() {
            return Err(VerifierError::PublicInputMismatch);
        }
        // Public inputs must directly bind the caller-declared root, nullifier, and scope digest.
        if public_inputs.get(0).as_ref() != Some(&root)
            || public_inputs.get(1).as_ref() != Some(&nullifier)
            || public_inputs.get(2).as_ref() != Some(&scope_digest)
        {
            return Err(VerifierError::PublicInputMismatch);
        }

        let bn = env.crypto().bn254();
        let ic0 = vk
            .ic_g1
            .get(0)
            .ok_or(VerifierError::InvalidVerificationKey)?;
        let mut vk_x = Bn254G1Affine::from_bytes(ic0);
        for i in 0..public_inputs.len() {
            let base_bytes = vk
                .ic_g1
                .get(i + 1)
                .ok_or(VerifierError::InvalidVerificationKey)?;
            let scalar_bytes = public_inputs
                .get(i)
                .ok_or(VerifierError::PublicInputMismatch)?;
            let base = Bn254G1Affine::from_bytes(base_bytes);
            let scalar = Bn254Fr::from_bytes(scalar_bytes);
            let term = bn.g1_mul(&base, &scalar);
            vk_x = bn.g1_add(&vk_x, &term);
        }

        let a_point = Bn254G1Affine::from_bytes(proof.a_g1);
        let neg_a = -a_point;
        let g1_points = svec![
            &env,
            neg_a,
            Bn254G1Affine::from_bytes(vk.alpha_g1),
            vk_x,
            Bn254G1Affine::from_bytes(proof.c_g1),
        ];
        let g2_points = svec![
            &env,
            Bn254G2Affine::from_bytes(proof.b_g2),
            Bn254G2Affine::from_bytes(vk.beta_g2),
            Bn254G2Affine::from_bytes(vk.gamma_g2),
            Bn254G2Affine::from_bytes(vk.delta_g2),
        ];
        if !bn.pairing_check(g1_points, g2_points) {
            return Err(VerifierError::InvalidProof);
        }

        let current_ledger = env.ledger().sequence();
        env.storage()
            .persistent()
            .set(&nullifier_key, &current_ledger);
        env.storage()
            .persistent()
            .extend_ttl(&nullifier_key, TTL_THRESHOLD, TTL_EXTEND);
        extend_instance(&env);

        ProofVerified {
            circuit_id,
            circuit_version,
            nullifier: nullifier.clone(),
            root: root.clone(),
            verified_ledger: current_ledger,
        }
        .publish(&env);

        Ok(ProofAttestation {
            circuit_id,
            circuit_version,
            root,
            nullifier,
            scope_digest,
            verified_ledger: current_ledger,
        })
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod test;
