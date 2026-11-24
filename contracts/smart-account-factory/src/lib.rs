#![no_std]
//! StealthBridge smart-account factory.
//!
//! Deploys `stealthbridge-smart-account` instances whose signers are bound by
//! the account's `__constructor` in the same operation that creates them
//! (ADR-0004). The deployment salt is derived from the full signer
//! configuration, so:
//!
//! - every configuration has exactly one, predictable account address
//!   (`account_address`), which a wallet can show before the account exists;
//! - `create_account` is safe to call by anyone, e.g. a fee-paying relayer.
//!   A third party can only ever create the account the owner asked for, with
//!   the owner's own keys, at the owner's predicted address.
//!
//! The factory holds no funds and has no authority over created accounts.
//! The administrator can only pause new creations or point *new* accounts at
//! a different reviewed account WASM; existing accounts are unaffected.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, xdr::ToXdr, Address, Bytes,
    BytesN, Env,
};

const TTL_THRESHOLD: u32 = 17_280;
const TTL_EXTEND: u32 = 30 * TTL_THRESHOLD;

/// Must stay XDR-identical to `stealthbridge_smart_account::SignerKey`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerKey {
    Ed25519(BytesN<32>),
    Secp256r1(BytesN<65>),
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    AccountWasm,
    Paused,
    Created(BytesN<32>),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FactoryError {
    Paused = 1,
    AccountExists = 2,
    InvalidWasmHash = 3,
}

#[contractevent(topics = ["factory", "account_created"])]
#[derive(Clone)]
pub struct AccountCreated {
    pub account: Address,
    pub owner_signer_id: BytesN<32>,
    pub account_wasm_hash: BytesN<32>,
}

#[contractevent(topics = ["factory", "account_wasm_updated"])]
#[derive(Clone)]
pub struct AccountWasmUpdated {
    pub account_wasm_hash: BytesN<32>,
}

fn extend_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

fn require_admin(env: &Env) {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}

/// Same derivation as `stealthbridge_smart_account::signer_id_for_key`.
pub fn signer_id_for_key(env: &Env, key: &SignerKey) -> BytesN<32> {
    let mut raw = Bytes::new(env);
    match key {
        SignerKey::Ed25519(k) => {
            raw.push_back(1);
            raw.extend_from_array(&k.to_array());
        }
        SignerKey::Secp256r1(k) => {
            raw.push_back(2);
            raw.extend_from_array(&k.to_array());
        }
    }
    env.crypto().sha256(&raw).into()
}

fn account_salt(
    env: &Env,
    owner_key: &SignerKey,
    rp_domain_sha256: &BytesN<32>,
    guardian_key: &Option<SignerKey>,
) -> BytesN<32> {
    let mut msg = Bytes::from_slice(env, b"stealthbridge-account-salt-v1:");
    msg.append(&owner_key.clone().to_xdr(env));
    msg.extend_from_array(&rp_domain_sha256.to_array());
    msg.append(&guardian_key.clone().to_xdr(env));
    env.crypto().sha256(&msg).into()
}

#[contract]
pub struct SmartAccountFactory;

#[contractimpl]
impl SmartAccountFactory {
    pub fn __constructor(env: Env, admin: Address, account_wasm_hash: BytesN<32>) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AccountWasm, &account_wasm_hash);
        env.storage().instance().set(&DataKey::Paused, &false);
        extend_instance(&env);
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    pub fn account_wasm_hash(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::AccountWasm).unwrap()
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(true)
    }

    pub fn set_paused(env: Env, paused: bool) {
        require_admin(&env);
        env.storage().instance().set(&DataKey::Paused, &paused);
        extend_instance(&env);
    }

    /// Points future accounts at a different, already uploaded account WASM.
    pub fn set_account_wasm(env: Env, account_wasm_hash: BytesN<32>) -> Result<(), FactoryError> {
        require_admin(&env);
        if account_wasm_hash.to_array() == [0u8; 32] {
            return Err(FactoryError::InvalidWasmHash);
        }
        env.storage()
            .instance()
            .set(&DataKey::AccountWasm, &account_wasm_hash);
        extend_instance(&env);
        AccountWasmUpdated { account_wasm_hash }.publish(&env);
        Ok(())
    }

    /// The address `create_account` will (or did) deploy for this exact
    /// signer configuration.
    pub fn account_address(
        env: Env,
        owner_key: SignerKey,
        rp_domain_sha256: BytesN<32>,
        guardian_key: Option<SignerKey>,
    ) -> Address {
        let salt = account_salt(&env, &owner_key, &rp_domain_sha256, &guardian_key);
        env.deployer()
            .with_current_contract(salt)
            .deployed_address()
    }

    pub fn is_created(
        env: Env,
        owner_key: SignerKey,
        rp_domain_sha256: BytesN<32>,
        guardian_key: Option<SignerKey>,
    ) -> bool {
        let salt = account_salt(&env, &owner_key, &rp_domain_sha256, &guardian_key);
        env.storage().persistent().has(&DataKey::Created(salt))
    }

    /// Deploys a smart account with signers bound atomically in its
    /// constructor. Permissionless by design (see module docs).
    pub fn create_account(
        env: Env,
        owner_key: SignerKey,
        rp_domain_sha256: BytesN<32>,
        guardian_key: Option<SignerKey>,
    ) -> Result<Address, FactoryError> {
        if Self::is_paused(env.clone()) {
            return Err(FactoryError::Paused);
        }
        let salt = account_salt(&env, &owner_key, &rp_domain_sha256, &guardian_key);
        let created = DataKey::Created(salt.clone());
        if env.storage().persistent().has(&created) {
            return Err(FactoryError::AccountExists);
        }
        let wasm = Self::account_wasm_hash(env.clone());
        let account = env.deployer().with_current_contract(salt).deploy_v2(
            wasm.clone(),
            (owner_key.clone(), rp_domain_sha256, guardian_key),
        );
        env.storage().persistent().set(&created, &true);
        env.storage()
            .persistent()
            .extend_ttl(&created, TTL_THRESHOLD, TTL_EXTEND);
        extend_instance(&env);
        AccountCreated {
            account: account.clone(),
            owner_signer_id: signer_id_for_key(&env, &owner_key),
            account_wasm_hash: wasm,
        }
        .publish(&env);
        Ok(account)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod test;
