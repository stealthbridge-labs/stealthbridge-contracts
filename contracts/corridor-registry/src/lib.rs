#![no_std]
//! Public corridor enablement flags only: no protected amounts, counterparties,
//! KYC, FX rates, issuer promises or fiat eligibility are stored here.
//!
//! "Enabled" is a governance flag, never a guarantee of available liquidity.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, String};

const TTL_THRESHOLD: u32 = 17_280;
const TTL_EXTEND: u32 = 30 * TTL_THRESHOLD;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    PendingAdmin,
    Paused,
    Corridor(String),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    NotInitialized = 1,
    NoPendingAdmin = 2,
    InvalidCorridorId = 3,
}

#[contract]
pub struct CorridorRegistry;

fn admin(env: &Env) -> Result<Address, RegistryError> {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(RegistryError::NotInitialized)
}
fn authorize_admin(env: &Env) -> Result<Address, RegistryError> {
    let current = admin(env)?;
    current.require_auth();
    Ok(current)
}
fn renew_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

#[contractimpl]
impl CorridorRegistry {
    pub fn __constructor(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        renew_instance(&env);
    }

    /// Public governance address; no payment or policy capabilities implied.
    pub fn get_admin(env: Env) -> Result<Address, RegistryError> {
        admin(&env)
    }

    pub fn pending_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingAdmin)
    }

    /// Step 1: current admin proposes a successor. Only that account may accept.
    pub fn propose_admin(env: Env, new_admin: Address) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        renew_instance(&env);
        Ok(())
    }

    /// Step 2: future admin must explicitly authorize acceptance.
    pub fn accept_admin(env: Env) -> Result<(), RegistryError> {
        let proposed: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(RegistryError::NoPendingAdmin)?;
        proposed.require_auth();
        env.storage().instance().set(&DataKey::Admin, &proposed);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        renew_instance(&env);
        Ok(())
    }

    /// Admin-controlled global stop. Reversing it also requires admin auth.
    pub fn set_paused(env: Env, paused: bool) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &paused);
        renew_instance(&env);
        Ok(())
    }
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// A registry flag does not prove an issuer, asset, or payout partner exists.
    pub fn set_enabled(env: Env, corridor: String, enabled: bool) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        if corridor.is_empty() || corridor.len() > 128 {
            return Err(RegistryError::InvalidCorridorId);
        }
        let key = DataKey::Corridor(corridor);
        env.storage().persistent().set(&key, &enabled);
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
        renew_instance(&env);
        Ok(())
    }

    pub fn is_enabled(env: Env, corridor: String) -> bool {
        if corridor.is_empty() || corridor.len() > 128 { return false; }
        if Self::is_paused(env.clone()) {
            return false;
        }
        env.storage()
            .persistent()
            .get(&DataKey::Corridor(corridor))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests;
