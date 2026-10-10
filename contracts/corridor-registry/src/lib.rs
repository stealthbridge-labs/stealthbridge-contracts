#![no_std]
//! Public corridor enablement flags only: no protected amounts, counterparties,
//! KYC, FX rates, issuer promises or fiat eligibility are stored here.
//!
//! "Enabled" is a governance flag, never a guarantee of available liquidity.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, String};

const TTL_THRESHOLD: u32 = 17_280;
const TTL_EXTEND: u32 = 30 * TTL_THRESHOLD;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    PendingAdmin,
    Paused,
    Corridor(String),
    Approval(String),
}

/// Public, on-chain approval of a *specific* off-chain corridor config.
/// A digest is not a verification of a provider, issuer or available funds.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorridorApproval {
    pub config_digest: BytesN<32>,
    pub expires_at_ledger: u32,
}
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    NotInitialized = 1,
    NoPendingAdmin = 2,
    InvalidCorridorId = 3,
    Paused = 4,
    InvalidExpiration = 5,
    NotEnabled = 6,
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

    /// Revoke an unaccepted nomination without changing the active admin.
    /// The current admin must authorize cancellation.
    pub fn cancel_admin_proposal(env: Env) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        env.storage().instance().remove(&DataKey::PendingAdmin);
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
            .unwrap_or(true)
    }

    /// A registry flag does not prove an issuer, asset, or payout partner exists.
    pub fn set_enabled(env: Env, corridor: String, enabled: bool) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        if corridor.is_empty() || corridor.len() > 128 {
            return Err(RegistryError::InvalidCorridorId);
        }
        // Do not stage newly enabled flags during an emergency pause.
        // Disabling an entry remains allowed while paused.
        if enabled && Self::is_paused(env.clone()) {
            return Err(RegistryError::Paused);
        }
        let key = DataKey::Corridor(corridor);
        // Revocation clears any previously approved digest. Re-enabling
        // never restores a revoked approval: an admin must review it again.
        if !enabled {
            env.storage()
                .persistent()
                .remove(&DataKey::Approval(corridor.clone()));
        }
        env.storage().persistent().set(&key, &enabled);
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
        renew_instance(&env);
        Ok(())
    }

    /// An administrator approves public evidence of a specific corridor
    /// configuration for at most 100,000 additional ledger sequences.
    /// Requires an already-enabled corridor and a non-paused registry.
    pub fn approve_config(
        env: Env,
        corridor: String,
        config_digest: BytesN<32>,
        expires_at_ledger: u32,
    ) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        if corridor.is_empty() || corridor.len() > 128 {
            return Err(RegistryError::InvalidCorridorId);
        }
        if Self::is_paused(env.clone()) {
            return Err(RegistryError::Paused);
        }
        if !Self::is_enabled(env.clone(), corridor.clone()) {
            return Err(RegistryError::NotEnabled);
        }
        let current = env.ledger().sequence();
        let Some(span) = expires_at_ledger.checked_sub(current) else {
            return Err(RegistryError::InvalidExpiration);
        };
        if span == 0 || span > 100_000 {
            return Err(RegistryError::InvalidExpiration);
        }
        let key = DataKey::Approval(corridor);
        env.storage().persistent().set(
            &key,
            &CorridorApproval {
                config_digest,
                expires_at_ledger,
            },
        );
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
        renew_instance(&env);
        Ok(())
    }

    /// Strict public read: checks enabled state, exact digest and ledger
    /// expiration. No private data, liquidity or settlement is implied.
    pub fn is_enabled_with_digest(env: Env, corridor: String, expected_digest: BytesN<32>) -> bool {
        if !Self::is_enabled(env.clone(), corridor.clone()) {
            return false;
        }
        matches!(
            env.storage()
                .persistent()
                .get::<_, CorridorApproval>(&DataKey::Approval(corridor)),
            Some(approval)
                if approval.config_digest == expected_digest
                    && env.ledger().sequence() <= approval.expires_at_ledger
        )
    }
    pub fn is_enabled(env: Env, corridor: String) -> bool {
        if corridor.is_empty() || corridor.len() > 128 {
            return false;
        }
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
