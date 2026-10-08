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
}

#[contract]
pub struct CorridorRegistry;

fn admin(env: &Env) -> Result<Address, RegistryError> {
    env.storage().instance().get(&DataKey::Admin)
        .ok_or(RegistryError::NotInitialized)
}
fn authorize_admin(env: &Env) -> Result<Address, RegistryError> {
    let current=admin(env)?;
    current.require_auth();
    Ok(current)
}
fn renew_instance(env: &Env) {
    env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
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
    pub fn propose_admin(env: Env, new_admin: Address) -> Result<(),RegistryError> {
        authorize_admin(&env)?;
        env.storage().instance().set(&DataKey::PendingAdmin, &new_admin);
        renew_instance(&env);
        Ok(())
    }

    /// Step 2: future admin must explicitly authorize acceptance.
    pub fn accept_admin(env: Env) -> Result<(),RegistryError> {
        let proposed: Address = env.storage().instance()
            .get(&DataKey::PendingAdmin).ok_or(RegistryError::NoPendingAdmin)?;
        proposed.require_auth();
        env.storage().instance().set(&DataKey::Admin, &proposed);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        renew_instance(&env);
        Ok(())
    }

    /// Admin-controlled global stop. Reversing it also requires admin auth.
    pub fn set_paused(env: Env, paused: bool) -> Result<(),RegistryError> {
        authorize_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &paused);
        renew_instance(&env);
        Ok(())
    }
    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    /// A registry flag does not prove an issuer, asset, or payout partner exists.
    pub fn set_enabled(env: Env, corridor: String, enabled: bool) -> Result<(), RegistryError> {
        authorize_admin(&env)?;
        let key=DataKey::Corridor(corridor);
        env.storage().persistent().set(&key,&enabled);
        env.storage().persistent().extend_ttl(&key,TTL_THRESHOLD,TTL_EXTEND);
        renew_instance(&env);
        Ok(())
    }

    pub fn is_enabled(env: Env, corridor: String) -> bool {
        if Self::is_paused(env.clone()) {return false;}
        env.storage().persistent().get(&DataKey::Corridor(corridor)).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn governance_and_pause_are_independent_from_payment_execution() {
        let env=Env::default();
        env.mock_all_auths();
        let initial=Address::generate(&env);
        let next=Address::generate(&env);
        let contract=env.register(CorridorRegistry,(initial.clone(),));
        let client=CorridorRegistryClient::new(&env,&contract);
        let id=String::from_str(&env,"opaque_corridor_id");

        assert_eq!(client.get_admin(),initial);
        assert!(!client.is_enabled(&id));
        assert!(!client.is_paused());
        client.set_enabled(&id,&true);
        assert!(client.is_enabled(&id));
        client.set_paused(&true);
        assert!(client.is_paused());
        assert!(!client.is_enabled(&id));
        client.set_paused(&false);
        assert!(client.is_enabled(&id));

        client.propose_admin(&next);
        assert_eq!(client.pending_admin(),Some(next.clone()));
        assert_eq!(client.get_admin(),initial);
        client.accept_admin();
        assert_eq!(client.get_admin(),next);
        assert_eq!(client.pending_admin(),None);
        client.set_enabled(&id,&false);
        assert!(!client.is_enabled(&id));
    }

    #[test]
    fn unapproved_mutations_do_not_succeed() {
        let env=Env::default();
        let current=Address::generate(&env);
        // Constructor authorization is mocked only for initial deployment in this test.
        env.mock_all_auths();
        let contract=env.register(CorridorRegistry,(current,));
        let client=CorridorRegistryClient::new(&env,&contract);
        let new_admin=Address::generate(&env);
        // Remove the all-auth mock for follow-up calls.
        env.mock_auths(&[]);
        assert!(client.try_set_paused(&true).is_err());
        assert!(client.try_propose_admin(&new_admin).is_err());
        assert!(client.try_set_enabled(&String::from_str(&env,"test_only"),&true).is_err());
        assert!(client.try_accept_admin().is_err());
    }
}
