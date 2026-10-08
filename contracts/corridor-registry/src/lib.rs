#![no_std]
//! Minimal policy-independent registry prototype.
//! Stores only public corridor enablement; no amounts, participants or secrets.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, String};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Corridor(String),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    NotInitialized = 1,
}

#[contract]
pub struct CorridorRegistry;

#[contractimpl]
impl CorridorRegistry {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn set_enabled(env: Env, corridor: String, enabled: bool) -> Result<(), RegistryError> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(RegistryError::NotInitialized)?;
        admin.require_auth();
        let key = DataKey::Corridor(corridor);
        env.storage().persistent().set(&key, &enabled);
        env.storage().persistent().extend_ttl(&key, 17_280, 30 * 17_280);
        env.storage().instance().extend_ttl(17_280, 30 * 17_280);
        Ok(())
    }

    pub fn is_enabled(env: Env, corridor: String) -> bool {
        env.storage().persistent()
            .get(&DataKey::Corridor(corridor))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn starts_disabled_then_supports_admin_configuration() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(CorridorRegistry, (admin,));
        let client = CorridorRegistryClient::new(&env, &id);
        let corridor = String::from_str(&env, "corridor_test_fixture");
        assert!(!client.is_enabled(&corridor));
        client.set_enabled(&corridor, &true);
        assert!(client.is_enabled(&corridor));
        client.set_enabled(&corridor, &false);
        assert!(!client.is_enabled(&corridor));
    }
}
