#![no_std]
//! Immutable, read-only cross-registry governance gate. It is not a payment,
//! privacy proof, compliance authorization, issuer or liquidity oracle.
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, IntoVal, String,
    Symbol, Val, Vec,
};

#[contracttype]
#[derive(Clone)]
enum Key {
    Admin,
    CorridorRegistry,
    PolicyRegistry,
}

/// Public policy versions/commitments to check atomically in one ledger.
/// These are governance metadata, not private witnesses or proof claims.
#[contracttype]
#[derive(Clone)]
pub struct GovernanceCheck {
    pub corridor: String,
    pub policy: String,
    pub expected_revision: u32,
    pub expected_commitment: BytesN<32>,
}

/// Both config and policy commitments are required for strict public checks.
/// Source-only ABI extension: existing Testnet deployments do not expose it.
#[contracttype]
#[derive(Clone)]
pub struct GovernanceConfigCheck {
    pub corridor: String,
    pub expected_config_digest: BytesN<32>,
    pub policy: String,
    pub expected_revision: u32,
    pub expected_policy_commitment: BytesN<32>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum GateError {
    InvalidBatchSize = 1,
}
#[contract]
pub struct GovernanceGate;

fn query_enabled(env: &Env, registry: &Address, method: &str, id: String) -> bool {
    let args: Vec<Val> = (id,).into_val(env);
    let function = Symbol::new(env, method);
    // Missing contracts, bad ABI, downstream panics, errors and malformed
    // return types must never be interpreted as governance approval.
    matches!(
        env.try_invoke_contract::<bool, soroban_sdk::Error>(registry, &function, args),
        Ok(Ok(true))
    )
}

#[contractimpl]
impl GovernanceGate {
    /// Both dependencies are fixed at deployment. Constructor requires the
    /// operator's explicit Soroban authorization for this exact invocation.
    pub fn __constructor(
        env: Env,
        admin: Address,
        corridor_registry: Address,
        policy_registry: Address,
    ) {
        admin.require_auth();
        env.storage().instance().set(&Key::Admin, &admin);
        env.storage()
            .instance()
            .set(&Key::CorridorRegistry, &corridor_registry);
        env.storage()
            .instance()
            .set(&Key::PolicyRegistry, &policy_registry);
    }

    /// Public dependency discovery only; these are governance addresses,
    /// not settlement wallets, token issuers or proof verifier contracts.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&Key::Admin)
    }
    pub fn corridor_registry(env: Env) -> Option<Address> {
        env.storage().instance().get(&Key::CorridorRegistry)
    }
    pub fn policy_registry(env: Env) -> Option<Address> {
        env.storage().instance().get(&Key::PolicyRegistry)
    }

    /// Bounded, ordered public-governance batch. On-chain cross-contract reads
    /// are relatively expensive; reject empty and >8 batches explicitly.
    /// Every result is independent and fail-closed; no writes or signatures.
    pub fn check_commitment_batch(
        env: Env,
        checks: Vec<GovernanceCheck>,
    ) -> Result<Vec<bool>, GateError> {
        if checks.is_empty() || checks.len() > 8 {
            return Err(GateError::InvalidBatchSize);
        }
        let mut verdicts = Vec::new(&env);
        for check in checks.iter() {
            verdicts.push_back(Self::public_flags_allow_commitment(
                env.clone(),
                check.corridor,
                check.policy,
                check.expected_revision,
                check.expected_commitment,
            ));
        }
        Ok(verdicts)
    }
    /// Strict metadata-only cross-registry check. Neither a bare enabled flag
    /// nor a stale/wrong corridor config or policy commitment is sufficient.
    /// No issuer, proof, settlement, transfer or authorization is checked.
    pub fn public_flags_allow_config(
        env: Env,
        corridor: String,
        expected_config_digest: BytesN<32>,
        policy: String,
        expected_revision: u32,
        expected_policy_commitment: BytesN<32>,
    ) -> bool {
        if corridor.is_empty()
            || corridor.len() > 128
            || policy.is_empty()
            || policy.len() > 128
            || expected_revision == 0
            || expected_config_digest == BytesN::from_array(&env, &[0; 32])
            || expected_policy_commitment == BytesN::from_array(&env, &[0; 32])
        {
            return false;
        }
        let Some(corridor_registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&Key::CorridorRegistry)
        else {
            return false;
        };
        let Some(policy_registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&Key::PolicyRegistry)
        else {
            return false;
        };
        let cargs: Vec<Val> = (corridor, expected_config_digest).into_val(&env);
        let good_corridor = matches!(
            env.try_invoke_contract::<bool, soroban_sdk::Error>(
                &corridor_registry,
                &Symbol::new(&env, "is_enabled_with_digest"),
                cargs
            ),
            Ok(Ok(true))
        );
        if !good_corridor {
            return false;
        }
        let pargs: Vec<Val> =
            (policy, expected_revision, expected_policy_commitment).into_val(&env);
        matches!(
            env.try_invoke_contract::<bool, soroban_sdk::Error>(
                &policy_registry,
                &Symbol::new(&env, "is_effective_commitment"),
                pargs
            ),
            Ok(Ok(true))
        )
    }
    /// Bounded strict config+policy checks at one ledger, preserving input order.
    pub fn check_config_batch(
        env: Env,
        checks: Vec<GovernanceConfigCheck>,
    ) -> Result<Vec<bool>, GateError> {
        if checks.is_empty() || checks.len() > 8 {
            return Err(GateError::InvalidBatchSize);
        }
        let mut verdicts = Vec::new(&env);
        for check in checks.iter() {
            verdicts.push_back(Self::public_flags_allow_config(
                env.clone(),
                check.corridor,
                check.expected_config_digest,
                check.policy,
                check.expected_revision,
                check.expected_policy_commitment,
            ));
        }
        Ok(verdicts)
    }
    /// An exact public policy version/commitment is required in addition
    /// to the corridor flag. This rejects stale/substituted policy bindings.
    /// True is public governance agreement, NEVER settlement authorization.
    pub fn public_flags_allow_commitment(
        env: Env,
        corridor: String,
        policy: String,
        expected_revision: u32,
        expected_commitment: BytesN<32>,
    ) -> bool {
        if corridor.is_empty()
            || corridor.len() > 128
            || policy.is_empty()
            || policy.len() > 128
            || expected_revision == 0
            || expected_commitment == BytesN::from_array(&env, &[0u8; 32])
        {
            return false;
        }
        let Some(corridor_registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&Key::CorridorRegistry)
        else {
            return false;
        };
        let Some(policy_registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&Key::PolicyRegistry)
        else {
            return false;
        };
        if !query_enabled(&env, &corridor_registry, "is_enabled", corridor) {
            return false;
        }
        let args: Vec<Val> = (policy, expected_revision, expected_commitment).into_val(&env);
        matches!(
            env.try_invoke_contract::<bool, soroban_sdk::Error>(
                &policy_registry,
                &Symbol::new(&env, "is_effective_commitment"),
                args,
            ),
            Ok(Ok(true))
        )
    }
    /// True means only that two *public registry flags* currently agree.
    /// Neither registry is an independently verified private payment rail.
    /// Fail closed if a dependency is absent, paused, expired or incompatible.
    pub fn public_flags_allow(env: Env, corridor: String, policy: String) -> bool {
        if corridor.is_empty() || corridor.len() > 128 || policy.is_empty() || policy.len() > 128 {
            return false;
        }
        let Some(corridor_registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&Key::CorridorRegistry)
        else {
            return false;
        };
        let Some(policy_registry) = env
            .storage()
            .instance()
            .get::<_, Address>(&Key::PolicyRegistry)
        else {
            return false;
        };
        query_enabled(&env, &corridor_registry, "is_enabled", corridor)
            && query_enabled(&env, &policy_registry, "is_effective", policy)
    }
}

#[cfg(test)]
mod tests;
