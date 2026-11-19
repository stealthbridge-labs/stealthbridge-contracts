#![no_std]
//! Governance-gated Soroban settlement adapter source contract.
//! Source-only artifact: not deployed to Testnet and does not claim live FX,
//! custody licensing, or verified shielded privacy rails on deployed addresses.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token, Address, BytesN,
    Env, IntoVal, String, Symbol, Val, Vec,
};

const TTL_THRESHOLD: u32 = 17_280;
const TTL_EXTEND: u32 = 30 * TTL_THRESHOLD;

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PrivacyRailMode {
    /// Transparent public Testnet SEP-41 asset leg only (no shielded counterparty/amount claims).
    TransparentTestnetOnly = 0,
    PrivatePaymentsPool = 1,
    ConfidentialSep41Token = 2,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementExecutionIntent {
    pub payer: Address,
    pub recipient: Address,
    pub asset: Address,
    pub amount: i128,
    pub intent_sha256: BytesN<32>,
    pub corridor_id: String,
    pub corridor_config_digest: BytesN<32>,
    pub policy_id: String,
    pub policy_revision: u32,
    pub policy_commitment: BytesN<32>,
    pub quote_sha256: BytesN<32>,
    pub quote_verified: bool,
    pub rail_mode: PrivacyRailMode,
    pub rail_proof_verified: bool,
    pub expires_at_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettlementReceipt {
    pub payer: Address,
    pub recipient: Address,
    pub asset: Address,
    pub amount: i128,
    pub corridor_id: String,
    pub policy_revision: u32,
    pub quote_sha256: BytesN<32>,
    pub settled_ledger: u32,
    pub rail_mode: PrivacyRailMode,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    PendingAdmin,
    GovernanceGate,
    Paused,
    TransferInProgress,
    Receipt(Address, BytesN<32>),
}

#[contractevent(topics = ["settlement", "executed"])]
#[derive(Clone)]
pub struct SettlementExecuted {
    pub payer: Address,
    pub intent_sha256: BytesN<32>,
    pub settled_ledger: u32,
    pub amount: i128,
}

#[contractevent(topics = ["settlement", "pause"])]
#[derive(Clone)]
pub struct AdapterPauseChanged {
    pub paused: bool,
}

#[contractevent(topics = ["settlement", "admin"])]
#[derive(Clone)]
pub struct AdapterAdminRotated {
    pub administrator: Address,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AdapterError {
    NotInitialized = 1,
    Paused = 2,
    Expired = 3,
    InvalidAmount = 4,
    InvalidDigest = 5,
    ReplayRejected = 6,
    GovernanceBlocked = 7,
    QuoteUnavailable = 8,
    PrivacyProofUnverified = 9,
    AssetTransferMismatch = 10,
    ReentrantExecution = 11,
    NoPendingAdmin = 12,
    SameParties = 13,
}

fn zero_digest(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn extend_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

fn require_admin(env: &Env) -> Result<Address, AdapterError> {
    let admin: Address = env
        .storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(AdapterError::NotInitialized)?;
    admin.require_auth();
    Ok(admin)
}

#[contract]
pub struct SettlementAdapter;

#[contractimpl]
impl SettlementAdapter {
    pub fn __constructor(env: Env, admin: Address, governance_gate: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::GovernanceGate, &governance_gate);
        env.storage().instance().set(&DataKey::Paused, &false);
        extend_instance(&env);
    }

    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    pub fn governance_gate(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::GovernanceGate)
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(true)
    }

    pub fn set_paused(env: Env, paused: bool) -> Result<(), AdapterError> {
        require_admin(&env)?;
        env.storage().instance().set(&DataKey::Paused, &paused);
        AdapterPauseChanged { paused }.publish(&env);
        extend_instance(&env);
        Ok(())
    }

    pub fn propose_admin(env: Env, next_admin: Address) -> Result<(), AdapterError> {
        require_admin(&env)?;
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &next_admin);
        extend_instance(&env);
        Ok(())
    }

    pub fn cancel_admin_proposal(env: Env) -> Result<(), AdapterError> {
        require_admin(&env)?;
        env.storage().instance().remove(&DataKey::PendingAdmin);
        extend_instance(&env);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), AdapterError> {
        let next: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(AdapterError::NoPendingAdmin)?;
        next.require_auth();
        env.storage().instance().set(&DataKey::Admin, &next);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        AdapterAdminRotated {
            administrator: next,
        }
        .publish(&env);
        extend_instance(&env);
        Ok(())
    }

    /// Executes an authorized settlement transfer after enforcing emergency pause,
    /// expiry, replay protection, cross-contract GovernanceGate checks, verified quote
    /// and privacy-rail attestations, and exact SEP-41 balance-delta conservation.
    pub fn authorize_and_settle(
        env: Env,
        intent: SettlementExecutionIntent,
    ) -> Result<BytesN<32>, AdapterError> {
        let gate: Address = env
            .storage()
            .instance()
            .get(&DataKey::GovernanceGate)
            .ok_or(AdapterError::NotInitialized)?;

        if Self::is_paused(env.clone()) {
            return Err(AdapterError::Paused);
        }
        if env.storage().temporary().has(&DataKey::TransferInProgress) {
            return Err(AdapterError::ReentrantExecution);
        }
        if env.ledger().sequence() > intent.expires_at_ledger {
            return Err(AdapterError::Expired);
        }
        if intent.payer == intent.recipient {
            return Err(AdapterError::SameParties);
        }
        if intent.amount <= 0 {
            return Err(AdapterError::InvalidAmount);
        }
        if intent.intent_sha256 == zero_digest(&env)
            || intent.corridor_config_digest == zero_digest(&env)
            || intent.policy_commitment == zero_digest(&env)
        {
            return Err(AdapterError::InvalidDigest);
        }

        // Fail closed unless an explicit verified quote digest & status were attested.
        if !intent.quote_verified || intent.quote_sha256 == zero_digest(&env) {
            return Err(AdapterError::QuoteUnavailable);
        }

        // Shielded modes cannot masquerade as transparent execution without verified proof.
        if intent.rail_mode != PrivacyRailMode::TransparentTestnetOnly
            && !intent.rail_proof_verified
        {
            return Err(AdapterError::PrivacyProofUnverified);
        }

        // Reject duplicate execution for the same payer + intent digest.
        let receipt_key = DataKey::Receipt(intent.payer.clone(), intent.intent_sha256.clone());
        if env.storage().persistent().has(&receipt_key) {
            return Err(AdapterError::ReplayRejected);
        }

        // Cross-contract verification against GovernanceGate -> CorridorRegistry & PolicyRegistry.
        let gate_args: Vec<Val> = (
            intent.corridor_id.clone(),
            intent.corridor_config_digest.clone(),
            intent.policy_id.clone(),
            intent.policy_revision,
            intent.policy_commitment.clone(),
        )
            .into_val(&env);
        let gate_allowed = matches!(
            env.try_invoke_contract::<bool, soroban_sdk::Error>(
                &gate,
                &Symbol::new(&env, "public_flags_allow_config"),
                gate_args
            ),
            Ok(Ok(true))
        );
        if !gate_allowed {
            return Err(AdapterError::GovernanceBlocked);
        }

        // Bind exact caller authorization to this entire intent payload.
        intent.payer.require_auth();

        env.storage()
            .temporary()
            .set(&DataKey::TransferInProgress, &true);

        let asset_client = token::TokenClient::new(&env, &intent.asset);
        let before = asset_client.balance(&intent.recipient);
        asset_client.transfer(&intent.payer, &intent.recipient, &intent.amount);
        let after = asset_client.balance(&intent.recipient);

        env.storage()
            .temporary()
            .remove(&DataKey::TransferInProgress);

        let delivered = after
            .checked_sub(before)
            .ok_or(AdapterError::AssetTransferMismatch)?;
        if delivered != intent.amount {
            return Err(AdapterError::AssetTransferMismatch);
        }

        let settled_ledger = env.ledger().sequence();
        let receipt = SettlementReceipt {
            payer: intent.payer.clone(),
            recipient: intent.recipient,
            asset: intent.asset,
            amount: intent.amount,
            corridor_id: intent.corridor_id,
            policy_revision: intent.policy_revision,
            quote_sha256: intent.quote_sha256,
            settled_ledger,
            rail_mode: intent.rail_mode,
        };
        env.storage().persistent().set(&receipt_key, &receipt);
        env.storage()
            .persistent()
            .extend_ttl(&receipt_key, TTL_THRESHOLD, TTL_EXTEND);
        extend_instance(&env);

        SettlementExecuted {
            payer: intent.payer,
            intent_sha256: intent.intent_sha256.clone(),
            settled_ledger,
            amount: intent.amount,
        }
        .publish(&env);

        Ok(intent.intent_sha256)
    }

    pub fn get_receipt(
        env: Env,
        payer: Address,
        intent_sha256: BytesN<32>,
    ) -> Option<SettlementReceipt> {
        let key = DataKey::Receipt(payer, intent_sha256);
        env.storage().persistent().get(&key).inspect(|_| {
            env.storage()
                .persistent()
                .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND);
        })
    }
}

#[cfg(test)]
mod test;
