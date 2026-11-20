#![cfg(test)]

use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
    Address, BytesN, Env, String,
};
use stealthbridge_corridor_registry::CorridorRegistry;
use stealthbridge_governance_gate::GovernanceGate;
use stealthbridge_policy_registry::PolicyRegistry;

/// Simulates a fee-on-transfer SEP-41 asset that skims 1 unit on every transfer,
/// allowing adversarial testing of exact-transfer delta verification.
#[contract]
pub struct TaxingToken;

#[contracttype]
#[derive(Clone)]
enum TaxKey {
    Bal(Address),
}

#[contractimpl]
impl TaxingToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let prev: i128 = env
            .storage()
            .persistent()
            .get(&TaxKey::Bal(to.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&TaxKey::Bal(to), &(prev + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TaxKey::Bal(id))
            .unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let fbal = Self::balance(env.clone(), from.clone());
        let tbal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&TaxKey::Bal(from), &(fbal - amount));
        // Deliver 1 unit short (tax/skim)
        env.storage()
            .persistent()
            .set(&TaxKey::Bal(to), &(tbal + amount - 1));
    }
}

struct Setup<'a> {
    env: Env,
    admin: Address,
    payer: Address,
    recipient: Address,
    token_id: Address,
    corridor_id: Address,
    policy_id: Address,
    adapter: SettlementAdapterClient<'a>,
    corridor_digest: BytesN<32>,
    policy_commitment: BytesN<32>,
    corridor_name: String,
    policy_name: String,
}

fn setup() -> Setup<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(500);

    let admin = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let corridor_id = env.register(CorridorRegistry, (&admin,));
    let policy_id = env.register(PolicyRegistry, (&admin,));
    let gate_id = env.register(GovernanceGate, (&admin, &corridor_id, &policy_id));
    let adapter_id = env.register(SettlementAdapter, (&admin, &gate_id));

    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token_id = sac.address();
    StellarAssetClient::new(&env, &token_id).mint(&payer, &10_000_000);

    let corridor_name = String::from_str(&env, "NG-GB-USDC");
    let corridor_digest = BytesN::from_array(&env, &[0x11u8; 32]);
    let policy_name = String::from_str(&env, "default-policy");
    let policy_commitment = BytesN::from_array(&env, &[0x22u8; 32]);

    let c_client = stealthbridge_corridor_registry::CorridorRegistryClient::new(&env, &corridor_id);
    c_client.set_enabled(&corridor_name, &true);
    c_client.approve_config(&corridor_name, &corridor_digest, &5_000u32);

    let p_client = stealthbridge_policy_registry::PolicyRegistryClient::new(&env, &policy_id);
    p_client.set_rule(
        &policy_name,
        &stealthbridge_policy_registry::PolicyRecord {
            revision: 1,
            enabled: true,
            public_commitment: policy_commitment.clone(),
        },
    );

    // Leak env handle only for `'static` test lifetime inside function? Use leaked Ref?
    // Construct client with `&env` bound: return tuple without lifetime coupling.
    let adapter = SettlementAdapterClient::new(Box::leak(Box::new(env.clone())), &adapter_id);
    Setup {
        env,
        admin,
        payer,
        recipient,
        token_id,
        corridor_id,
        policy_id,
        adapter,
        corridor_digest,
        policy_commitment,
        corridor_name,
        policy_name,
    }
}

extern crate std;
use std::boxed::Box;

fn sample_intent(s: &Setup) -> SettlementExecutionIntent {
    SettlementExecutionIntent {
        payer: s.payer.clone(),
        recipient: s.recipient.clone(),
        asset: s.token_id.clone(),
        amount: 2_500_000,
        intent_sha256: BytesN::from_array(&s.env, &[0x33u8; 32]),
        corridor_id: s.corridor_name.clone(),
        corridor_config_digest: s.corridor_digest.clone(),
        policy_id: s.policy_name.clone(),
        policy_revision: 1,
        policy_commitment: s.policy_commitment.clone(),
        quote_sha256: BytesN::from_array(&s.env, &[0x44u8; 32]),
        quote_verified: true,
        rail_mode: PrivacyRailMode::TransparentTestnetOnly,
        rail_proof_verified: false,
        expires_at_ledger: 1_000,
    }
}

#[test]
fn executes_governance_gated_transfer_and_blocks_replay() {
    let s = setup();
    let intent = sample_intent(&s);

    let digest = s.adapter.authorize_and_settle(&intent);
    assert_eq!(digest, intent.intent_sha256);

    let token = token::TokenClient::new(&s.env, &s.token_id);
    assert_eq!(token.balance(&s.payer), 7_500_000);
    assert_eq!(token.balance(&s.recipient), 2_500_000);

    let receipt = s
        .adapter
        .get_receipt(&s.payer, &intent.intent_sha256)
        .expect("receipt recorded");
    assert_eq!(receipt.settled_ledger, 500);
    assert_eq!(receipt.amount, 2_500_000);

    // Replay with identical (payer, intent_sha256) must fail closed.
    let replay = s.adapter.try_authorize_and_settle(&intent);
    assert!(matches!(replay, Err(Ok(AdapterError::ReplayRejected))));
}

#[test]
fn blocks_missing_quote_and_unverified_shielded_rails() {
    let s = setup();

    let mut no_quote = sample_intent(&s);
    no_quote.quote_verified = false;
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&no_quote),
        Err(Ok(AdapterError::QuoteUnavailable))
    ));

    let mut unverified_privacy = sample_intent(&s);
    unverified_privacy.rail_mode = PrivacyRailMode::PrivatePaymentsPool;
    unverified_privacy.rail_proof_verified = false;
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&unverified_privacy),
        Err(Ok(AdapterError::PrivacyProofUnverified))
    ));
}

#[test]
fn blocks_expired_paused_and_governance_drift() {
    let s = setup();

    // Expired intent
    let mut expired = sample_intent(&s);
    expired.expires_at_ledger = 499;
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&expired),
        Err(Ok(AdapterError::Expired))
    ));

    // Adapter emergency pause
    s.adapter.set_paused(&true);
    let intent = sample_intent(&s);
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&intent),
        Err(Ok(AdapterError::Paused))
    ));
    s.adapter.set_paused(&false);

    // Stale corridor or policy digest rejected via cross-contract GovernanceGate
    let mut wrong_policy = sample_intent(&s);
    wrong_policy.policy_commitment = BytesN::from_array(&s.env, &[0x99u8; 32]);
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&wrong_policy),
        Err(Ok(AdapterError::GovernanceBlocked))
    ));

    // Pausing upstream policy registry blocks execution cleanly
    let p_client = stealthbridge_policy_registry::PolicyRegistryClient::new(&s.env, &s.policy_id);
    p_client.set_paused(&true);
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&intent),
        Err(Ok(AdapterError::GovernanceBlocked))
    ));
    let _ = (&s.admin, &s.corridor_id);
}

#[test]
fn rejects_fee_on_transfer_asset_shortfall() {
    let s = setup();
    let bad_token = s.env.register(TaxingToken, ());
    let bad_client = TaxingTokenClient::new(&s.env, &bad_token);
    bad_client.mint(&s.payer, &1_000_000);

    let mut intent = sample_intent(&s);
    intent.asset = bad_token;
    intent.amount = 100_000;
    assert!(matches!(
        s.adapter.try_authorize_and_settle(&intent),
        Err(Ok(AdapterError::AssetTransferMismatch))
    ));
}
