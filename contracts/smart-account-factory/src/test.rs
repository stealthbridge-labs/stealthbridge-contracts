use crate::{
    signer_id_for_key, FactoryError, SignerKey, SmartAccountFactory, SmartAccountFactoryClient,
};
use ed25519_dalek::{Signer as _, SigningKey};
use soroban_sdk::{
    auth::{Context, ContractContext},
    contracttype,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec as svec, Address, BytesN, Env, IntoVal, Symbol, Vec,
};

/// The real account implementation, built by CI before this crate is tested
/// (`cargo build --release --target wasm32v1-none` in contracts/smart-account).
const ACCOUNT_WASM: &[u8] = include_bytes!(
    "../../smart-account/target/wasm32v1-none/release/stealthbridge_smart_account.wasm"
);

/// Mirror of the account's `AuthSignature::Ed25519` variant (same XDR).
#[contracttype]
#[derive(Clone)]
enum AuthSignature {
    Ed25519(BytesN<32>, BytesN<64>),
}

fn setup() -> (Env, Address, SmartAccountFactoryClient<'static>, BytesN<32>) {
    let env = Env::default();
    let wasm_hash = env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    let id = env.register(SmartAccountFactory, (admin.clone(), wasm_hash.clone()));
    env.set_auths(&[]);
    let client = SmartAccountFactoryClient::new(
        std::boxed::Box::leak(std::boxed::Box::new(env.clone())),
        &id,
    );
    (env, admin, client, wasm_hash)
}

fn ed_key(env: &Env, k: &SigningKey) -> SignerKey {
    SignerKey::Ed25519(BytesN::from_array(env, &k.verifying_key().to_bytes()))
}

#[test]
fn creates_constructor_bound_account_at_predicted_address() {
    let (env, _admin, factory, wasm_hash) = setup();
    let owner = SigningKey::from_bytes(&[1u8; 32]);
    let guardian = SigningKey::from_bytes(&[2u8; 32]);
    let rp = BytesN::from_array(&env, &[7u8; 32]);
    let owner_key = ed_key(&env, &owner);
    let guardian_key = Some(ed_key(&env, &guardian));

    let predicted = factory.account_address(&owner_key, &rp, &guardian_key);
    assert!(!factory.is_created(&owner_key, &rp, &guardian_key));
    // Permissionless: no auth is mocked for this call.
    let account = factory.create_account(&owner_key, &rp, &guardian_key);
    assert_eq!(account, predicted);
    assert!(factory.is_created(&owner_key, &rp, &guardian_key));
    assert_eq!(factory.account_wasm_hash(), wasm_hash);

    // The deployed account carries exactly the requested signers.
    let threshold: u32 =
        env.invoke_contract(&account, &Symbol::new(&env, "get_threshold"), svec![&env]);
    assert_eq!(threshold, 1);
    let ids: Vec<BytesN<32>> =
        env.invoke_contract(&account, &Symbol::new(&env, "list_signer_ids"), svec![&env]);
    assert_eq!(ids.len(), 2);
    let owner_id = signer_id_for_key(&env, &owner_key);
    assert!(ids.contains(&owner_id));

    // And it really authorizes with the owner's key (and nobody else's).
    let payload: [u8; 32] = [9u8; 32];
    let ctx = Context::Contract(ContractContext {
        contract: Address::generate(&env),
        fn_name: Symbol::new(&env, "transfer"),
        args: svec![&env],
    });
    let good = AuthSignature::Ed25519(
        owner_id.clone(),
        BytesN::from_array(&env, &owner.sign(&payload).to_bytes()),
    );
    assert!(env
        .try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &account,
            &BytesN::from_array(&env, &payload),
            svec![&env, good].into_val(&env),
            &svec![&env, ctx.clone()],
        )
        .is_ok());
    let stranger = SigningKey::from_bytes(&[3u8; 32]);
    let forged = AuthSignature::Ed25519(
        owner_id,
        BytesN::from_array(&env, &stranger.sign(&payload).to_bytes()),
    );
    assert!(env
        .try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &account,
            &BytesN::from_array(&env, &payload),
            svec![&env, forged].into_val(&env),
            &svec![&env, ctx],
        )
        .is_err());
}

#[test]
fn each_configuration_is_created_once_and_configs_do_not_collide() {
    let (env, _admin, factory, _) = setup();
    let owner = ed_key(&env, &SigningKey::from_bytes(&[4u8; 32]));
    let rp_a = BytesN::from_array(&env, &[1u8; 32]);
    let rp_b = BytesN::from_array(&env, &[2u8; 32]);
    let a = factory.create_account(&owner, &rp_a, &None);
    assert_eq!(
        factory.try_create_account(&owner, &rp_a, &None),
        Err(Ok(FactoryError::AccountExists))
    );
    // A different RP (or guardian) is a different account, not a takeover.
    let b = factory.create_account(&owner, &rp_b, &None);
    assert_ne!(a, b);
}

#[test]
fn pause_and_wasm_rotation_are_admin_only() {
    let (env, admin, factory, _) = setup();
    let new_hash = BytesN::from_array(&env, &[5u8; 32]);
    // Without the admin's authorization both calls fail.
    assert!(factory.try_set_paused(&true).is_err());
    assert!(factory.try_set_account_wasm(&new_hash).is_err());

    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &factory.address,
            fn_name: "set_paused",
            args: (true,).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    factory.set_paused(&true);
    let owner = ed_key(&env, &SigningKey::from_bytes(&[6u8; 32]));
    let rp = BytesN::from_array(&env, &[0u8; 32]);
    assert_eq!(
        factory.try_create_account(&owner, &rp, &None),
        Err(Ok(FactoryError::Paused))
    );
}
