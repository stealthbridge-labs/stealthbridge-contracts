//! StealthBridge evidence (scratch copy, not upstream): can an OpenZeppelin
//! passkey smart account authorize the shielded pool's `transact`?
//!
//! Uses the exact WASM deployed on Stellar Testnet for the OpenZeppelin
//! stellar-accounts v0.8.0 account (c514d35e…) and the shared WebAuthn
//! verifier (e63a030d…), a real Stellar Asset Contract as the pool token, a
//! real Groth16 deposit proof from the released Testnet keys, and NO auth
//! mocking for the transact call: the host runs the account's own
//! `__check_auth`, which calls the real WebAuthn verifier on a P-256
//! assertion over the account's auth digest.

use super::utils::{
    DeployedContracts, LEVELS, ProvenTransaction, prove_transaction, sync_contract_state, test_env, wasm_hash,
};
use anyhow::Result;
use asp_membership::ASPMembership;
use asp_non_membership::ASPNonMembership;
use circom_groth16_verifier::CircomGroth16Verifier;
use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::hazmat::PrehashSigner};
use pool::{ExtData, PoolContract, PoolContractClient, Proof};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, IntoVal, Map, TryFromVal, U256, Val, Vec as SorobanVec, contracttype,
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    xdr::{
        self, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ScVal, SorobanAddressCredentials,
        SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
        WriteXdr,
    },
};
use stellar_private_payments::types::PolicyFlags;

const OZ_ACCOUNT_WASM: &[u8] = include_bytes!("../../../../../ozwasm/oz_account_v080.wasm");
const OZ_WEBAUTHN_VERIFIER_WASM: &[u8] = include_bytes!("../../../../../ozwasm/oz_webauthn_verifier.wasm");

/// Mirrors stellar-accounts v0.8.0 `Signer` (contracttype encoding is by name).
#[contracttype]
#[derive(Clone)]
enum Signer {
    Delegated(Address),
    External(Address, Bytes),
}

/// Mirrors stellar-accounts v0.8.0 `AuthPayload`.
#[contracttype]
#[derive(Clone)]
struct AuthPayload {
    signers: Map<Signer, Bytes>,
    context_rule_ids: soroban_sdk::Vec<u32>,
}

/// Mirrors stellar-accounts v0.8.0 `AuthDigestPreimage` (preimage-v1).
#[contracttype]
#[derive(Clone)]
struct AuthDigestPreimage {
    account: Address,
    signature_payload: BytesN<32>,
    context_rule_ids: soroban_sdk::Vec<u32>,
}

/// Mirrors stellar-accounts v0.8.0 `WebAuthnSigData`.
#[contracttype]
#[derive(Clone)]
struct WebAuthnSigData {
    signature: BytesN<64>,
    authenticator_data: Bytes,
    client_data: Bytes,
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
fn b64url(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(B64URL[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn deploy_with_sac(env: &Env) -> DeployedContracts {
    let admin = Address::generate(env);
    let token = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let verifier = env.register(CircomGroth16Verifier, ());
    let asp_membership = env.register(ASPMembership, (admin.clone(), 10u32));
    let asp_non_membership = env.register(ASPNonMembership, (admin.clone(),));
    let pool = env.register(
        PoolContract,
        (
            admin,
            token.clone(),
            verifier,
            asp_membership.clone(),
            asp_non_membership.clone(),
            wasm_hash(&asp_membership),
            wasm_hash(&asp_non_membership),
            0i128,
            0i128,
            U256::from_u32(env, 1_000_000_000),
            u32::try_from(LEVELS).unwrap(),
            (PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST).bits(),
            soroban_sdk::String::from_str(env, "tests"),
        ),
    );
    DeployedContracts { pool, token, asp_membership, asp_non_membership, fee: 0 }
}

struct Setup {
    env: Env,
    contracts: DeployedContracts,
    wallet: Address,
    verifier: Address,
    key_data: Bytes,
    signing_key: SigningKey,
    proof: Proof,
    ext_data: ExtData,
}

fn setup(deposit: i32) -> Result<Setup> {
    let env = test_env();
    env.mock_all_auths();
    let contracts = deploy_with_sac(&env);

    // OpenZeppelin passkey wallet: one External(WebAuthn verifier, P-256 point || credential id) signer.
    let verifier = env.register(OZ_WEBAUTHN_VERIFIER_WASM, ());
    let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let mut key = point.as_bytes().to_vec();
    key.extend_from_slice(b"stealthbridge-evidence-credential");
    let key_data = Bytes::from_slice(&env, &key);
    let signers = SorobanVec::from_array(&env, [Signer::External(verifier.clone(), key_data.clone())]);
    let policies: Map<Address, Val> = Map::new(&env);
    let wallet = env.register(OZ_ACCOUNT_WASM, (signers, policies));

    // A deposit of `deposit` from two zero-value inputs; outputs hold it.
    let mut proven: ProvenTransaction =
        prove_transaction(&env, &contracts, [0, 0], [deposit as u64, 0], deposit, 11)?;
    let roots = sync_contract_state(&env, &contracts, &proven.case, &mut proven.leaves, &proven.membership_trees, &proven.witness);
    let ext_data = proven.ext_data.clone();
    let proof = proven.into_proof(&env, &roots);

    StellarAssetClient::new(&env, &contracts.token).mint(&wallet, &1_000i128);
    Ok(Setup { env, contracts, wallet, verifier, key_data, signing_key, proof, ext_data })
}

fn invocation(env: &Env, contract: &Address, name: &str, args: SorobanVec<Val>, subs: std::vec::Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizedInvocation {
    let args: std::vec::Vec<ScVal> = args.iter().map(|v| ScVal::try_from_val(env, &v).unwrap()).collect();
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
            contract_address: contract.try_into().unwrap(),
            function_name: name.try_into().unwrap(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: subs.try_into().unwrap(),
    }
}

/// Builds the wallet's signed authorization entry for `root`, with a genuine
/// WebAuthn assertion over the account's own auth digest.
fn signed_entry(s: &Setup, root: SorobanAuthorizedInvocation, contexts: u32, corrupt_signature: bool) -> SorobanAuthorizationEntry {
    let env = &s.env;
    let nonce = 4242i64;
    let expiration = env.ledger().sequence() + 100;
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(env.ledger().network_id().to_array()),
        nonce,
        signature_expiration_ledger: expiration,
        invocation: root.clone(),
    });
    let payload: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(env, &preimage.to_xdr(Limits::none()).unwrap()))
        .into();
    let rule_ids = SorobanVec::from_array(env, [0u32; 2]);
    let rule_ids = SorobanVec::from_iter(env, rule_ids.iter().take(contexts as usize));
    // The account computes its own digest (AuthDigestPreimage, preimage-v1).
    let digest: BytesN<32> = env.invoke_contract(
        &s.wallet,
        &soroban_sdk::Symbol::new(env, "auth_digest"),
        soroban_sdk::vec![env, AuthDigestPreimage { account: s.wallet.clone(), signature_payload: payload, context_rule_ids: rule_ids.clone() }.into_val(env)],
    );
    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://stealthbridge.vercel.app"}}"#,
        b64url(&digest.to_array())
    );
    let mut auth_data = env.crypto().sha256(&Bytes::from_slice(env, b"stealthbridge.vercel.app")).to_array().to_vec();
    auth_data.push(0x05); // UP | UV
    auth_data.extend_from_slice(&[0, 0, 0, 1]);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&env.crypto().sha256(&Bytes::from_slice(env, client_data.as_bytes())).to_array());
    let prehash = env.crypto().sha256(&Bytes::from_slice(env, &signed)).to_array();
    let sig: P256Signature = s.signing_key.sign_prehash(&prehash).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut raw = sig.to_bytes().to_vec();
    if corrupt_signature {
        raw[10] ^= 1;
    }
    let sig_data = WebAuthnSigData {
        signature: BytesN::from_array(env, &raw.try_into().unwrap()),
        authenticator_data: Bytes::from_slice(env, &auth_data),
        client_data: Bytes::from_slice(env, client_data.as_bytes()),
    };
    let mut signers = Map::new(env);
    signers.set(Signer::External(s.verifier.clone(), s.key_data.clone()), soroban_sdk::xdr::ToXdr::to_xdr(sig_data, env));
    let payload_val: Val = AuthPayload { signers, context_rule_ids: rule_ids }.into_val(env);
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: (&s.wallet).try_into().unwrap(),
            nonce,
            signature_expiration_ledger: expiration,
            signature: ScVal::try_from_val(env, &payload_val).unwrap(),
        }),
        root_invocation: root,
    }
}

fn transact_root(s: &Setup, ext_data: &ExtData, with_transfer: bool) -> SorobanAuthorizedInvocation {
    let env = &s.env;
    let amount: i128 = 13;
    let transfer = invocation(
        env,
        &s.contracts.token,
        "transfer",
        soroban_sdk::vec![env, s.wallet.into_val(env), s.contracts.pool.into_val(env), amount.into_val(env)],
        vec![],
    );
    invocation(
        env,
        &s.contracts.pool,
        "transact",
        soroban_sdk::vec![env, (&s.proof).into_val(env), ext_data.clone().into_val(env), s.wallet.into_val(env)],
        if with_transfer { vec![transfer] } else { vec![] },
    )
}

#[test]
#[ignore = "manual: StealthBridge OZ passkey authorization evidence"]
fn stealthbridge_oz_passkey_account_authorizes_a_real_pool_deposit() -> Result<()> {
    let s = setup(13)?;
    let pool = PoolContractClient::new(&s.env, &s.contracts.pool);
    let token = TokenClient::new(&s.env, &s.contracts.token);
    let before = token.balance(&s.wallet);

    let entry = signed_entry(&s, transact_root(&s, &s.ext_data, true), 2, false);
    s.env.set_auths(&[entry]); // enforcing: no mocks from here on
    pool.transact(&s.proof, &s.ext_data, &s.wallet);

    assert_eq!(token.balance(&s.wallet), before - 13, "the wallet paid the deposit");
    assert_eq!(token.balance(&s.contracts.pool), 13, "the pool received it");
    println!("OZ passkey wallet authorized pool.transact + SAC.transfer: deposit of 13 settled");
    Ok(())
}

#[test]
#[ignore = "manual: StealthBridge OZ passkey authorization evidence"]
fn stealthbridge_oz_passkey_refusals() -> Result<()> {
    // 1. The tree must include the nested SAC transfer.
    let s = setup(13)?;
    s.env.set_auths(&[signed_entry(&s, transact_root(&s, &s.ext_data, false), 1, false)]);
    assert!(PoolContractClient::new(&s.env, &s.contracts.pool).try_transact(&s.proof, &s.ext_data, &s.wallet).is_err(),
        "an entry without the nested transfer must not authorize the deposit");

    // 2. A wrong passkey signature is refused by the WebAuthn verifier.
    let s = setup(13)?;
    s.env.set_auths(&[signed_entry(&s, transact_root(&s, &s.ext_data, true), 2, true)]);
    assert!(PoolContractClient::new(&s.env, &s.contracts.pool).try_transact(&s.proof, &s.ext_data, &s.wallet).is_err(),
        "a corrupted passkey signature must be refused");

    // 3. Changing ext_data after signing (e.g. another recipient) breaks the authorization.
    let s = setup(13)?;
    s.env.set_auths(&[signed_entry(&s, transact_root(&s, &s.ext_data, true), 2, false)]);
    let mut altered = s.ext_data.clone();
    altered.recipient = Address::generate(&s.env);
    assert!(PoolContractClient::new(&s.env, &s.contracts.pool).try_transact(&s.proof, &altered, &s.wallet).is_err(),
        "a call that differs from the signed one must not be authorized");
    println!("missing transfer, corrupted signature and altered ext_data were all refused");
    Ok(())
}
