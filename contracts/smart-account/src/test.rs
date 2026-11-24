use crate::{
    signer_id_for_key, AccountError, AuthSignature, SignerKey, SignerRole,
    StealthBridgeSmartAccount, StealthBridgeSmartAccountClient, WebAuthnProof,
};
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature as P256Sig, SigningKey as P256Key};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::{Address as _, Ledger as _},
    token::StellarAssetClient,
    vec as svec, Address, Bytes, BytesN, Env, IntoVal, Symbol,
};

fn p256_pubkey_bytes(env: &Env, key: &P256Key) -> BytesN<65> {
    let encoded = key.verifying_key().to_encoded_point(false);
    let slice: &[u8] = encoded.as_bytes();
    let mut arr = [0u8; 65];
    arr.copy_from_slice(slice);
    BytesN::from_array(env, &arr)
}

fn sign_p256_prehash(env: &Env, key: &P256Key, digest: &[u8; 32]) -> BytesN<64> {
    let sig: P256Sig = key.sign_prehash(digest).expect("sign");
    let normalized = sig.normalize_s().unwrap_or(sig);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&normalized.to_bytes());
    BytesN::from_array(env, &arr)
}

fn sign_ed25519(env: &Env, key: &EdSigningKey, msg: &[u8]) -> BytesN<64> {
    let sig = key.sign(msg);
    BytesN::from_array(env, &sig.to_bytes())
}

fn base64url(bytes: &[u8]) -> std::string::String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = std::string::String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let a = bytes[i];
        let b = bytes[i + 1];
        let c = bytes[i + 2];
        out.push(TABLE[((a >> 2) & 0x3f) as usize] as char);
        out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        out.push(TABLE[(c & 0x3f) as usize] as char);
        i += 3;
    }
    if bytes.len() - i == 2 {
        let a = bytes[i];
        let b = bytes[i + 1];
        out.push(TABLE[((a >> 2) & 0x3f) as usize] as char);
        out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(TABLE[((b & 0x0f) << 2) as usize] as char);
    }
    out
}

#[test]
fn smart_account_supports_webauthn_passkey_session_limits_and_timelocked_recovery() {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 1_000);

    let rp_hash: [u8; 32] = Sha256::digest(b"stealthbridge.vercel.app").into();
    let rp_hash_n = BytesN::from_array(&env, &rp_hash);

    let passkey_owner = P256Key::from_bytes(&[7u8; 32].into()).unwrap();
    let guardian_ed = EdSigningKey::from_bytes(&[9u8; 32]);
    let session_ed = EdSigningKey::from_bytes(&[11u8; 32]);
    let replacement_p256 = P256Key::from_bytes(&[13u8; 32].into()).unwrap();

    let owner_key = SignerKey::Secp256r1(p256_pubkey_bytes(&env, &passkey_owner));
    let guardian_key = SignerKey::Ed25519(BytesN::from_array(
        &env,
        &guardian_ed.verifying_key().to_bytes(),
    ));
    let account_id = env.register(
        StealthBridgeSmartAccount,
        (
            owner_key.clone(),
            rp_hash_n.clone(),
            Some(guardian_key.clone()),
        ),
    );
    let client = StealthBridgeSmartAccountClient::new(&env, &account_id);
    let owner_id = signer_id_for_key(&env, &owner_key);
    let guardian_id = signer_id_for_key(&env, &guardian_key);

    // 1. Check WebAuthn passkey authorization via __check_auth directly
    let payload_bytes: [u8; 32] = Sha256::digest(b"tx-auth-payload-1").into();
    let payload_hash = BytesN::from_array(&env, &payload_bytes);
    let mut auth_data = std::vec::Vec::from(rp_hash);
    auth_data.push(0x05); // UP | UV
    auth_data.extend_from_slice(&1u32.to_be_bytes());
    let challenge_b64 = base64url(&payload_bytes);
    let client_json = std::format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"https://stealthbridge.vercel.app"}}"#
    );
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_json.as_bytes()));
    let webauthn_digest: [u8; 32] = Sha256::digest(&signed).into();
    let sig_webauthn = sign_p256_prehash(&env, &passkey_owner, &webauthn_digest);

    let auth_entry = AuthSignature::WebAuthn(WebAuthnProof {
        signer_id: owner_id.clone(),
        authenticator_data: Bytes::from_slice(&env, &auth_data),
        client_data_json: Bytes::from_slice(&env, client_json.as_bytes()),
        signature: sig_webauthn,
    });

    let sac_admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(sac_admin.clone());
    let token_addr = sac.address();
    let recipient = Address::generate(&env);
    let ctx_transfer = Context::Contract(ContractContext {
        contract: token_addr.clone(),
        fn_name: Symbol::new(&env, "transfer"),
        args: svec![
            &env,
            account_id.clone().into_val(&env),
            recipient.clone().into_val(&env),
            500_i128.into_val(&env)
        ],
    });

    env.try_invoke_contract_check_auth::<AccountError>(
        &account_id,
        &payload_hash,
        svec![&env, auth_entry].into_val(&env),
        &svec![&env, ctx_transfer.clone()],
    )
    .expect("valid passkey auth passes");

    // 2. Wrong RP ID fails cleanly
    let mut bad_auth_data = auth_data.clone();
    bad_auth_data[0] ^= 0xff;
    let bad_entry = AuthSignature::WebAuthn(WebAuthnProof {
        signer_id: owner_id.clone(),
        authenticator_data: Bytes::from_slice(&env, &bad_auth_data),
        client_data_json: Bytes::from_slice(&env, client_json.as_bytes()),
        signature: sign_p256_prehash(&env, &passkey_owner, &webauthn_digest),
    });
    assert!(env
        .try_invoke_contract_check_auth::<AccountError>(
            &account_id,
            &payload_hash,
            svec![&env, bad_entry].into_val(&env),
            &svec![&env, ctx_transfer.clone()],
        )
        .is_err());

    // 3. Add Session key with 1000 max_per_tx, 1500 window_limit, expires ledger 1200
    let session_key = SignerKey::Ed25519(BytesN::from_array(
        &env,
        &session_ed.verifying_key().to_bytes(),
    ));
    let session_id = {
        env.mock_all_auths();
        client.add_signer(
            &session_key,
            &SignerRole::Session,
            &Some(1200),
            &1000,
            &1500,
            &50,
        )
    };

    // Session works within limit (500 <= 1000)
    let ses_sig = sign_ed25519(&env, &session_ed, &payload_bytes);
    let ses_entry = AuthSignature::Ed25519(session_id.clone(), ses_sig.clone());
    env.try_invoke_contract_check_auth::<AccountError>(
        &account_id,
        &payload_hash,
        svec![&env, ses_entry.clone()].into_val(&env),
        &svec![&env, ctx_transfer.clone()],
    )
    .expect("session transfer under limit passes");

    // Session cannot exceed per-tx limit or call self contract
    let big_ctx = Context::Contract(ContractContext {
        contract: token_addr.clone(),
        fn_name: Symbol::new(&env, "transfer"),
        args: svec![
            &env,
            account_id.clone().into_val(&env),
            recipient.clone().into_val(&env),
            1200_i128.into_val(&env)
        ],
    });
    assert!(env
        .try_invoke_contract_check_auth::<AccountError>(
            &account_id,
            &payload_hash,
            svec![&env, ses_entry.clone()].into_val(&env),
            &svec![&env, big_ctx],
        )
        .is_err());

    // 4. Guardian recovery works after delay_ledgers (100) and rotates out old owner
    let new_owner_key = SignerKey::Secp256r1(p256_pubkey_bytes(&env, &replacement_p256));
    let new_owner_id = signer_id_for_key(&env, &new_owner_key);
    let recovery_digest = client.recovery_challenge(&new_owner_key, &100).to_array();
    let guardian_sig = AuthSignature::Ed25519(
        guardian_id.clone(),
        sign_ed25519(&env, &guardian_ed, &recovery_digest),
    );
    client.propose_recovery(&guardian_id, &guardian_sig, &new_owner_key, &100);
    assert_eq!(
        client.try_execute_recovery(),
        Err(Ok(AccountError::RecoveryNotReady))
    );

    env.ledger().with_mut(|l| l.sequence_number = 1_100);
    let promoted = client.execute_recovery();
    assert_eq!(promoted, new_owner_id);
    assert!(!client.get_signer(&owner_id).unwrap().active);
    assert!(client.get_signer(&new_owner_id).unwrap().active);
    // Session keys from the old device set do not survive recovery (H-2).
    assert!(!client.get_signer(&session_id).unwrap().active);

    // Silence unused token helper warning while confirming StellarAssetClient compatibility
    let _sac_client = StellarAssetClient::new(&env, &token_addr);
}

// ---------------------------------------------------------------------------
// Regression tests for the 2026-11-24 baseline audit (C-3, H-1, H-2).
// ---------------------------------------------------------------------------

struct Fixture {
    env: Env,
    account: Address,
    owner: EdSigningKey,
    owner_id: BytesN<32>,
    guardian: EdSigningKey,
    guardian_id: BytesN<32>,
}

fn ed_key(env: &Env, k: &EdSigningKey) -> SignerKey {
    SignerKey::Ed25519(BytesN::from_array(env, &k.verifying_key().to_bytes()))
}

fn fixture(seed: u8) -> Fixture {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 1_000);
    let owner = EdSigningKey::from_bytes(&[seed; 32]);
    let guardian = EdSigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
    let owner_key = ed_key(&env, &owner);
    let guardian_key = ed_key(&env, &guardian);
    let account = env.register(
        StealthBridgeSmartAccount,
        (
            owner_key.clone(),
            BytesN::from_array(&env, &[0u8; 32]),
            Some(guardian_key.clone()),
        ),
    );
    let owner_id = signer_id_for_key(&env, &owner_key);
    let guardian_id = signer_id_for_key(&env, &guardian_key);
    Fixture {
        env,
        account,
        owner,
        owner_id,
        guardian,
        guardian_id,
    }
}

fn self_ctx(
    env: &Env,
    account: &Address,
    name: &str,
    args: soroban_sdk::Vec<soroban_sdk::Val>,
) -> Context {
    Context::Contract(ContractContext {
        contract: account.clone(),
        fn_name: Symbol::new(env, name),
        args,
    })
}

fn owner_auth(
    f: &Fixture,
    ctx: Context,
) -> Result<(), Result<AccountError, soroban_sdk::InvokeError>> {
    let payload: [u8; 32] = Sha256::digest(b"owner-payload").into();
    let sig = AuthSignature::Ed25519(f.owner_id.clone(), sign_ed25519(&f.env, &f.owner, &payload));
    f.env.try_invoke_contract_check_auth::<AccountError>(
        &f.account,
        &BytesN::from_array(&f.env, &payload),
        svec![&f.env, sig].into_val(&f.env),
        &svec![&f.env, ctx],
    )
}

#[test]
fn constructor_binds_signers_atomically() {
    let f = fixture(21);
    let client = StealthBridgeSmartAccountClient::new(&f.env, &f.account);
    assert_eq!(client.get_threshold(), 1);
    assert!(!client.is_paused());
    assert!(client.get_signer(&f.owner_id).unwrap().active);
    assert_eq!(
        client.get_signer(&f.guardian_id).unwrap().role,
        SignerRole::Guardian
    );
}

#[test]
fn paused_account_can_still_be_unpaused_by_owner_threshold() {
    let f = fixture(31);
    let client = StealthBridgeSmartAccountClient::new(&f.env, &f.account);
    f.env.mock_all_auths();
    client.set_paused(&true);
    f.env.set_auths(&[]);
    assert!(client.is_paused());

    // Ordinary spending is blocked while paused.
    let token = Address::generate(&f.env);
    let spend = Context::Contract(ContractContext {
        contract: token,
        fn_name: Symbol::new(&f.env, "transfer"),
        args: svec![
            &f.env,
            f.account.clone().into_val(&f.env),
            f.account.clone().into_val(&f.env),
            1_i128.into_val(&f.env)
        ],
    });
    assert_eq!(owner_auth(&f, spend), Err(Ok(AccountError::Paused)));

    // Re-pausing or any other self call is blocked.
    let repause = self_ctx(
        &f.env,
        &f.account,
        "set_paused",
        svec![&f.env, true.into_val(&f.env)],
    );
    assert_eq!(owner_auth(&f, repause), Err(Ok(AccountError::Paused)));

    // Unpause and cancel_recovery are allowed for owners (C-3).
    let unpause = self_ctx(
        &f.env,
        &f.account,
        "set_paused",
        svec![&f.env, false.into_val(&f.env)],
    );
    assert_eq!(owner_auth(&f, unpause), Ok(()));
    let cancel = self_ctx(&f.env, &f.account, "cancel_recovery", svec![&f.env]);
    assert_eq!(owner_auth(&f, cancel), Ok(()));

    // The guardian cannot use the escape hatch.
    let payload: [u8; 32] = Sha256::digest(b"guardian-payload").into();
    let gsig = AuthSignature::Ed25519(
        f.guardian_id.clone(),
        sign_ed25519(&f.env, &f.guardian, &payload),
    );
    let unpause = self_ctx(
        &f.env,
        &f.account,
        "set_paused",
        svec![&f.env, false.into_val(&f.env)],
    );
    assert!(f
        .env
        .try_invoke_contract_check_auth::<AccountError>(
            &f.account,
            &BytesN::from_array(&f.env, &payload),
            svec![&f.env, gsig].into_val(&f.env),
            &svec![&f.env, unpause],
        )
        .is_err());
}

#[test]
fn guardian_recovery_signature_cannot_be_replayed() {
    let f = fixture(41);
    let client = StealthBridgeSmartAccountClient::new(&f.env, &f.account);
    let new_owner = ed_key(&f.env, &EdSigningKey::from_bytes(&[99u8; 32]));
    let digest = client.recovery_challenge(&new_owner, &100).to_array();
    let gsig = AuthSignature::Ed25519(
        f.guardian_id.clone(),
        sign_ed25519(&f.env, &f.guardian, &digest),
    );

    client.propose_recovery(&f.guardian_id, &gsig, &new_owner, &100);

    // Owner cancels; resubmitting the same guardian signature must fail.
    f.env.mock_all_auths();
    client.cancel_recovery();
    f.env.set_auths(&[]);
    assert!(client
        .try_propose_recovery(&f.guardian_id, &gsig, &new_owner, &100)
        .is_err());

    // The same guardian key on a different account cannot reuse it either.
    let other = fixture(41); // identical keys, different contract address
    let other_client = StealthBridgeSmartAccountClient::new(&other.env, &other.account);
    let gsig_other = AuthSignature::Ed25519(
        other.guardian_id.clone(),
        sign_ed25519(&other.env, &other.guardian, &digest),
    );
    // `other` is a fresh Env, so register a second account there to compare addresses.
    let second = other.env.register(
        StealthBridgeSmartAccount,
        (
            ed_key(&other.env, &other.owner),
            BytesN::from_array(&other.env, &[0u8; 32]),
            Some(ed_key(&other.env, &other.guardian)),
        ),
    );
    let second_client = StealthBridgeSmartAccountClient::new(&other.env, &second);
    let new_owner_other = ed_key(&other.env, &EdSigningKey::from_bytes(&[99u8; 32]));
    // Same keys and nonce, different account address => different challenge.
    assert_ne!(
        other_client.recovery_challenge(&new_owner_other, &100),
        second_client.recovery_challenge(&new_owner_other, &100)
    );
    // A signature over the first account's challenge is useless on the second.
    assert!(second_client
        .try_propose_recovery(&other.guardian_id, &gsig_other, &new_owner_other, &100)
        .is_err());
}

#[test]
fn session_keys_cannot_authorize_unmetered_functions() {
    let f = fixture(51);
    let client = StealthBridgeSmartAccountClient::new(&f.env, &f.account);
    let session = EdSigningKey::from_bytes(&[53u8; 32]);
    f.env.mock_all_auths();
    let sid = client.add_signer(
        &ed_key(&f.env, &session),
        &SignerRole::Session,
        &Some(2_000),
        &100,
        &200,
        &50,
    );
    f.env.set_auths(&[]);
    let payload: [u8; 32] = Sha256::digest(b"session-payload").into();
    let sig = AuthSignature::Ed25519(sid, sign_ed25519(&f.env, &session, &payload));
    let ctx = Context::Contract(ContractContext {
        contract: Address::generate(&f.env),
        fn_name: Symbol::new(&f.env, "execute_settlement"),
        args: svec![&f.env],
    });
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<AccountError>(
            &f.account,
            &BytesN::from_array(&f.env, &payload),
            svec![&f.env, sig].into_val(&f.env),
            &svec![&f.env, ctx],
        ),
        Err(Ok(AccountError::SessionRestrictedContext))
    );
}

fn webauthn_attempt(
    client_json: &str,
) -> Result<(), Result<AccountError, soroban_sdk::InvokeError>> {
    let env = Env::default();
    let key = P256Key::from_bytes(&[61u8; 32].into()).unwrap();
    let owner_key = SignerKey::Secp256r1(p256_pubkey_bytes(&env, &key));
    let account = env.register(
        StealthBridgeSmartAccount,
        (
            owner_key.clone(),
            BytesN::from_array(&env, &[0u8; 32]),
            Option::<SignerKey>::None,
        ),
    );
    let payload: [u8; 32] = Sha256::digest(b"webauthn-payload").into();
    let json = client_json.replace("{C}", &base64url(&payload));
    let mut auth_data = std::vec![0u8; 32];
    auth_data.push(0x05);
    auth_data.extend_from_slice(&1u32.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(json.as_bytes()));
    let digest: [u8; 32] = Sha256::digest(&signed).into();
    let proof = AuthSignature::WebAuthn(WebAuthnProof {
        signer_id: signer_id_for_key(&env, &owner_key),
        authenticator_data: Bytes::from_slice(&env, &auth_data),
        client_data_json: Bytes::from_slice(&env, json.as_bytes()),
        signature: sign_p256_prehash(&env, &key, &digest),
    });
    let ctx = Context::Contract(ContractContext {
        contract: Address::generate(&env),
        fn_name: Symbol::new(&env, "transfer"),
        args: svec![&env],
    });
    env.try_invoke_contract_check_auth::<AccountError>(
        &account,
        &BytesN::from_array(&env, &payload),
        svec![&env, proof].into_val(&env),
        &svec![&env, ctx],
    )
}

#[test]
fn webauthn_requires_assertion_type_and_exact_challenge_field() {
    assert_eq!(
        webauthn_attempt(r#"{"type":"webauthn.get","challenge":"{C}","origin":"https://x.test"}"#),
        Ok(())
    );
    // Registration ceremony data is not an assertion.
    assert_eq!(
        webauthn_attempt(
            r#"{"type":"webauthn.create","challenge":"{C}","origin":"https://x.test"}"#
        ),
        Err(Ok(AccountError::InvalidWebAuthn))
    );
    // Payload smuggled outside the challenge member.
    assert_eq!(
        webauthn_attempt(
            r#"{"type":"webauthn.get","challenge":"other","origin":"https://{C}.test"}"#
        ),
        Err(Ok(AccountError::InvalidWebAuthn))
    );
}
