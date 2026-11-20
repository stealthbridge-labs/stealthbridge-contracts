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

    let account_id = env.register(StealthBridgeSmartAccount, ());
    let client = StealthBridgeSmartAccountClient::new(&env, &account_id);

    let owner_key = SignerKey::Secp256r1(p256_pubkey_bytes(&env, &passkey_owner));
    let guardian_key = SignerKey::Ed25519(BytesN::from_array(
        &env,
        &guardian_ed.verifying_key().to_bytes(),
    ));
    let owner_id = client.initialize(&owner_key, &rp_hash_n, &Some(guardian_key.clone()));
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
    let mut recovery_msg = std::vec::Vec::from(&b"stealthbridge-recovery-v1:"[..]);
    recovery_msg.extend_from_slice(&new_owner_id.to_array());
    recovery_msg.extend_from_slice(&100u32.to_be_bytes());
    let recovery_digest: [u8; 32] = Sha256::digest(&recovery_msg).into();
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

    // Silence unused token helper warning while confirming StellarAssetClient compatibility
    let _sac_client = StellarAssetClient::new(&env, &token_addr);
}
