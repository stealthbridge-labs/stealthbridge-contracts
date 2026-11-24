use crate::{Groth16Proof, Groth16Vk, PrivacyVerifier, PrivacyVerifierClient, VerifierError};
use ark_bn254::{Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    vec as svec, Address, BytesN, Env,
};

fn hash_to_fr(label: &[u8], parts: &[&[u8]]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(label);
    for p in parts {
        hasher.update((*p).len().to_be_bytes());
        hasher.update(p);
    }
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

fn fq_to_be32(f: &ark_bn254::Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn fr_to_be32(f: &Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn g1_bytes(env: &Env, p: &G1Affine) -> BytesN<64> {
    let mut buf = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        buf[..32].copy_from_slice(&fq_to_be32(&x));
        buf[32..].copy_from_slice(&fq_to_be32(&y));
    }
    BytesN::from_array(env, &buf)
}

fn g2_bytes(env: &Env, p: &G2Affine) -> BytesN<128> {
    let mut buf = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        let x: Fq2 = x;
        let y: Fq2 = y;
        buf[0..32].copy_from_slice(&fq_to_be32(&x.c1));
        buf[32..64].copy_from_slice(&fq_to_be32(&x.c0));
        buf[64..96].copy_from_slice(&fq_to_be32(&y.c1));
        buf[96..128].copy_from_slice(&fq_to_be32(&y.c0));
    }
    BytesN::from_array(env, &buf)
}

fn setup_groth16(env: &Env, num_inputs: usize) -> (Fr, Fr, Fr, Fr, std::vec::Vec<Fr>, Groth16Vk) {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let alpha = hash_to_fr(b"vk-alpha", &[]);
    let beta = hash_to_fr(b"vk-beta", &[]);
    let gamma = hash_to_fr(b"vk-gamma", &[]);
    let delta = hash_to_fr(b"vk-delta", &[]);

    let mut gamma_abc = std::vec::Vec::new();
    let mut ic_g1 = soroban_sdk::Vec::new(env);
    for idx in 0..=num_inputs {
        let s = hash_to_fr(b"vk-ic", &[&(idx as u64).to_be_bytes()]);
        gamma_abc.push(s);
        ic_g1.push_back(g1_bytes(env, &(G1Projective::from(g1) * s).into_affine()));
    }
    let vk = Groth16Vk {
        alpha_g1: g1_bytes(env, &(G1Projective::from(g1) * alpha).into_affine()),
        beta_g2: g2_bytes(env, &(G2Projective::from(g2) * beta).into_affine()),
        gamma_g2: g2_bytes(env, &(G2Projective::from(g2) * gamma).into_affine()),
        delta_g2: g2_bytes(env, &(G2Projective::from(g2) * delta).into_affine()),
        ic_g1,
        active: true,
    };
    (alpha, beta, gamma, delta, gamma_abc, vk)
}

fn prove_groth16(
    env: &Env,
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,
    gamma_abc: &[Fr],
    inputs: &[Fr],
    seed: &[u8],
) -> Groth16Proof {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let a = hash_to_fr(b"a-scalar", &[seed]);
    let b = hash_to_fr(b"b-scalar", &[seed]);
    let mut vk_x = gamma_abc[0];
    for (i, x) in inputs.iter().enumerate() {
        vk_x += *x * gamma_abc[i + 1];
    }
    let rhs = (a * b) - (alpha * beta) - (vk_x * gamma);
    let c = rhs * delta.inverse().unwrap();
    Groth16Proof {
        a_g1: g1_bytes(env, &(G1Projective::from(g1) * a).into_affine()),
        b_g2: g2_bytes(env, &(G2Projective::from(g2) * b).into_affine()),
        c_g1: g1_bytes(env, &(G1Projective::from(g1) * c).into_affine()),
    }
}

#[test]
fn groth16_verifier_accepts_valid_proof_and_rejects_replay_tamper_expiry_and_wrong_vk() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.sequence_number = 100);

    let admin = Address::generate(&env);
    let contract_id = env.register(PrivacyVerifier, (admin.clone(),));
    let client = PrivacyVerifierClient::new(&env, &contract_id);

    let (alpha, beta, gamma, delta, gamma_abc, vk) = setup_groth16(&env, 3);
    client.register_verification_key(&1, &1, &vk);

    let root_fr = hash_to_fr(b"root", &[b"merkle-v1"]);
    let nullifier_fr = hash_to_fr(b"nullifier", &[b"note-01"]);
    let scope_fr = hash_to_fr(b"scope", &[b"testnet-private-transfer"]);

    let root = BytesN::from_array(&env, &fr_to_be32(&root_fr));
    let nullifier = BytesN::from_array(&env, &fr_to_be32(&nullifier_fr));
    let scope = BytesN::from_array(&env, &fr_to_be32(&scope_fr));
    client.register_root(&root, &200);

    let pub_inputs = svec![&env, root.clone(), nullifier.clone(), scope.clone()];
    let proof = prove_groth16(
        &env,
        alpha,
        beta,
        gamma,
        delta,
        &gamma_abc,
        &[root_fr, nullifier_fr, scope_fr],
        b"proof-seed-1",
    );

    // 1. Wrong public input binding rejected cleanly
    let bad_scope = BytesN::from_array(&env, &fr_to_be32(&hash_to_fr(b"scope", &[b"other"])));
    assert_eq!(
        client.try_verify_and_spend(&1, &1, &root, &nullifier, &bad_scope, &pub_inputs, &proof),
        Err(Ok(VerifierError::PublicInputMismatch))
    );

    // 2. Tampered proof rejected without spending nullifier
    let mut tampered_proof = proof.clone();
    tampered_proof.c_g1 = g1_bytes(&env, &G1Affine::generator());
    assert_eq!(
        client.try_verify_and_spend(
            &1,
            &1,
            &root,
            &nullifier,
            &scope,
            &pub_inputs,
            &tampered_proof
        ),
        Err(Ok(VerifierError::InvalidProof))
    );
    assert!(!client.is_nullifier_spent(&nullifier));

    // 3. Valid proof succeeds and spends nullifier
    let att = client.verify_and_spend(&1, &1, &root, &nullifier, &scope, &pub_inputs, &proof);
    assert_eq!(att.verified_ledger, 100);
    assert!(client.is_nullifier_spent(&nullifier));

    // 4. Nullifier replay fails
    assert_eq!(
        client.try_verify_and_spend(&1, &1, &root, &nullifier, &scope, &pub_inputs, &proof),
        Err(Ok(VerifierError::NullifierAlreadySpent))
    );

    // 5. Wrong/revoked circuit version fails
    let n2_fr = hash_to_fr(b"nullifier", &[b"note-02"]);
    let n2 = BytesN::from_array(&env, &fr_to_be32(&n2_fr));
    let p2_inputs = svec![&env, root.clone(), n2.clone(), scope.clone()];
    let p2 = prove_groth16(
        &env,
        alpha,
        beta,
        gamma,
        delta,
        &gamma_abc,
        &[root_fr, n2_fr, scope_fr],
        b"s2",
    );
    assert_eq!(
        client.try_verify_and_spend(&1, &99, &root, &n2, &scope, &p2_inputs, &p2),
        Err(Ok(VerifierError::VerificationKeyInactive))
    );

    // 6. Expired root rejected
    env.ledger().with_mut(|l| l.sequence_number = 201);
    assert_eq!(
        client.try_verify_and_spend(&1, &1, &root, &n2, &scope, &p2_inputs, &p2),
        Err(Ok(VerifierError::UnknownOrExpiredRoot))
    );
}

/// BN254 scalar field modulus r, big-endian.
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Big-endian 256-bit addition `a + r` (caller guarantees no overflow).
fn add_modulus(a: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = a[i] as u16 + FR_MODULUS_BE[i] as u16 + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0, "test value must not overflow 256 bits");
    out
}

/// Regression for audit finding C-1: a nullifier `N` and its non-canonical
/// alias `N + r` are the same field element, so without a canonical-encoding
/// check one proof could be spent once per alias.
#[test]
fn non_canonical_field_element_aliases_cannot_double_spend() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.sequence_number = 100);

    let admin = Address::generate(&env);
    let contract_id = env.register(PrivacyVerifier, (admin.clone(),));
    let client = PrivacyVerifierClient::new(&env, &contract_id);

    let (alpha, beta, gamma, delta, gamma_abc, vk) = setup_groth16(&env, 3);
    client.register_verification_key(&1, &1, &vk);

    // Small nullifier value so `N + r` still fits in 256 bits.
    let root_fr = hash_to_fr(b"root", &[b"alias"]);
    let nullifier_fr = Fr::from(7u64);
    let scope_fr = hash_to_fr(b"scope", &[b"alias"]);
    let root = BytesN::from_array(&env, &fr_to_be32(&root_fr));
    let nullifier = BytesN::from_array(&env, &fr_to_be32(&nullifier_fr));
    let scope = BytesN::from_array(&env, &fr_to_be32(&scope_fr));
    client.register_root(&root, &200);

    let proof = prove_groth16(
        &env,
        alpha,
        beta,
        gamma,
        delta,
        &gamma_abc,
        &[root_fr, nullifier_fr, scope_fr],
        b"alias-seed",
    );
    let inputs = svec![&env, root.clone(), nullifier.clone(), scope.clone()];
    client.verify_and_spend(&1, &1, &root, &nullifier, &scope, &inputs, &proof);

    // Same field element, different byte encoding: must be rejected.
    let alias = BytesN::from_array(&env, &add_modulus(&fr_to_be32(&nullifier_fr)));
    let alias_inputs = svec![&env, root.clone(), alias.clone(), scope.clone()];
    assert_eq!(
        client.try_verify_and_spend(&1, &1, &root, &alias, &scope, &alias_inputs, &proof),
        Err(Ok(VerifierError::NonCanonicalFieldElement))
    );
    assert!(!client.is_nullifier_spent(&alias));

    // Non-canonical roots are rejected at registration too.
    let root_alias = BytesN::from_array(&env, &add_modulus(&fr_to_be32(&Fr::from(9u64))));
    assert_eq!(
        client.try_register_root(&root_alias, &200),
        Err(Ok(VerifierError::NonCanonicalFieldElement))
    );
}

/// Regression for audit finding H-1: the admin is fixed atomically at deploy
/// time, so there is no front-runnable initializer.
#[test]
fn admin_is_bound_at_construction() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(PrivacyVerifier, (admin.clone(),));
    let client = PrivacyVerifierClient::new(&env, &contract_id);
    assert_eq!(client.get_admin(), Some(admin));
    assert!(!client.is_paused());
}
