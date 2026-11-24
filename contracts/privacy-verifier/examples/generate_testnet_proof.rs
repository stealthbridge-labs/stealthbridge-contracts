//! PAIRING SMOKE TEST ONLY. NOT A ZERO-KNOWLEDGE PROOF SYSTEM.
//!
//! This generator derives the Groth16 toxic waste (alpha, beta, gamma, delta,
//! IC scalars) from public SHA-256 labels and has no circuit. Anyone can
//! therefore compute a "valid" proof for ANY public inputs against the
//! verification key it prints (audit finding C-2). It exists only to exercise
//! the Soroban BN254 `pairing_check` host function. A key produced here must
//! never be registered on a verifier that guards value or identity, and its
//! Testnet use proves only that the pairing host function works. Real proofs
//! require an upstream circuit with a proper setup (see docs/adr in the
//! workspace and integrations/stellar-private-payments).

use ark_bn254::{Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use sha2::{Digest, Sha256};

fn hash_to_fr(label: &[u8], parts: &[&[u8]]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(label);
    for p in parts {
        hasher.update((*p).len().to_be_bytes());
        hasher.update(p);
    }
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
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

fn g1_hex(p: &G1Affine) -> String {
    let mut buf = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        buf[..32].copy_from_slice(&fq_to_be32(&x));
        buf[32..].copy_from_slice(&fq_to_be32(&y));
    }
    to_hex(&buf)
}

fn g2_hex(p: &G2Affine) -> String {
    let mut buf = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        let x: Fq2 = x;
        let y: Fq2 = y;
        buf[0..32].copy_from_slice(&fq_to_be32(&x.c1));
        buf[32..64].copy_from_slice(&fq_to_be32(&x.c0));
        buf[64..96].copy_from_slice(&fq_to_be32(&y.c1));
        buf[96..128].copy_from_slice(&fq_to_be32(&y.c0));
    }
    to_hex(&buf)
}

fn main() {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let alpha = hash_to_fr(b"vk-alpha", &[]);
    let beta = hash_to_fr(b"vk-beta", &[]);
    let gamma = hash_to_fr(b"vk-gamma", &[]);
    let delta = hash_to_fr(b"vk-delta", &[]);

    let mut gamma_abc = Vec::new();
    let mut ic_hex = Vec::new();
    for idx in 0..=3usize {
        let s = hash_to_fr(b"vk-ic", &[&(idx as u64).to_be_bytes()]);
        gamma_abc.push(s);
        ic_hex.push(format!(
            "\"{}\"",
            g1_hex(&(G1Projective::from(g1) * s).into_affine())
        ));
    }

    let vk_json = format!(
        "{{\"alpha_g1\":\"{}\",\"beta_g2\":\"{}\",\"gamma_g2\":\"{}\",\"delta_g2\":\"{}\",\"ic_g1\":[{}],\"active\":true}}",
        g1_hex(&(G1Projective::from(g1) * alpha).into_affine()),
        g2_hex(&(G2Projective::from(g2) * beta).into_affine()),
        g2_hex(&(G2Projective::from(g2) * gamma).into_affine()),
        g2_hex(&(G2Projective::from(g2) * delta).into_affine()),
        ic_hex.join(",")
    );

    let root_fr = hash_to_fr(b"root", &[b"testnet-merkle-v1"]);
    let nullifier_fr = hash_to_fr(b"nullifier", &[b"testnet-note-01"]);
    let scope_fr = hash_to_fr(b"scope", &[b"stealthbridge-testnet-v3"]);

    let a = hash_to_fr(b"a-scalar", &[b"testnet-proof-seed-1"]);
    let b = hash_to_fr(b"b-scalar", &[b"testnet-proof-seed-1"]);
    let vk_x = gamma_abc[0]
        + root_fr * gamma_abc[1]
        + nullifier_fr * gamma_abc[2]
        + scope_fr * gamma_abc[3];
    let rhs = (a * b) - (alpha * beta) - (vk_x * gamma);
    let c = rhs * delta.inverse().expect("delta non-zero");

    let proof_json = format!(
        "{{\"a_g1\":\"{}\",\"b_g2\":\"{}\",\"c_g1\":\"{}\"}}",
        g1_hex(&(G1Projective::from(g1) * a).into_affine()),
        g2_hex(&(G2Projective::from(g2) * b).into_affine()),
        g1_hex(&(G1Projective::from(g1) * c).into_affine())
    );

    println!("VK_JSON={vk_json}");
    println!("ROOT_HEX={}", to_hex(&fr_to_be32(&root_fr)));
    println!("NULLIFIER_HEX={}", to_hex(&fr_to_be32(&nullifier_fr)));
    println!("SCOPE_HEX={}", to_hex(&fr_to_be32(&scope_fr)));
    println!("PROOF_JSON={proof_json}");
}
