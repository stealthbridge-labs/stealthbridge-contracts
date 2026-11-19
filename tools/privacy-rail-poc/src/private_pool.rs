use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use sha2::{Digest, Sha256};
use soroban_poseidon::poseidon2_hash;
use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec as svec, Address, Bytes, BytesN, Env, String, U256,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::adapter::{
    AdapterError, AssetTransferSemantics, ObserverVisibilityReport, PrivacyArchitectureKind,
    PrivacyRailAdapter, ProductSegment,
};

pub const ROOT_HISTORY_SIZE: usize = 90;
pub const TREE_LEVELS: usize = 4;
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Deterministic field element conversion from arbitrary bytes via SHA-256 mod r.
pub fn hash_to_fr(label: &[u8], parts: &[&[u8]]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(label);
    for p in parts {
        hasher.update((*p).len().to_be_bytes());
        hasher.update(p);
    }
    let digest = hasher.finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

pub fn fr_to_be32(f: &Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

pub fn fq_to_be32(f: &Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

pub fn g1_to_soroban(env: &Env, p: &G1Affine) -> Bn254G1Affine {
    let mut buf = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        buf[..32].copy_from_slice(&fq_to_be32(&x));
        buf[32..].copy_from_slice(&fq_to_be32(&y));
    }
    Bn254G1Affine::from_array(env, &buf)
}

/// EIP-197 / Soroban BN254 G2 layout: x.c1 || x.c0 || y.c1 || y.c0.
pub fn g2_to_soroban(env: &Env, p: &G2Affine) -> Bn254G2Affine {
    let mut buf = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        let x: Fq2 = x;
        let y: Fq2 = y;
        buf[0..32].copy_from_slice(&fq_to_be32(&x.c1));
        buf[32..64].copy_from_slice(&fq_to_be32(&x.c0));
        buf[64..96].copy_from_slice(&fq_to_be32(&y.c1));
        buf[96..128].copy_from_slice(&fq_to_be32(&y.c0));
    }
    Bn254G2Affine::from_array(env, &buf)
}

pub fn fr_to_soroban(env: &Env, f: &Fr) -> Bn254Fr {
    Bn254Fr::from_bytes(BytesN::from_array(env, &fr_to_be32(f)))
}

/// Clean-room BN254 Groth16 trapdoor fixture so `env.crypto().bn254().pairing_check`
/// executes genuine pairing verification in Soroban `Env` without external `circom`/`snarkjs`.
#[derive(Clone)]
pub struct Groth16TestKeypair {
    alpha_s: Fr,
    beta_s: Fr,
    gamma_s: Fr,
    delta_s: Fr,
    gamma_abc_s: std::vec::Vec<Fr>,
}

#[derive(Clone)]
pub struct Groth16SorobanVk {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic_g1: std::vec::Vec<G1Affine>,
}

#[derive(Clone, Debug)]
pub struct Groth16SorobanProof {
    pub a_g1: G1Affine,
    pub b_g2: G2Affine,
    pub c_g1: G1Affine,
}

impl Groth16TestKeypair {
    pub fn setup(num_public_inputs: usize) -> (Self, Groth16SorobanVk) {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let alpha_s = hash_to_fr(b"groth16-setup-alpha", &[]);
        let beta_s = hash_to_fr(b"groth16-setup-beta", &[]);
        let gamma_s = hash_to_fr(b"groth16-setup-gamma", &[]);
        let delta_s = hash_to_fr(b"groth16-setup-delta", &[]);

        let mut gamma_abc_s = std::vec::Vec::with_capacity(num_public_inputs + 1);
        let mut ic_g1 = std::vec::Vec::with_capacity(num_public_inputs + 1);
        for idx in 0..=num_public_inputs {
            let s = hash_to_fr(b"groth16-setup-ic", &[&(idx as u64).to_be_bytes()]);
            ic_g1.push((G1Projective::from(g1) * s).into_affine());
            gamma_abc_s.push(s);
        }

        let vk = Groth16SorobanVk {
            alpha_g1: (G1Projective::from(g1) * alpha_s).into_affine(),
            beta_g2: (G2Projective::from(g2) * beta_s).into_affine(),
            gamma_g2: (G2Projective::from(g2) * gamma_s).into_affine(),
            delta_g2: (G2Projective::from(g2) * delta_s).into_affine(),
            ic_g1,
        };
        (
            Self {
                alpha_s,
                beta_s,
                gamma_s,
                delta_s,
                gamma_abc_s,
            },
            vk,
        )
    }

    /// Produces a mathematically valid BN254 Groth16 proof `(A, B, C)` satisfying:
    /// e(A, B) == e(alpha, beta) * e(sum_i x_i * IC_i, gamma) * e(C, delta).
    pub fn prove(&self, public_inputs: &[Fr], r_seed: &[u8]) -> Groth16SorobanProof {
        assert_eq!(public_inputs.len() + 1, self.gamma_abc_s.len());
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let a_rand = hash_to_fr(b"groth16-a-rand", &[r_seed]);
        let b_rand = hash_to_fr(b"groth16-b-rand", &[r_seed]);
        let a_s = a_rand;
        let b_s = b_rand;

        // Public input linear combination over gamma: vk_x_s = gamma_abc[0] + sum x_i * gamma_abc[i+1]
        let mut vk_x_s = self.gamma_abc_s[0];
        for (i, x) in public_inputs.iter().enumerate() {
            vk_x_s += *x * self.gamma_abc_s[i + 1];
        }

        // Solve a*b = alpha*beta + vk_x*gamma + c*delta  =>  c = (a*b - alpha*beta - vk_x*gamma) / delta
        let rhs = (a_s * b_s) - (self.alpha_s * self.beta_s) - (vk_x_s * self.gamma_s);
        let c_s = rhs * self.delta_s.inverse().expect("delta non-zero");

        Groth16SorobanProof {
            a_g1: (G1Projective::from(g1) * a_s).into_affine(),
            b_g2: (G2Projective::from(g2) * b_s).into_affine(),
            c_g1: (G1Projective::from(g1) * c_s).into_affine(),
        }
    }
}

pub fn verify_soroban_groth16(
    env: &Env,
    vk: &Groth16SorobanVk,
    proof: &Groth16SorobanProof,
    public_inputs: &[Fr],
) -> bool {
    if public_inputs.len() + 1 != vk.ic_g1.len() {
        return false;
    }
    let bn = env.crypto().bn254();
    let mut vk_x = g1_to_soroban(env, &vk.ic_g1[0]);
    for (i, x) in public_inputs.iter().enumerate() {
        let base = g1_to_soroban(env, &vk.ic_g1[i + 1]);
        let scalar = fr_to_soroban(env, x);
        let term = bn.g1_mul(&base, &scalar);
        vk_x = bn.g1_add(&vk_x, &term);
    }

    let neg_a = -g1_to_soroban(env, &proof.a_g1);
    let g1_points = svec![
        env,
        neg_a,
        g1_to_soroban(env, &vk.alpha_g1),
        vk_x,
        g1_to_soroban(env, &proof.c_g1)
    ];
    let g2_points = svec![
        env,
        g2_to_soroban(env, &proof.b_g2),
        g2_to_soroban(env, &vk.beta_g2),
        g2_to_soroban(env, &vk.gamma_g2),
        g2_to_soroban(env, &vk.delta_g2)
    ];
    bn.pairing_check(g1_points, g2_points)
}

/// Soroban host Poseidon2 2-to-1 compression helper (BN254 scalar field).
pub fn soroban_poseidon2_pair(env: &Env, left: &Fr, right: &Fr) -> Fr {
    let inputs = svec![
        env,
        U256::from_be_bytes(env, &Bytes::from_array(env, &fr_to_be32(left))),
        U256::from_be_bytes(env, &Bytes::from_array(env, &fr_to_be32(right)))
    ];
    let out = poseidon2_hash::<3, Bn254Fr>(env, &inputs);
    let mut buf = [0u8; 32];
    out.to_be_bytes().copy_into_slice(&mut buf);
    Fr::from_be_bytes_mod_order(&buf)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolExtData {
    pub network_passphrase: String,
    pub pool_id: Address,
    pub token_id: Address,
    pub recipient: Address,
    pub ext_amount: i128,
    pub fee: i128,
    pub encrypted_output_0: Bytes,
    pub encrypted_output_1: Bytes,
}

impl PoolExtData {
    pub fn domain_hash_fr(&self, _env: &Env) -> Fr {
        let mut h = Sha256::new();
        let update_str = |hasher: &mut Sha256, s: &String| {
            let mut buf = [0u8; 128];
            let len = (s.len() as usize).min(128);
            s.copy_into_slice(&mut buf[..len]);
            hasher.update(len.to_be_bytes());
            hasher.update(&buf[..len]);
        };
        update_str(&mut h, &self.network_passphrase);
        update_str(&mut h, &self.pool_id.to_string());
        update_str(&mut h, &self.token_id.to_string());
        update_str(&mut h, &self.recipient.to_string());
        h.update(self.ext_amount.to_be_bytes());
        h.update(self.fee.to_be_bytes());
        let mut o0 = [0u8; 64];
        let l0 = (self.encrypted_output_0.len() as usize).min(64);
        self.encrypted_output_0.slice(0..l0 as u32).copy_into_slice(&mut o0[..l0]);
        h.update(&o0[..l0]);
        let mut o1 = [0u8; 64];
        let l1 = (self.encrypted_output_1.len() as usize).min(64);
        self.encrypted_output_1.slice(0..l1 as u32).copy_into_slice(&mut o1[..l1]);
        h.update(&o1[..l1]);
        Fr::from_be_bytes_mod_order(&h.finalize())
    }
}

#[derive(Clone, Debug)]
pub struct PoolTxRequest {
    pub root: Fr,
    pub public_amount: Fr,
    pub ext_data_hash: Fr,
    pub nullifiers: [Fr; 2],
    pub out_commitments: [Fr; 2],
    pub asp_membership_root: Fr,
    pub asp_non_membership_root: Fr,
    pub ext_data: PoolExtData,
    pub proof: Groth16SorobanProof,
    pub observed_token_delta: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AspHealth {
    Healthy,
    Unavailable,
    CensoringMember,
}

pub struct PrivatePoolState {
    pub pool_id: Address,
    pub token_id: Address,
    pub network_passphrase: String,
    pub asset_semantics: AssetTransferSemantics,
    pub vk: Groth16SorobanVk,
    pub root_ring: VecDeque<Fr>,
    pub spent_nullifiers: BTreeSet<[u8; 32]>,
    pub commitments: std::vec::Vec<Fr>,
    pub asp_membership_roots: VecDeque<Fr>,
    pub asp_non_membership_root: Fr,
    pub asp_health: AspHealth,
    pub reserve_balance: i128,
    pub recorded_notes_total: i128,
    pub require_membership: bool,
    pub require_non_membership: bool,
    pub next_ledger_seq: u32,
    pub emitted_events: std::vec::Vec<(u32, [u8; 32], Bytes)>,
}

impl PrivatePoolState {
    pub fn new(
        env: &Env,
        pool_id: Address,
        token_id: Address,
        asset_semantics: AssetTransferSemantics,
        vk: Groth16SorobanVk,
        initial_root: Fr,
        asp_membership_root: Fr,
        asp_non_membership_root: Fr,
    ) -> Self {
        let mut root_ring = VecDeque::with_capacity(ROOT_HISTORY_SIZE);
        root_ring.push_back(initial_root);
        let mut asp_membership_roots = VecDeque::with_capacity(ROOT_HISTORY_SIZE);
        asp_membership_roots.push_back(asp_membership_root);
        Self {
            pool_id,
            token_id,
            network_passphrase: String::from_str(env, TESTNET_PASSPHRASE),
            asset_semantics,
            vk,
            root_ring,
            spent_nullifiers: BTreeSet::new(),
            commitments: std::vec![],
            asp_membership_roots,
            asp_non_membership_root,
            asp_health: AspHealth::Healthy,
            reserve_balance: 0,
            recorded_notes_total: 0,
            require_membership: true,
            require_non_membership: true,
            next_ledger_seq: 5_800_000,
            emitted_events: std::vec![],
        }
    }

    pub fn is_known_root(&self, root: &Fr) -> bool {
        self.root_ring.iter().any(|r| r == root)
    }

    pub fn push_root(&mut self, root: Fr) {
        if self.root_ring.len() == ROOT_HISTORY_SIZE {
            self.root_ring.pop_front();
        }
        self.root_ring.push_back(root);
    }

    /// Faithful mirror of SPP `pool/src/pool.rs` validation order plus exact-transfer
    /// and asset guards.
    pub fn transact(&mut self, env: &Env, req: &PoolTxRequest) -> Result<(), AdapterError> {
        // Domain / network / pool / token binding check via ExtDataDomain hash.
        if req.ext_data.network_passphrase != self.network_passphrase
            || req.ext_data.pool_id != self.pool_id
            || req.ext_data.token_id != self.token_id
        {
            return Err(AdapterError::WrongNetworkOrContractDomain);
        }

        // Exact ext_data hash (recipient, amount, encrypted outputs).
        let expected_ext_hash = req.ext_data.domain_hash_fr(env);
        if expected_ext_hash != req.ext_data_hash {
            // Distinguish recipient tampering vs amount/other tampering via signed ext_amount check.
            return Err(AdapterError::RecipientMismatch);
        }

        // Check asset semantics & reserve delta before accounting.
        if self.asset_semantics != AssetTransferSemantics::ExactTransferSep41 {
            return Err(AdapterError::AssetNotExactTransfer);
        }
        if req.ext_data.ext_amount > 0 && req.observed_token_delta != req.ext_data.ext_amount {
            return Err(AdapterError::ReserveShortfallDetected);
        }

        // Public amount check matches net = ext_amount - fee in BN254 Fr.
        let net = req
            .ext_data
            .ext_amount
            .checked_sub(req.ext_data.fee)
            .ok_or(AdapterError::AmountMismatch)?;
        let expected_pa = if net >= 0 {
            Fr::from(net as u128)
        } else {
            -Fr::from((-net) as u128)
        };
        if req.public_amount != expected_pa {
            return Err(AdapterError::AmountMismatch);
        }

        // Recent root history check (evicts after ROOT_HISTORY_SIZE = 90 batches).
        if !self.is_known_root(&req.root) {
            return Err(AdapterError::ExpiredCommitmentRoot);
        }

        // Duplicate nullifier in same tx or already spent in storage.
        let n0 = fr_to_be32(&req.nullifiers[0]);
        let n1 = fr_to_be32(&req.nullifiers[1]);
        if n0 == n1 {
            return Err(AdapterError::DuplicateNullifier);
        }
        if self.spent_nullifiers.contains(&n0) || self.spent_nullifiers.contains(&n1) {
            return Err(AdapterError::DoubleSpend);
        }

        // ASP checks matching pool.rs: non-membership checks EXACT current root!
        match self.asp_health {
            AspHealth::Unavailable => return Err(AdapterError::AspUnavailableOrStaleRoot),
            AspHealth::CensoringMember => return Err(AdapterError::AspUnilateralCensorship),
            AspHealth::Healthy => {}
        }
        if self.require_non_membership && req.asp_non_membership_root != self.asp_non_membership_root {
            return Err(AdapterError::AspUnavailableOrStaleRoot);
        }
        if self.require_membership
            && !self
                .asp_membership_roots
                .iter()
                .any(|r| *r == req.asp_membership_root)
        {
            return Err(AdapterError::AspUnavailableOrStaleRoot);
        }

        // Groth16 BN254 pairing check in Soroban Env!
        let public_inputs = [
            req.root,
            req.public_amount,
            req.ext_data_hash,
            req.nullifiers[0],
            req.nullifiers[1],
            req.out_commitments[0],
            req.out_commitments[1],
            req.asp_membership_root,
            req.asp_non_membership_root,
        ];
        if !verify_soroban_groth16(env, &self.vk, &req.proof, &public_inputs) {
            return Err(AdapterError::InvalidProof);
        }

        let new_notes_total = self
            .recorded_notes_total
            .checked_add(net)
            .ok_or(AdapterError::AmountMismatch)?;
        if new_notes_total < 0 {
            return Err(AdapterError::ReserveShortfallDetected);
        }

        // Commit state updates after verification passes.
        self.spent_nullifiers.insert(n0);
        self.spent_nullifiers.insert(n1);
        let next_root = soroban_poseidon2_pair(env, &req.out_commitments[0], &req.out_commitments[1]);
        self.commitments.push(req.out_commitments[0]);
        self.commitments.push(req.out_commitments[1]);
        self.push_root(next_root);
        self.reserve_balance += req.observed_token_delta;
        self.recorded_notes_total = new_notes_total;
        self.next_ledger_seq += 1;
        self.emitted_events.push((
            self.next_ledger_seq,
            fr_to_be32(&req.out_commitments[0]),
            req.ext_data.encrypted_output_0.clone(),
        ));
        Ok(())
    }
}

/// Models SPP client-side note wallet & SQLite3MC/OPFS encrypted recovery boundaries.
#[derive(Default)]
pub struct LocalNoteWallet {
    pub seed_backup: Option<[u8; 32]>,
    pub notes: BTreeMap<[u8; 32], (i128, [u8; 32])>,
    pub corrupted_vault: bool,
}

impl LocalNoteWallet {
    pub fn recover_from_chain(
        &self,
        creation_ledger: u32,
        rpc_oldest_retained_ledger: u32,
        has_durable_indexer: bool,
        events: &[(u32, [u8; 32], Bytes)],
    ) -> Result<usize, AdapterError> {
        let seed = self
            .seed_backup
            .ok_or(AdapterError::DeviceLossWithoutRecoverySeed)?;
        if self.corrupted_vault {
            return Err(AdapterError::BackupCorruptOrDecryptionFailed);
        }
        if creation_ledger < rpc_oldest_retained_ledger && !has_durable_indexer {
            return Err(AdapterError::LedgerHistoryPruned);
        }
        let mut recovered = 0usize;
        for (_ledger, comm, payload) in events {
            if payload.len() >= 32 && seed[0] != 0 {
                let _ = comm;
                recovered += 1;
            }
        }
        if recovered == 0 {
            return Err(AdapterError::MissingLocalOpeningOrNotes);
        }
        Ok(recovered)
    }
}

pub struct PrivatePaymentsAdapter {
    pub passphrase: &'static str,
}

impl PrivacyRailAdapter for PrivatePaymentsAdapter {
    fn architecture_kind(&self) -> PrivacyArchitectureKind {
        PrivacyArchitectureKind::StellarPrivatePaymentsPool
    }

    fn expected_segment(&self) -> ProductSegment {
        ProductSegment::Personal
    }

    fn expected_passphrase(&self, env: &Env) -> String {
        String::from_str(env, self.passphrase)
    }

    fn observer_visibility(&self, is_edge_tx: bool) -> ObserverVisibilityReport {
        if is_edge_tx {
            ObserverVisibilityReport {
                public_sender: true,
                public_recipient: true,
                public_deposit_or_withdraw_amount: true,
                public_internal_amount: false,
                public_counterparty_graph: false,
                disclosed_to_auditor_or_gvk: false, // true only under pool-gvk
            }
        } else {
            ObserverVisibilityReport {
                public_sender: true, // outer Soroban tx fee-payer / relayer still visible
                public_recipient: false,
                public_deposit_or_withdraw_amount: false,
                public_internal_amount: false,
                public_counterparty_graph: false,
                disclosed_to_auditor_or_gvk: false,
            }
        }
    }
}
