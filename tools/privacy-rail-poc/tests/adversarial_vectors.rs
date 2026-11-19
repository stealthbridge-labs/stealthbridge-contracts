use ark_bn254::{Fr, G1Projective};
use ark_ec::CurveGroup;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String};
use stealthbridge_privacy_rail_poc::{
    adapter::{
        check_event_retention_coverage, reject_draft_as_settlement, AdapterError,
        AssetTransferSemantics, EncryptedDraftArtifact, PrivacyArchitectureKind,
        PrivacyRailAdapter, ProductSegment, TransferIntent,
    },
    confidential_token::{
        pedersen_commit, verify_oz_ultrahonk_vk_real, ConfidentialTokenAdapter,
        ConfidentialTokenPool, OZ_REGISTER_VK_BIN, OZ_TRANSFER_VK_BIN, OZ_WITHDRAW_VK_BIN,
    },
    private_pool::{
        hash_to_fr, soroban_poseidon2_pair, verify_soroban_groth16, AspHealth,
        Groth16TestKeypair, LocalNoteWallet, PoolExtData, PoolTxRequest, PrivatePaymentsAdapter,
        PrivatePoolState, TESTNET_PASSPHRASE,
    },
};

fn build_valid_pool_fixture(
    env: &Env,
) -> (
    Groth16TestKeypair,
    PrivatePoolState,
    Address,
    Fr,
    Fr,
    Fr,
) {
    let pool_id = Address::generate(env);
    let token_id = Address::generate(env);
    let recipient = Address::generate(env);
    let (kp, vk) = Groth16TestKeypair::setup(9);
    let initial_root = hash_to_fr(b"init-root", &[]);
    let asp_mem_root = hash_to_fr(b"asp-mem-root", &[]);
    let asp_nonmem_root = hash_to_fr(b"asp-nonmem-root", &[]);
    let pool = PrivatePoolState::new(
        env,
        pool_id,
        token_id,
        AssetTransferSemantics::ExactTransferSep41,
        vk,
        initial_root,
        asp_mem_root,
        asp_nonmem_root,
    );
    (kp, pool, recipient, initial_root, asp_mem_root, asp_nonmem_root)
}

fn make_pool_req(
    env: &Env,
    kp: &Groth16TestKeypair,
    pool: &PrivatePoolState,
    recipient: Address,
    ext_amount: i128,
    fee: i128,
    root: Fr,
    seed: &[u8],
) -> PoolTxRequest {
    let ext_data = PoolExtData {
        network_passphrase: pool.network_passphrase.clone(),
        pool_id: pool.pool_id.clone(),
        token_id: pool.token_id.clone(),
        recipient,
        ext_amount,
        fee,
        encrypted_output_0: Bytes::from_slice(env, &[0x11u8; 48]),
        encrypted_output_1: Bytes::from_slice(env, &[0x22u8; 48]),
    };
    let net = ext_amount - fee;
    let public_amount = if net >= 0 {
        Fr::from(net as u128)
    } else {
        -Fr::from((-net) as u128)
    };
    let ext_data_hash = ext_data.domain_hash_fr(env);
    let n0 = hash_to_fr(b"nullifier-0", &[seed]);
    let n1 = hash_to_fr(b"nullifier-1", &[seed]);
    let c0 = hash_to_fr(b"commit-0", &[seed]);
    let c1 = hash_to_fr(b"commit-1", &[seed]);
    let asp_mem = *pool.asp_membership_roots.back().unwrap();
    let asp_nonmem = pool.asp_non_membership_root;
    let public_inputs = [
        root,
        public_amount,
        ext_data_hash,
        n0,
        n1,
        c0,
        c1,
        asp_mem,
        asp_nonmem,
    ];
    let proof = kp.prove(&public_inputs, seed);
    PoolTxRequest {
        root,
        public_amount,
        ext_data_hash,
        nullifiers: [n0, n1],
        out_commitments: [c0, c1],
        asp_membership_root: asp_mem,
        asp_non_membership_root: asp_nonmem,
        ext_data,
        proof,
        observed_token_delta: ext_amount,
    }
}

#[test]
fn adapter_prevents_draft_confusion_and_rail_interchange() {
    let env = Env::default();
    let draft = EncryptedDraftArtifact {
        draft_id: String::from_str(&env, "draft-001"),
        ciphertext_sha256: BytesN::from_array(&env, &[0xAA; 32]),
        review_commitment_sha256: BytesN::from_array(&env, &[0xBB; 32]),
    };
    assert_eq!(
        reject_draft_as_settlement(&draft),
        Err(AdapterError::DraftNotSettleableOnChain)
    );

    let spp_adapter = PrivatePaymentsAdapter {
        passphrase: TESTNET_PASSPHRASE,
    };
    let ct_adapter = ConfidentialTokenAdapter {
        passphrase: TESTNET_PASSPHRASE,
    };
    let wrong_rail_intent = TransferIntent {
        segment: ProductSegment::Personal,
        requested_rail: PrivacyArchitectureKind::ConfidentialSep41Token,
        network_passphrase: String::from_str(&env, TESTNET_PASSPHRASE),
        recipient: Address::generate(&env),
        amount_stroops: 1_000_000,
        asset_semantics: AssetTransferSemantics::ExactTransferSep41,
    };
    assert_eq!(
        spp_adapter.validate_intent(&env, &wrong_rail_intent),
        Err(AdapterError::RailMismatch)
    );
    assert_eq!(
        ct_adapter.validate_intent(&env, &wrong_rail_intent),
        Ok(())
    );
}

#[test]
fn vector_01_invalid_proofs_rejected_on_both_rails() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    let mut req = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"v01");
    assert!(verify_soroban_groth16(
        &env,
        &pool.vk,
        &req.proof,
        &[
            req.root,
            req.public_amount,
            req.ext_data_hash,
            req.nullifiers[0],
            req.nullifiers[1],
            req.out_commitments[0],
            req.out_commitments[1],
            req.asp_membership_root,
            req.asp_non_membership_root,
        ]
    ));
    // Tamper proof C point on curve.
    req.proof.c_g1 = (G1Projective::from(req.proof.c_g1) + G1Projective::from(pool.vk.alpha_g1)).into_affine();
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::InvalidProof));

    // Real OZ UltraHonk verifier rejects forged proof bytes against real MIT .vk.bin files.
    let junk_proof = [0xABu8; 64];
    let junk_pi = [0x00u8; 32];
    assert_eq!(
        verify_oz_ultrahonk_vk_real(&env, OZ_REGISTER_VK_BIN, &junk_proof, &junk_pi),
        Err(AdapterError::InvalidProof)
    );
    assert_eq!(
        verify_oz_ultrahonk_vk_real(&env, OZ_TRANSFER_VK_BIN, &junk_proof, &junk_pi),
        Err(AdapterError::InvalidProof)
    );
    assert_eq!(
        verify_oz_ultrahonk_vk_real(&env, OZ_WITHDRAW_VK_BIN, &junk_proof, &junk_pi),
        Err(AdapterError::InvalidProof)
    );
}

#[test]
fn vector_02_modified_recipient_data_rejected() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    let mut req = make_pool_req(&env, &kp, &pool, recipient, -5_000_000, 5_000, root, b"v02");
    // Attacker swaps withdrawal recipient without updating proof-bound ext_data_hash.
    req.ext_data.recipient = Address::generate(&env);
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::RecipientMismatch));
}

#[test]
fn vector_03_modified_amounts_rejected_across_both_rails() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    let mut req = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"v03");
    req.ext_data.ext_amount = 100_000_000;
    req.observed_token_delta = 100_000_000;
    req.ext_data_hash = req.ext_data.domain_hash_fr(&env);
    // Proof still commits to previous public_amount, failing amount conservation check.
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::AmountMismatch));

    let ct_addr = Address::generate(&env);
    let asset = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let mut ct = ConfidentialTokenPool::new(
        &env,
        ct_addr.clone(),
        asset,
        TESTNET_PASSPHRASE,
        AssetTransferSemantics::ExactTransferSep41,
        false,
    );
    let r_old = Fr::from(11u64);
    let r_new = Fr::from(5u64);
    let r_tx = Fr::from(6u64);
    ct.register_account(&alice, 0, 500, r_old);
    ct.register_account(&bob, 0, 0, Fr::from(1u64));
    let old_c = ct.accounts.get(&alice.to_string().to_string()).unwrap().spendable_commitment;
    // Modified claimed transfer amount (250 != 200) breaks Pedersen conservation C_old == C_new + C_tx.
    let err = ct.confidential_transfer(
        &env,
        &ct_addr,
        TESTNET_PASSPHRASE,
        &alice,
        &bob,
        &old_c,
        pedersen_commit(300, r_new),
        pedersen_commit(200, r_tx),
        250,
        r_new,
        r_tx,
        &[],
        &[],
        false,
    );
    assert_eq!(err, Err(AdapterError::AmountMismatch));
}

#[test]
fn vector_04_replayed_authorization_rejected() {
    let env = Env::default();
    let ct_addr = Address::generate(&env);
    let asset = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let mut ct = ConfidentialTokenPool::new(
        &env,
        ct_addr.clone(),
        asset,
        TESTNET_PASSPHRASE,
        AssetTransferSemantics::ExactTransferSep41,
        false,
    );
    let r_old = Fr::from(15u64);
    let r_new = Fr::from(9u64);
    let r_tx = r_old - r_new;
    ct.register_account(&alice, 0, 500, r_old);
    ct.register_account(&bob, 0, 0, Fr::from(2u64));
    let c_old = ct.accounts.get(&alice.to_string().to_string()).unwrap().spendable_commitment;
    let c_new = pedersen_commit(400, r_new);
    let c_tx = pedersen_commit(100, r_tx);

    assert_eq!(
        ct.confidential_transfer(
            &env, &ct_addr, TESTNET_PASSPHRASE, &alice, &bob, &c_old, c_new, c_tx, 100, r_new, r_tx, &[], &[], false
        ),
        Ok(())
    );
    // Replaying exact same payload fails because spendable commitment chained forward to `c_new`.
    assert_eq!(
        ct.confidential_transfer(
            &env, &ct_addr, TESTNET_PASSPHRASE, &alice, &bob, &c_old, c_new, c_tx, 100, r_new, r_tx, &[], &[], false
        ),
        Err(AdapterError::ReplayedAuthorization)
    );
}

#[test]
fn vector_05_duplicate_nullifier_in_single_tx_rejected() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    let mut req = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"v05");
    req.nullifiers[1] = req.nullifiers[0];
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::DuplicateNullifier));
}

#[test]
fn vector_06_double_spend_across_transactions_rejected() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    let req1 = make_pool_req(&env, &kp, &pool, recipient.clone(), 10_000_000, 10_000, root, b"v06-a");
    assert_eq!(pool.transact(&env, &req1), Ok(()));

    let mut req2 = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"v06-b");
    req2.nullifiers[0] = req1.nullifiers[0];
    assert_eq!(pool.transact(&env, &req2), Err(AdapterError::DoubleSpend));
}

#[test]
fn vector_07_expired_commitment_root_and_expired_allowance_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    // Push 90 subsequent root updates so `initial_root` is evicted from ROOT_HISTORY_SIZE=90.
    for i in 0..90u64 {
        let seed = i.to_be_bytes();
        let req = make_pool_req(&env, &kp, &pool, recipient.clone(), 10_000_000, 10_000, *pool.root_ring.back().unwrap(), &seed);
        assert_eq!(pool.transact(&env, &req), Ok(()));
    }
    let stale_req = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"stale");
    assert_eq!(pool.transact(&env, &stale_req), Err(AdapterError::ExpiredCommitmentRoot));

    // Confidential token spender allowance expiry at ledger_seq > live_until_ledger.
    let ct_addr = Address::generate(&env);
    let asset = Address::generate(&env);
    let owner = Address::generate(&env);
    let spender = Address::generate(&env);
    let mut ct = ConfidentialTokenPool::new(
        &env,
        ct_addr,
        asset,
        TESTNET_PASSPHRASE,
        AssetTransferSemantics::ExactTransferSep41,
        false,
    );
    ct.ledger_seq = 5_800_000;
    ct.set_spender(&owner, &spender, 500, Fr::from(3u64), 5_800_010);
    assert_eq!(ct.spender_transfer(&owner, &spender), Ok(()));
    ct.ledger_seq = 5_800_011;
    assert_eq!(ct.spender_transfer(&owner, &spender), Err(AdapterError::ExpiredDelegationAllowance));
}

#[test]
fn vector_08_wrong_network_or_contract_domain_rejected() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    let mut req = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"v08");
    req.ext_data.network_passphrase = String::from_str(&env, "Public Global Stellar Network ; September 2015");
    req.ext_data_hash = req.ext_data.domain_hash_fr(&env);
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::WrongNetworkOrContractDomain));

    let ct_addr = Address::generate(&env);
    let asset = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let mut ct = ConfidentialTokenPool::new(
        &env,
        ct_addr,
        asset,
        TESTNET_PASSPHRASE,
        AssetTransferSemantics::ExactTransferSep41,
        false,
    );
    let r = Fr::from(7u64);
    ct.register_account(&alice, 0, 100, r);
    ct.register_account(&bob, 0, 0, r);
    let c = ct.accounts.get(&alice.to_string().to_string()).unwrap().spendable_commitment;
    let err = ct.confidential_transfer(
        &env,
        &Address::generate(&env),
        TESTNET_PASSPHRASE,
        &alice,
        &bob,
        &c,
        c,
        pedersen_commit(0, Fr::from(0u64)),
        0,
        r,
        Fr::from(0u64),
        &[],
        &[],
        false,
    );
    assert_eq!(err, Err(AdapterError::WrongNetworkOrContractDomain));
}

#[test]
fn vector_09_invalid_asset_identities_fee_on_transfer_and_clawback_shortfall() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);
    pool.asset_semantics = AssetTransferSemantics::FeeOnTransfer;
    let req = make_pool_req(&env, &kp, &pool, recipient, 10_000_000, 10_000, root, b"v09");
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::AssetNotExactTransfer));

    pool.asset_semantics = AssetTransferSemantics::ExactTransferSep41;
    let mut shortfall_req = make_pool_req(&env, &kp, &pool, Address::generate(&env), 10_000_000, 10_000, root, b"v09b");
    shortfall_req.observed_token_delta = 9_900_000; // e.g. unexpected transfer tax
    assert_eq!(pool.transact(&env, &shortfall_req), Err(AdapterError::ReserveShortfallDetected));

    // Confidential Token SAC freeze & underlying clawback hazards (OZ compliance.md).
    let ct_addr = Address::generate(&env);
    let asset = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let mut ct = ConfidentialTokenPool::new(
        &env,
        ct_addr.clone(),
        asset,
        TESTNET_PASSPHRASE,
        AssetTransferSemantics::ExactTransferSep41,
        true,
    );
    let r = Fr::from(20u64);
    ct.register_account(&alice, 1, 1_000, r);
    ct.register_account(&bob, 1, 0, r);
    ct.pool_sac_frozen = true;
    let c = ct.accounts.get(&alice.to_string().to_string()).unwrap().spendable_commitment;
    assert_eq!(
        ct.confidential_transfer(&env, &ct_addr, TESTNET_PASSPHRASE, &alice, &bob, &c, c, pedersen_commit(0, Fr::from(0u64)), 0, r, Fr::from(0u64), &[], &[], false),
        Err(AdapterError::PoolSacFreezeDeadlock)
    );
    ct.pool_sac_frozen = false;
    assert_eq!(ct.simulate_underlying_sac_clawback(1), Err(AdapterError::ReserveShortfallDetected));
}

#[test]
fn vector_10_missing_note_or_opening_prevents_spending() {
    let env = Env::default();
    let ct_addr = Address::generate(&env);
    let asset = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let mut ct = ConfidentialTokenPool::new(
        &env,
        ct_addr.clone(),
        asset,
        TESTNET_PASSPHRASE,
        AssetTransferSemantics::ExactTransferSep41,
        false,
    );
    let r = Fr::from(9u64);
    ct.register_account(&alice, 0, 100, r);
    ct.register_account(&bob, 0, 0, r);
    let c = ct.accounts.get(&alice.to_string().to_string()).unwrap().spendable_commitment;
    // Clearing local opening `(balance, blinding)` traps spend capability despite on-chain commitment!
    ct.accounts.get_mut(&alice.to_string().to_string()).unwrap().local_opening = None;
    assert_eq!(
        ct.confidential_transfer(&env, &ct_addr, TESTNET_PASSPHRASE, &alice, &bob, &c, c, pedersen_commit(0, Fr::from(0u64)), 0, r, Fr::from(0u64), &[], &[], false),
        Err(AdapterError::MissingLocalOpeningOrNotes)
    );
}

#[test]
fn vector_11_and_12_failed_recovery_and_device_loss() {
    let env = Env::default();
    let wallet_no_seed = LocalNoteWallet::default();
    let sample_events = std::vec![(5_810_000u32, [1u8; 32], Bytes::from_slice(&env, &[7u8; 48]))];

    // Vector 12: Device loss without exported seed backup.
    assert_eq!(
        wallet_no_seed.recover_from_chain(5_810_000, 5_696_840, false, &sample_events),
        Err(AdapterError::DeviceLossWithoutRecoverySeed)
    );

    // Vector 11: Seed present, but corrupt SQLite3MC / vault backup decryption fails.
    let corrupt_wallet = LocalNoteWallet {
        seed_backup: Some([9u8; 32]),
        corrupted_vault: true,
        ..Default::default()
    };
    assert_eq!(
        corrupt_wallet.recover_from_chain(5_810_000, 5_696_840, false, &sample_events),
        Err(AdapterError::BackupCorruptOrDecryptionFailed)
    );

    // Healthy seed within Testnet retention recovers encrypted note stream.
    let good_wallet = LocalNoteWallet {
        seed_backup: Some([9u8; 32]),
        corrupted_vault: false,
        ..Default::default()
    };
    assert_eq!(
        good_wallet.recover_from_chain(5_810_000, 5_696_840, false, &sample_events),
        Ok(1)
    );
}

#[test]
fn vector_13_malicious_or_unavailable_asp_and_stale_non_membership_root() {
    let env = Env::default();
    let (kp, mut pool, recipient, root, _, _) = build_valid_pool_fixture(&env);

    // Unavailable ASP node stalls proving/submission.
    pool.asp_health = AspHealth::Unavailable;
    let req = make_pool_req(&env, &kp, &pool, recipient.clone(), 10_000_000, 10_000, root, b"v13-unavail");
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::AspUnavailableOrStaleRoot));

    // Malicious / censoring ASP denies member inclusion.
    pool.asp_health = AspHealth::CensoringMember;
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::AspUnilateralCensorship));

    // Healthy ASP updates non-membership SMT root while user proves: because `pool.rs` has
    // NO root history for non-membership (`non_member_root != proof.asp_non_membership_root`),
    // valid in-flight proofs revert with InvalidProof / AspUnavailableOrStaleRoot!
    pool.asp_health = AspHealth::Healthy;
    pool.asp_non_membership_root = hash_to_fr(b"new-asp-blocklist-root", &[]);
    assert_eq!(pool.transact(&env, &req), Err(AdapterError::AspUnavailableOrStaleRoot));
}

#[test]
fn vector_14_event_retention_and_indexing_gap_blocks_recovery() {
    // Grounded in live Testnet RPC `getHealth` observation:
    // latestLedger=5817799, oldestLedger=5696840, ledgerRetentionWindow=120960 (~7 days).
    let rpc_oldest = 5_696_840u32;
    let older_account_ledger = 5_500_000u32;

    assert_eq!(
        check_event_retention_coverage(older_account_ledger, rpc_oldest, false),
        Err(AdapterError::LedgerHistoryPruned)
    );
    assert_eq!(
        check_event_retention_coverage(older_account_ledger, rpc_oldest, true),
        Ok(())
    );
    // Also verified via note wallet cold recovery path:
    let env = Env::default();
    let wallet = LocalNoteWallet {
        seed_backup: Some([5u8; 32]),
        ..Default::default()
    };
    let events = std::vec![(5_700_000u32, [1u8; 32], Bytes::from_slice(&env, &[7u8; 48]))];
    assert_eq!(
        wallet.recover_from_chain(older_account_ledger, rpc_oldest, false, &events),
        Err(AdapterError::LedgerHistoryPruned)
    );
}

#[test]
fn vector_15_metadata_correlation_and_disclosure_boundaries() {
    let spp = PrivatePaymentsAdapter {
        passphrase: TESTNET_PASSPHRASE,
    };
    let ct = ConfidentialTokenAdapter {
        passphrase: TESTNET_PASSPHRASE,
    };

    // Private Payments hides internal counterparties/amounts, but edge deposits/withdrawals
    // expose public sender, recipient, and edge amount!
    let spp_internal = spp.observer_visibility(false);
    assert!(spp_internal.public_sender); // Soroban outer tx source / relayer visible
    assert!(!spp_internal.public_recipient);
    assert!(!spp_internal.public_internal_amount);
    assert!(!spp_internal.public_counterparty_graph);

    let spp_edge = spp.observer_visibility(true);
    assert!(spp_edge.public_recipient);
    assert!(spp_edge.public_deposit_or_withdraw_amount);

    // Confidential Tokens hide amounts inside Pedersen commitments, but ALWAYS expose
    // sender, recipient, counterparty graph, and auditor visibility!
    let ct_internal = ct.observer_visibility(false);
    assert!(ct_internal.public_sender);
    assert!(ct_internal.public_recipient);
    assert!(ct_internal.public_counterparty_graph);
    assert!(!ct_internal.public_internal_amount);
    assert!(ct_internal.disclosed_to_auditor_or_gvk);

    let _ = soroban_poseidon2_pair;
}
