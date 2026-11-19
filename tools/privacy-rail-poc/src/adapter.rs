use soroban_sdk::{Address, BytesN, Env, String};

/// Distinguishes StealthBridge storage/draft artifacts from actual on-chain
/// settlement rails so the two cannot be confused or swapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyArchitectureKind {
    LocalEncryptedDraftOnly,
    StellarPrivatePaymentsPool,
    ConfidentialSep41Token,
}

/// Product target evaluated under Milestone 4 (never a final production lock).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductSegment {
    Personal,
    Business,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetTransferSemantics {
    ExactTransferSep41,
    FeeOnTransfer,
    Rebasing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    DraftNotSettleableOnChain,
    RailMismatch,
    UnsupportedNetworkPassphrase,
    AssetNotExactTransfer,
    LedgerHistoryPruned,
    MissingLocalOpeningOrNotes,
    BackupCorruptOrDecryptionFailed,
    DeviceLossWithoutRecoverySeed,
    AspUnavailableOrStaleRoot,
    AspUnilateralCensorship,
    InvalidProof,
    RecipientMismatch,
    AmountMismatch,
    ReplayedAuthorization,
    DuplicateNullifier,
    DoubleSpend,
    ExpiredCommitmentRoot,
    ExpiredDelegationAllowance,
    WrongNetworkOrContractDomain,
    ReserveShortfallDetected,
    PoolSacFreezeDeadlock,
}

/// Captures exactly what any passive chain/RPC observer can see even when
/// cryptography succeeds cleanly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverVisibilityReport {
    pub public_sender: bool,
    pub public_recipient: bool,
    pub public_deposit_or_withdraw_amount: bool,
    pub public_internal_amount: bool,
    pub public_counterparty_graph: bool,
    pub disclosed_to_auditor_or_gvk: bool,
}

/// StealthBridge domain-level encrypted draft reference. Explicitly non-settleable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedDraftArtifact {
    pub draft_id: String,
    pub ciphertext_sha256: BytesN<32>,
    pub review_commitment_sha256: BytesN<32>,
}

/// Domain-level transfer intent passed into the isolation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferIntent {
    pub segment: ProductSegment,
    pub requested_rail: PrivacyArchitectureKind,
    pub network_passphrase: String,
    pub recipient: Address,
    pub amount_stroops: i128,
    pub asset_semantics: AssetTransferSemantics,
}

/// Isolated adapter contract decoupling StealthBridge product orchestration
/// from third-party cryptographic state machines.
pub trait PrivacyRailAdapter {
    fn architecture_kind(&self) -> PrivacyArchitectureKind;
    fn expected_segment(&self) -> ProductSegment;
    fn expected_passphrase(&self, env: &Env) -> String;
    fn observer_visibility(&self, is_edge_tx: bool) -> ObserverVisibilityReport;

    /// Rejects local encrypted drafts, cross-rail swaps, wrong networks, and
    /// non-exact-transfer tokens before any third-party rail state is entered.
    fn validate_intent(&self, env: &Env, intent: &TransferIntent) -> Result<(), AdapterError> {
        if intent.requested_rail == PrivacyArchitectureKind::LocalEncryptedDraftOnly {
            return Err(AdapterError::DraftNotSettleableOnChain);
        }
        if intent.requested_rail != self.architecture_kind() {
            return Err(AdapterError::RailMismatch);
        }
        if intent.network_passphrase != self.expected_passphrase(env) {
            return Err(AdapterError::WrongNetworkOrContractDomain);
        }
        if intent.asset_semantics != AssetTransferSemantics::ExactTransferSep41 {
            return Err(AdapterError::AssetNotExactTransfer);
        }
        if intent.amount_stroops <= 0 {
            return Err(AdapterError::AmountMismatch);
        }
        Ok(())
    }
}

/// Explicitly blocks any attempt to treat ciphertext vault drafts or hash
/// commitments as on-chain confidential settlement.
pub fn reject_draft_as_settlement(_draft: &EncryptedDraftArtifact) -> Result<(), AdapterError> {
    Err(AdapterError::DraftNotSettleableOnChain)
}

/// Verifies whether a wallet/client can cold-sync historical state given the
/// RPC node's oldest retained ledger (e.g. observed Testnet `ledgerRetentionWindow = 120960`).
pub fn check_event_retention_coverage(
    account_creation_ledger: u32,
    rpc_oldest_retained_ledger: u32,
    has_verified_durable_indexer: bool,
) -> Result<(), AdapterError> {
    if account_creation_ledger < rpc_oldest_retained_ledger && !has_verified_durable_indexer {
        return Err(AdapterError::LedgerHistoryPruned);
    }
    Ok(())
}
