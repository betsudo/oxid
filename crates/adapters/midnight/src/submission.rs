// SPDX-License-Identifier: Apache-2.0

//! Bounded standalone completion of an authorized Midnight transfer.

use std::{
    fmt,
    future::Future,
    io,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use futures::{SinkExt, StreamExt};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::TokenType;
use midnight_ledger::{
    dust::{DustActions, DustLocalState, DustOutput, DustParameters, DustPublicKey, DustSecretKey},
    structure::{
        Intent, LedgerParameters, ProofPreimageMarker, ProofPreimageVersioned, ProofVersioned,
        Signature, StandardTransaction, Transaction,
    },
};
use midnight_onchain_runtime::cost_model::CostModel;
use midnight_storage::{
    DefaultDB,
    arena::Sp,
    storage::{Array, HashMap as LedgerHashMap},
};
use midnight_transient_crypto::{
    commitment::PedersenRandomness,
    curve::Fr,
    proofs::{
        KeyLocation, Proof, ProofPreimage, ProvingKeyMaterial, ProvingProvider, Resolver, WrappedIr,
    },
};
use oxid_adapter_platform_system::{
    NativeRequestAuthentication, TransportTrustError, connect_json_rpc_websocket_with_headers,
    http_client_builder_for, websocket_connector_for,
};
use oxid_platform_ports::ClockPort;
use oxid_wallet_application::WalletTransactionPortError;
use oxid_wallet_domain::WalletTransferSubmissionMode;
use rand::rngs::OsRng;
use reqwest::{Method, StatusCode, Url, header::CONTENT_TYPE};
use serde_json::{Value, json};
use subxt::{OnlineClient, SubstrateConfig, backend::rpc::RpcClient, dynamic};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::{Message, protocol::WebSocketConfig};
use zeroize::Zeroizing;

use crate::{
    MidnightIndexerConfig, MidnightIndexerConfigError, MidnightLocalProvingConfig,
    dust_checkpoint::{
        MidnightDustCheckpointStore, StoredDustCheckpoint, UnavailableMidnightDustCheckpointStore,
    },
    dust_replay::{DustReplayKeys, DustReplayState, replay_dust_batch},
    local_proving,
    replay_era::{LedgerEra, ReplayEvent, ReplayWindow, replay_era},
    submission_journal::{StoredSubmissionJournalEntry, StoredSubmissionState},
    transaction::{
        MidnightCompletionOutcome, MidnightCompletionRequest, MidnightRegistrationContext,
        MidnightRegistrationContextFuture, MidnightSubmissionReconciler,
        MidnightSubmissionReconciliation, MidnightTransactionCompleter,
    },
};

const DUST_QUERY: &str = include_str!("../queries/dust_ledger_events.graphql");
const MIXED_DUST_QUERY: &str = include_str!("../queries/mixed_dust_ledger_events.graphql");
const CHAIN_TIP_QUERY: &str = include_str!("../queries/chain_tip.graphql");
const DUST_BALANCE_SEGMENT: u16 = 0xFEED;
use crate::preprod_transport::{
    INDEXER_ROUTE, INDEXER_SOCKET_ROUTE, MidnightPreprodCredential, MidnightPreprodPreflightError,
    MidnightPublicChainPreflightError, MidnightTransportRoute, is_preprod_node_route,
    preflight_blockfrost_preprod, verify_public_chain,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const ACK_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const DUST_RECEIVE_SEGMENT_QUIET_TIMEOUT: Duration = Duration::from_secs(1);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PROOF_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_ENDPOINT_CHARACTERS: usize = 2_048;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_DUST_EVENTS: usize = 1_000_000;
const MAX_DUST_EVENT_BYTES: usize = 1024 * 1024;
const MAX_DUST_TOTAL_BYTES: usize = 512 * 1024 * 1024;
const DUST_REPLAY_BATCH_EVENTS: usize = 256;
const MAX_DUST_REPLAY_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_DUST_RECEIVE_SEGMENT_EVENTS: usize = 16 * 1024;
const DUST_RECEIVE_SEGMENT_WIRE_BATCHES: usize = 4;
const MAX_DUST_RECEIVE_SEGMENT_BYTES: usize =
    MAX_DUST_REPLAY_BATCH_BYTES * DUST_RECEIVE_SEGMENT_WIRE_BATCHES;
const MAX_CHAIN_TIP_BYTES: usize = 1024 * 1024;
const MAX_PROOF_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROOF_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRANSACTION_BYTES: usize = 16 * 1024 * 1024;
const MAX_BALANCE_ITERATIONS: usize = 16;
const MAX_FEE_RECONCILIATION_ITERATIONS: usize = 3;
const MAX_RECONCILIATION_BLOCKS: usize = 2_048;
const MIDNIGHT_RUNTIME_STACK_BYTES: usize = 8 * 1024 * 1024;

type UnprovenTransaction =
    Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

fn run_isolated_midnight_runtime<Output, Factory, Operation>(
    operation: Factory,
) -> Result<Output, WalletTransactionPortError>
where
    Output: Send,
    Factory: FnOnce() -> Operation + Send,
    Operation: Future<Output = Result<Output, WalletTransactionPortError>>,
{
    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .name("oxid-midnight-runtime".to_owned())
            .stack_size(MIDNIGHT_RUNTIME_STACK_BYTES)
            .spawn_scoped(scope, move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| WalletTransactionPortError::Unavailable)?;
                runtime.block_on(operation())
            })
            .map_err(|_| WalletTransactionPortError::Unavailable)?;
        worker
            .join()
            .map_err(|_| WalletTransactionPortError::Unavailable)?
    })
}

/// Explicit source of authenticated public proving material for application
/// circuits that are not built into the standalone proof server.
pub trait MidnightRemoteProvingMaterialSource: Send + Sync {
    fn resolve_key(&self, key_location: &str) -> io::Result<Option<ProvingKeyMaterial>>;
}

/// The native wallet operation whose finalized transaction is being submitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MidnightPreBroadcastKind {
    Transfer,
    DustRegistration,
    ContractCall,
}

/// Borrowed evidence from one finalized, tagged Ledger 9 transaction.
///
/// Keep the payload private until broadcast. The ledger hash and identifiers
/// use the lowercase hex encoding of the Ledger 9 WASM API.
#[non_exhaustive]
pub struct MidnightPreBroadcastEvidence<'a> {
    pub kind: MidnightPreBroadcastKind,
    pub profile_id: &'a str,
    pub network_id: &'a str,
    pub draft_id: &'a str,
    pub planning_fingerprint: [u8; 32],
    pub expires_at_seconds: u64,
    pub transaction_bytes: &'a [u8],
    pub ledger_transaction_hash: &'a str,
    pub ledger_identifiers: &'a [String],
    pub extrinsic_hash: [u8; 32],
    pub finalized_anchor: [u8; 32],
    pub fee_specks: u128,
}

/// Safe denial from the native pre-broadcast acknowledgement boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MidnightPreBroadcastDenied;

/// Trusted native composition hook for a caller-owned durable submission record.
///
/// Return success only after recording the evidence durably. This runs on the
/// submission worker. Keep it bounded and avoid re-entering the wallet.
/// Cancellation, journal failure, or process death can prevent broadcast even
/// after acknowledgement. Reconcile an acknowledged attempt before replacing it.
pub trait MidnightPreBroadcast: Send + Sync {
    fn acknowledge(
        &self,
        evidence: MidnightPreBroadcastEvidence<'_>,
    ) -> Result<(), MidnightPreBroadcastDenied>;
}

/// Optional native integrations for a standalone wallet's live submitter.
#[derive(Clone, Default)]
pub struct MidnightStandaloneSubmissionOptions {
    pub remote_proving_material: Option<Arc<dyn MidnightRemoteProvingMaterialSource>>,
    pub pre_broadcast: Option<Arc<dyn MidnightPreBroadcast>>,
}

/// Validated public routes for the complete standalone transaction path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidnightStandaloneConfig {
    indexer: MidnightIndexerConfig,
    indexer_http_url: String,
    node_websocket_url: String,
    proving: MidnightProvingMode,
}

/// Selected proof boundary for an explicitly configured standalone wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MidnightProvingMode {
    /// Keep proof witnesses on-device and use an authenticated bounded cache.
    Local(MidnightLocalProvingConfig),
    /// Explicit remote proof service using loopback HTTP or authenticated HTTPS.
    Remote { proof_server_url: String },
}

/// Payload-free failures when checking the private public-network prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightProofServerVersionError {
    Unavailable,
    IncompatibleVersion,
}

impl MidnightStandaloneConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: impl Into<String>,
        indexer_websocket_url: impl AsRef<str>,
        indexer_http_url: impl AsRef<str>,
        node_websocket_url: impl AsRef<str>,
        proof_server_url: impl AsRef<str>,
        unshielded_address: impl AsRef<str>,
    ) -> Result<Self, MidnightStandaloneConfigError> {
        let indexer =
            MidnightIndexerConfig::new(network_id, indexer_websocket_url, unshielded_address)
                .map_err(MidnightStandaloneConfigError::Indexer)?;
        let indexer_http_url = validate_http_url(indexer_http_url.as_ref(), false)
            .map_err(|_| MidnightStandaloneConfigError::InvalidIndexerHttpEndpoint)?;
        let indexer = indexer.with_http_url(indexer_http_url.clone());
        let node_websocket_url =
            super::indexer::validate_websocket_url(node_websocket_url.as_ref())
                .map_err(|_| MidnightStandaloneConfigError::InvalidNodeEndpoint)?;
        let proof_server_url = validate_http_url(proof_server_url.as_ref(), true)
            .map_err(|_| MidnightStandaloneConfigError::InvalidProofEndpoint)?;
        Ok(Self {
            indexer,
            indexer_http_url,
            node_websocket_url,
            proving: MidnightProvingMode::Remote { proof_server_url },
        })
    }

    /// Builds a deployment configuration before protected custody derives an
    /// account. It intentionally retains no configuration receive address.
    #[allow(clippy::too_many_arguments)]
    pub fn new_without_unshielded_address(
        network_id: impl Into<String>,
        indexer_websocket_url: impl AsRef<str>,
        indexer_http_url: impl AsRef<str>,
        node_websocket_url: impl AsRef<str>,
        proof_server_url: impl AsRef<str>,
    ) -> Result<Self, MidnightStandaloneConfigError> {
        let indexer =
            MidnightIndexerConfig::without_unshielded_address(network_id, indexer_websocket_url)
                .map_err(MidnightStandaloneConfigError::Indexer)?;
        let indexer_http_url = validate_http_url(indexer_http_url.as_ref(), false)
            .map_err(|_| MidnightStandaloneConfigError::InvalidIndexerHttpEndpoint)?;
        let indexer = indexer.with_http_url(indexer_http_url.clone());
        let node_websocket_url =
            super::indexer::validate_websocket_url(node_websocket_url.as_ref())
                .map_err(|_| MidnightStandaloneConfigError::InvalidNodeEndpoint)?;
        let proof_server_url = validate_http_url(proof_server_url.as_ref(), true)
            .map_err(|_| MidnightStandaloneConfigError::InvalidProofEndpoint)?;
        Ok(Self {
            indexer,
            indexer_http_url,
            node_websocket_url,
            proving: MidnightProvingMode::Remote { proof_server_url },
        })
    }

    /// Builds a standalone configuration that keeps proof witnesses on-device.
    pub fn new_private(
        network_id: impl Into<String>,
        indexer_websocket_url: impl AsRef<str>,
        indexer_http_url: impl AsRef<str>,
        node_websocket_url: impl AsRef<str>,
        local_proving: MidnightLocalProvingConfig,
        unshielded_address: impl AsRef<str>,
    ) -> Result<Self, MidnightStandaloneConfigError> {
        let indexer =
            MidnightIndexerConfig::new(network_id, indexer_websocket_url, unshielded_address)
                .map_err(MidnightStandaloneConfigError::Indexer)?;
        let indexer_http_url = validate_http_url(indexer_http_url.as_ref(), false)
            .map_err(|_| MidnightStandaloneConfigError::InvalidIndexerHttpEndpoint)?;
        let indexer = indexer.with_http_url(indexer_http_url.clone());
        let node_websocket_url =
            super::indexer::validate_websocket_url(node_websocket_url.as_ref())
                .map_err(|_| MidnightStandaloneConfigError::InvalidNodeEndpoint)?;
        Ok(Self {
            indexer,
            indexer_http_url,
            node_websocket_url,
            proving: MidnightProvingMode::Local(local_proving),
        })
    }

    /// Installs one PreProd credential atomically for the exact configured node and indexer cohort.
    pub fn with_preprod_credential(
        mut self,
        credential: MidnightPreprodCredential,
    ) -> Result<Self, MidnightStandaloneConfigError> {
        if self.indexer.network_id().as_str() != "preprod"
            || self.indexer_http_url != INDEXER_ROUTE
            || self.indexer.websocket_url() != INDEXER_SOCKET_ROUTE
            || !is_preprod_node_route(&self.node_websocket_url)
        {
            return Err(MidnightStandaloneConfigError::InvalidPreprodRoutes);
        }
        self.indexer.preprod_credential = Some(Arc::new(credential));
        Ok(self)
    }

    /// Executes a read-only genesis and indexer check using the configured routes.
    pub async fn verify_preprod_chain(
        &self,
        genesis_hash: &[u8; 32],
    ) -> Result<u64, MidnightPreprodPreflightError> {
        let credential = self
            .indexer
            .preprod_credential
            .as_deref()
            .ok_or(MidnightPreprodPreflightError::InvalidCredential)?;
        preflight_blockfrost_preprod(
            self.node_websocket_url(),
            self.indexer_http_url(),
            self.indexer().websocket_url(),
            genesis_hash,
            credential,
        )
        .await
    }

    /// Authenticates a signed Preview profile's node and both indexer transports.
    pub async fn verify_preview_chain(
        &self,
        genesis_hash: &[u8; 32],
    ) -> Result<u64, MidnightPublicChainPreflightError> {
        if self.indexer.network_id().as_str() != "preview"
            || !self.node_websocket_url().starts_with("wss://")
            || !self.indexer_http_url().starts_with("https://")
            || !self.indexer.websocket_url().starts_with("wss://")
        {
            return Err(MidnightPublicChainPreflightError::InvalidRoute);
        }
        verify_public_chain(
            self.node_websocket_url(),
            self.indexer_http_url(),
            self.indexer.websocket_url(),
            genesis_hash,
            None,
        )
        .await
    }

    /// Verify the exact prover paired with this app's Ledger 9 dependency.
    /// This sends only an unauthenticated version request, without witnesses.
    pub async fn verify_public_proof_server(&self) -> Result<(), MidnightProofServerVersionError> {
        let MidnightProvingMode::Remote { proof_server_url } = &self.proving else {
            return Err(MidnightProofServerVersionError::Unavailable);
        };
        let endpoint = Url::parse(proof_server_url)
            .map_err(|_| MidnightProofServerVersionError::Unavailable)?;
        if endpoint.scheme() != "https" {
            return Err(MidnightProofServerVersionError::Unavailable);
        }
        verify_ledger9_proof_server_version(&endpoint).await
    }

    /// Supplies only the two authenticated read routes needed by contract-state readers.
    pub fn contract_state_authentication(&self) -> Option<Arc<dyn NativeRequestAuthentication>> {
        self.indexer.preprod_credential.as_ref()?;
        Some(Arc::new(self.clone()))
    }

    pub(crate) fn indexer_http_route(&self) -> MidnightTransportRoute<'_> {
        MidnightTransportRoute::new(
            &self.indexer_http_url,
            self.indexer.preprod_credential.as_deref(),
        )
    }

    fn node_route(&self) -> MidnightTransportRoute<'_> {
        MidnightTransportRoute::new(
            &self.node_websocket_url,
            self.indexer.preprod_credential.as_deref(),
        )
    }

    #[must_use]
    pub const fn indexer(&self) -> &MidnightIndexerConfig {
        &self.indexer
    }

    #[must_use]
    pub fn indexer_http_url(&self) -> &str {
        &self.indexer_http_url
    }

    #[must_use]
    pub fn node_websocket_url(&self) -> &str {
        &self.node_websocket_url
    }

    #[must_use]
    pub const fn proving(&self) -> &MidnightProvingMode {
        &self.proving
    }
}

impl NativeRequestAuthentication for MidnightStandaloneConfig {
    fn headers_for(
        &self,
        endpoint: &str,
    ) -> Result<reqwest::header::HeaderMap, TransportTrustError> {
        let route = if endpoint == self.indexer_http_url() {
            self.indexer_http_route()
        } else if endpoint == self.node_websocket_url()
            || (is_preprod_node_route(endpoint) && is_preprod_node_route(self.node_websocket_url()))
        {
            self.node_route()
        } else {
            return Err(TransportTrustError::InvalidEndpoint);
        };
        route
            .headers()
            .map_err(|_| TransportTrustError::ConnectionUnavailable)
    }
}

/// Safe standalone route validation errors. Endpoint values are never rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightStandaloneConfigError {
    Indexer(MidnightIndexerConfigError),
    InvalidIndexerHttpEndpoint,
    InvalidNodeEndpoint,
    InvalidProofEndpoint,
    InvalidPreprodRoutes,
}

impl fmt::Display for MidnightStandaloneConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Indexer(error) => error.fmt(formatter),
            Self::InvalidIndexerHttpEndpoint => {
                formatter.write_str("Midnight indexer HTTP endpoint is invalid")
            }
            Self::InvalidNodeEndpoint => {
                formatter.write_str("Midnight node WebSocket endpoint is invalid")
            }
            Self::InvalidPreprodRoutes => {
                formatter.write_str("Midnight PreProd routes are invalid")
            }
            Self::InvalidProofEndpoint => formatter.write_str(
                "Midnight proof endpoint must use loopback HTTP or HTTPS without credentials",
            ),
        }
    }
}

impl std::error::Error for MidnightStandaloneConfigError {}

/// Safe failures while binding an authenticated deployment profile to the
/// chain actually exposed by its reviewed node route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightChainIdentityError {
    InvalidNodeEndpoint,
    NodeUnavailable,
    GenesisMismatch,
}

impl fmt::Display for MidnightChainIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNodeEndpoint => "Midnight node endpoint is invalid",
            Self::NodeUnavailable => "Midnight node chain identity is unavailable",
            Self::GenesisMismatch => {
                "Midnight node chain identity does not match the deployment profile"
            }
        })
    }
}

impl std::error::Error for MidnightChainIdentityError {}

/// Checks the node genesis hash before an authenticated production profile can
/// be composed. Endpoint values and observed identifiers are never logged or
/// returned in failures.
pub async fn authenticate_midnight_chain_identity(
    node_websocket_url: &str,
    expected_genesis_hash: &[u8; 32],
) -> Result<(), MidnightChainIdentityError> {
    super::indexer::validate_websocket_url(node_websocket_url)
        .map_err(|_| MidnightChainIdentityError::InvalidNodeEndpoint)?;
    let client = timeout(
        CONNECT_TIMEOUT,
        connect_midnight_node(MidnightTransportRoute::new(node_websocket_url, None)),
    )
    .await
    .map_err(|_| MidnightChainIdentityError::NodeUnavailable)?
    .map_err(|_| MidnightChainIdentityError::NodeUnavailable)?;
    let genesis_hash = client.genesis_hash();
    let observed: &[u8] = genesis_hash.as_ref();
    if observed == expected_genesis_hash {
        Ok(())
    } else {
        Err(MidnightChainIdentityError::GenesisMismatch)
    }
}

async fn connect_midnight_node(
    route: MidnightTransportRoute<'_>,
) -> Result<OnlineClient<SubstrateConfig>, ()> {
    connect_midnight_node_with_headers(route.endpoint(), route.headers().map_err(|_| ())?).await
}

async fn connect_midnight_node_with_headers(
    endpoint: &str,
    headers: reqwest::header::HeaderMap,
) -> Result<OnlineClient<SubstrateConfig>, ()> {
    let url = Url::parse(endpoint).map_err(|_| ())?;
    if url.scheme() == "ws" && url.query().is_none() && headers.is_empty() {
        return OnlineClient::from_insecure_url(endpoint)
            .await
            .map_err(|_| ());
    }
    let client = connect_json_rpc_websocket_with_headers(endpoint, headers)
        .await
        .map_err(|_| ())?;
    OnlineClient::from_rpc_client(RpcClient::new(client))
        .await
        .map_err(|_| ())
}

#[derive(Clone)]
pub(crate) struct LiveMidnightTransactionCompleter<C> {
    config: MidnightStandaloneConfig,
    local_proving_gate: Arc<Mutex<()>>,
    dust_checkpoints: Arc<dyn MidnightDustCheckpointStore>,
    clock: Arc<C>,
    options: MidnightStandaloneSubmissionOptions,
}

impl<C> LiveMidnightTransactionCompleter<C> {
    pub(crate) fn new(config: MidnightStandaloneConfig, clock: Arc<C>) -> Self {
        Self {
            config,
            local_proving_gate: Arc::new(Mutex::new(())),
            dust_checkpoints: Arc::new(UnavailableMidnightDustCheckpointStore),
            clock,
            options: MidnightStandaloneSubmissionOptions::default(),
        }
    }

    pub(crate) fn new_with_dust_store(
        config: MidnightStandaloneConfig,
        dust_checkpoints: Arc<dyn MidnightDustCheckpointStore>,
        clock: Arc<C>,
    ) -> Self {
        Self {
            config,
            local_proving_gate: Arc::new(Mutex::new(())),
            dust_checkpoints,
            clock,
            options: MidnightStandaloneSubmissionOptions::default(),
        }
    }

    pub(crate) fn with_submission_options(
        mut self,
        options: MidnightStandaloneSubmissionOptions,
    ) -> Self {
        self.options = options;
        self
    }
}

#[derive(Clone)]
pub(crate) struct LiveMidnightSubmissionReconciler {
    config: MidnightStandaloneConfig,
}

impl LiveMidnightSubmissionReconciler {
    pub(crate) const fn new(config: MidnightStandaloneConfig) -> Self {
        Self { config }
    }

    fn validate_entry(
        &self,
        entry: &StoredSubmissionJournalEntry,
    ) -> Result<(), WalletTransactionPortError> {
        if entry.mode != WalletTransferSubmissionMode::Live
            || !matches!(
                entry.state,
                StoredSubmissionState::Broadcasting | StoredSubmissionState::OutcomeUnknown
            )
            || &entry.network_id != self.config.indexer().network_id()
        {
            return Err(WalletTransactionPortError::InvalidData);
        }
        Ok(())
    }
}

impl MidnightSubmissionReconciler for LiveMidnightSubmissionReconciler {
    fn reconcile(
        &self,
        entry: &StoredSubmissionJournalEntry,
    ) -> Result<MidnightSubmissionReconciliation, WalletTransactionPortError> {
        self.validate_entry(entry)?;
        run_isolated_midnight_runtime(move || async move {
            reconcile_live_submission(&self.config, entry).await
        })
    }

    fn reconcile_async<'a>(
        &'a self,
        entry: &'a StoredSubmissionJournalEntry,
    ) -> crate::transaction::MidnightSubmissionReconciliationFuture<'a> {
        Box::pin(async move {
            self.validate_entry(entry)?;
            reconcile_live_submission(&self.config, entry).await
        })
    }
}

async fn reconcile_live_submission(
    config: &MidnightStandaloneConfig,
    entry: &StoredSubmissionJournalEntry,
) -> Result<MidnightSubmissionReconciliation, WalletTransactionPortError> {
    let client = timeout(CONNECT_TIMEOUT, connect_midnight_node(config.node_route()))
        .await
        .map_err(|_| WalletTransactionPortError::Timeout)?
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    let mut block = timeout(CONNECT_TIMEOUT, client.blocks().at_latest())
        .await
        .map_err(|_| WalletTransactionPortError::Timeout)?
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    let mut reached_anchor = false;
    for _ in 0..MAX_RECONCILIATION_BLOCKS {
        if block.hash().0 == entry.anchor_block_hash {
            reached_anchor = true;
            break;
        }
        let extrinsics = timeout(CONNECT_TIMEOUT, block.extrinsics())
            .await
            .map_err(|_| WalletTransactionPortError::Timeout)?
            .map_err(|_| WalletTransactionPortError::Unavailable)?;
        for extrinsic in extrinsics.iter() {
            if extrinsic.hash().0 != entry.transaction_hash {
                continue;
            }
            let events = timeout(CONNECT_TIMEOUT, extrinsic.events())
                .await
                .map_err(|_| WalletTransactionPortError::Timeout)?
                .map_err(|_| WalletTransactionPortError::Unavailable)?;
            let mut succeeded = false;
            let mut failed = false;
            for event in events.iter() {
                let event = event.map_err(|_| WalletTransactionPortError::InvalidChainState)?;
                if event.pallet_name() == "System" && event.variant_name() == "ExtrinsicSuccess" {
                    succeeded = true;
                }
                if event.pallet_name() == "System" && event.variant_name() == "ExtrinsicFailed" {
                    failed = true;
                }
            }
            return match (succeeded, failed) {
                (true, false) => Ok(MidnightSubmissionReconciliation::Included {
                    block_hash: block.hash().0,
                    block_height: u64::from(block.header().number),
                }),
                (false, true) => Ok(MidnightSubmissionReconciliation::Rejected),
                _ => Err(WalletTransactionPortError::InvalidChainState),
            };
        }
        let parent_hash = block.header().parent_hash;
        block = timeout(CONNECT_TIMEOUT, client.blocks().at(parent_hash))
            .await
            .map_err(|_| WalletTransactionPortError::Timeout)?
            .map_err(|_| WalletTransactionPortError::Unavailable)?;
    }
    if block.hash().0 == entry.anchor_block_hash {
        reached_anchor = true;
    }
    if !reached_anchor {
        return Ok(MidnightSubmissionReconciliation::Unresolved);
    }
    let chain_tip = fetch_chain_tip(config.indexer_http_route()).await?;
    if Timestamp::from_secs(entry.expires_at.value() / 1_000) <= chain_tip.timestamp {
        Ok(MidnightSubmissionReconciliation::Expired)
    } else {
        Ok(MidnightSubmissionReconciliation::Unresolved)
    }
}

impl<C> MidnightTransactionCompleter for LiveMidnightTransactionCompleter<C>
where
    C: ClockPort + 'static,
{
    fn registration_context(&self) -> MidnightRegistrationContextFuture<'_> {
        Box::pin(async move {
            let chain_tip = fetch_chain_tip(self.config.indexer_http_route()).await?;
            Ok(MidnightRegistrationContext {
                timestamp: chain_tip.timestamp,
                parameters: chain_tip.parameters,
            })
        })
    }

    fn complete(
        &self,
        request: MidnightCompletionRequest,
        dust_seed: &[u8; 32],
    ) -> Result<MidnightCompletionOutcome, WalletTransactionPortError> {
        let _local_proving_permit =
            if matches!(self.config.proving(), MidnightProvingMode::Local(_)) {
                Some(
                    self.local_proving_gate
                        .lock()
                        .map_err(|_| WalletTransactionPortError::Unavailable)?,
                )
            } else {
                None
            };
        let dust_key = DustSecretKey::derive_secret_key(dust_seed);
        let route = self.config.indexer.websocket_route();
        let keys = DustReplayKeys::new(&dust_key, route.mixed_eras().then_some(dust_seed));
        run_isolated_midnight_runtime(move || async move {
            complete_live(
                &self.config,
                request,
                &keys,
                self.dust_checkpoints.as_ref(),
                self.clock.as_ref(),
                &self.options,
            )
            .await
        })
    }
}

async fn complete_live<C>(
    config: &MidnightStandaloneConfig,
    request: MidnightCompletionRequest,
    keys: &DustReplayKeys<'_>,
    checkpoints: &dyn MidnightDustCheckpointStore,
    clock: &C,
    options: &MidnightStandaloneSubmissionOptions,
) -> Result<MidnightCompletionOutcome, WalletTransactionPortError>
where
    C: ClockPort,
{
    let cancellation = request.cancellation_token();
    ensure_submission_active(&cancellation)?;
    let chain_tip = fetch_chain_tip(config.indexer_http_route()).await?;
    ensure_submission_active(&cancellation)?;
    let dust_public_key = DustPublicKey::from(keys.current.clone());
    let route = config.indexer.websocket_route();
    let checkpoint = if route.mixed_eras() {
        checkpoints.load_latest(config.indexer.network_id(), &dust_public_key)
    } else {
        checkpoints.load(
            config.indexer.network_id(),
            &dust_public_key,
            chain_tip.parameters.dust,
        )
    }
    .ok()
    .flatten();
    let mut persist_progress = |progress: &DustSyncProgress<'_>| {
        if let Ok(updated_at) = clock.now() {
            let _ = checkpoints.save_state(
                config.indexer.network_id(),
                &dust_public_key,
                progress.current_cursor,
                progress.target_cursor,
                updated_at,
                progress.state,
            );
        }
        Ok(())
    };
    let synchronized = synchronize_dust_with_control(
        route,
        keys,
        chain_tip.parameters.dust,
        checkpoint,
        &cancellation,
        &mut persist_progress,
    )
    .await?;
    let dust_state = synchronized.state;
    ensure_submission_active(&cancellation)?;
    if dust_state.params != chain_tip.parameters.dust {
        return Err(WalletTransactionPortError::InvalidChainState);
    }

    let current_time = if chain_tip.timestamp > dust_state.sync_time {
        chain_tip.timestamp
    } else {
        dust_state.sync_time
    };
    let ttl = Timestamp::from_secs(request.expires_at_seconds);
    if ttl <= current_time {
        return Err(WalletTransactionPortError::DraftExpired);
    }
    // Ledger 9 fee calculation is accurate only for proven transactions. The
    // first pass therefore uses the unproven estimate to construct the DUST
    // intent, then bounded reconciliation passes rebuild that intent with the
    // actual sealed fee. Re-proving is intentional: changing the DUST spend
    // changes the transaction binding input, so the first proof cannot be
    // submitted with the corrected fee.
    let original_transaction = request.transaction.clone();
    let original_dust_state = dust_state.clone();
    let mut required_fee = None;
    let mut reconciled = None;
    for _ in 0..MAX_FEE_RECONCILIATION_ITERATIONS {
        ensure_submission_active(&cancellation)?;
        let mut candidate_dust_state = original_dust_state.clone();
        let (balanced, funded_fee) = balance_dust(
            original_transaction.clone(),
            &mut candidate_dust_state,
            keys.current,
            &chain_tip.parameters,
            current_time,
            ttl,
            config.indexer.network_id().as_str(),
            required_fee,
        )?;
        let cost_model = &chain_tip.parameters.cost_model.runtime_cost_model;
        let sealed = match config.proving() {
            MidnightProvingMode::Local(local_config) => {
                let outcome = local_proving::prove_transaction(
                    balanced,
                    local_config,
                    cost_model,
                    &cancellation,
                )
                .await?;
                let _metrics = outcome.metrics;
                outcome.transaction
            }
            MidnightProvingMode::Remote { proof_server_url } => {
                prove_via_http(
                    balanced,
                    proof_server_url,
                    options.remote_proving_material.clone(),
                    cost_model,
                )
                .await?
            }
        };
        ensure_submission_active(&cancellation)?;
        let sealed_fee = sealed
            .fees(&chain_tip.parameters, false)
            .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
        let sealed_balance = sealed
            .balance(Some(sealed_fee))
            .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
        let final_fee_is_covered =
            funded_fee >= sealed_fee && sealed_balance.values().all(|balance| *balance >= 0);
        if final_fee_is_covered {
            reconciled = Some((sealed, sealed_fee));
            break;
        }
        required_fee = Some(sealed_fee);
    }
    let (sealed, fee_specks) = reconciled.ok_or(WalletTransactionPortError::InvalidChainState)?;
    let mut transaction_bytes = Zeroizing::new(Vec::new());
    midnight_serialize::tagged_serialize(&sealed, &mut *transaction_bytes)
        .map_err(|_| WalletTransactionPortError::InvalidData)?;
    if transaction_bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(WalletTransactionPortError::InvalidData);
    }
    ensure_submission_active(&cancellation)?;
    let acknowledgement = if let Some(hook) = options.pre_broadcast.as_deref() {
        Some(PreBroadcastAcknowledgement {
            hook,
            ledger_transaction_hash: ledger_hex(&sealed.transaction_hash())?,
            ledger_identifiers: sealed
                .identifiers()
                .map(|id| ledger_hex(&id))
                .collect::<Result<Vec<_>, _>>()?,
        })
    } else {
        None
    };
    let (transaction_hash, block_hash, block_height) = submit_unsigned(
        config.node_route(),
        &transaction_bytes,
        &request,
        fee_specks,
        acknowledgement,
    )
    .await?;
    Ok(MidnightCompletionOutcome {
        fee_specks,
        transaction_hash,
        block_hash,
        block_height,
        mode: WalletTransferSubmissionMode::Live,
    })
}

pub(crate) fn ensure_submission_active(
    cancellation: &AtomicBool,
) -> Result<(), WalletTransactionPortError> {
    if cancellation.load(Ordering::Acquire) {
        Err(WalletTransactionPortError::SubmissionCancelled)
    } else {
        Ok(())
    }
}

fn ensure_dust_sync_active(
    cancellation: &AtomicBool,
    started_at: Instant,
) -> Result<(), WalletTransactionPortError> {
    ensure_submission_active(cancellation)?;
    if started_at.elapsed() >= SNAPSHOT_TIMEOUT {
        Err(WalletTransactionPortError::Timeout)
    } else {
        Ok(())
    }
}

pub(crate) struct ChainTip {
    pub(crate) height: u64,
    pub(crate) timestamp: Timestamp,
    pub(crate) parameters: LedgerParameters,
}

pub(crate) async fn fetch_chain_tip(
    route: MidnightTransportRoute<'_>,
) -> Result<ChainTip, WalletTransactionPortError> {
    let headers = route
        .headers()
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    fetch_chain_tip_with_headers(route.endpoint(), headers).await
}

pub(super) async fn fetch_chain_tip_with_headers(
    endpoint: &str,
    headers: reqwest::header::HeaderMap,
) -> Result<ChainTip, WalletTransactionPortError> {
    let body = fetch_chain_tip_body(endpoint, headers).await?;
    decode_chain_tip_body(&body)
}

/// Returns the Ledger 9 tip height, block hash, and runtime for node comparison.
pub(super) async fn fetch_identified_chain_tip(
    route: MidnightTransportRoute<'_>,
) -> Result<(u64, [u8; 32], u32), WalletTransactionPortError> {
    let headers = route
        .headers()
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    let body = fetch_chain_tip_body(route.endpoint(), headers).await?;
    decode_identified_chain_tip(&body)
}

fn decode_identified_chain_tip(
    body: &[u8],
) -> Result<(u64, [u8; 32], u32), WalletTransactionPortError> {
    let root = parse_chain_tip_body(body)?;
    let tip = decode_chain_tip(&root)?;
    let hash = root
        .pointer("/data/block/hash")
        .and_then(Value::as_str)
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let mut bytes = [0; 32];
    hex::decode_to_slice(hash.strip_prefix("0x").unwrap_or(hash), &mut bytes)
        .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
    let runtime = root
        .pointer("/data/block/protocolVersion")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    Ok((tip.height, bytes, runtime))
}

async fn fetch_chain_tip_body(
    endpoint: &str,
    headers: reqwest::header::HeaderMap,
) -> Result<Vec<u8>, WalletTransactionPortError> {
    ensure_tls_provider()?;
    let endpoint = Url::parse(endpoint).map_err(|_| WalletTransactionPortError::Unavailable)?;
    let client = chain_tip_client(&endpoint)?;
    let mut request = chain_tip_request(endpoint.as_str())?;
    request.headers_mut().extend(headers);
    let response = client
        .execute(request)
        .await
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    validate_chain_tip_status(response.status())?;
    bounded_response(response, MAX_CHAIN_TIP_BYTES)
        .await
        .map_err(|_| WalletTransactionPortError::InvalidChainState)
}

fn chain_tip_request(endpoint: &str) -> Result<reqwest::Request, WalletTransactionPortError> {
    let endpoint = Url::parse(endpoint).map_err(|_| WalletTransactionPortError::Unavailable)?;
    let body = serde_json::to_vec(&json!({ "query": CHAIN_TIP_QUERY, "variables": {} }))
        .map_err(|_| WalletTransactionPortError::InvalidData)?;
    let mut request = reqwest::Request::new(Method::POST, endpoint);
    request.headers_mut().insert(
        CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    *request.body_mut() = Some(reqwest::Body::from(body));
    Ok(request)
}

fn chain_tip_client(endpoint: &Url) -> Result<reqwest::Client, WalletTransactionPortError> {
    http_client_builder_for(endpoint)
        .map_err(|_| WalletTransactionPortError::Unavailable)?
        // Standalone wallet routes are explicit trust-boundary configuration. Do not let
        // ambient proxy variables silently redirect them.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|_| WalletTransactionPortError::Unavailable)
}

fn validate_chain_tip_status(status: StatusCode) -> Result<(), WalletTransactionPortError> {
    status
        .is_success()
        .then_some(())
        .ok_or(WalletTransactionPortError::InvalidChainState)
}

fn decode_chain_tip_body(body: &[u8]) -> Result<ChainTip, WalletTransactionPortError> {
    decode_chain_tip(&parse_chain_tip_body(body)?)
}

fn parse_chain_tip_body(body: &[u8]) -> Result<Value, WalletTransactionPortError> {
    if body.len() > MAX_CHAIN_TIP_BYTES {
        return Err(WalletTransactionPortError::InvalidChainState);
    }
    serde_json::from_slice(body).map_err(|_| WalletTransactionPortError::InvalidChainState)
}

fn decode_chain_tip(root: &Value) -> Result<ChainTip, WalletTransactionPortError> {
    if root
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(WalletTransactionPortError::InvalidChainState);
    }
    let block = root
        .pointer("/data/block")
        .and_then(Value::as_object)
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let height = block
        .get("height")
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let timestamp_millis = block
        .get("timestamp")
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let parameters_hex = block
        .get("ledgerParameters")
        .and_then(Value::as_str)
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let parameters_bytes = decode_bounded_hex(parameters_hex, MAX_CHAIN_TIP_BYTES)?;
    let parameters = midnight_serialize::tagged_deserialize(&parameters_bytes[..])
        .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
    Ok(ChainTip {
        height,
        // Midnight indexer v4 exposes its DateTime scalar as Unix
        // milliseconds. The ledger Timestamp is second-granular.
        timestamp: Timestamp::from_secs(timestamp_millis / 1_000),
        parameters,
    })
}

#[cfg(test)]
async fn synchronize_dust(
    endpoint: &str,
    dust_key: &DustSecretKey,
    parameters: DustParameters,
    checkpoint: Option<StoredDustCheckpoint>,
) -> Result<DustSynchronization, WalletTransactionPortError> {
    let cancellation = AtomicBool::new(false);
    let mut ignore_progress = |_: &DustSyncProgress<'_>| Ok(());
    synchronize_dust_controlled(
        MidnightTransportRoute::new(endpoint, None),
        &DustReplayKeys::new(dust_key, None),
        parameters,
        checkpoint,
        &cancellation,
        &mut ignore_progress,
    )
    .await
}

pub(crate) async fn synchronize_dust_controlled(
    route: MidnightTransportRoute<'_>,
    keys: &DustReplayKeys<'_>,
    parameters: DustParameters,
    checkpoint: Option<StoredDustCheckpoint>,
    cancellation: &AtomicBool,
    observe: &mut dyn FnMut(&DustSyncProgress<'_>) -> Result<(), WalletTransactionPortError>,
) -> Result<DustSynchronization, WalletTransactionPortError> {
    synchronize_dust_controlled_with_limits(
        route,
        keys,
        parameters,
        checkpoint,
        cancellation,
        observe,
        (MAX_DUST_EVENTS, MAX_DUST_TOTAL_BYTES),
    )
    .await
}

async fn synchronize_dust_controlled_with_limits(
    route: MidnightTransportRoute<'_>,
    keys: &DustReplayKeys<'_>,
    parameters: DustParameters,
    checkpoint: Option<StoredDustCheckpoint>,
    cancellation: &AtomicBool,
    observe: &mut dyn FnMut(&DustSyncProgress<'_>) -> Result<(), WalletTransactionPortError>,
    limits: (usize, usize),
) -> Result<DustSynchronization, WalletTransactionPortError> {
    ensure_submission_active(cancellation)?;
    let (mut state, starting_cursor, starting_target) = checkpoint.map_or_else(
        || (None, None, None),
        |checkpoint| {
            (
                Some(checkpoint.state),
                Some(checkpoint.current_cursor),
                Some(checkpoint.target_cursor),
            )
        },
    );
    if !route.mixed_eras()
        && state
            .as_ref()
            .and_then(DustReplayState::current)
            .is_some_and(|state| state.params != parameters)
    {
        return Err(WalletTransactionPortError::InvalidChainState);
    }
    ensure_tls_provider()?;

    let started_at = Instant::now();
    let synchronization = timeout(SNAPSHOT_TIMEOUT, async {
        let mut durable_cursor = starting_cursor;
        let mut target_id = starting_target;
        let mut window = ReplayWindow::new(limits, route.mixed_eras(), starting_cursor);
        let mut replayed_events = 0_usize;
        loop {
            ensure_dust_sync_active(cancellation, started_at)?;
            // Public streams include the requested event. Reconfirm a
            // checkpoint that looked complete using that event's live watermark.
            let mut anchor =
                durable_cursor.filter(|cursor| route.mixed_eras() && Some(*cursor) == target_id);
            let starting_id = match (anchor, durable_cursor) {
                (Some(cursor), _) => cursor,
                (None, Some(cursor)) => cursor
                    .checked_add(1)
                    .ok_or(WalletTransactionPortError::InvalidChainState)?,
                (None, None) => 0,
            };
            let starting_id = i64::try_from(starting_id)
                .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
            let request = route
                .graphql_request()
                .map_err(|_| WalletTransactionPortError::Unavailable)?;
            let mut websocket_config = WebSocketConfig::default();
            websocket_config.max_message_size = Some(MAX_MESSAGE_BYTES);
            websocket_config.max_frame_size = Some(MAX_FRAME_BYTES);
            let endpoint_url = Url::parse(route.endpoint())
                .map_err(|_| WalletTransactionPortError::Unavailable)?;
            let connector = websocket_connector_for(&endpoint_url)
                .map_err(|_| WalletTransactionPortError::Unavailable)?;
            let connected = timeout(
                CONNECT_TIMEOUT,
                tokio_tungstenite::connect_async_tls_with_config(
                    request,
                    Some(websocket_config),
                    false,
                    connector,
                ),
            )
            .await;
            ensure_dust_sync_active(cancellation, started_at)?;
            let (mut socket, response) = connected
                .map_err(|_| WalletTransactionPortError::Timeout)?
                .map_err(|_| WalletTransactionPortError::Unavailable)?;
            if response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|value| value.to_str().ok())
                != Some("graphql-transport-ws")
            {
                return Err(WalletTransactionPortError::InvalidChainState);
            }
            let initialized = send_websocket_json(
                &mut socket,
                json!({ "type": "connection_init", "payload": {} }),
            )
            .await;
            ensure_dust_sync_active(cancellation, started_at)?;
            initialized?;
            let acknowledged = wait_for_ack(&mut socket).await;
            ensure_dust_sync_active(cancellation, started_at)?;
            acknowledged?;
            let query = if route.mixed_eras() {
                MIXED_DUST_QUERY
            } else {
                DUST_QUERY
            };
            let subscribed = send_websocket_json(
                &mut socket,
                json!({
                    "type": "subscribe",
                    "id": "oxid-dust",
                    "payload": { "query": query, "variables": { "id": starting_id } }
                }),
            )
            .await;
            ensure_dust_sync_active(cancellation, started_at)?;
            subscribed?;

            let mut segment =
                Vec::<DecodedDustEvent>::with_capacity(MAX_DUST_RECEIVE_SEGMENT_EVENTS);
            let mut segment_bytes = 0_usize;
            let mut received_cursor = durable_cursor;
            let outcome = loop {
                ensure_dust_sync_active(cancellation, started_at)?;
                let receive_timeout = if segment.len() >= DUST_REPLAY_BATCH_EVENTS {
                    DUST_RECEIVE_SEGMENT_QUIET_TIMEOUT
                } else {
                    IDLE_TIMEOUT
                };
                let received = timeout(receive_timeout, socket.next()).await;
                ensure_dust_sync_active(cancellation, started_at)?;
                let message = match received {
                    Ok(Some(message)) => {
                        message.map_err(|_| WalletTransactionPortError::InvalidChainState)?
                    }
                    Err(_) if segment.is_empty() && durable_cursor.is_some() => {
                        break DustReceiveOutcome::IdleCheckpoint;
                    }
                    Err(_) if !segment.is_empty() => break DustReceiveOutcome::Saturated,
                    Ok(None) => return Err(WalletTransactionPortError::InvalidChainState),
                    Err(_) => return Err(WalletTransactionPortError::Timeout),
                };
                match message {
                    Message::Text(text) => {
                        let value: Value = serde_json::from_str(text.as_str())
                            .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
                        match websocket_message_type(&value)? {
                            "next" => {
                                if value.get("id").and_then(Value::as_str) != Some("oxid-dust") {
                                    return Err(WalletTransactionPortError::InvalidChainState);
                                }
                                let data = value
                                    .pointer("/payload/data/dustLedgerEvents")
                                    .ok_or(WalletTransactionPortError::InvalidChainState)?;
                                let decoded =
                                    decode_dust_event_for_route(data, route.mixed_eras())?;
                                if let Some(saved) = anchor.take() {
                                    let matches_era = state.as_ref().is_some_and(|state| {
                                        state.current().is_some()
                                            == (decoded.event.era() == LedgerEra::V9)
                                    });
                                    if decoded.id != saved || decoded.max_id < saved || !matches_era
                                    {
                                        return Err(WalletTransactionPortError::InvalidChainState);
                                    }
                                    target_id = Some(decoded.max_id);
                                    if decoded.max_id == saved {
                                        break DustReceiveOutcome::TargetReached;
                                    }
                                    // The anchor was already applied. Replay only the new events.
                                    continue;
                                }
                                let sequence_valid = match received_cursor {
                                    // DUST IDs are sparse global indexer cursors:
                                    // unrelated ledger activity can create gaps.
                                    // They must still move strictly forward.
                                    Some(last) => decoded.id > last,
                                    None => true,
                                };
                                if !sequence_valid
                                    || decoded.id > decoded.max_id
                                    || target_id.is_some_and(|target| decoded.max_id < target)
                                {
                                    return Err(WalletTransactionPortError::InvalidChainState);
                                }
                                target_id = Some(decoded.max_id);
                                let next_segment_bytes = segment_bytes
                                    .checked_add(decoded.raw_bytes)
                                    .ok_or(WalletTransactionPortError::InvalidChainState)?;
                                if !segment.is_empty()
                                    && next_segment_bytes > MAX_DUST_RECEIVE_SEGMENT_BYTES
                                {
                                    break DustReceiveOutcome::Saturated;
                                }
                                if !window.accept(decoded.raw_bytes) {
                                    break DustReceiveOutcome::BudgetExhausted;
                                }
                                segment_bytes = next_segment_bytes;
                                received_cursor = Some(decoded.id);
                                let reached_target = decoded.id == decoded.max_id;
                                segment.push(decoded);
                                if reached_target {
                                    break DustReceiveOutcome::TargetReached;
                                }
                                if segment.len() == MAX_DUST_RECEIVE_SEGMENT_EVENTS {
                                    break DustReceiveOutcome::Saturated;
                                }
                            }
                            "ping" => {
                                send_websocket_json(
                                    &mut socket,
                                    json!({ "type": "pong", "payload": value.get("payload") }),
                                )
                                .await?;
                            }
                            "pong" => {}
                            "complete"
                                if value.get("id").and_then(Value::as_str) == Some("oxid-dust")
                                    && segment.is_empty()
                                    && durable_cursor.is_some() =>
                            {
                                break DustReceiveOutcome::EmptyCheckpoint;
                            }
                            _ => return Err(WalletTransactionPortError::InvalidChainState),
                        }
                    }
                    Message::Ping(payload) => socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|_| WalletTransactionPortError::Unavailable)?,
                    Message::Pong(_) => {}
                    _ => return Err(WalletTransactionPortError::InvalidChainState),
                }
            };

            // Do not perform ledger replay or checkpoint persistence while the
            // indexer subscription is open. The receive segment is capped at
            // 16 MiB of decoded serialized event input and 16,384 events, 32 times fewer
            // events than the prototype queue while keeping cold replay to
            // roughly 33 reconnects at the observed PreProd event count.
            let _ = timeout(
                IDLE_TIMEOUT,
                send_websocket_json(
                    &mut socket,
                    json!({ "type": "complete", "id": "oxid-dust" }),
                ),
            )
            .await;
            drop(socket);

            if segment.is_empty() {
                if outcome == DustReceiveOutcome::BudgetExhausted {
                    if window.renew(durable_cursor) {
                        continue;
                    }
                    return Err(WalletTransactionPortError::Timeout);
                }
                if route.mixed_eras() && outcome != DustReceiveOutcome::TargetReached {
                    return Err(WalletTransactionPortError::Timeout);
                }
                let current_cursor =
                    durable_cursor.ok_or(WalletTransactionPortError::InvalidChainState)?;
                let target_cursor =
                    target_id.ok_or(WalletTransactionPortError::InvalidChainState)?;
                if current_cursor != target_cursor {
                    return Err(if outcome == DustReceiveOutcome::IdleCheckpoint {
                        WalletTransactionPortError::Timeout
                    } else {
                        WalletTransactionPortError::InvalidChainState
                    });
                }
                let state = state.ok_or(WalletTransactionPortError::InvalidChainState)?;
                observe(&DustSyncProgress {
                    state: &state,
                    current_cursor,
                    target_cursor,
                    events_processed: 0,
                    segment_complete: true,
                })?;
                ensure_dust_sync_active(cancellation, started_at)?;
                return Ok(DustSynchronization {
                    state: state.into_current()?,
                    current_cursor,
                    target_cursor,
                    events_processed: replayed_events,
                });
            }

            let target_cursor = target_id.ok_or(WalletTransactionPortError::InvalidChainState)?;
            let segment_cursor =
                received_cursor.ok_or(WalletTransactionPortError::InvalidChainState)?;
            let mut events = segment.into_iter().peekable();
            let mut batch = Vec::with_capacity(DUST_REPLAY_BATCH_EVENTS);
            while let Some(first) = events.next() {
                let era = first.event.era();
                let mut batch_bytes = first.raw_bytes;
                let mut current_cursor = first.id;
                batch.push(first.event);
                while batch.len() < DUST_REPLAY_BATCH_EVENTS
                    && events.peek().is_some_and(|next| {
                        next.event.era() == era
                            && batch_bytes + next.raw_bytes <= MAX_DUST_REPLAY_BATCH_BYTES
                    })
                {
                    let next = events
                        .next()
                        .ok_or(WalletTransactionPortError::InvalidChainState)?;
                    batch_bytes += next.raw_bytes;
                    current_cursor = next.id;
                    batch.push(next.event);
                }
                ensure_dust_sync_active(cancellation, started_at)?;
                let replayed = replay_dust_batch(state.as_ref(), keys, parameters, &batch)?;
                replayed_events = replayed_events
                    .checked_add(batch.len())
                    .ok_or(WalletTransactionPortError::InvalidChainState)?;
                observe(&DustSyncProgress {
                    state: &replayed,
                    current_cursor,
                    target_cursor,
                    events_processed: replayed_events,
                    segment_complete: current_cursor == segment_cursor,
                })?;
                state = Some(replayed);
                durable_cursor = Some(current_cursor);
                batch.clear();
            }
            if outcome == DustReceiveOutcome::BudgetExhausted {
                if window.renew(durable_cursor) {
                    continue;
                }
                return Err(WalletTransactionPortError::Timeout);
            }
            if durable_cursor != Some(segment_cursor) {
                return Err(WalletTransactionPortError::InvalidChainState);
            }
            ensure_dust_sync_active(cancellation, started_at)?;
            if outcome == DustReceiveOutcome::TargetReached {
                if segment_cursor != target_cursor {
                    return Err(WalletTransactionPortError::InvalidChainState);
                }
                return Ok(DustSynchronization {
                    state: state
                        .ok_or(WalletTransactionPortError::InvalidChainState)?
                        .into_current()?,
                    current_cursor: segment_cursor,
                    target_cursor,
                    events_processed: replayed_events,
                });
            }
        }
    })
    .await
    .map_err(|_| WalletTransactionPortError::Timeout)??;
    Ok(synchronization)
}

#[cfg(test)]
async fn synchronize_dust_with_fallback(
    endpoint: &str,
    dust_key: &DustSecretKey,
    parameters: DustParameters,
    checkpoint: Option<StoredDustCheckpoint>,
) -> Result<DustSynchronization, WalletTransactionPortError> {
    let cancellation = AtomicBool::new(false);
    let mut ignore_progress = |_: &DustSyncProgress<'_>| Ok(());
    synchronize_dust_with_control(
        MidnightTransportRoute::new(endpoint, None),
        &DustReplayKeys::new(dust_key, None),
        parameters,
        checkpoint,
        &cancellation,
        &mut ignore_progress,
    )
    .await
}

pub(crate) async fn synchronize_dust_with_control(
    route: MidnightTransportRoute<'_>,
    keys: &DustReplayKeys<'_>,
    parameters: DustParameters,
    checkpoint: Option<StoredDustCheckpoint>,
    cancellation: &AtomicBool,
    observe: &mut dyn FnMut(&DustSyncProgress<'_>) -> Result<(), WalletTransactionPortError>,
) -> Result<DustSynchronization, WalletTransactionPortError> {
    let had_checkpoint = checkpoint.is_some();
    let mut emitted_progress = false;
    let mut observer_failed = false;
    let result = {
        let mut tracking_observer = |progress: &DustSyncProgress<'_>| {
            let result = observe(progress);
            if result.is_ok() {
                emitted_progress = true;
            } else {
                observer_failed = true;
            }
            result
        };
        synchronize_dust_controlled(
            route,
            keys,
            parameters,
            checkpoint,
            cancellation,
            &mut tracking_observer,
        )
        .await
    };
    match result {
        Err(WalletTransactionPortError::InvalidChainState)
            if had_checkpoint && !route.mixed_eras() && !emitted_progress && !observer_failed =>
        {
            synchronize_dust_controlled(route, keys, parameters, None, cancellation, observe).await
        }
        result => result,
    }
}

pub(crate) struct DustSynchronization {
    pub(crate) state: DustLocalState<DefaultDB>,
    pub(crate) current_cursor: u64,
    pub(crate) target_cursor: u64,
    pub(crate) events_processed: usize,
}

pub(crate) struct DustSyncProgress<'state> {
    pub(crate) state: &'state DustReplayState,
    pub(crate) current_cursor: u64,
    pub(crate) target_cursor: u64,
    pub(crate) events_processed: usize,
    /// Public balance/status projection is bounded to a closed receive
    /// segment; durable checkpoint observers still run for every replay batch.
    pub(crate) segment_complete: bool,
}

struct DecodedDustEvent {
    id: u64,
    max_id: u64,
    raw_bytes: usize,
    event: ReplayEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DustReceiveOutcome {
    Saturated,
    BudgetExhausted,
    TargetReached,
    EmptyCheckpoint,
    IdleCheckpoint,
}

#[cfg(test)]
fn decode_dust_event(value: &Value) -> Result<DecodedDustEvent, WalletTransactionPortError> {
    decode_dust_event_for_route(value, false)
}

fn decode_dust_event_for_route(
    value: &Value,
    mixed_eras: bool,
) -> Result<DecodedDustEvent, WalletTransactionPortError> {
    let id = value
        .get("id")
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let max_id = value
        .get("maxId")
        .and_then(Value::as_i64)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let raw = value
        .get("raw")
        .and_then(Value::as_str)
        .ok_or(WalletTransactionPortError::InvalidChainState)?;
    let bytes = decode_bounded_hex(raw, MAX_DUST_EVENT_BYTES)?;
    let raw_bytes = bytes.len();
    let era = replay_era(value, mixed_eras).ok_or(WalletTransactionPortError::InvalidChainState)?;
    let event =
        ReplayEvent::decode(era, &bytes).ok_or(WalletTransactionPortError::InvalidChainState)?;
    Ok(DecodedDustEvent {
        id,
        max_id,
        raw_bytes,
        event,
    })
}

#[allow(clippy::too_many_arguments)]
fn balance_dust(
    transaction: UnprovenTransaction,
    dust_state: &mut DustLocalState<DefaultDB>,
    dust_key: &DustSecretKey,
    parameters: &LedgerParameters,
    current_time: Timestamp,
    ttl: Timestamp,
    network_id: &str,
    required_fee: Option<u128>,
) -> Result<(UnprovenTransaction, u128), WalletTransactionPortError> {
    let original_transaction = transaction.clone();
    let original_dust = dust_state.clone();
    let mut current = transaction;
    let mut accumulated_dust = 0_u128;
    for _ in 0..MAX_BALANCE_ITERATIONS {
        let estimated_fees = current
            .fees(parameters, false)
            .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
        let fees = required_fee.unwrap_or(estimated_fees);
        let balance = current
            .balance(Some(fees))
            .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
        let shortfall = match balance.get(&(TokenType::Dust, 0)).copied() {
            Some(value) if value < 0 => value
                .checked_neg()
                .and_then(|value| u128::try_from(value).ok())
                .ok_or(WalletTransactionPortError::InvalidChainState)?,
            _ => 0,
        };
        if shortfall == 0 {
            return Ok((current, fees));
        }
        accumulated_dust = accumulated_dust
            .checked_add(shortfall)
            .ok_or(WalletTransactionPortError::InvalidChainState)?;
        *dust_state = original_dust.clone();
        let mut remaining = accumulated_dust;
        let mut spends = Array::new();
        let outputs = dust_state.utxos().collect::<Vec<_>>();
        for output in outputs {
            if remaining == 0 {
                break;
            }
            let generation = dust_state
                .generation_info(&output)
                .ok_or(WalletTransactionPortError::InvalidChainState)?;
            let value =
                DustOutput::from(output).updated_value(&generation, current_time, &parameters.dust);
            if value == 0 {
                continue;
            }
            let spend_value = value.min(remaining);
            let (next_state, spend) = dust_state
                .clone()
                .spend(dust_key, &output, spend_value, current_time)
                .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
            *dust_state = next_state;
            spends = spends.push(spend);
            remaining = remaining.saturating_sub(spend_value);
        }
        if remaining > 0 {
            return Err(WalletTransactionPortError::InsufficientDust);
        }
        let mut intent = Intent::empty(&mut OsRng, ttl);
        intent.dust_actions = Some(Sp::new(DustActions {
            spends,
            registrations: Array::new(),
            ctime: current_time,
        }));
        let mut intents = LedgerHashMap::new();
        intents = intents.insert(DUST_BALANCE_SEGMENT, intent);
        let dust_transaction = Transaction::Standard(StandardTransaction::new(
            network_id,
            intents,
            None,
            LedgerHashMap::new(),
        ));
        current = original_transaction
            .merge(&dust_transaction)
            .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
    }
    Err(WalletTransactionPortError::InvalidChainState)
}

#[derive(Clone)]
struct HttpDustProvingProvider {
    client: reqwest::Client,
    endpoint: String,
    remote_proving_material: Option<Arc<dyn MidnightRemoteProvingMaterialSource>>,
}

impl ProvingProvider for HttpDustProvingProvider {
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        let ir = if Self::is_builtin_key(preimage.key_location.0.as_ref()) {
            None
        } else {
            Some(WrappedIr(
                self.resolve_external_material(preimage)?.ir_source,
            ))
        };
        let payload = (ProofPreimageVersioned::V2(Arc::new(preimage.clone())), ir);
        let mut body = Vec::new();
        midnight_serialize::tagged_serialize(&payload, &mut body)?;
        if body.len() > MAX_PROOF_REQUEST_BYTES {
            return Err(anyhow::anyhow!(
                "proof check request exceeds the configured limit"
            ));
        }
        let response = self
            .client
            .post(format!("{}/check", self.endpoint.trim_end_matches('/')))
            .body(body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("proof server rejected the check request"));
        }
        let body = bounded_response(response, MAX_PROOF_RESPONSE_BYTES)
            .await
            .map_err(|_| anyhow::anyhow!("proof check response exceeds the configured limit"))?;
        let skips: Vec<Option<u64>> = midnight_serialize::tagged_deserialize(&body[..])?;
        skips
            .into_iter()
            .map(|skip| {
                skip.map(usize::try_from)
                    .transpose()
                    .map_err(|_| anyhow::anyhow!("proof check response is out of range"))
            })
            .collect()
    }

    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        let builtin = Self::is_builtin_key(preimage.key_location.0.as_ref());
        let material = if builtin {
            None
        } else {
            Some(self.resolve_external_material(preimage)?)
        };
        let payload = (
            ProofPreimageVersioned::V2(Arc::new(preimage.clone())),
            material,
            overwrite_binding_input,
        );
        let mut body = Vec::new();
        midnight_serialize::tagged_serialize(&payload, &mut body)?;
        if body.len() > MAX_PROOF_REQUEST_BYTES {
            return Err(anyhow::anyhow!(
                "proof request exceeds the configured limit"
            ));
        }
        let response = self
            .client
            .post(format!("{}/prove", self.endpoint.trim_end_matches('/')))
            .body(body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("proof server rejected the request"));
        }
        let body = bounded_response(response, MAX_PROOF_RESPONSE_BYTES)
            .await
            .map_err(|_| anyhow::anyhow!("proof response exceeds the configured limit"))?;
        let proof: ProofVersioned = midnight_serialize::tagged_deserialize(&body[..])?;
        match proof {
            ProofVersioned::V2(proof) => Ok(proof),
            _ => Err(anyhow::anyhow!(
                "proof server returned an unsupported proof"
            )),
        }
    }

    fn split(&mut self) -> Self {
        self.clone()
    }

    fn resolver(&self) -> &impl Resolver {
        self
    }
}

impl Resolver for HttpDustProvingProvider {
    async fn resolve_key(&self, key: KeyLocation) -> io::Result<Option<ProvingKeyMaterial>> {
        if Self::is_builtin_key(key.0.as_ref()) {
            return Ok(None);
        }
        self.remote_proving_material
            .as_ref()
            .ok_or_else(|| io::Error::other("external proving material is unavailable"))?
            .resolve_key(key.0.as_ref())
    }
}

impl HttpDustProvingProvider {
    fn is_builtin_key(location: &str) -> bool {
        matches!(
            location,
            "midnight/zswap/spend"
                | "midnight/zswap/output"
                | "midnight/zswap/sign"
                | "midnight/dust/spend"
        )
    }

    fn resolve_external_material(
        &self,
        preimage: &ProofPreimage,
    ) -> Result<ProvingKeyMaterial, anyhow::Error> {
        self.remote_proving_material
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("external proving material is unavailable"))?
            .resolve_key(preimage.key_location.0.as_ref())?
            .ok_or_else(|| anyhow::anyhow!("external proving material is unavailable"))
    }
}

async fn verify_ledger9_proof_server_version(
    endpoint: &Url,
) -> Result<(), MidnightProofServerVersionError> {
    use MidnightProofServerVersionError::{IncompatibleVersion, Unavailable};

    // Paired with the Ledger 9.1.0.2 dependency and its proof wire format.
    const PROOF_SERVER_VERSION: &[u8] = b"9.0.2";
    let response = chain_tip_client(endpoint)
        .map_err(|_| Unavailable)?
        .get(format!(
            "{}/version",
            endpoint.as_str().trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|_| Unavailable)?;
    if !response.status().is_success() {
        return Err(Unavailable);
    }
    let body = bounded_response(response, 64)
        .await
        .map_err(|_| Unavailable)?;
    if body != PROOF_SERVER_VERSION {
        return Err(IncompatibleVersion);
    }
    Ok(())
}

async fn prove_via_http(
    transaction: UnprovenTransaction,
    endpoint: &str,
    remote_proving_material: Option<Arc<dyn MidnightRemoteProvingMaterialSource>>,
    cost_model: &CostModel,
) -> Result<
    Transaction<
        Signature,
        midnight_ledger::structure::ProofMarker,
        midnight_transient_crypto::commitment::PureGeneratorPedersen,
        DefaultDB,
    >,
    WalletTransactionPortError,
> {
    ensure_tls_provider()?;
    let endpoint_url =
        Url::parse(endpoint).map_err(|_| WalletTransactionPortError::ProvingFailed)?;
    let client = http_client_builder_for(&endpoint_url)
        .map_err(|_| WalletTransactionPortError::ProvingFailed)?
        // Keep proof material on the explicitly configured route rather than an ambient
        // process proxy. This also preserves loopback proving inside pure Nix builds.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(PROOF_TIMEOUT)
        .build()
        .map_err(|_| WalletTransactionPortError::ProvingFailed)?;
    let provider = HttpDustProvingProvider {
        client,
        endpoint: endpoint.to_owned(),
        remote_proving_material,
    };
    let proved = timeout(PROOF_TIMEOUT, transaction.prove(provider, cost_model))
        .await
        .map_err(|_| WalletTransactionPortError::Timeout)?
        .map_err(|_| WalletTransactionPortError::ProvingFailed)?;
    Ok(proved.seal(OsRng))
}

fn ledger_hex(
    value: &impl midnight_serialize::Serializable,
) -> Result<String, WalletTransactionPortError> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut bytes)
        .map_err(|_| WalletTransactionPortError::InvalidData)?;
    Ok(hex::encode(bytes))
}

struct PreBroadcastAcknowledgement<'a> {
    hook: &'a dyn MidnightPreBroadcast,
    ledger_transaction_hash: String,
    ledger_identifiers: Vec<String>,
}

fn acknowledge_and_begin_broadcast(
    request: &MidnightCompletionRequest,
    transaction_bytes: &[u8],
    fee_specks: u128,
    extrinsic_hash: [u8; 32],
    finalized_anchor: [u8; 32],
    acknowledgement: Option<PreBroadcastAcknowledgement<'_>>,
) -> Result<(), WalletTransactionPortError> {
    if let Some(acknowledgement) = acknowledgement {
        ensure_submission_active(&request.cancellation_token())?;
        let (kind, profile_id, draft_id) = request.pre_broadcast_scope();
        acknowledgement
            .hook
            .acknowledge(MidnightPreBroadcastEvidence {
                kind,
                profile_id,
                network_id: request.network_id(),
                draft_id,
                planning_fingerprint: request.planning_fingerprint(),
                expires_at_seconds: request.expires_at_seconds,
                transaction_bytes,
                ledger_transaction_hash: &acknowledgement.ledger_transaction_hash,
                ledger_identifiers: &acknowledgement.ledger_identifiers,
                extrinsic_hash,
                finalized_anchor,
                fee_specks,
            })
            .map_err(|_| WalletTransactionPortError::PreBroadcastDenied)?;
    }
    request.begin_broadcast(
        fee_specks,
        extrinsic_hash,
        finalized_anchor,
        WalletTransferSubmissionMode::Live,
    )
}

async fn submit_unsigned(
    route: MidnightTransportRoute<'_>,
    transaction: &[u8],
    request: &MidnightCompletionRequest,
    fee_specks: u128,
    acknowledgement: Option<PreBroadcastAcknowledgement<'_>>,
) -> Result<([u8; 32], [u8; 32], u64), WalletTransactionPortError> {
    let client = timeout(CONNECT_TIMEOUT, connect_midnight_node(route))
        .await
        .map_err(|_| WalletTransactionPortError::Timeout)?
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    let call = dynamic::tx(
        "Midnight",
        "send_mn_transaction",
        vec![dynamic::Value::from_bytes(transaction)],
    );
    let unsigned = client
        .tx()
        .create_unsigned(&call)
        .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
    let anchor = timeout(CONNECT_TIMEOUT, client.blocks().at_latest())
        .await
        .map_err(|_| WalletTransactionPortError::Timeout)?
        .map_err(|_| WalletTransactionPortError::Unavailable)?;
    let transaction_hash = unsigned.hash().0;
    acknowledge_and_begin_broadcast(
        request,
        transaction,
        fee_specks,
        transaction_hash,
        anchor.hash().0,
        acknowledgement,
    )?;
    let mut progress = timeout(SUBMISSION_TIMEOUT, unsigned.submit_and_watch())
        .await
        .map_err(|_| WalletTransactionPortError::SubmissionOutcomeUnknown)?
        .map_err(|_| WalletTransactionPortError::SubmissionOutcomeUnknown)?;
    timeout(SUBMISSION_TIMEOUT, async {
        use subxt::tx::TxStatus;
        loop {
            let status = progress
                .next()
                .await
                .ok_or(WalletTransactionPortError::SubmissionOutcomeUnknown)?
                .map_err(|_| WalletTransactionPortError::SubmissionOutcomeUnknown)?;
            match status {
                TxStatus::InFinalizedBlock(in_block) => {
                    if in_block.extrinsic_hash().0 != transaction_hash {
                        return Err(WalletTransactionPortError::InvalidChainState);
                    }
                    let events = in_block
                        .fetch_events()
                        .await
                        .map_err(|_| WalletTransactionPortError::SubmissionOutcomeUnknown)?;
                    let mut succeeded = false;
                    let mut failed = false;
                    for event in events.iter() {
                        let event = event
                            .map_err(|_| WalletTransactionPortError::SubmissionOutcomeUnknown)?;
                        if event.pallet_name() == "System"
                            && event.variant_name() == "ExtrinsicSuccess"
                        {
                            succeeded = true;
                        }
                        if event.pallet_name() == "System"
                            && event.variant_name() == "ExtrinsicFailed"
                        {
                            failed = true;
                        }
                    }
                    return match (succeeded, failed) {
                        (true, false) => {
                            let finalized = client
                                .blocks()
                                .at(in_block.block_hash())
                                .await
                                .map_err(|_| {
                                    WalletTransactionPortError::SubmissionOutcomeUnknown
                                })?;
                            Ok((
                                transaction_hash,
                                in_block.block_hash().0,
                                u64::from(finalized.header().number),
                            ))
                        }
                        (false, true) => Err(WalletTransactionPortError::SubmissionRejected),
                        _ => Err(WalletTransactionPortError::SubmissionOutcomeUnknown),
                    };
                }
                TxStatus::InBestBlock(_) => {}
                TxStatus::Error { .. } | TxStatus::Invalid { .. } | TxStatus::Dropped { .. } => {
                    // Subxt explicitly documents these stream-terminal states as
                    // probabilistic: the transaction can still reach a block.
                    // Only a finalized extrinsic failure is safe to replace.
                    return Err(WalletTransactionPortError::SubmissionOutcomeUnknown);
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| WalletTransactionPortError::SubmissionOutcomeUnknown)?
}

async fn bounded_response(
    response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, WalletTransactionPortError> {
    bounded_stream(response.content_length(), response.bytes_stream(), maximum).await
}

async fn bounded_stream<S, B, E>(
    content_length: Option<u64>,
    mut stream: S,
    maximum: usize,
) -> Result<Vec<u8>, WalletTransactionPortError>
where
    S: futures::Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
{
    if content_length.is_some_and(|length| length > maximum as u64) {
        return Err(WalletTransactionPortError::InvalidData);
    }
    let mut result = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| WalletTransactionPortError::Unavailable)?;
        let chunk = chunk.as_ref();
        if result
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(WalletTransactionPortError::InvalidData);
        }
        result.extend_from_slice(chunk);
    }
    Ok(result)
}

fn decode_bounded_hex(
    value: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, WalletTransactionPortError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() > maximum_bytes.saturating_mul(2) || !value.len().is_multiple_of(2) {
        return Err(WalletTransactionPortError::InvalidChainState);
    }
    hex::decode(value).map_err(|_| WalletTransactionPortError::InvalidChainState)
}

fn validate_http_url(value: &str, proof_endpoint: bool) -> Result<String, ()> {
    if value.is_empty() || value.chars().count() > MAX_ENDPOINT_CHARACTERS {
        return Err(());
    }
    let url = Url::parse(value).map_err(|_| ())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(());
    }
    match url.scheme() {
        "https" => {}
        "http" if !proof_endpoint || is_loopback(&url) => {}
        _ => return Err(()),
    }
    Ok(url.to_string())
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let ip_literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || ip_literal
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn ensure_tls_provider() -> Result<(), WalletTransactionPortError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    rustls::crypto::CryptoProvider::get_default()
        .map(|_| ())
        .ok_or(WalletTransactionPortError::Unavailable)
}

async fn send_websocket_json<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    value: Value,
) -> Result<(), WalletTransactionPortError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .map_err(|_| WalletTransactionPortError::Unavailable)
}

async fn wait_for_ack<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
) -> Result<(), WalletTransactionPortError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    timeout(ACK_TIMEOUT, async {
        loop {
            let message = socket
                .next()
                .await
                .ok_or(WalletTransactionPortError::InvalidChainState)?
                .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
            match message {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(text.as_str())
                        .map_err(|_| WalletTransactionPortError::InvalidChainState)?;
                    match websocket_message_type(&value)? {
                        "connection_ack" => return Ok(()),
                        "ping" => {
                            send_websocket_json(
                                socket,
                                json!({ "type": "pong", "payload": value.get("payload") }),
                            )
                            .await?;
                        }
                        _ => return Err(WalletTransactionPortError::InvalidChainState),
                    }
                }
                Message::Ping(payload) => socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|_| WalletTransactionPortError::Unavailable)?,
                Message::Pong(_) => {}
                _ => return Err(WalletTransactionPortError::InvalidChainState),
            }
        }
    })
    .await
    .map_err(|_| WalletTransactionPortError::Timeout)?
}

fn websocket_message_type(value: &Value) -> Result<&str, WalletTransactionPortError> {
    value
        .get("type")
        .and_then(Value::as_str)
        .ok_or(WalletTransactionPortError::InvalidChainState)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, ErrorKind, Write},
        net::TcpListener,
        sync::Condvar,
        thread,
    };

    use midnight_ledger::{
        events::{Event, EventDetails, EventSource},
        structure::{INITIAL_PARAMETERS, TransactionHash},
    };
    use oxid_foundation::UnixTimestampMillis;
    use oxid_wallet_domain::{
        WalletProfileId, WalletTransactionDraftId, WalletTransactionSubmissionState,
    };

    use crate::{
        submission_journal::{
            MemoryMidnightSubmissionJournalStore, MidnightSubmissionJournalStore,
        },
        transaction::{
            MidnightCompletionOrigin, MidnightSubmissionAttempt, MidnightSubmissionControl,
        },
    };
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    use super::*;

    const ADDRESS: &str =
        "mn_addr_undeployed1asujt0dayj4pelgq97wv75hjhscqv9epmzzpapkf8sy8c87jhh9smkp9zh";
    type DustSubscriptionScenario = (u64, Vec<(u64, u64, String)>);

    fn config(proof: &str) -> Result<MidnightStandaloneConfig, MidnightStandaloneConfigError> {
        MidnightStandaloneConfig::new(
            "undeployed",
            "ws://127.0.0.1:8088/api/v1/graphql/ws",
            "http://127.0.0.1:8088/api/v1/graphql",
            "ws://127.0.0.1:9944",
            proof,
            ADDRESS,
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds")
    }

    fn submission_entry(state: StoredSubmissionState) -> StoredSubmissionJournalEntry {
        StoredSubmissionJournalEntry {
            profile_id: WalletProfileId::parse("profile-submission").expect("profile"),
            network_id: config("http://127.0.0.1:6300")
                .expect("config")
                .indexer()
                .network_id()
                .clone(),
            draft_id: WalletTransactionDraftId::parse("txdraft-submission").expect("draft"),
            planning_fingerprint: [1; 32],
            expires_at: UnixTimestampMillis::new(2_000),
            updated_at: UnixTimestampMillis::new(1_000),
            fee_specks: 42,
            transaction_hash: [7; 32],
            anchor_block_hash: [8; 32],
            block_hash: None,
            block_height: None,
            state,
            mode: WalletTransferSubmissionMode::Live,
        }
    }

    #[test]
    fn blockfrost_credential_can_only_be_installed_on_complete_preprod_route_cohort() {
        fn config(network: &str, ws: &str) -> MidnightStandaloneConfig {
            MidnightStandaloneConfig::new_without_unshielded_address(
                network,
                ws,
                INDEXER_ROUTE,
                crate::preprod_transport::NODE_ROUTE,
                "https://proof.example.test",
            )
            .unwrap()
        }
        fn credential() -> MidnightPreprodCredential {
            MidnightPreprodCredential::new(format!("nightpreprod{}", "X".repeat(32))).unwrap()
        }

        let config_before = config("preprod", INDEXER_SOCKET_ROUTE);
        assert!(config_before.indexer_http_route().headers().is_err());
        assert!(config_before.node_route().headers().is_err());
        let configured = config_before.with_preprod_credential(credential()).unwrap();
        assert_eq!(configured.indexer_http_url(), INDEXER_ROUTE);
        assert_eq!(configured.indexer().websocket_url(), INDEXER_SOCKET_ROUTE);
        assert!(configured.node_route().headers().unwrap()["project_id"].is_sensitive());
        assert!(configured.indexer_http_route().headers().unwrap()["project_id"].is_sensitive());
        assert!(!format!("{configured:?}").contains("nightpreprodXXXX"));
        let authentication = configured.contract_state_authentication().unwrap();
        for endpoint in [
            configured.indexer_http_url(),
            configured.node_websocket_url(),
        ] {
            assert!(authentication.headers_for(endpoint).unwrap()["project_id"].is_sensitive());
        }
        let canonical_node = format!("{}/", configured.node_websocket_url());
        assert!(authentication.headers_for(&canonical_node).unwrap()["project_id"].is_sensitive());
        for endpoint in [INDEXER_SOCKET_ROUTE, "https://proof.example.test"] {
            assert_eq!(
                authentication.headers_for(endpoint),
                Err(TransportTrustError::InvalidEndpoint),
            );
        }
        for (network, ws) in [
            ("preview", INDEXER_SOCKET_ROUTE),
            ("preprod", "wss://other.example.test/api/v0/ws"),
        ] {
            assert_eq!(
                config(network, ws).with_preprod_credential(credential()),
                Err(MidnightStandaloneConfigError::InvalidPreprodRoutes),
            );
        }
    }

    fn completion_request(
        entry: &StoredSubmissionJournalEntry,
        journal: Arc<dyn MidnightSubmissionJournalStore>,
        origin: MidnightCompletionOrigin,
    ) -> (MidnightCompletionRequest, Arc<MidnightSubmissionControl>) {
        let control = Arc::new(MidnightSubmissionControl::new(
            MidnightSubmissionAttempt {
                profile_id: entry.profile_id.clone(),
                network_id: entry.network_id.clone(),
                draft_id: entry.draft_id.clone(),
                planning_fingerprint: entry.planning_fingerprint,
                expires_at: entry.expires_at,
                updated_at: entry.updated_at,
            },
            journal,
        ));
        let request = MidnightCompletionRequest::new(
            Transaction::Standard(StandardTransaction::new(
                "undeployed",
                LedgerHashMap::new(),
                None,
                LedgerHashMap::new(),
            )),
            2,
            Arc::clone(&control),
            origin,
        );
        (request, control)
    }

    #[test]
    fn transaction_submission_connection_failure_does_not_create_a_broadcast_record() {
        let entry = submission_entry(StoredSubmissionState::Broadcasting);
        let journal: Arc<dyn MidnightSubmissionJournalStore> =
            Arc::new(MemoryMidnightSubmissionJournalStore::default());
        let (request, control) = completion_request(
            &entry,
            Arc::clone(&journal),
            MidnightCompletionOrigin::Transfer,
        );
        let result = runtime().block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("test node binds");
            let address = listener.local_addr().expect("test node address");
            let endpoint = format!("wss://{address}");
            let disconnect = async {
                let (connection, _) = timeout(CONNECT_TIMEOUT, listener.accept())
                    .await
                    .expect("client connects")
                    .expect("node accepts connection");
                drop(connection);
            };
            let (result, ()) = tokio::join!(
                submit_unsigned(
                    MidnightTransportRoute::new(&endpoint, None),
                    &[0],
                    &request,
                    entry.fee_specks,
                    None,
                ),
                disconnect,
            );
            result
        });

        assert_eq!(result, Err(WalletTransactionPortError::Unavailable));
        assert!(
            journal
                .load(&entry.profile_id, &entry.draft_id)
                .expect("journal reads")
                .is_none(),
            "the durable broadcast barrier starts only after the node connection and anchor resolve"
        );
        assert_eq!(
            control.public_state().expect("control state reads"),
            WalletTransactionSubmissionState::Running
        );
    }

    #[test]
    fn acknowledgement_precedes_journaling_and_denial_or_cancellation_blocks_broadcast() {
        #[derive(Clone, Copy)]
        enum Decision {
            Accept,
            Deny,
            Cancel,
        }
        struct Hook<'a> {
            entry: &'a StoredSubmissionJournalEntry,
            journal: &'a dyn MidnightSubmissionJournalStore,
            control: &'a MidnightSubmissionControl,
            decision: Decision,
            kind: MidnightPreBroadcastKind,
        }
        impl MidnightPreBroadcast for Hook<'_> {
            fn acknowledge(
                &self,
                evidence: MidnightPreBroadcastEvidence<'_>,
            ) -> Result<(), MidnightPreBroadcastDenied> {
                assert_eq!(evidence.kind, self.kind);
                let (profile_id, draft_id) = if self.kind == MidnightPreBroadcastKind::ContractCall
                {
                    ("profile-portal", "did-deploy-1")
                } else {
                    (self.entry.profile_id.as_str(), self.entry.draft_id.as_str())
                };
                assert_eq!(evidence.profile_id, profile_id);
                assert_eq!(evidence.draft_id, draft_id);
                assert_eq!(evidence.network_id, self.entry.network_id.as_str());
                assert_eq!(
                    evidence.planning_fingerprint,
                    self.entry.planning_fingerprint
                );
                assert_eq!(evidence.expires_at_seconds, 2);
                assert_eq!(evidence.transaction_bytes, &[7, 4, 2]);
                assert_eq!(evidence.ledger_transaction_hash, "abcd");
                assert_eq!(evidence.ledger_identifiers, ["1122", "3344"]);
                assert_eq!(evidence.extrinsic_hash, self.entry.transaction_hash);
                assert_eq!(evidence.finalized_anchor, self.entry.anchor_block_hash);
                assert_eq!(evidence.fee_specks, self.entry.fee_specks);
                assert!(
                    self.journal
                        .load(&self.entry.profile_id, &self.entry.draft_id)
                        .unwrap()
                        .is_none()
                );
                match self.decision {
                    Decision::Accept => Ok(()),
                    Decision::Deny => Err(MidnightPreBroadcastDenied),
                    Decision::Cancel => {
                        self.control.request_cancellation().unwrap();
                        Ok(())
                    }
                }
            }
        }

        for (decision, expected) in [
            (Decision::Accept, Ok(())),
            (
                Decision::Deny,
                Err(WalletTransactionPortError::PreBroadcastDenied),
            ),
            (
                Decision::Cancel,
                Err(WalletTransactionPortError::SubmissionCancelled),
            ),
        ] {
            for (origin, kind) in [
                (
                    MidnightCompletionOrigin::ContractCall {
                        profile_id: WalletProfileId::parse("profile-portal").unwrap(),
                        draft_id: "did-deploy-1".to_string(),
                    },
                    MidnightPreBroadcastKind::ContractCall,
                ),
                (
                    MidnightCompletionOrigin::DustRegistration,
                    MidnightPreBroadcastKind::DustRegistration,
                ),
            ] {
                let entry = submission_entry(StoredSubmissionState::Broadcasting);
                let journal: Arc<dyn MidnightSubmissionJournalStore> =
                    Arc::new(MemoryMidnightSubmissionJournalStore::default());
                let (request, control) = completion_request(&entry, Arc::clone(&journal), origin);
                let hook = Hook {
                    entry: &entry,
                    journal: journal.as_ref(),
                    control: &control,
                    decision,
                    kind,
                };
                let result = acknowledge_and_begin_broadcast(
                    &request,
                    &[7, 4, 2],
                    entry.fee_specks,
                    entry.transaction_hash,
                    entry.anchor_block_hash,
                    Some(PreBroadcastAcknowledgement {
                        hook: &hook,
                        ledger_transaction_hash: "abcd".to_owned(),
                        ledger_identifiers: vec!["1122".to_owned(), "3344".to_owned()],
                    }),
                );
                assert_eq!(result, expected);
                assert_eq!(
                    journal.load(&entry.profile_id, &entry.draft_id).unwrap(),
                    expected.is_ok().then_some(entry),
                );
                assert_eq!(control.broadcast_started().unwrap(), expected.is_ok());
            }
        }
    }

    #[test]
    fn live_reconciliation_rejects_terminal_records_but_keeps_unknowns_reconcilable() {
        let reconciler =
            LiveMidnightSubmissionReconciler::new(config("http://127.0.0.1:6300").expect("config"));
        let rejected = submission_entry(StoredSubmissionState::Rejected);
        let unknown = submission_entry(StoredSubmissionState::OutcomeUnknown);

        assert_eq!(
            reconciler.validate_entry(&rejected),
            Err(WalletTransactionPortError::InvalidData),
            "a terminal rejection must never be probed or changed into an ambiguous outcome"
        );
        assert_eq!(
            reconciler.validate_entry(&unknown),
            Ok(()),
            "an outcome-unknown record remains eligible for a fresh durable observation"
        );
    }

    #[test]
    fn synchronous_adapter_boundary_is_safe_inside_an_async_runtime() {
        let result = runtime().block_on(async {
            run_isolated_midnight_runtime(|| async {
                Ok::<_, WalletTransactionPortError>("completed")
            })
        });

        assert_eq!(result, Ok("completed"));
    }

    #[allow(clippy::result_large_err)] // tungstenite's test-server callback owns the error type.
    fn serve_dust_event(raw: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        listener
            .set_nonblocking(true)
            .expect("test listener becomes nonblocking");
        let address = listener.local_addr().expect("test listener has an address");
        let worker = thread::spawn(move || {
            runtime().block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("Tokio listener accepts the socket");
                let (stream, _) = listener.accept().await.expect("client connects");
                let mut socket =
                    accept_hdr_async(stream, |request: &Request, mut response: Response| {
                        assert_eq!(
                            request
                                .headers()
                                .get("Sec-WebSocket-Protocol")
                                .and_then(|value| value.to_str().ok()),
                            Some("graphql-transport-ws")
                        );
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "graphql-transport-ws"
                                .parse()
                                .expect("protocol header is valid"),
                        );
                        Ok(response)
                    })
                    .await
                    .expect("WebSocket handshake succeeds");
                let initialization = socket
                    .next()
                    .await
                    .expect("initialization arrives")
                    .expect("initialization is valid");
                assert!(initialization.to_text().is_ok_and(|text| {
                    serde_json::from_str::<Value>(text)
                        .ok()
                        .and_then(|value| value.get("type").cloned())
                        == Some(Value::String("connection_init".to_owned()))
                }));
                socket
                    .send(Message::Text(
                        json!({ "type": "connection_ack", "payload": {} })
                            .to_string()
                            .into(),
                    ))
                    .await
                    .expect("acknowledgement sends");
                let subscription = socket
                    .next()
                    .await
                    .expect("subscription arrives")
                    .expect("subscription is valid");
                assert!(subscription.to_text().is_ok_and(|text| {
                    serde_json::from_str::<Value>(text)
                        .ok()
                        .and_then(|value| value.get("type").cloned())
                        == Some(Value::String("subscribe".to_owned()))
                }));
                socket
                    .send(Message::Text(
                        json!({ "type": "ping", "payload": { "request": "keepalive" } })
                            .to_string()
                            .into(),
                    ))
                    .await
                    .expect("protocol ping sends");
                let pong = socket
                    .next()
                    .await
                    .expect("protocol pong arrives")
                    .expect("protocol pong is valid");
                assert!(pong.to_text().is_ok_and(|text| {
                    serde_json::from_str::<Value>(text).is_ok_and(|value| {
                        value.get("type").and_then(Value::as_str) == Some("pong")
                            && value.pointer("/payload/request").and_then(Value::as_str)
                                == Some("keepalive")
                    })
                }));
                socket
                    .send(Message::Text(
                        json!({
                            "type": "next",
                            "id": "oxid-dust",
                            "payload": {
                                "data": {
                                    "dustLedgerEvents": {
                                        "id": 1,
                                        "maxId": 1,
                                        "raw": raw
                                    }
                                }
                            }
                        })
                        .to_string()
                        .into(),
                    ))
                    .await
                    .expect("event sends");
            });
        });
        (format!("ws://{address}/graphql/ws"), worker)
    }

    #[allow(clippy::result_large_err)]
    fn serve_dust_subscriptions(
        scenarios: Vec<DustSubscriptionScenario>,
    ) -> (String, thread::JoinHandle<()>) {
        serve_dust_subscriptions_for_eras(scenarios, false)
    }

    #[allow(clippy::result_large_err)]
    fn serve_dust_subscriptions_for_eras(
        scenarios: Vec<DustSubscriptionScenario>,
        mixed_eras: bool,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        listener
            .set_nonblocking(true)
            .expect("test listener becomes nonblocking");
        let address = listener.local_addr().expect("test listener has an address");
        let worker = thread::spawn(move || {
            runtime().block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("Tokio listener accepts sockets");
                for (expected_start, events) in scenarios {
                    let (stream, _) = listener.accept().await.expect("client connects");
                    let mut socket =
                        accept_hdr_async(stream, |_: &Request, mut response: Response| {
                            response.headers_mut().insert(
                                "Sec-WebSocket-Protocol",
                                "graphql-transport-ws"
                                    .parse()
                                    .expect("protocol header is valid"),
                            );
                            Ok(response)
                        })
                        .await
                        .expect("WebSocket handshake succeeds");
                    let _ = socket.next().await.expect("initialization arrives");
                    socket
                        .send(Message::Text(
                            json!({ "type": "connection_ack", "payload": {} })
                                .to_string()
                                .into(),
                        ))
                        .await
                        .expect("acknowledgement sends");
                    let subscription = socket
                        .next()
                        .await
                        .expect("subscription arrives")
                        .expect("subscription is valid");
                    let request: Value = serde_json::from_str(
                        subscription.to_text().expect("subscription is textual"),
                    )
                    .expect("subscription is JSON");
                    assert_eq!(
                        request
                            .pointer("/payload/variables/id")
                            .and_then(Value::as_u64),
                        Some(expected_start)
                    );
                    assert_eq!(
                        request["payload"]["query"],
                        if mixed_eras {
                            MIXED_DUST_QUERY
                        } else {
                            DUST_QUERY
                        }
                    );
                    if events.is_empty() {
                        socket
                            .send(Message::Text(
                                json!({ "type": "complete", "id": "oxid-dust" })
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .expect("completion sends");
                    } else {
                        for (id, max_id, raw) in events {
                            let (raw, legacy) = raw
                                .strip_prefix("legacy:")
                                .map_or((raw.as_str(), false), |raw| (raw, true));
                            let mut event = json!({"id": id, "maxId": max_id, "raw": raw});
                            if mixed_eras {
                                event["protocolVersion"] = if legacy {
                                    json!(1_000_000)
                                } else {
                                    json!(2_001_100)
                                };
                            }
                            socket
                                .send(Message::Text(
                                    json!({
                                        "type": "next",
                                        "id": "oxid-dust",
                                        "payload": {"data": {"dustLedgerEvents": event}}
                                    })
                                    .to_string()
                                    .into(),
                                ))
                                .await
                                .expect("event sends");
                        }
                    }
                }
            });
        });
        (format!("ws://{address}/graphql/ws"), worker)
    }

    #[allow(clippy::result_large_err)]
    fn serve_backpressure_segmented_dust(
        raw: String,
        first_segment_closed: Arc<(Mutex<bool>, Condvar)>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener binds");
        listener
            .set_nonblocking(true)
            .expect("test listener becomes nonblocking");
        let address = listener.local_addr().expect("test listener has an address");
        let worker = thread::spawn(move || {
            runtime().block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("Tokio listener accepts sockets");
                for (expected_start, range) in [
                    (0_u64, 1_u64..=MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64),
                    (
                        MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1,
                        MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1
                            ..=MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1,
                    ),
                ] {
                    let (stream, _) = listener.accept().await.expect("client connects");
                    let mut socket =
                        accept_hdr_async(stream, |_: &Request, mut response: Response| {
                            response.headers_mut().insert(
                                "Sec-WebSocket-Protocol",
                                "graphql-transport-ws"
                                    .parse()
                                    .expect("protocol header is valid"),
                            );
                            Ok(response)
                        })
                        .await
                        .expect("WebSocket handshake succeeds");
                    let _ = socket.next().await.expect("initialization arrives");
                    socket
                        .send(Message::Text(
                            json!({ "type": "connection_ack", "payload": {} })
                                .to_string()
                                .into(),
                        ))
                        .await
                        .expect("acknowledgement sends");
                    let subscription = socket
                        .next()
                        .await
                        .expect("subscription arrives")
                        .expect("subscription is valid");
                    let request: Value = serde_json::from_str(
                        subscription.to_text().expect("subscription is textual"),
                    )
                    .expect("subscription is JSON");
                    assert_eq!(
                        request
                            .pointer("/payload/variables/id")
                            .and_then(Value::as_u64),
                        Some(expected_start)
                    );
                    for id in range {
                        socket
                            .send(Message::Text(
                                json!({
                                    "type": "next",
                                    "id": "oxid-dust",
                                    "payload": {
                                        "data": {
                                            "dustLedgerEvents": {
                                                "id": id,
                                                "maxId": MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1,
                                                "raw": raw.clone()
                                            }
                                        }
                                    }
                                })
                                .to_string()
                                .into(),
                            ))
                            .await
                            .expect("event sends");
                    }
                    if expected_start == 0 {
                        loop {
                            let message = socket
                                .next()
                                .await
                                .expect("controlled close arrives")
                                .expect("controlled close is valid");
                            if message.to_text().is_ok_and(|text| {
                                serde_json::from_str::<Value>(text).is_ok_and(|value| {
                                    value.get("type").and_then(Value::as_str) == Some("complete")
                                        && value.get("id").and_then(Value::as_str)
                                            == Some("oxid-dust")
                                })
                            }) {
                                let (closed, ready) = &*first_segment_closed;
                                *closed.lock().expect("close signal locks") = true;
                                ready.notify_all();
                                break;
                            }
                        }
                    }
                }
            });
        });
        (format!("ws://{address}/graphql/ws"), worker)
    }

    fn parameter_change_event_hex() -> String {
        let event = Event::<DefaultDB> {
            source: EventSource {
                transaction_hash: TransactionHash::default(),
                logical_segment: 0,
                physical_segment: 0,
            },
            content: EventDetails::ParamChange(Sp::new(INITIAL_PARAMETERS)),
        };
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&event, &mut bytes).expect("event serializes");
        hex::encode(bytes)
    }

    #[test]
    fn standalone_routes_accept_loopback_http_proving() {
        let value = config("http://127.0.0.1:6300").expect("routes are valid");
        assert_eq!(value.indexer().network_id().as_str(), "undeployed");
        assert_eq!(
            value.indexer_http_url(),
            "http://127.0.0.1:8088/api/v1/graphql"
        );
        assert_eq!(
            value.indexer().http_url(),
            Some("http://127.0.0.1:8088/api/v1/graphql")
        );
        assert_eq!(value.node_websocket_url(), "ws://127.0.0.1:9944");
        assert!(matches!(
            value.proving(),
            MidnightProvingMode::Remote { proof_server_url }
                if proof_server_url == "http://127.0.0.1:6300/"
        ));
    }

    #[test]
    fn deployment_configuration_needs_no_public_receive_address() {
        let value = MidnightStandaloneConfig::new_without_unshielded_address(
            "mainnet",
            "wss://indexer.example.test/api/v4/graphql/ws",
            "https://indexer.example.test/api/v4/graphql",
            "wss://node.example.test",
            "https://prover.example.test",
        )
        .expect("deployment routes are valid");

        assert_eq!(value.indexer().network_id().as_str(), "mainnet");
    }

    #[test]
    fn proof_route_rejects_remote_plaintext_and_credentials() {
        assert_eq!(
            config("http://proof.example.test"),
            Err(MidnightStandaloneConfigError::InvalidProofEndpoint)
        );
        assert_eq!(
            config("https://user:secret@proof.example.test"),
            Err(MidnightStandaloneConfigError::InvalidProofEndpoint)
        );
        let bad_http = MidnightStandaloneConfig::new(
            "undeployed",
            "ws://127.0.0.1:8088/graphql/ws",
            "ftp://127.0.0.1/graphql",
            "ws://127.0.0.1:9944",
            "http://127.0.0.1:6300",
            ADDRESS,
        )
        .expect_err("non-HTTP indexer route is rejected");
        assert_eq!(
            bad_http.to_string(),
            "Midnight indexer HTTP endpoint is invalid"
        );
        let bad_node = MidnightStandaloneConfig::new(
            "undeployed",
            "ws://127.0.0.1:8088/graphql/ws",
            "http://127.0.0.1/graphql",
            "http://127.0.0.1:9944",
            "http://127.0.0.1:6300",
            ADDRESS,
        )
        .expect_err("non-WebSocket node route is rejected");
        assert_eq!(
            bad_node.to_string(),
            "Midnight node WebSocket endpoint is invalid"
        );
        let bad_network = MidnightStandaloneConfig::new(
            "unknown-network",
            "ws://127.0.0.1:8088/graphql/ws",
            "http://127.0.0.1/graphql",
            "ws://127.0.0.1:9944",
            "http://127.0.0.1:6300",
            ADDRESS,
        )
        .expect_err("unknown network is rejected");
        assert!(matches!(
            bad_network,
            MidnightStandaloneConfigError::Indexer(_)
        ));
        assert_eq!(
            bad_network.to_string(),
            "Midnight indexer network is not supported"
        );
    }

    #[test]
    fn proof_route_accepts_remote_tls_without_rendering_it_in_errors() {
        assert!(config("https://proof.example.test/base").is_ok());
        let error = config("http://proof.example.test")
            .expect_err("plaintext remote route is rejected")
            .to_string();
        assert!(!error.contains("proof.example.test"));
    }

    #[test]
    fn route_validation_rejects_ambiguous_and_unbounded_urls() {
        assert!(validate_http_url("", false).is_err());
        assert!(validate_http_url(&format!("https://{}", "a".repeat(2_048)), false).is_err());
        assert!(validate_http_url("https://indexer.test/graphql?token=public", false).is_err());
        assert!(validate_http_url("https://indexer.test/graphql#fragment", false).is_err());
        assert!(validate_http_url("ftp://indexer.test/graphql", false).is_err());
        assert!(validate_http_url("http://proof.example.test", true).is_err());
        assert!(validate_http_url("http://localhost:6300", true).is_ok());
        assert!(validate_http_url("http://[::1]:6300", true).is_ok());
        assert!(!is_loopback(
            &Url::parse("https://proof.example.test").expect("URL is valid")
        ));
    }

    #[test]
    fn malformed_dust_envelopes_fail_before_ledger_decode() {
        let missing = decode_dust_event(&json!({ "id": 0, "maxId": 0 }));
        assert_eq!(
            missing.err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
        let oversized = "00".repeat(MAX_DUST_EVENT_BYTES + 1);
        let result = decode_dust_event(&json!({ "id": 0, "maxId": 0, "raw": oversized }));
        assert_eq!(
            result.err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
    }

    #[test]
    fn chain_tip_timestamp_converts_indexer_milliseconds_to_ledger_seconds() {
        let mut parameters = Vec::new();
        midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut parameters)
            .expect("initial parameters serialize");
        let tip = decode_chain_tip(&json!({
            "data": {
                "block": {
                    "height": 5_255,
                    "timestamp": 1_750_000_000_123_i64,
                    "ledgerParameters": hex::encode(parameters)
                }
            }
        }))
        .expect("valid chain tip decodes");

        assert_eq!(tip.height, 5_255);
        assert_eq!(tip.timestamp, Timestamp::from_secs(1_750_000_000));
        assert_eq!(tip.parameters, INITIAL_PARAMETERS);
    }

    #[test]
    fn chain_tip_decoder_rejects_missing_negative_and_malformed_fields() {
        for value in [
            json!({ "data": { "block": null } }),
            json!({ "data": { "block": { "height": 1, "timestamp": -1, "ledgerParameters": "00" } } }),
            json!({ "data": { "block": { "height": 1, "timestamp": 1 } } }),
            json!({ "data": { "block": { "height": 1, "timestamp": 1, "ledgerParameters": "0" } } }),
            json!({ "data": { "block": { "height": 1, "timestamp": 1, "ledgerParameters": "zz" } } }),
        ] {
            assert_eq!(
                decode_chain_tip(&value).err(),
                Some(WalletTransactionPortError::InvalidChainState)
            );
        }
        assert_eq!(
            decode_bounded_hex(&"00".repeat(3), 2).err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
    }

    #[test]
    fn chain_tip_http_response_uses_the_bounded_decoder() {
        let mut parameters = Vec::new();
        midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut parameters)
            .expect("initial parameters serialize");
        let body = serde_json::to_vec(&json!({
            "data": {
                "block": {
                    "height": 5_255,
                    "timestamp": 1_750_000_123_999_i64,
                    "ledgerParameters": format!("0x{}", hex::encode(parameters))
                }
            }
        }))
        .expect("response serializes");
        validate_chain_tip_status(StatusCode::OK).expect("successful status is accepted");
        let tip = decode_chain_tip_body(&body).expect("bounded chain tip succeeds");

        assert_eq!(tip.height, 5_255);
        assert_eq!(tip.timestamp, Timestamp::from_secs(1_750_000_123));
        assert_eq!(tip.parameters, INITIAL_PARAMETERS);
        let request = chain_tip_request("http://127.0.0.1:8088/api/v1/graphql")
            .expect("chain tip request builds");
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().path(), "/api/v1/graphql");
        assert_eq!(
            request
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert!(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .is_some_and(|body| serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|value| value.get("query").cloned())
                    == Some(Value::String(CHAIN_TIP_QUERY.to_owned())))
        );
        assert_eq!(
            chain_tip_request("://invalid").err(),
            Some(WalletTransactionPortError::Unavailable)
        );
        assert_eq!(
            decode_chain_tip_body(&vec![0_u8; MAX_CHAIN_TIP_BYTES + 1]).err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
    }

    #[test]
    fn preprod_identified_tip_requires_a_full_hash_and_ledger9_parameters() {
        let mut parameters = Vec::new();
        midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut parameters).unwrap();
        let mut tip = json!({
            "data": { "block": {
                "height": 42,
                "timestamp": 1_750_000_000_000_u64,
                "hash": "42".repeat(32),
                "protocolVersion": 2_001_100_u32,
                "ledgerParameters": hex::encode(parameters),
            }}
        });
        assert_eq!(
            decode_identified_chain_tip(&serde_json::to_vec(&tip).unwrap()).unwrap(),
            (42, [0x42; 32], 2_001_100),
        );
        tip["data"]["block"]["hash"] = json!("1234");
        assert!(decode_identified_chain_tip(&serde_json::to_vec(&tip).unwrap()).is_err());
    }

    #[test]
    fn public_proof_server_version_probe_uses_the_prover_path_and_rejects_old_releases() {
        use std::io::{BufRead as _, BufReader, Write as _};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (version, expected) in [
            ("9.0.2", Ok(())),
            (
                "9.0.1",
                Err(MidnightProofServerVersionError::IncompatibleVersion),
            ),
        ] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let endpoint =
                Url::parse(&format!("http://{}/prover", listener.local_addr().unwrap())).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = BufReader::new(&mut stream);
                let mut line = String::new();
                request.read_line(&mut line).unwrap();
                assert_eq!(line.trim_end(), "GET /prover/version HTTP/1.1");
                loop {
                    line.clear();
                    if request.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    assert!(!line.to_ascii_lowercase().starts_with("project_id:"));
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{version}",
                    version.len()
                )
                .unwrap();
            });
            assert_eq!(
                runtime.block_on(verify_ledger9_proof_server_version(&endpoint)),
                expected
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn chain_tip_authenticates_one_request_and_refuses_redirects() {
        const PROJECT_ID: &str = "fixture-indexer-credential";
        let redirect_target = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        redirect_target.set_nonblocking(true).unwrap();
        let destination = redirect_target.local_addr().unwrap();
        let server = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let route = format!("http://{}/api/v0", server.local_addr().unwrap());
        let fixture = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            stream.set_read_timeout(Some(CONNECT_TIMEOUT)).unwrap();
            let mut request = BufReader::new(&mut stream);
            let mut request_line = String::new();
            request.read_line(&mut request_line).unwrap();
            assert_eq!(request_line, "POST /api/v0 HTTP/1.1\r\n");
            let mut project_id_received = false;
            loop {
                let mut line = String::new();
                assert_ne!(request.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("project_id")
                {
                    project_id_received = value.trim() == PROJECT_ID;
                }
            }
            assert!(project_id_received);
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{destination}/unexpected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        });

        let mut headers = reqwest::header::HeaderMap::new();
        let mut project_id = reqwest::header::HeaderValue::from_static(PROJECT_ID);
        project_id.set_sensitive(true);
        headers.insert("project_id", project_id);
        let result = runtime().block_on(fetch_chain_tip_with_headers(&route, headers));
        assert!(matches!(
            result,
            Err(WalletTransactionPortError::InvalidChainState)
        ));
        fixture.join().unwrap();
        assert_eq!(
            redirect_target.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock,
        );
    }

    #[test]
    fn chain_tip_http_response_rejects_http_and_graphql_failures() {
        assert_eq!(
            validate_chain_tip_status(StatusCode::SERVICE_UNAVAILABLE).err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );

        let body = serde_json::to_vec(&json!({
            "errors": [{ "message": "not exposed by the adapter" }],
            "data": { "block": null }
        }))
        .expect("response serializes");
        assert_eq!(
            decode_chain_tip_body(&body).err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
        assert_eq!(
            decode_chain_tip_body(b"not-json").err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
    }

    #[test]
    fn bounded_stream_rejects_declared_streamed_and_transport_overflow() {
        let success = runtime()
            .block_on(bounded_stream(
                Some(4),
                futures::stream::iter([Ok::<_, ()>(vec![1_u8, 2]), Ok(vec![3_u8, 4])]),
                4,
            ))
            .expect("bounded chunks collect");
        assert_eq!(success, vec![1, 2, 3, 4]);
        assert_eq!(
            runtime()
                .block_on(bounded_stream(
                    Some(5),
                    futures::stream::iter([Ok::<_, ()>(vec![1_u8])]),
                    4,
                ))
                .err(),
            Some(WalletTransactionPortError::InvalidData)
        );
        assert_eq!(
            runtime()
                .block_on(bounded_stream(
                    None,
                    futures::stream::iter([Ok::<_, ()>(vec![1_u8, 2, 3]), Ok(vec![4, 5])]),
                    4,
                ))
                .err(),
            Some(WalletTransactionPortError::InvalidData)
        );
        assert_eq!(
            runtime()
                .block_on(bounded_stream(
                    None,
                    futures::stream::iter([Err::<Vec<u8>, _>(())]),
                    4,
                ))
                .err(),
            Some(WalletTransactionPortError::Unavailable)
        );
    }

    #[test]
    fn dust_snapshot_negotiates_graphql_and_replays_tagged_events() {
        let event = Event::<DefaultDB> {
            source: EventSource {
                transaction_hash: TransactionHash::default(),
                logical_segment: 0,
                physical_segment: 0,
            },
            content: EventDetails::ParamChange(Sp::new(INITIAL_PARAMETERS)),
        };
        let mut event_bytes = Vec::new();
        midnight_serialize::tagged_serialize(&event, &mut event_bytes).expect("event serializes");
        let (endpoint, worker) = serve_dust_event(hex::encode(event_bytes));
        let dust_key = DustSecretKey::derive_secret_key(&[7; 32]);
        let state = runtime()
            .block_on(synchronize_dust(
                &endpoint,
                &dust_key,
                INITIAL_PARAMETERS.dust,
                None,
            ))
            .expect("bounded DUST snapshot succeeds");
        worker.join().expect("WebSocket worker completes");

        assert_eq!(state.state.sync_time, Timestamp::from_secs(0));
        assert_eq!(state.state.params, INITIAL_PARAMETERS.dust);
        assert_eq!(state.current_cursor, 1);
        assert_eq!(state.target_cursor, 1);
    }

    #[test]
    fn dust_checkpoint_resumes_from_the_next_cursor_and_accepts_live_empty_catchup() {
        use oxid_foundation::UnixTimestampMillis;

        let raw = parameter_change_event_hex();
        let (endpoint, worker) = serve_dust_subscriptions(vec![(43, vec![(43, 43, raw)])]);
        let dust_key = DustSecretKey::derive_secret_key(&[7; 32]);
        let checkpoint = StoredDustCheckpoint {
            current_cursor: 42,
            target_cursor: 42,
            updated_at: UnixTimestampMillis::new(1_700_000_000_000),
            state: DustReplayState::Current(DustLocalState::new(INITIAL_PARAMETERS.dust)),
        };
        let synchronized = runtime()
            .block_on(synchronize_dust(
                &endpoint,
                &dust_key,
                INITIAL_PARAMETERS.dust,
                Some(checkpoint),
            ))
            .expect("delta replay succeeds");
        worker.join().expect("WebSocket worker completes");
        assert_eq!(synchronized.current_cursor, 43);
        assert_eq!(synchronized.target_cursor, 43);

        let (endpoint, worker) = serve_dust_subscriptions(vec![(44, Vec::new())]);
        let caught_up = runtime()
            .block_on(synchronize_dust(
                &endpoint,
                &dust_key,
                INITIAL_PARAMETERS.dust,
                Some(StoredDustCheckpoint {
                    current_cursor: 43,
                    target_cursor: 43,
                    updated_at: UnixTimestampMillis::new(1_700_000_000_001),
                    state: DustReplayState::Current(synchronized.state),
                }),
            ))
            .expect("live empty delta confirms an up-to-date checkpoint");
        worker.join().expect("WebSocket worker completes");
        assert_eq!(caught_up.current_cursor, 43);
        assert_eq!(caught_up.target_cursor, 43);
    }

    #[cfg(feature = "mixed-era-replay")]
    #[test]
    fn dust_replay_resumes_across_the_upgrade_and_rejects_era_rollback() {
        use crate::MidnightDustCheckpointConfig;
        use crate::dust_checkpoint::BinaryMidnightDustCheckpointStore;
        use midnight_legacy_ledger::{
            events::{Event as OldEvent, EventDetails as OldDetails, EventSource as OldSource},
            structure::INITIAL_PARAMETERS as OLD_PARAMETERS,
        };
        use midnight_legacy_storage::{DefaultDB as OldDb, arena::Sp as OldSp};
        use oxid_wallet_domain::ChainNetworkId;

        let fixture = OldEvent::<OldDb> {
            source: OldSource {
                transaction_hash: Default::default(),
                logical_segment: 0,
                physical_segment: 0,
            },
            content: OldDetails::ParamChange(OldSp::new(OLD_PARAMETERS)),
        };
        let mut bytes = Vec::new();
        midnight_legacy_serialize::tagged_serialize(&fixture, &mut bytes).unwrap();
        let legacy = format!("legacy:{}", hex::encode(bytes));
        let current = parameter_change_event_hex();
        let (endpoint, worker) = serve_dust_subscriptions_for_eras(
            vec![
                (0, vec![(1, 8, legacy.clone()), (8, 8, current.clone())]),
                (0, vec![(1, 8, legacy.clone()), (8, 8, current.clone())]),
                (2, vec![(8, 8, current.clone())]),
                (8, vec![]),
                (8, vec![(8, 8, current.clone())]),
                (8, vec![(8, 12, current.clone()), (12, 12, current)]),
                (8, vec![(8, 8, legacy)]),
            ],
            true,
        );
        let route = MidnightTransportRoute::new(&endpoint, None).with_mixed_eras(true);
        let seed = [7; 32];
        let dust_key = DustSecretKey::derive_secret_key(&seed);
        let keys = DustReplayKeys::new(&dust_key, Some(&seed));
        let public_key = DustPublicKey::from(dust_key.clone());
        let network = ChainNetworkId::parse("preview").unwrap();
        let directory = crate::legacy_replay_tests::private_checkpoint_directory();
        let config = MidnightDustCheckpointConfig::new(directory.path().join("dust.bin")).unwrap();
        let parameters = INITIAL_PARAMETERS.dust;
        let cancel = AtomicBool::new(false);
        let uninterrupted = runtime()
            .block_on(synchronize_dust_with_control(
                route,
                &keys,
                parameters,
                None,
                &cancel,
                &mut |_| Ok(()),
            ))
            .unwrap();
        assert_eq!(uninterrupted.events_processed, 2);
        let interrupted = runtime().block_on(synchronize_dust_with_control(
            route,
            &keys,
            parameters,
            None,
            &cancel,
            &mut |progress| {
                assert!(progress.state.current().is_none());
                assert_eq!(progress.current_cursor, 1);
                BinaryMidnightDustCheckpointStore::new(config.clone())
                    .save_state(
                        &network,
                        &public_key,
                        progress.current_cursor,
                        progress.target_cursor,
                        UnixTimestampMillis::new(1),
                        progress.state,
                    )
                    .unwrap();
                cancel.store(true, Ordering::Release);
                Ok(())
            },
        ));
        assert_eq!(
            interrupted.err(),
            Some(WalletTransactionPortError::SubmissionCancelled)
        );
        let store = BinaryMidnightDustCheckpointStore::new(config);
        let legacy_checkpoint = store
            .load(&network, &public_key, parameters)
            .unwrap()
            .unwrap();
        assert!(legacy_checkpoint.state.current().is_none());
        cancel.store(false, Ordering::Release);
        let synchronized = runtime()
            .block_on(synchronize_dust_with_control(
                route,
                &keys,
                parameters,
                Some(legacy_checkpoint),
                &cancel,
                &mut |progress| {
                    store
                        .save_state(
                            &network,
                            &public_key,
                            progress.current_cursor,
                            progress.target_cursor,
                            UnixTimestampMillis::new(2),
                            progress.state,
                        )
                        .unwrap();
                    Ok(())
                },
            ))
            .unwrap();
        assert_eq!(synchronized.current_cursor, 8);
        assert_eq!(synchronized.events_processed, 1);
        assert_eq!(
            synchronized
                .state
                .wallet_balance(synchronized.state.sync_time),
            0
        );
        let post_upgrade = store
            .load(&network, &public_key, parameters)
            .unwrap()
            .unwrap();
        assert!(post_upgrade.state.current().is_some());
        assert_eq!(
            runtime()
                .block_on(synchronize_dust_with_control(
                    route,
                    &keys,
                    parameters,
                    Some(post_upgrade),
                    &cancel,
                    &mut |_| panic!("a public checkpoint needs a live watermark"),
                ))
                .err(),
            Some(WalletTransactionPortError::Timeout)
        );
        let post_upgrade = store
            .load(&network, &public_key, parameters)
            .unwrap()
            .unwrap();
        let resumed = runtime()
            .block_on(synchronize_dust_with_control(
                route,
                &keys,
                parameters,
                Some(post_upgrade),
                &cancel,
                &mut |_| Ok(()),
            ))
            .unwrap();
        assert_eq!(resumed.events_processed, 0);
        assert_eq!(
            (resumed.current_cursor, resumed.target_cursor),
            (uninterrupted.current_cursor, uninterrupted.target_cursor)
        );
        let mut uninterrupted_bytes = Vec::new();
        let mut resumed_bytes = Vec::new();
        midnight_serialize::tagged_serialize(&uninterrupted.state, &mut uninterrupted_bytes)
            .unwrap();
        midnight_serialize::tagged_serialize(&resumed.state, &mut resumed_bytes).unwrap();
        assert!(
            resumed_bytes == uninterrupted_bytes,
            "DUST checkpoint changed native state"
        );
        let post_upgrade = store
            .load(&network, &public_key, parameters)
            .unwrap()
            .unwrap();
        let advanced = runtime()
            .block_on(synchronize_dust_with_control(
                route,
                &keys,
                parameters,
                Some(post_upgrade),
                &cancel,
                &mut |progress| {
                    assert_eq!((progress.current_cursor, progress.target_cursor), (12, 12));
                    Ok(())
                },
            ))
            .unwrap();
        assert_eq!((advanced.current_cursor, advanced.target_cursor), (12, 12));
        assert_eq!(advanced.events_processed, 1);
        let post_upgrade = store
            .load(&network, &public_key, parameters)
            .unwrap()
            .unwrap();
        assert_eq!(
            runtime()
                .block_on(synchronize_dust_with_control(
                    route,
                    &keys,
                    parameters,
                    Some(post_upgrade),
                    &cancel,
                    &mut |_| panic!("a backward era must not be persisted"),
                ))
                .err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
        worker.join().unwrap();
    }

    #[test]
    fn public_dust_continues_at_the_durable_cursor_after_a_full_window() {
        let raw = parameter_change_event_hex();
        let (endpoint, worker) = serve_dust_subscriptions_for_eras(
            vec![
                (
                    0,
                    vec![
                        (1, 8, raw.clone()),
                        (2, 8, raw.clone()),
                        (8, 8, raw.clone()),
                    ],
                ),
                (3, vec![(8, 8, raw)]),
            ],
            true,
        );
        let route = MidnightTransportRoute::new(&endpoint, None).with_mixed_eras(true);
        let secret = DustSecretKey::derive_secret_key(&[7; 32]);
        let keys = DustReplayKeys::new(&secret, None);
        let mut observed = Vec::new();
        let synchronized = runtime()
            .block_on(synchronize_dust_controlled_with_limits(
                route,
                &keys,
                INITIAL_PARAMETERS.dust,
                None,
                &AtomicBool::new(false),
                &mut |progress| {
                    observed.push((progress.current_cursor, progress.events_processed));
                    Ok(())
                },
                (2, MAX_DUST_TOTAL_BYTES),
            ))
            .unwrap();
        worker.join().unwrap();

        assert_eq!(observed, [(2, 2), (8, 3)]);
        assert_eq!(synchronized.current_cursor, synchronized.target_cursor);
        assert_eq!(synchronized.events_processed, 3);
    }

    #[test]
    fn dust_sync_accepts_sparse_global_cursors_but_preserves_order() {
        let raw = parameter_change_event_hex();
        let (endpoint, worker) =
            serve_dust_subscriptions(vec![(0, vec![(1, 30, raw.clone()), (30, 30, raw)])]);
        let dust_key = DustSecretKey::derive_secret_key(&[7; 32]);
        let synchronized = runtime()
            .block_on(synchronize_dust(
                &endpoint,
                &dust_key,
                INITIAL_PARAMETERS.dust,
                None,
            ))
            .expect("sparse global DUST cursors replay");
        worker.join().expect("WebSocket worker completes");

        assert_eq!(synchronized.current_cursor, 30);
        assert_eq!(synchronized.target_cursor, 30);
        assert_eq!(synchronized.events_processed, 2);
    }

    #[test]
    fn dust_sync_closes_a_bounded_segment_before_replay_and_resumes_from_durable_cursor() {
        let raw = parameter_change_event_hex();
        let first_segment_closed = Arc::new((Mutex::new(false), Condvar::new()));
        let (endpoint, worker) =
            serve_backpressure_segmented_dust(raw, Arc::clone(&first_segment_closed));
        let dust_key = DustSecretKey::derive_secret_key(&[7; 32]);
        let cancellation = AtomicBool::new(false);
        let mut observed = Vec::new();
        let synchronized = runtime()
            .block_on(synchronize_dust_controlled(
                MidnightTransportRoute::new(&endpoint, None),
                &DustReplayKeys::new(&dust_key, None),
                INITIAL_PARAMETERS.dust,
                None,
                &cancellation,
                &mut |progress| {
                    if observed.is_empty() {
                        let (closed, ready) = &*first_segment_closed;
                        let (closed, wait) = ready
                            .wait_timeout_while(
                                closed.lock().expect("close signal locks"),
                                Duration::from_secs(2),
                                |closed| !*closed,
                            )
                            .expect("close signal waits");
                        if wait.timed_out() || !*closed {
                            return Err(WalletTransactionPortError::Unavailable);
                        }
                    }
                    observed.push((
                        progress.current_cursor,
                        progress.target_cursor,
                        progress.events_processed,
                        progress.segment_complete,
                    ));
                    Ok(())
                },
            ))
            .expect("bounded segments replay only after the open subscription closes");
        worker.join().expect("both bounded subscriptions complete");

        let final_cursor = MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1;
        assert_eq!(
            observed.len(),
            MAX_DUST_RECEIVE_SEGMENT_EVENTS / DUST_REPLAY_BATCH_EVENTS + 1
        );
        for (batch_index, progress) in observed[..observed.len() - 1].iter().enumerate() {
            let expected = ((batch_index + 1) * DUST_REPLAY_BATCH_EVENTS) as u64;
            let segment_complete =
                batch_index + 1 == MAX_DUST_RECEIVE_SEGMENT_EVENTS / DUST_REPLAY_BATCH_EVENTS;
            assert_eq!(
                *progress,
                (expected, final_cursor, expected as usize, segment_complete)
            );
        }
        assert_eq!(
            observed.last(),
            Some(&(final_cursor, final_cursor, final_cursor as usize, true))
        );
        assert_eq!(
            observed.iter().filter(|progress| progress.3).count(),
            2,
            "expensive public projections stay at closed-segment boundaries"
        );
        assert_eq!(synchronized.current_cursor, final_cursor);
        assert_eq!(synchronized.target_cursor, final_cursor);
        assert_eq!(synchronized.events_processed, final_cursor as usize);
    }

    #[test]
    fn dust_sync_rejects_a_target_regression_after_a_bounded_resume() {
        let raw = parameter_change_event_hex();
        let first_target = MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1_000;
        let first_segment = (1_u64..=MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64)
            .map(|id| (id, first_target, raw.clone()))
            .collect::<Vec<_>>();
        let next_cursor = MAX_DUST_RECEIVE_SEGMENT_EVENTS as u64 + 1;
        let (endpoint, worker) = serve_dust_subscriptions(vec![
            (0, first_segment),
            (next_cursor, vec![(next_cursor, first_target - 1, raw)]),
        ]);
        let dust_key = DustSecretKey::derive_secret_key(&[7; 32]);
        let result = runtime().block_on(synchronize_dust(
            &endpoint,
            &dust_key,
            INITIAL_PARAMETERS.dust,
            None,
        ));
        worker.join().expect("both bounded subscriptions complete");

        assert_eq!(
            result.err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
    }

    #[test]
    fn controlled_dust_sync_reports_a_consistent_batch_before_cancellation() {
        let raw = parameter_change_event_hex();
        let events = (1_u64..=257)
            .map(|id| (id, 257, raw.clone()))
            .collect::<Vec<_>>();
        let (endpoint, worker) = serve_dust_subscriptions(vec![(0, events)]);
        let dust_key = DustSecretKey::derive_secret_key(&[7; 32]);
        let cancellation = AtomicBool::new(false);
        let mut observed = Vec::new();
        let result = runtime().block_on(synchronize_dust_controlled(
            MidnightTransportRoute::new(&endpoint, None),
            &DustReplayKeys::new(&dust_key, None),
            INITIAL_PARAMETERS.dust,
            None,
            &cancellation,
            &mut |progress| {
                observed.push((
                    progress.current_cursor,
                    progress.target_cursor,
                    progress.events_processed,
                ));
                cancellation.store(true, Ordering::Release);
                Ok(())
            },
        ));
        worker.join().expect("WebSocket worker completes");

        assert_eq!(
            result.err(),
            Some(WalletTransactionPortError::SubmissionCancelled)
        );
        assert_eq!(observed, vec![(256, 257, 256)]);
    }

    #[test]
    fn incompatible_dust_delta_replays_once_from_zero() {
        use oxid_foundation::UnixTimestampMillis;

        let raw = parameter_change_event_hex();
        let (endpoint, worker) =
            serve_dust_subscriptions(vec![(1, vec![(0, 2, raw.clone())]), (0, vec![(1, 1, raw)])]);
        let dust_key = DustSecretKey::derive_secret_key(&[8; 32]);
        let synchronized = runtime()
            .block_on(synchronize_dust_with_fallback(
                &endpoint,
                &dust_key,
                INITIAL_PARAMETERS.dust,
                Some(StoredDustCheckpoint {
                    current_cursor: 0,
                    target_cursor: 0,
                    updated_at: UnixTimestampMillis::new(1_700_000_000_000),
                    state: DustReplayState::Current(DustLocalState::new(INITIAL_PARAMETERS.dust)),
                }),
            ))
            .expect("incompatible delta recovers with one clean replay");
        worker.join().expect("both WebSocket attempts complete");
        assert_eq!(synchronized.current_cursor, 1);
        assert_eq!(synchronized.target_cursor, 1);
    }

    #[test]
    fn dust_checkpoint_observer_error_is_not_reclassified_as_an_incompatible_delta() {
        use oxid_foundation::UnixTimestampMillis;

        let raw = parameter_change_event_hex();
        let (endpoint, worker) = serve_dust_subscriptions(vec![(1, vec![(1, 1, raw)])]);
        let dust_key = DustSecretKey::derive_secret_key(&[8; 32]);
        let cancellation = AtomicBool::new(false);
        let mut observer_calls = 0_usize;
        let result = runtime().block_on(synchronize_dust_with_control(
            MidnightTransportRoute::new(&endpoint, None),
            &DustReplayKeys::new(&dust_key, None),
            INITIAL_PARAMETERS.dust,
            Some(StoredDustCheckpoint {
                current_cursor: 0,
                target_cursor: 0,
                updated_at: UnixTimestampMillis::new(1_700_000_000_000),
                state: DustReplayState::Current(DustLocalState::new(INITIAL_PARAMETERS.dust)),
            }),
            &cancellation,
            &mut |_| {
                observer_calls += 1;
                Err(WalletTransactionPortError::InvalidChainState)
            },
        ));
        worker.join().expect("single subscription completes");

        assert_eq!(observer_calls, 1);
        assert_eq!(
            result.err(),
            Some(WalletTransactionPortError::InvalidChainState)
        );
    }

    #[test]
    fn cached_dust_state_does_not_hide_a_live_transport_failure() {
        use oxid_foundation::UnixTimestampMillis;

        let listener = TcpListener::bind("127.0.0.1:0").expect("unused endpoint reserves a port");
        let address = listener.local_addr().expect("listener has an address");
        drop(listener);
        let dust_key = DustSecretKey::derive_secret_key(&[9; 32]);
        let result = runtime().block_on(synchronize_dust_with_fallback(
            &format!("ws://{address}/graphql/ws"),
            &dust_key,
            INITIAL_PARAMETERS.dust,
            Some(StoredDustCheckpoint {
                current_cursor: 7,
                target_cursor: 7,
                updated_at: UnixTimestampMillis::new(1_700_000_000_000),
                state: DustReplayState::Current(DustLocalState::new(INITIAL_PARAMETERS.dust)),
            }),
        ));
        assert_eq!(result.err(), Some(WalletTransactionPortError::Unavailable));
    }

    #[test]
    fn chain_identity_authentication_rejects_invalid_routes_without_network_io() {
        assert_eq!(
            runtime().block_on(authenticate_midnight_chain_identity(
                "http://node.example.test",
                &[0; 32],
            )),
            Err(MidnightChainIdentityError::InvalidNodeEndpoint)
        );
    }

    #[test]
    fn preview_chain_rejects_insecure_or_cross_network_routes() {
        for (network, indexer_ws, indexer_http, node) in [
            (
                "preprod",
                "wss://indexer.example.test/graphql",
                "https://indexer.example.test/graphql",
                "wss://node.example.test",
            ),
            (
                "preview",
                "ws://127.0.0.1:80/graphql",
                "https://indexer.example.test/graphql",
                "wss://node.example.test",
            ),
            (
                "preview",
                "wss://indexer.example.test/graphql",
                "http://127.0.0.1:80/graphql",
                "wss://node.example.test",
            ),
            (
                "preview",
                "wss://indexer.example.test/graphql",
                "https://indexer.example.test/graphql",
                "ws://127.0.0.1:80",
            ),
        ] {
            let config = MidnightStandaloneConfig::new_without_unshielded_address(
                network,
                indexer_ws,
                indexer_http,
                node,
                "https://proof.example.test",
            )
            .unwrap();
            assert_eq!(
                runtime().block_on(config.verify_preview_chain(&[0; 32])),
                Err(MidnightPublicChainPreflightError::InvalidRoute)
            );
        }
    }

    #[test]
    #[allow(clippy::result_large_err)] // tungstenite's test-server callback owns the error type.
    fn public_chain_rejects_an_indexed_block_from_another_node() {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

        runtime().block_on(async {
            let node = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let node_url = format!("ws://{}", node.local_addr().unwrap());
            let indexed = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let indexer_url = format!("http://{}/graphql", indexed.local_addr().unwrap());
            let node_fixture = tokio::spawn(async move {
                let (stream, _) = node.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |request: &Request, response: Response| {
                        assert!(!request.headers().contains_key("project_id"));
                        Ok(response)
                    })
                    .await
                    .unwrap();
                for (height, hash) in [(0, [1; 32]), (50, [2; 32])] {
                    let request = socket.next().await.unwrap().unwrap();
                    let request: Value = serde_json::from_str(request.to_text().unwrap()).unwrap();
                    assert_eq!(request["method"], "chain_getBlockHash");
                    assert_eq!(request["params"], json!([height]));
                    socket
                        .send(Message::Text(
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": format!("0x{}", hex::encode(hash))
                            })
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                }
            });
            let indexer_fixture = tokio::spawn(async move {
                let (stream, _) = indexed.accept().await.unwrap();
                let mut request = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(request.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        assert!(!name.eq_ignore_ascii_case("project_id"));
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0; length];
                request.read_exact(&mut body).await.unwrap();
                let request_body: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request_body["query"], CHAIN_TIP_QUERY);
                let mut parameters = Vec::new();
                midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut parameters).unwrap();
                let response = json!({"data": {"block": {
                    "height": 50,
                    "timestamp": 1_750_000_000_000_i64,
                    "hash": hex::encode([3; 32]),
                    "protocolVersion": 2_001_100,
                    "ledgerParameters": hex::encode(parameters)
                }}})
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                );
                request
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            });

            let result = timeout(
                Duration::from_secs(5),
                verify_public_chain(&node_url, &indexer_url, "ws://127.0.0.1:1", &[1; 32], None),
            )
            .await
            .expect("loopback preflight must settle");
            assert_eq!(
                result,
                Err(MidnightPublicChainPreflightError::ChainViewMismatch)
            );
            node_fixture.await.unwrap();
            indexer_fixture.await.unwrap();
        });
    }

    #[test]
    fn remote_prover_keeps_builtin_and_application_circuits_separate() {
        for location in [
            "midnight/zswap/spend",
            "midnight/zswap/output",
            "midnight/zswap/sign",
            "midnight/dust/spend",
        ] {
            assert!(HttpDustProvingProvider::is_builtin_key(location));
        }
        for location in [
            "setVerificationMethod",
            "setSchnorrJubjubVerificationMethod",
            "setVerificationMethodRelation",
            "midnight/did/setVerificationMethod",
            "",
        ] {
            assert!(!HttpDustProvingProvider::is_builtin_key(location));
        }
    }

    #[test]
    fn empty_standard_transaction_fails_closed_without_dust() {
        let transaction = Transaction::Standard(StandardTransaction::new(
            "undeployed",
            LedgerHashMap::new(),
            None,
            LedgerHashMap::new(),
        ));
        let dust_key = DustSecretKey::derive_secret_key(&[9; 32]);
        let mut dust_state = DustLocalState::new(INITIAL_PARAMETERS.dust);
        assert_eq!(
            balance_dust(
                transaction,
                &mut dust_state,
                &dust_key,
                &INITIAL_PARAMETERS,
                Timestamp::from_secs(1_700_000_000),
                Timestamp::from_secs(1_700_003_600),
                "undeployed",
                None,
            )
            .err(),
            Some(WalletTransactionPortError::InsufficientDust)
        );
    }

    #[test]
    fn dust_reconciliation_uses_the_proven_fee_instead_of_the_unproven_estimate() {
        use midnight_base_crypto::{hash::HashOutput, time::Timestamp};
        use midnight_ledger::dust::{
            DustGenerationInfo, InitialNonce, QualifiedDustOutput, dust_first_nonce,
        };

        let dust_key = DustSecretKey::derive_secret_key(&[0x5a; 32]);
        let owner = DustPublicKey::from(dust_key.clone());
        let backing_night = InitialNonce(HashOutput([0x2a; 32]));
        let created_at = Timestamp::from_secs(1);
        let generation = DustGenerationInfo {
            value: 1_000_000_000_000_000,
            owner,
            nonce: backing_night,
            dtime: Timestamp::MAX,
        };
        let output = QualifiedDustOutput {
            initial_value: generation.value,
            owner,
            nonce: dust_first_nonce(&backing_night, &owner),
            seq: 0,
            ctime: created_at,
            backing_night,
            mt_index: 0,
        };
        let mut dust_state = DustLocalState::<DefaultDB>::new(INITIAL_PARAMETERS.dust)
            .insert_generation_info(0, generation, Some(backing_night))
            .expect("generation info inserts")
            .insert_commitment(0, output, true)
            .expect("commitment inserts")
            .add_utxo(&output.nullifier(&dust_key), &output, None)
            .expect("DUST output inserts");
        let transaction = Transaction::Standard(StandardTransaction::new(
            "undeployed",
            LedgerHashMap::new(),
            None,
            LedgerHashMap::new(),
        ));
        let proven_fee = 123_456_789_u128;

        let (balanced, funded_fee) = balance_dust(
            transaction,
            &mut dust_state,
            &dust_key,
            &INITIAL_PARAMETERS,
            Timestamp::from_secs(2),
            Timestamp::from_secs(3_600),
            "undeployed",
            Some(proven_fee),
        )
        .expect("the proven fee is funded");

        assert_eq!(funded_fee, proven_fee);
        assert!(
            balanced
                .balance(Some(proven_fee))
                .expect("balanced transaction has a ledger balance")
                .values()
                .all(|value| *value >= 0)
        );
    }
}
