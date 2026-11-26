// SPDX-License-Identifier: Apache-2.0

//! Composition bridge for a native, ledger-backed Midnight DID deployment.
//!
//! This service is intentionally not exposed through the legacy synchronous
//! `CreateDidUseCase` yet. It first proves the durable headless path and stays
//! fail-closed until the post-deploy verification methods and relationships are
//! independently resolvable.

use std::{error::Error, fmt, future::Future, io, pin::Pin, sync::Arc};

use oxid_adapter_did_midnight::{
    MidnightDidBootstrapCall, MidnightDidBootstrapCircuit, MidnightDidCallCompositionPort,
    MidnightDidCallContext, MidnightDidCompactArtifacts, NativeMidnightDidCallComposer,
    NativeMidnightDidDeploymentComposer, NativeMidnightDidDeploymentRequest,
    NativeMidnightDidMaintenanceComposer, NativeMidnightDidMaintenanceRequest,
};
use oxid_adapter_midnight::{
    MidnightContractCallFundingPort, MidnightContractCallFundingRequest,
    MidnightContractCallSubmissionMode, MidnightContractCallSubmissionPort,
    MidnightContractCallSubmissionRequest, MidnightContractCallSubmissionState,
    MidnightPublicCallContextSource, MidnightRemoteProvingMaterialSource, MidnightStandaloneConfig,
};
use oxid_adapter_passport_vault::{
    CanonicalMidnightOperation, NodeAnchoredPassportVaultStateSource,
    PassportVaultCallChainContextSource,
};
use oxid_diagnostics_application::{DiagnosticCode, DiagnosticEventSinkPort, DiagnosticSeverity};
use oxid_foundation::UnixTimestampMillis;
use oxid_identity_application::{
    DeployDidCommand, DeployDidFuture, DeployDidUseCase, DidDeploymentEffect, DidDeploymentFailure,
    DidDeploymentObservation, DidDeploymentOperation, DidDeploymentOperationError,
    DidDeploymentOperationId, DidDeploymentOperationRepository, DidDeploymentReceipt,
    DidDeploymentState, DidDeploymentUseCaseError, DidResolution, DidResolutionPort,
    DidResolutionPortError, DidResolutionSource, IdentityProfileId, JwkCurve, MidnightDid,
    MidnightNetwork, VerificationRelationship,
};
use oxid_passport_vault_application::{
    PassportVaultContractStateSnapshot, PassportVaultContractStateSourceError,
};
use oxid_platform_ports::{ClockPort, RandomPort};
use oxid_wallet_application::{
    WalletDerivedSecretUsePort, WalletKeyOperationPort, WalletProfileId, WalletTransactionPortError,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const DEPLOYMENT_TTL_MILLIS: u64 = 60 * 60 * 1_000;
const MAX_AUTOMATIC_REPLACEMENTS: u32 = 2;

struct NativeDidProvingMaterialSource {
    artifacts: MidnightDidCompactArtifacts,
}

impl MidnightRemoteProvingMaterialSource for NativeDidProvingMaterialSource {
    fn resolve_key(
        &self,
        key_location: &str,
    ) -> io::Result<Option<midnight_transient_crypto::proofs::ProvingKeyMaterial>> {
        let circuit = match key_location {
            "setVerificationMethod" => MidnightDidBootstrapCircuit::VerificationMethod,
            "setSchnorrJubjubVerificationMethod" => {
                MidnightDidBootstrapCircuit::SchnorrJubjubVerificationMethod
            }
            "setVerificationMethodRelation" => {
                MidnightDidBootstrapCircuit::VerificationMethodRelation
            }
            _ => return Ok(None),
        };
        self.artifacts
            .proving_key_material(circuit)
            .map(Some)
            .map_err(|_| io::Error::other("DID proving artifact authentication failed"))
    }
}

pub(super) fn native_did_proving_material() -> Option<Arc<dyn MidnightRemoteProvingMaterialSource>>
{
    let artifacts = load_native_did_artifacts()?;
    Some(Arc::new(NativeDidProvingMaterialSource { artifacts }))
}

fn load_native_did_artifacts() -> Option<MidnightDidCompactArtifacts> {
    #[cfg(all(
        feature = "mobile-did-compact-artifacts",
        any(target_os = "ios", target_os = "android")
    ))]
    {
        return MidnightDidCompactArtifacts::load_embedded_mobile().ok();
    }
    #[cfg(not(all(
        feature = "mobile-did-compact-artifacts",
        any(target_os = "ios", target_os = "android")
    )))]
    {
        std::env::var_os("OXID_MIDNIGHT_DID_ARTIFACTS_DIR")
            .and_then(|root| MidnightDidCompactArtifacts::load(root).ok())
    }
}

#[cfg(any(
    feature = "mobile-portal",
    not(any(target_os = "ios", target_os = "android"))
))]
pub(super) fn with_native_did_deployment<K, M>(
    mut services: super::services::ApplicationServices,
    config: &MidnightStandaloneConfig,
    security: Arc<K>,
    midnight: Arc<M>,
) -> super::services::ApplicationServices
where
    K: WalletDerivedSecretUsePort + WalletKeyOperationPort + 'static,
    M: MidnightPublicCallContextSource
        + MidnightContractCallFundingPort
        + MidnightContractCallSubmissionPort
        + 'static,
{
    if let Some(deployment) = native_did_deployment(
        config,
        security,
        midnight,
        Arc::clone(&services.did_resolution_port),
        super::identity::headless_did_deployment_repository(),
        services.diagnostic_events(),
    ) {
        services.deploy_did = deployment;
    }
    services
}

pub(super) fn native_did_deployment<K, M>(
    config: &MidnightStandaloneConfig,
    security: Arc<K>,
    midnight: Arc<M>,
    resolver: Arc<dyn DidResolutionPort>,
    operations: Arc<dyn DidDeploymentOperationRepository>,
    diagnostics: Arc<dyn DiagnosticEventSinkPort>,
) -> Option<Arc<dyn DeployDidUseCase>>
where
    K: WalletDerivedSecretUsePort + WalletKeyOperationPort + 'static,
    M: MidnightPublicCallContextSource
        + MidnightContractCallFundingPort
        + MidnightContractCallSubmissionPort
        + 'static,
{
    let artifacts = load_native_did_artifacts()?;
    let wallet: Arc<dyn MidnightPublicCallContextSource> = midnight.clone();
    let contexts = Arc::new(NodeAnchoredDidDeploymentContextSource::new(config, wallet).ok()?);
    let custody: Arc<dyn WalletDerivedSecretUsePort> = security.clone();
    let keys: Arc<dyn WalletKeyOperationPort> = security;
    let calls = Arc::new(NativeMidnightDidCallComposer::new(
        Arc::clone(&custody),
        keys,
        artifacts,
    ));
    let funding: Arc<dyn MidnightContractCallFundingPort> = midnight.clone();
    let submission: Arc<dyn MidnightContractCallSubmissionPort> = midnight;
    Some(Arc::new(NativeDidDeploymentService::new(
        Arc::new(NativeMidnightDidDeploymentComposer::new(Arc::clone(
            &custody,
        ))),
        Arc::new(NativeMidnightDidMaintenanceComposer::new(custody)),
        calls,
        contexts,
        funding,
        submission,
        resolver,
        operations,
        diagnostics,
        Arc::new(oxid_adapter_platform_system::SystemClock),
        Arc::new(oxid_adapter_platform_system::OsRandom),
    )))
}

pub(super) struct NativeDidDeploymentService {
    effects: Arc<dyn DidDeploymentEffectComposer>,
    funding: Arc<dyn MidnightContractCallFundingPort>,
    submission: Arc<dyn MidnightContractCallSubmissionPort>,
    resolver: Arc<dyn DidResolutionPort>,
    operations: Arc<dyn DidDeploymentOperationRepository>,
    diagnostics: Arc<dyn DiagnosticEventSinkPort>,
    clock: Arc<dyn ClockPort>,
    random: Arc<dyn RandomPort>,
}

struct DidDeploymentEffectPlan {
    did: Option<MidnightDid>,
    profile_id: String,
    network_id: String,
    expires_at_seconds: u64,
    planning_fingerprint: [u8; 32],
    transaction: Zeroizing<Vec<u8>>,
}

type DidDeploymentEffectFuture<'a> = Pin<
    Box<dyn Future<Output = Result<DidDeploymentEffectPlan, NativeDidDeploymentError>> + Send + 'a>,
>;

trait DidDeploymentEffectComposer: Send + Sync {
    fn compose<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
        account_index: u32,
    ) -> DidDeploymentEffectFuture<'a>;

    /// Reads authenticated state for the exact finalized predecessor. This is
    /// deliberately distinct from composition so an indexer result, node ack,
    /// or best block cannot advance the ordered cursor.
    fn observe<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> DidDeploymentObservationFuture<'a>;
}

type DidDeploymentObservationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<DidDeploymentObservation, NativeDidDeploymentError>> + Send + 'a,
    >,
>;

type DidDeploymentContextFuture<'a> = Pin<
    Box<dyn Future<Output = Result<MidnightDidCallContext, NativeDidDeploymentError>> + Send + 'a>,
>;

pub(super) trait DidDeploymentContextSource: Send + Sync {
    fn context<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> DidDeploymentContextFuture<'a>;

    fn observe<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> DidDeploymentObservationFuture<'a> {
        Box::pin(async move {
            let context = self.context(operation).await?;
            let receipt = operation
                .next_observation_receipt()
                .ok_or(NativeDidDeploymentError::Integrity)?;
            DidDeploymentObservation::restore(
                receipt.effect(),
                hex::encode(context.observation_transaction_hash),
                hex::encode(context.observation_block_hash),
                context.observation_block_height,
                None,
            )
            .map_err(NativeDidDeploymentError::from)
        })
    }
}

struct NodeAnchoredDidDeploymentContextSource {
    chain: NodeAnchoredPassportVaultStateSource,
    wallet: Arc<dyn MidnightPublicCallContextSource>,
}

impl NodeAnchoredDidDeploymentContextSource {
    fn new(
        config: &MidnightStandaloneConfig,
        wallet: Arc<dyn MidnightPublicCallContextSource>,
    ) -> Result<Self, NativeDidDeploymentError> {
        let chain = NodeAnchoredPassportVaultStateSource::new_with_authentication(
            config.indexer_http_url(),
            config.node_websocket_url(),
            config.contract_state_authentication(),
        )
        .map_err(|_| NativeDidDeploymentError::Unavailable)?;
        Ok(Self { chain, wallet })
    }

    async fn authenticated_state(
        &self,
        contract_address: [u8; 32],
        receipt: &DidDeploymentReceipt,
        historical: bool,
    ) -> Result<PassportVaultContractStateSnapshot, NativeDidDeploymentError> {
        let address = hex::encode(contract_address);
        let expected = match receipt.effect() {
            DidDeploymentEffect::DeployContract => {
                CanonicalMidnightOperation::Deploy(contract_address)
            }
            DidDeploymentEffect::InstallVerificationMethodVerifier
            | DidDeploymentEffect::InstallJubjubVerifier
            | DidDeploymentEffect::InstallRelationshipVerifier => {
                CanonicalMidnightOperation::Maintain(contract_address)
            }
            DidDeploymentEffect::AddAuthenticationMethod
            | DidDeploymentEffect::AddAuthenticationRelationship
            | DidDeploymentEffect::AddAssertionMethod
            | DidDeploymentEffect::AddAssertionRelationship => {
                CanonicalMidnightOperation::Call(contract_address)
            }
            DidDeploymentEffect::ResolveDocument => {
                return Err(NativeDidDeploymentError::Integrity);
            }
        };
        self.chain
            .read_verified_effect(
                &address,
                expected,
                decode_hex_32(receipt.transaction_hash_hex())?,
                decode_hex_32(receipt.block_hash_hex())?,
                receipt.block_height(),
                historical,
            )
            .await
            .map_err(map_contract_state_error)
    }
}

impl DidDeploymentContextSource for NodeAnchoredDidDeploymentContextSource {
    fn context<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> DidDeploymentContextFuture<'a> {
        Box::pin(async move {
            let did = operation.did().ok_or(NativeDidDeploymentError::Integrity)?;
            let contract_address = did_contract_address(did)?;
            let receipt = operation
                .receipts()
                .last()
                .ok_or(NativeDidDeploymentError::Integrity)?;
            let snapshot = self
                .authenticated_state(contract_address, receipt, false)
                .await?;
            if operation.observations().last().is_none_or(|observation| {
                observation.action_transaction_hash_hex() != snapshot.transaction_hash_hex
            }) {
                return Err(NativeDidDeploymentError::LedgerStateConflict);
            }
            let chain = self
                .chain
                .chain_context(&snapshot)
                .map_err(|_| NativeDidDeploymentError::IndexerPending)?;
            let wallet = self
                .wallet
                .public_call_context(operation.profile_id().as_str())
                .map_err(|_| NativeDidDeploymentError::Unavailable)?;
            if wallet.network_id().as_str() != operation.network().as_str() {
                return Err(NativeDidDeploymentError::Integrity);
            }
            let timestamp_millis = snapshot
                .finalized_head_time_seconds
                .checked_mul(1_000)
                .ok_or(NativeDidDeploymentError::Integrity)?;
            Ok(MidnightDidCallContext {
                contract_state: snapshot.serialized_contract_state,
                contract_address,
                observation_transaction_hash: decode_hex_32(&snapshot.transaction_hash_hex)?,
                observation_block_hash: decode_hex_32(&snapshot.action_block_hash_hex)?,
                observation_block_height: snapshot.action_block_height,
                zswap_chain_state: Some(chain.zswap_chain_state().to_vec()),
                ledger_parameters: Some(chain.ledger_parameters().to_vec()),
                network_id: wallet.network_id().as_str().to_owned(),
                timestamp_millis,
                expires_at_millis: request_expires_at(operation)?.value(),
                coin_public_key: wallet.coin_public_key(),
                encryption_public_key: wallet.encryption_public_key(),
            })
        })
    }

    fn observe<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> DidDeploymentObservationFuture<'a> {
        Box::pin(async move {
            let did = operation.did().ok_or(NativeDidDeploymentError::Integrity)?;
            let receipt = operation
                .next_observation_receipt()
                .ok_or(NativeDidDeploymentError::Integrity)?;
            let snapshot = self
                .authenticated_state(
                    did_contract_address(did)?,
                    receipt,
                    operation.legacy_observations_pending(),
                )
                .await?;
            DidDeploymentObservation::restore(
                receipt.effect(),
                snapshot.transaction_hash_hex,
                snapshot.action_block_hash_hex,
                snapshot.action_block_height,
                None,
            )
            .map_err(NativeDidDeploymentError::from)
        })
    }
}

struct NativeDidDeploymentEffects {
    deployment: Arc<NativeMidnightDidDeploymentComposer>,
    maintenance: Arc<NativeMidnightDidMaintenanceComposer>,
    calls: Arc<dyn MidnightDidCallCompositionPort>,
    contexts: Arc<dyn DidDeploymentContextSource>,
    artifacts: Option<MidnightDidCompactArtifacts>,
}

impl NativeDidDeploymentEffects {
    fn new(
        deployment: Arc<NativeMidnightDidDeploymentComposer>,
        maintenance: Arc<NativeMidnightDidMaintenanceComposer>,
        calls: Arc<dyn MidnightDidCallCompositionPort>,
        contexts: Arc<dyn DidDeploymentContextSource>,
    ) -> Self {
        let artifacts = load_native_did_artifacts();
        Self {
            deployment,
            maintenance,
            calls,
            contexts,
            artifacts,
        }
    }
}

impl DidDeploymentEffectComposer for NativeDidDeploymentEffects {
    fn compose<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
        account_index: u32,
    ) -> DidDeploymentEffectFuture<'a> {
        Box::pin(async move {
            if operation.effect() == DidDeploymentEffect::DeployContract {
                let request = deployment_request(operation, account_index)?;
                let plan = self.deployment.compose(&request)?;
                return Ok(DidDeploymentEffectPlan {
                    did: Some(plan.did().clone()),
                    profile_id: plan.profile_id().to_owned(),
                    network_id: plan.network_id().to_owned(),
                    expires_at_seconds: plan.expires_at_seconds(),
                    planning_fingerprint: plan.planning_fingerprint(),
                    transaction: plan.into_transaction(),
                });
            }
            let context = self.contexts.context(operation).await?;
            let profile_id = WalletProfileId::parse(operation.profile_id().as_str().to_owned())
                .map_err(|_| NativeDidDeploymentError::InvalidRequest)?;
            let call = match operation.effect() {
                DidDeploymentEffect::AddAuthenticationMethod => {
                    Some(MidnightDidBootstrapCall::AddAuthenticationMethod)
                }
                DidDeploymentEffect::AddAuthenticationRelationship => {
                    Some(MidnightDidBootstrapCall::AddAuthenticationRelationship)
                }
                DidDeploymentEffect::AddAssertionMethod => {
                    Some(MidnightDidBootstrapCall::AddAssertionMethod)
                }
                DidDeploymentEffect::AddAssertionRelationship => {
                    Some(MidnightDidBootstrapCall::AddAssertionRelationship)
                }
                _ => None,
            };
            if let Some(call) = call {
                let plan = self
                    .calls
                    .compose_bootstrap_call(
                        profile_id,
                        account_index,
                        controller_index(operation)?,
                        operation.operation_id().as_str().to_owned(),
                        context,
                        call,
                    )
                    .await?;
                return Ok(DidDeploymentEffectPlan {
                    did: None,
                    profile_id: operation.profile_id().as_str().to_owned(),
                    network_id: operation.network().as_str().to_owned(),
                    expires_at_seconds: request_expires_at(operation)?.value() / 1_000,
                    planning_fingerprint: plan.planning_fingerprint,
                    transaction: plan.transaction,
                });
            }
            let (circuit, counter) = match operation.effect() {
                DidDeploymentEffect::InstallVerificationMethodVerifier => {
                    (MidnightDidBootstrapCircuit::VerificationMethod, 0)
                }
                DidDeploymentEffect::InstallJubjubVerifier => (
                    MidnightDidBootstrapCircuit::SchnorrJubjubVerificationMethod,
                    1,
                ),
                DidDeploymentEffect::InstallRelationshipVerifier => {
                    (MidnightDidBootstrapCircuit::VerificationMethodRelation, 2)
                }
                DidDeploymentEffect::ResolveDocument => {
                    return Err(NativeDidDeploymentError::Unavailable);
                }
                DidDeploymentEffect::AddAuthenticationMethod
                | DidDeploymentEffect::AddAuthenticationRelationship
                | DidDeploymentEffect::AddAssertionMethod
                | DidDeploymentEffect::AddAssertionRelationship => unreachable!(),
                DidDeploymentEffect::DeployContract => unreachable!(),
            };
            let artifacts = self
                .artifacts
                .as_ref()
                .ok_or(NativeDidDeploymentError::Unavailable)?;
            let did = operation.did().ok_or(NativeDidDeploymentError::Integrity)?;
            let address = did_contract_address(did)?;
            let request = NativeMidnightDidMaintenanceRequest::new(
                profile_id,
                operation.network().as_str(),
                account_index,
                address,
                circuit.artifact_id(),
                artifacts
                    .verifier_key(circuit)
                    .map_err(|_| NativeDidDeploymentError::Unavailable)?,
                counter,
                request_expires_at(operation)?.value(),
                effect_recipe(operation, b"maintenance"),
            )?;
            let plan = self.maintenance.compose(&request)?;
            Ok(DidDeploymentEffectPlan {
                did: None,
                profile_id: plan.profile_id().to_owned(),
                network_id: plan.network_id().to_owned(),
                expires_at_seconds: plan.expires_at_seconds(),
                planning_fingerprint: plan.planning_fingerprint(),
                transaction: plan.into_transaction(),
            })
        })
    }

    fn observe<'a>(
        &'a self,
        operation: &'a DidDeploymentOperation,
    ) -> DidDeploymentObservationFuture<'a> {
        self.contexts.observe(operation)
    }
}

impl NativeDidDeploymentService {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        deployment: Arc<NativeMidnightDidDeploymentComposer>,
        maintenance: Arc<NativeMidnightDidMaintenanceComposer>,
        calls: Arc<dyn MidnightDidCallCompositionPort>,
        contexts: Arc<dyn DidDeploymentContextSource>,
        funding: Arc<dyn MidnightContractCallFundingPort>,
        submission: Arc<dyn MidnightContractCallSubmissionPort>,
        resolver: Arc<dyn DidResolutionPort>,
        operations: Arc<dyn DidDeploymentOperationRepository>,
        diagnostics: Arc<dyn DiagnosticEventSinkPort>,
        clock: Arc<dyn ClockPort>,
        random: Arc<dyn RandomPort>,
    ) -> Self {
        Self {
            effects: Arc::new(NativeDidDeploymentEffects::new(
                deployment,
                maintenance,
                calls,
                contexts,
            )),
            funding,
            submission,
            resolver,
            operations,
            diagnostics,
            clock,
            random,
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn with_effects(
        effects: Arc<dyn DidDeploymentEffectComposer>,
        funding: Arc<dyn MidnightContractCallFundingPort>,
        submission: Arc<dyn MidnightContractCallSubmissionPort>,
        resolver: Arc<dyn DidResolutionPort>,
        operations: Arc<dyn DidDeploymentOperationRepository>,
        clock: Arc<dyn ClockPort>,
        random: Arc<dyn RandomPort>,
    ) -> Self {
        Self {
            effects,
            funding,
            submission,
            resolver,
            operations,
            diagnostics: Arc::new(oxid_diagnostics_application::NoopDiagnosticEventSink),
            clock,
            random,
        }
    }

    pub(super) async fn run(
        &self,
        profile_id: IdentityProfileId,
        network: MidnightNetwork,
        account_index: u32,
    ) -> Result<DidDeploymentOperation, NativeDidDeploymentError> {
        if network == MidnightNetwork::Offchain {
            return Err(NativeDidDeploymentError::InvalidRequest);
        }
        let _worker = match self.operations.try_acquire_worker() {
            Ok(worker) => worker,
            Err(DidDeploymentOperationError::Conflict) => {
                return self
                    .operations
                    .latest(&profile_id, network)?
                    .ok_or(NativeDidDeploymentError::Unavailable);
            }
            Err(error) => return Err(error.into()),
        };
        let mut operation = match self.operations.active(&profile_id, network)? {
            Some(operation) => operation,
            None => match self.operations.latest(&profile_id, network)? {
                Some(operation) if operation.state() == DidDeploymentState::Ready => {
                    return Ok(operation);
                }
                Some(_) => return Err(NativeDidDeploymentError::Integrity),
                None => self.new_operation(profile_id, network, account_index)?,
            },
        };

        if operation
            .account_index()
            .is_some_and(|saved| saved != account_index)
        {
            return Err(NativeDidDeploymentError::InvalidRequest);
        }

        // Each of eight writes has a distinct finalization and visibility
        // transition, followed by live resolution.
        for _ in 0..24 {
            if operation.state() == DidDeploymentState::AwaitingVisibility
                || (operation.legacy_observations_pending()
                    && !matches!(
                        operation.state(),
                        DidDeploymentState::Submitting
                            | DidDeploymentState::Confirming
                            | DidDeploymentState::OutcomeUnknown
                            | DidDeploymentState::RetryableFailure
                    ))
            {
                match self.effects.observe(&operation).await {
                    Ok(observation) => {
                        operation = operation.observed(
                            observation.action_transaction_hash_hex().to_owned(),
                            observation.action_block_hash_hex().to_owned(),
                            observation.action_block_height(),
                            self.now()?,
                        )?;
                        self.operations.upsert(operation.clone())?;
                        self.diagnostics.record(
                            DiagnosticCode::IdentityDidPublicationEffectVisible,
                            DiagnosticSeverity::Info,
                        );
                        continue;
                    }
                    // Preserve the finalized receipt and do no protected work
                    // until the exact action becomes observable on the same
                    // canonical history.
                    Err(
                        NativeDidDeploymentError::IndexerPending
                        | NativeDidDeploymentError::Unavailable,
                    ) => return Ok(operation),
                    Err(NativeDidDeploymentError::LedgerStateConflict) => {
                        return self.pause(operation, DidDeploymentFailure::LedgerStateConflict);
                    }
                    Err(error) => return Err(error),
                }
            }
            match operation.state() {
                DidDeploymentState::Ready => return Ok(operation),
                DidDeploymentState::Resolving => return self.resolve(operation).await,
                DidDeploymentState::AwaitingVisibility => {
                    return Err(NativeDidDeploymentError::Integrity);
                }
                DidDeploymentState::OutcomeUnknown => {
                    operation = self.reconcile(operation)?;
                    if operation.state() == DidDeploymentState::OutcomeUnknown {
                        return Ok(operation);
                    }
                    continue;
                }
                DidDeploymentState::Submitting | DidDeploymentState::Confirming => {
                    // These states can be restored after the process is suspended or
                    // terminated while a submission is in flight. Re-funding and
                    // broadcasting here could duplicate the contract effect, so the
                    // durable submission receipt must be reconciled first.
                    operation = self.reconcile(operation)?;
                    if matches!(
                        operation.state(),
                        DidDeploymentState::Submitting
                            | DidDeploymentState::Confirming
                            | DidDeploymentState::OutcomeUnknown
                            | DidDeploymentState::RetryableFailure
                    ) {
                        return Ok(operation);
                    }
                    continue;
                }
                DidDeploymentState::RetryableFailure => {
                    if operation.failure() == Some(DidDeploymentFailure::AttemptLimitReached) {
                        return Ok(operation);
                    }
                    let resume = operation
                        .resume_from()
                        .ok_or(NativeDidDeploymentError::Integrity)?;
                    operation = operation.transition(resume, self.now()?)?;
                    self.operations.upsert(operation.clone())?;
                    continue;
                }
                DidDeploymentState::Composing
                | DidDeploymentState::Funding
                | DidDeploymentState::Proving => {}
            }

            if request_expires_at(&operation)?.value() <= self.now()?.value() {
                operation = operation.renew_unarmed_attempt(self.now()?)?;
                self.operations.upsert(operation.clone())?;
            }
            let plan = match self.effects.compose(&operation, account_index).await {
                Ok(plan) => plan,
                Err(NativeDidDeploymentError::IndexerPending) => return Ok(operation),
                Err(NativeDidDeploymentError::Unavailable) => {
                    return self.pause(operation, DidDeploymentFailure::CompositionUnavailable);
                }
                Err(NativeDidDeploymentError::ProtectionLocked) => {
                    return self.pause(operation, DidDeploymentFailure::ProtectionLocked);
                }
                Err(NativeDidDeploymentError::LedgerStateConflict) => {
                    return self.pause(operation, DidDeploymentFailure::LedgerStateConflict);
                }
                Err(error) => return Err(error),
            };
            let draft_id = operation
                .submission_id()
                .map_or_else(|| effect_submission_id(&operation), str::to_owned);
            if operation.state() == DidDeploymentState::Composing {
                operation = if operation.effect() == DidDeploymentEffect::DeployContract {
                    operation.composed(
                        plan.did
                            .clone()
                            .ok_or(NativeDidDeploymentError::Integrity)?,
                        draft_id.clone(),
                        self.now()?,
                    )?
                } else {
                    if plan.did.is_some() {
                        return Err(NativeDidDeploymentError::Integrity);
                    }
                    operation.prepared_effect(draft_id.clone(), self.now()?)?
                };
                self.operations.upsert(operation.clone())?;
            } else if operation.submission_id() != Some(&draft_id)
                || (operation.effect() == DidDeploymentEffect::DeployContract
                    && operation.did() != plan.did.as_ref())
            {
                return Err(NativeDidDeploymentError::Integrity);
            }

            let funded =
                match self
                    .funding
                    .fund_contract_call(MidnightContractCallFundingRequest::new(
                        plan.profile_id,
                        plan.network_id,
                        plan.expires_at_seconds,
                        false,
                        plan.transaction,
                    )) {
                    Ok(funded) => funded,
                    Err(error) => return self.pause(operation, map_transaction_failure(error)),
                };

            operation = operation.transition(DidDeploymentState::Proving, self.now()?)?;
            self.operations.upsert(operation.clone())?;
            operation = operation.transition(DidDeploymentState::Submitting, self.now()?)?;
            self.operations.upsert(operation.clone())?;

            let outcome = match self.submission.complete_contract_call(
                MidnightContractCallSubmissionRequest::new(
                    operation.profile_id().as_str(),
                    operation.network().as_str(),
                    draft_id,
                    plan.planning_fingerprint,
                    request_expires_at(&operation)?,
                    self.now()?,
                    funded.into_transaction(),
                ),
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    // Once submission has started, only the journal can
                    // distinguish a pre-arm failure from an ambiguous send.
                    if error != WalletTransactionPortError::SubmissionOutcomeUnknown
                        && matches!(
                            self.submission.contract_call_submission_status(
                                operation.profile_id().as_str(),
                                operation
                                    .submission_id()
                                    .ok_or(NativeDidDeploymentError::Integrity)?,
                            ),
                            Err(WalletTransactionPortError::DraftNotFound)
                        )
                    {
                        return self.pause(operation, map_transaction_failure(error));
                    }
                    let unknown = operation.outcome_unknown(self.now()?)?;
                    self.operations.upsert(unknown.clone())?;
                    self.diagnostics.record(
                        DiagnosticCode::IdentityDidPublicationOutcomeUnknown,
                        DiagnosticSeverity::Warning,
                    );
                    return Ok(unknown);
                }
            };
            if outcome.mode != MidnightContractCallSubmissionMode::Live {
                return Err(NativeDidDeploymentError::Integrity);
            }
            operation = operation.transition(DidDeploymentState::Confirming, self.now()?)?;
            self.operations.upsert(operation.clone())?;
            operation = operation.included(
                hex::encode(outcome.transaction_hash),
                hex::encode(outcome.block_hash),
                outcome.block_height,
                self.now()?,
            )?;
            self.operations.upsert(operation.clone())?;
            // Yield at the durable finality boundary. The UI can report the
            // saved phase and the next command verifies visibility separately.
            self.diagnostics.record(
                DiagnosticCode::IdentityDidPublicationAwaitingVisibility,
                DiagnosticSeverity::Info,
            );
            return Ok(operation);
        }
        Err(NativeDidDeploymentError::Integrity)
    }

    fn new_operation(
        &self,
        profile_id: IdentityProfileId,
        network: MidnightNetwork,
        account_index: u32,
    ) -> Result<DidDeploymentOperation, NativeDidDeploymentError> {
        let mut random = [0_u8; 16];
        self.random
            .fill_bytes(&mut random)
            .map_err(|_| NativeDidDeploymentError::Unavailable)?;
        let id = DidDeploymentOperationId::parse(format!("did-deployment-{}", hex::encode(random)))
            .map_err(|_| NativeDidDeploymentError::InvalidRequest)?;
        let operation =
            DidDeploymentOperation::new(id, profile_id, network, account_index, self.now()?)?;
        self.operations.upsert(operation.clone())?;
        Ok(operation)
    }

    fn reconcile(
        &self,
        operation: DidDeploymentOperation,
    ) -> Result<DidDeploymentOperation, NativeDidDeploymentError> {
        let draft_id = operation
            .submission_id()
            .ok_or(NativeDidDeploymentError::Integrity)?;
        let profile = operation.profile_id().as_str();
        let status = match self
            .submission
            .reconcile_contract_call_submission(profile, draft_id)
        {
            Ok(status) => status,
            Err(WalletTransactionPortError::DraftNotFound)
                if operation.state() == DidDeploymentState::Submitting
                    && matches!(
                        self.submission
                            .contract_call_submission_status(profile, draft_id),
                        Err(WalletTransactionPortError::DraftNotFound)
                    ) =>
            {
                // The worker permit fences other preparations. The native adapter
                // writes the durable receipt before it can ever dispatch.
                return self.pause(operation, DidDeploymentFailure::FundingUnavailable);
            }
            Err(WalletTransactionPortError::Unavailable | WalletTransactionPortError::Timeout) => {
                return Ok(operation);
            }
            Err(_) => return Err(NativeDidDeploymentError::Transaction),
        };
        if status.draft_id != draft_id {
            return Err(NativeDidDeploymentError::Integrity);
        }
        match status.state {
            MidnightContractCallSubmissionState::Included => {
                if status.mode != Some(MidnightContractCallSubmissionMode::Live) {
                    return Err(NativeDidDeploymentError::Integrity);
                }
                let confirming =
                    operation.transition(DidDeploymentState::Confirming, self.now()?)?;
                self.operations.upsert(confirming.clone())?;
                let included = confirming.included(
                    hex::encode(
                        status
                            .transaction_hash
                            .ok_or(NativeDidDeploymentError::Integrity)?,
                    ),
                    hex::encode(
                        status
                            .block_hash
                            .ok_or(NativeDidDeploymentError::Integrity)?,
                    ),
                    status
                        .block_height
                        .ok_or(NativeDidDeploymentError::Integrity)?,
                    self.now()?,
                )?;
                self.operations.upsert(included.clone())?;
                self.diagnostics.record(
                    DiagnosticCode::IdentityDidPublicationAwaitingVisibility,
                    DiagnosticSeverity::Info,
                );
                Ok(included)
            }
            MidnightContractCallSubmissionState::OutcomeUnknown => {
                // Repeated read-only reconciliations are normal after a lost
                // watch. They must not manufacture a second transition or
                // reopen broadcast admission.
                if operation.state() == DidDeploymentState::OutcomeUnknown {
                    Ok(operation)
                } else {
                    let unknown = operation.outcome_unknown(self.now()?)?;
                    self.operations.upsert(unknown.clone())?;
                    self.diagnostics.record(
                        DiagnosticCode::IdentityDidPublicationOutcomeUnknown,
                        DiagnosticSeverity::Warning,
                    );
                    Ok(unknown)
                }
            }
            MidnightContractCallSubmissionState::Running
            | MidnightContractCallSubmissionState::CancellationRequested
            | MidnightContractCallSubmissionState::Broadcasting => Ok(operation),
            MidnightContractCallSubmissionState::Rejected
            | MidnightContractCallSubmissionState::Expired => {
                // Only the submission adapter can return these terminal
                // states: it has checked finalized rejection or canonical
                // coverage through the journaled anchor and deadline. A new
                // identity/deadline is therefore safe; no receipt is lost.
                let replacement =
                    operation.replace_attempt(self.now()?, MAX_AUTOMATIC_REPLACEMENTS)?;
                self.operations.upsert(replacement.clone())?;
                if replacement.failure() == Some(DidDeploymentFailure::AttemptLimitReached) {
                    self.diagnostics.record(
                        DiagnosticCode::IdentityDidPublicationPaused,
                        DiagnosticSeverity::Warning,
                    );
                }
                Ok(replacement)
            }
        }
    }

    async fn resolve(
        &self,
        operation: DidDeploymentOperation,
    ) -> Result<DidDeploymentOperation, NativeDidDeploymentError> {
        let did = operation
            .did()
            .cloned()
            .ok_or(NativeDidDeploymentError::Integrity)?;
        let resolution = match self.resolver.resolve(&did).await {
            Ok(resolution) => resolution,
            Err(DidResolutionPortError::Unavailable | DidResolutionPortError::NotFound) => {
                return Ok(operation);
            }
            Err(_) => return Err(NativeDidDeploymentError::Resolution),
        };
        if resolution.source() != DidResolutionSource::Live || resolution.document().id() != &did {
            return self.pause(operation, DidDeploymentFailure::ResolutionMismatch);
        }
        // The resolver may observe each included maintenance transaction at a
        // different indexed height. A live document that still lacks one of
        // the required holder methods is therefore an incomplete projection,
        // not evidence of corruption. Keep the durable operation in Resolving
        // so the caller can query again without resubmitting any transaction.
        if !required_holder_methods_resolve(&resolution) {
            return Ok(operation);
        }
        let ready = operation.transition(DidDeploymentState::Ready, self.now()?)?;
        self.operations.upsert(ready.clone())?;
        self.diagnostics.record(
            DiagnosticCode::IdentityDidPublicationReady,
            DiagnosticSeverity::Info,
        );
        Ok(ready)
    }

    fn pause(
        &self,
        operation: DidDeploymentOperation,
        failure: DidDeploymentFailure,
    ) -> Result<DidDeploymentOperation, NativeDidDeploymentError> {
        let paused = operation.retryable_failure(failure, self.now()?)?;
        self.operations.upsert(paused.clone())?;
        self.diagnostics.record(
            if failure == DidDeploymentFailure::ProtectionLocked {
                DiagnosticCode::IdentityDidPublicationApprovalRequired
            } else {
                DiagnosticCode::IdentityDidPublicationPaused
            },
            DiagnosticSeverity::Warning,
        );
        Ok(paused)
    }

    fn now(&self) -> Result<UnixTimestampMillis, NativeDidDeploymentError> {
        self.clock
            .now()
            .map_err(|_| NativeDidDeploymentError::Unavailable)
    }
}

impl DeployDidUseCase for NativeDidDeploymentService {
    fn execute<'a>(&'a self, command: DeployDidCommand) -> DeployDidFuture<'a> {
        Box::pin(async move {
            self.run(command.profile_id, command.network, command.account_index)
                .await
                .map_err(DidDeploymentUseCaseError::from)
        })
    }

    fn status(
        &self,
        profile_id: &IdentityProfileId,
        network: MidnightNetwork,
    ) -> Result<Option<DidDeploymentOperation>, DidDeploymentUseCaseError> {
        if network == MidnightNetwork::Offchain {
            return Err(DidDeploymentUseCaseError::InvalidRequest);
        }
        self.operations
            .latest(profile_id, network)
            .map_err(|error| NativeDidDeploymentError::from(error).into())
    }
}

fn deployment_request(
    operation: &DidDeploymentOperation,
    account_index: u32,
) -> Result<NativeMidnightDidDeploymentRequest, NativeDidDeploymentError> {
    let id = operation.operation_id().as_str().as_bytes();
    let nonce_recipe = derive_public_recipe(b"oxid:did-deploy:nonce:v1", id);
    let intent_recipe = derive_public_recipe(b"oxid:did-deploy:rng:v1", id);
    NativeMidnightDidDeploymentRequest::new(
        WalletProfileId::parse(operation.profile_id().as_str().to_owned())
            .map_err(|_| NativeDidDeploymentError::InvalidRequest)?,
        operation.network(),
        operation.network().as_str(),
        account_index,
        controller_index(operation)?,
        operation.created_at().value(),
        request_expires_at(operation)?.value(),
        nonce_recipe,
        intent_recipe,
    )
    .map_err(|_| NativeDidDeploymentError::Lifecycle)
}

fn controller_index(operation: &DidDeploymentOperation) -> Result<u32, NativeDidDeploymentError> {
    let digest = derive_public_recipe(
        b"oxid:did-controller:index:v1",
        operation.operation_id().as_str().as_bytes(),
    );
    Ok(u32::from_be_bytes(
        digest[..4]
            .try_into()
            .map_err(|_| NativeDidDeploymentError::Integrity)?,
    ) & oxid_wallet_application::WalletHdPathComponent::MAX_INDEX)
}

fn did_contract_address(did: &MidnightDid) -> Result<[u8; 32], NativeDidDeploymentError> {
    let encoded = did
        .as_str()
        .rsplit(':')
        .next()
        .ok_or(NativeDidDeploymentError::Integrity)?;
    let decoded = hex::decode(encoded).map_err(|_| NativeDidDeploymentError::Integrity)?;
    decoded
        .try_into()
        .map_err(|_| NativeDidDeploymentError::Integrity)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], NativeDidDeploymentError> {
    let bytes = hex::decode(value).map_err(|_| NativeDidDeploymentError::Integrity)?;
    bytes
        .try_into()
        .map_err(|_| NativeDidDeploymentError::Integrity)
}

fn effect_submission_id(operation: &DidDeploymentOperation) -> String {
    format!(
        "{}-{}-attempt-{}",
        operation.operation_id().as_str(),
        operation.effect().as_str(),
        operation.attempt().saturating_add(1),
    )
}

fn effect_recipe(operation: &DidDeploymentOperation, domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"oxid:did-deployment:effect:v1");
    hasher.update(domain);
    hasher.update(operation.operation_id().as_str().as_bytes());
    hasher.update(operation.effect().as_str().as_bytes());
    hasher.finalize().into()
}

fn request_expires_at(
    operation: &DidDeploymentOperation,
) -> Result<UnixTimestampMillis, NativeDidDeploymentError> {
    operation
        .attempt_started_at()
        .value()
        .checked_add(DEPLOYMENT_TTL_MILLIS)
        .map(UnixTimestampMillis::new)
        .ok_or(NativeDidDeploymentError::InvalidRequest)
}

fn derive_public_recipe(domain: &[u8], operation_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(operation_id);
    hasher.finalize().into()
}

const fn map_contract_state_error(
    error: PassportVaultContractStateSourceError,
) -> NativeDidDeploymentError {
    match error {
        PassportVaultContractStateSourceError::NotFound
        | PassportVaultContractStateSourceError::Unavailable => {
            NativeDidDeploymentError::IndexerPending
        }
        PassportVaultContractStateSourceError::InvalidConfiguration
        | PassportVaultContractStateSourceError::InvalidAddress
        | PassportVaultContractStateSourceError::CapacityExceeded
        | PassportVaultContractStateSourceError::InvalidResponse => {
            NativeDidDeploymentError::Integrity
        }
        PassportVaultContractStateSourceError::FinalityMismatch => {
            NativeDidDeploymentError::LedgerStateConflict
        }
    }
}

fn required_holder_methods_resolve(resolution: &DidResolution) -> bool {
    let document = resolution.document();
    let ed25519 = document
        .verification_methods()
        .iter()
        .filter(|method| method.public_key_jwk().curve() == JwkCurve::Ed25519)
        .map(|method| method.id())
        .collect::<Vec<_>>();
    let jubjub = document
        .verification_methods()
        .iter()
        .filter(|method| method.public_key_jwk().curve() == JwkCurve::Jubjub)
        .map(|method| method.id())
        .collect::<Vec<_>>();
    let relationship_contains = |relationship, ids: &[&str]| {
        document.relationships().iter().any(|entry| {
            entry.relationship() == relationship
                && ids.iter().any(|id| {
                    entry.method_ids().iter().any(|candidate| {
                        candidate == id
                            || candidate.strip_prefix('#').is_some_and(|fragment| {
                                *id == format!("{}#{fragment}", document.id().as_str())
                            })
                    })
                })
        })
    };
    !ed25519.is_empty()
        && !jubjub.is_empty()
        && relationship_contains(VerificationRelationship::Authentication, &ed25519)
        && relationship_contains(VerificationRelationship::AssertionMethod, &jubjub)
}

fn map_transaction_failure(error: WalletTransactionPortError) -> DidDeploymentFailure {
    match error {
        WalletTransactionPortError::ProtectionLocked
        | WalletTransactionPortError::ProtectionNotInitialized => {
            DidDeploymentFailure::ProtectionLocked
        }
        WalletTransactionPortError::InsufficientDust => DidDeploymentFailure::InsufficientDust,
        WalletTransactionPortError::InsufficientFunds => DidDeploymentFailure::InsufficientNight,
        WalletTransactionPortError::InvalidChainState => {
            DidDeploymentFailure::ChainStateUnavailable
        }
        WalletTransactionPortError::UnsupportedNetwork => DidDeploymentFailure::UnsupportedNetwork,
        WalletTransactionPortError::InvalidData | WalletTransactionPortError::DraftConflict => {
            DidDeploymentFailure::InvalidFundingPlan
        }
        WalletTransactionPortError::ProvingFailed => DidDeploymentFailure::ProvingUnavailable,
        WalletTransactionPortError::SubmissionRejected
        | WalletTransactionPortError::DraftExpired => DidDeploymentFailure::SubmissionRejected,
        WalletTransactionPortError::AccountNotDerived
        | WalletTransactionPortError::AccountNotSynchronized
        | WalletTransactionPortError::ShieldedStateNotCurrent => {
            DidDeploymentFailure::AccountUnavailable
        }
        _ => DidDeploymentFailure::FundingUnavailable,
    }
}

#[derive(Debug)]
pub(super) enum NativeDidDeploymentError {
    Unavailable,
    IndexerPending,
    ProtectionLocked,
    LedgerStateConflict,
    InvalidRequest,
    Integrity,
    Operation,
    Lifecycle,
    Transaction,
    Resolution,
}

impl fmt::Display for NativeDidDeploymentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "native DID deployment dependencies are unavailable",
            Self::IndexerPending => "native DID deployment is waiting for indexed finality",
            Self::ProtectionLocked => "native DID publication requires wallet unlock",
            Self::LedgerStateConflict => "finalized ledger state conflicts with the DID receipt",
            Self::InvalidRequest => "native DID deployment request is invalid",
            Self::Integrity => "native DID deployment state failed integrity validation",
            Self::Operation => "native DID deployment operation persistence failed",
            Self::Lifecycle => "native DID deployment composition failed",
            Self::Transaction => "native DID deployment transaction failed",
            Self::Resolution => "native DID deployment resolution failed",
        })
    }
}

impl Error for NativeDidDeploymentError {}

impl From<DidDeploymentOperationError> for NativeDidDeploymentError {
    fn from(error: DidDeploymentOperationError) -> Self {
        match error {
            DidDeploymentOperationError::Integrity
            | DidDeploymentOperationError::InvalidData
            | DidDeploymentOperationError::InvalidTransition => Self::Integrity,
            DidDeploymentOperationError::Unavailable
            | DidDeploymentOperationError::NotFound
            | DidDeploymentOperationError::Conflict
            | DidDeploymentOperationError::CapacityExceeded => Self::Operation,
        }
    }
}

impl From<oxid_identity_application::DidLifecyclePortError> for NativeDidDeploymentError {
    fn from(error: oxid_identity_application::DidLifecyclePortError) -> Self {
        if error == oxid_identity_application::DidLifecyclePortError::Locked {
            Self::ProtectionLocked
        } else {
            Self::Lifecycle
        }
    }
}

impl From<WalletTransactionPortError> for NativeDidDeploymentError {
    fn from(_: WalletTransactionPortError) -> Self {
        Self::Transaction
    }
}

impl From<NativeDidDeploymentError> for DidDeploymentUseCaseError {
    fn from(error: NativeDidDeploymentError) -> Self {
        match error {
            NativeDidDeploymentError::Unavailable => Self::Unavailable,
            NativeDidDeploymentError::IndexerPending => Self::Unavailable,
            NativeDidDeploymentError::ProtectionLocked => Self::Composition,
            NativeDidDeploymentError::LedgerStateConflict => Self::Integrity,
            NativeDidDeploymentError::InvalidRequest => Self::InvalidRequest,
            NativeDidDeploymentError::Integrity => Self::Integrity,
            NativeDidDeploymentError::Operation => Self::Persistence,
            NativeDidDeploymentError::Lifecycle => Self::Composition,
            NativeDidDeploymentError::Transaction => Self::Transaction,
            NativeDidDeploymentError::Resolution => Self::Resolution,
        }
    }
}

#[cfg(test)]
#[path = "did_deployment/tests.rs"]
mod tests;
