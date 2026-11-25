// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    sync::Mutex,
};

use oxid_adapter_store_atomic as store_atomic;
use oxid_identity_application::{
    DidDeploymentEffect, DidDeploymentFailure, DidDeploymentObservation, DidDeploymentOperation,
    DidDeploymentOperationError, DidDeploymentOperationId, DidDeploymentOperationParts,
    DidDeploymentOperationRepository, DidDeploymentReceipt, DidDeploymentState,
    DidDeploymentWorkerPermit,
};
use oxid_identity_domain::{IdentityProfileId, MidnightDid, MidnightNetwork};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 3;
const MAX_OPERATIONS: usize = 128;
const MAX_STORE_BYTES: usize = 512 * 1_024;

/// Owner-private, durable progress journal for safe DID deployment metadata.
pub struct JsonDidDeploymentOperationRepository {
    path: PathBuf,
    access: Mutex<()>,
}

struct JsonDidDeploymentWorkerPermit {
    _file: File,
}

impl DidDeploymentWorkerPermit for JsonDidDeploymentWorkerPermit {}

impl JsonDidDeploymentOperationRepository {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: Mutex::new(()),
        }
    }

    #[must_use]
    pub fn configured_path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<StoredOperations, DidDeploymentOperationError> {
        if let Some(parent) = self.path.parent() {
            store_atomic::reject_non_private_directory(parent).map_err(map_store_error)?;
        }
        let Some(bytes) = store_atomic::read_owner_private_bounded(&self.path, MAX_STORE_BYTES)
            .map_err(map_store_error)?
        else {
            return Ok(StoredOperations::default());
        };
        let mut stored: StoredOperations =
            serde_json::from_slice(&bytes).map_err(|_| DidDeploymentOperationError::Integrity)?;
        if stored.schema_version == 2 {
            for operation in &mut stored.operations {
                operation.legacy_observations_pending =
                    operation.observations.len() < operation.receipts.len();
                if operation.state == DidDeploymentState::Ready.as_str()
                    && operation.legacy_observations_pending
                {
                    operation.state = DidDeploymentState::Resolving.as_str().to_owned();
                }
                if operation.state == DidDeploymentState::RetryableFailure.as_str()
                    && operation.submission_id.is_some()
                {
                    // Legacy pauses did not retain the broadcast boundary.
                    // Resolve the original draft before rebuilding it.
                    operation.state = DidDeploymentState::Submitting.as_str().to_owned();
                    operation.failure = None;
                    operation.resume_from = None;
                }
            }
            stored.schema_version = SCHEMA_VERSION;
        }
        validate(&stored)?;
        Ok(stored)
    }

    fn save(&self, stored: &StoredOperations) -> Result<(), DidDeploymentOperationError> {
        validate(stored)?;
        let bytes = serde_json::to_vec_pretty(stored)
            .map_err(|_| DidDeploymentOperationError::Unavailable)?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(DidDeploymentOperationError::CapacityExceeded);
        }
        store_atomic::write_owner_private(&self.path, &bytes).map_err(map_store_error)
    }
}

impl DidDeploymentOperationRepository for JsonDidDeploymentOperationRepository {
    fn try_acquire_worker(
        &self,
    ) -> Result<Box<dyn DidDeploymentWorkerPermit>, DidDeploymentOperationError> {
        let parent = self
            .path
            .parent()
            .ok_or(DidDeploymentOperationError::Unavailable)?;
        store_atomic::ensure_private_directory(parent).map_err(map_store_error)?;
        let lock_path = self.path.with_extension("worker-lock");
        let mut create = OpenOptions::new();
        create.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            create.mode(0o600);
        }
        let lock = match create.open(&lock_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                store_atomic::reject_non_private_file(&lock_path).map_err(map_store_error)?;
                OpenOptions::new()
                    .write(true)
                    .open(&lock_path)
                    .map_err(|_| DidDeploymentOperationError::Unavailable)?
            }
            Err(_) => return Err(DidDeploymentOperationError::Unavailable),
        };
        match lock.try_lock() {
            Ok(()) => Ok(Box::new(JsonDidDeploymentWorkerPermit { _file: lock })),
            Err(TryLockError::WouldBlock) => Err(DidDeploymentOperationError::Conflict),
            Err(TryLockError::Error(_)) => Err(DidDeploymentOperationError::Unavailable),
        }
    }

    fn upsert(&self, operation: DidDeploymentOperation) -> Result<(), DidDeploymentOperationError> {
        let _guard = self
            .access
            .lock()
            .map_err(|_| DidDeploymentOperationError::Unavailable)?;
        let mut stored = self.load()?;
        if !operation.state().terminal()
            && stored.operations.iter().any(|candidate| {
                candidate.operation_id != operation.operation_id().as_str()
                    && candidate.profile_id == operation.profile_id().as_str()
                    && candidate.network == operation.network().as_str()
                    && candidate.state != DidDeploymentState::Ready.as_str()
            })
        {
            return Err(DidDeploymentOperationError::Conflict);
        }
        let encoded = StoredOperation::from(&operation);
        if let Some(existing) = stored
            .operations
            .iter_mut()
            .find(|candidate| candidate.operation_id == operation.operation_id().as_str())
        {
            let current = existing.to_domain()?;
            if operation.revision() != current.revision().saturating_add(1) {
                return Err(DidDeploymentOperationError::Conflict);
            }
            *existing = encoded;
        } else {
            if operation.revision() != 0 {
                return Err(DidDeploymentOperationError::Conflict);
            }
            if stored.operations.len() >= MAX_OPERATIONS {
                return Err(DidDeploymentOperationError::CapacityExceeded);
            }
            stored.operations.push(encoded);
        }
        self.save(&stored)
    }

    fn get(
        &self,
        operation_id: &DidDeploymentOperationId,
    ) -> Result<DidDeploymentOperation, DidDeploymentOperationError> {
        let _guard = self
            .access
            .lock()
            .map_err(|_| DidDeploymentOperationError::Unavailable)?;
        self.load()?
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation_id.as_str())
            .ok_or(DidDeploymentOperationError::NotFound)?
            .to_domain()
    }

    fn active(
        &self,
        profile_id: &IdentityProfileId,
        network: MidnightNetwork,
    ) -> Result<Option<DidDeploymentOperation>, DidDeploymentOperationError> {
        let _guard = self
            .access
            .lock()
            .map_err(|_| DidDeploymentOperationError::Unavailable)?;
        let stored = self.load()?;
        let matches = stored
            .operations
            .iter()
            .filter(|candidate| {
                candidate.profile_id == profile_id.as_str()
                    && candidate.network == network.as_str()
                    && candidate.state != DidDeploymentState::Ready.as_str()
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [operation] => operation.to_domain().map(Some),
            _ => Err(DidDeploymentOperationError::Integrity),
        }
    }

    fn latest(
        &self,
        profile_id: &IdentityProfileId,
        network: MidnightNetwork,
    ) -> Result<Option<DidDeploymentOperation>, DidDeploymentOperationError> {
        let _guard = self
            .access
            .lock()
            .map_err(|_| DidDeploymentOperationError::Unavailable)?;
        self.load()?
            .operations
            .iter()
            .filter(|candidate| {
                candidate.profile_id == profile_id.as_str() && candidate.network == network.as_str()
            })
            .max_by_key(|candidate| candidate.updated_at_millis)
            .map(StoredOperation::to_domain)
            .transpose()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredOperations {
    schema_version: u32,
    operations: Vec<StoredOperation>,
}

impl Default for StoredOperations {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            operations: Vec::new(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredOperation {
    operation_id: String,
    profile_id: String,
    network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_index: Option<u32>,
    state: String,
    resume_from: Option<String>,
    failure: Option<String>,
    effect: String,
    did: Option<String>,
    submission_id: Option<String>,
    receipts: Vec<StoredReceipt>,
    /// Missing in schema-two records; such receipts are re-observed before
    /// progression rather than trusted as visibility evidence.
    #[serde(default)]
    observations: Vec<StoredObservation>,
    #[serde(default)]
    legacy_observations_pending: bool,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    attempt: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_started_at_millis: Option<u64>,
    transaction_hash_hex: Option<String>,
    block_hash_hex: Option<String>,
    block_height: Option<u64>,
    created_at_millis: u64,
    updated_at_millis: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredObservation {
    effect: String,
    action_transaction_hash_hex: String,
    action_block_hash_hex: String,
    action_block_height: u64,
    #[serde(default)]
    visibility_wait_millis: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredReceipt {
    effect: String,
    submission_id: String,
    transaction_hash_hex: String,
    block_hash_hex: String,
    block_height: u64,
    #[serde(default)]
    attempt_elapsed_millis: Option<u64>,
}

impl From<&DidDeploymentOperation> for StoredOperation {
    fn from(operation: &DidDeploymentOperation) -> Self {
        let parts = operation.to_parts();
        Self {
            operation_id: parts.operation_id.as_str().to_owned(),
            profile_id: parts.profile_id.as_str().to_owned(),
            network: parts.network.as_str().to_owned(),
            account_index: parts.account_index,
            state: parts.state.as_str().to_owned(),
            resume_from: parts
                .resume_from
                .map(DidDeploymentState::as_str)
                .map(str::to_owned),
            failure: parts
                .failure
                .map(DidDeploymentFailure::as_str)
                .map(str::to_owned),
            effect: parts.effect.as_str().to_owned(),
            did: parts.did.map(|did| did.as_str().to_owned()),
            submission_id: parts.submission_id,
            receipts: parts
                .receipts
                .into_iter()
                .map(|receipt| StoredReceipt {
                    effect: receipt.effect().as_str().to_owned(),
                    submission_id: receipt.submission_id().to_owned(),
                    transaction_hash_hex: receipt.transaction_hash_hex().to_owned(),
                    block_hash_hex: receipt.block_hash_hex().to_owned(),
                    block_height: receipt.block_height(),
                    attempt_elapsed_millis: receipt.attempt_elapsed_millis(),
                })
                .collect(),
            observations: parts
                .observations
                .into_iter()
                .map(|observation| StoredObservation {
                    effect: observation.effect().as_str().to_owned(),
                    action_transaction_hash_hex: observation
                        .action_transaction_hash_hex()
                        .to_owned(),
                    action_block_hash_hex: observation.action_block_hash_hex().to_owned(),
                    action_block_height: observation.action_block_height(),
                    visibility_wait_millis: observation.visibility_wait_millis(),
                })
                .collect(),
            legacy_observations_pending: parts.legacy_observations_pending,
            revision: parts.revision,
            attempt: parts.attempt,
            attempt_started_at_millis: Some(parts.attempt_started_at_millis),
            transaction_hash_hex: parts.transaction_hash_hex,
            block_hash_hex: parts.block_hash_hex,
            block_height: parts.block_height,
            created_at_millis: parts.created_at_millis,
            updated_at_millis: parts.updated_at_millis,
        }
    }
}

impl StoredOperation {
    fn to_domain(&self) -> Result<DidDeploymentOperation, DidDeploymentOperationError> {
        DidDeploymentOperation::restore(DidDeploymentOperationParts {
            operation_id: DidDeploymentOperationId::parse(self.operation_id.clone())
                .map_err(|_| DidDeploymentOperationError::Integrity)?,
            profile_id: IdentityProfileId::parse(self.profile_id.clone())
                .map_err(|_| DidDeploymentOperationError::Integrity)?,
            network: parse_network(&self.network)?,
            account_index: self.account_index,
            state: parse_state(&self.state)?,
            resume_from: self.resume_from.as_deref().map(parse_state).transpose()?,
            failure: self.failure.as_deref().map(parse_failure).transpose()?,
            effect: parse_effect(&self.effect)?,
            did: self
                .did
                .as_ref()
                .map(|value| MidnightDid::parse(value.clone()))
                .transpose()
                .map_err(|_| DidDeploymentOperationError::Integrity)?,
            submission_id: self.submission_id.clone(),
            receipts: self
                .receipts
                .iter()
                .map(|receipt| {
                    DidDeploymentReceipt::restore(
                        parse_effect(&receipt.effect)?,
                        receipt.submission_id.clone(),
                        receipt.transaction_hash_hex.clone(),
                        receipt.block_hash_hex.clone(),
                        receipt.block_height,
                        receipt.attempt_elapsed_millis,
                    )
                    .map_err(|_| DidDeploymentOperationError::Integrity)
                })
                .collect::<Result<Vec<_>, _>>()?,
            observations: self
                .observations
                .iter()
                .map(|observation| {
                    DidDeploymentObservation::restore(
                        parse_effect(&observation.effect)?,
                        observation.action_transaction_hash_hex.clone(),
                        observation.action_block_hash_hex.clone(),
                        observation.action_block_height,
                        observation.visibility_wait_millis,
                    )
                    .map_err(|_| DidDeploymentOperationError::Integrity)
                })
                .collect::<Result<Vec<_>, _>>()?,
            legacy_observations_pending: self.legacy_observations_pending,
            revision: self.revision,
            attempt: self.attempt,
            attempt_started_at_millis: self
                .attempt_started_at_millis
                .unwrap_or(self.created_at_millis),
            transaction_hash_hex: self.transaction_hash_hex.clone(),
            block_hash_hex: self.block_hash_hex.clone(),
            block_height: self.block_height,
            created_at_millis: self.created_at_millis,
            updated_at_millis: self.updated_at_millis,
        })
    }
}

fn validate(stored: &StoredOperations) -> Result<(), DidDeploymentOperationError> {
    if stored.schema_version != SCHEMA_VERSION || stored.operations.len() > MAX_OPERATIONS {
        return Err(DidDeploymentOperationError::Integrity);
    }
    let ids = stored
        .operations
        .iter()
        .map(|operation| operation.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != stored.operations.len() {
        return Err(DidDeploymentOperationError::Integrity);
    }
    let operations = stored
        .operations
        .iter()
        .map(StoredOperation::to_domain)
        .collect::<Result<Vec<_>, _>>()?;
    let active = operations
        .iter()
        .filter(|operation| !operation.state().terminal())
        .map(|operation| (operation.profile_id().as_str(), operation.network()))
        .collect::<BTreeSet<_>>();
    if active.len()
        != operations
            .iter()
            .filter(|operation| !operation.state().terminal())
            .count()
    {
        return Err(DidDeploymentOperationError::Integrity);
    }
    Ok(())
}

fn parse_network(value: &str) -> Result<MidnightNetwork, DidDeploymentOperationError> {
    MidnightNetwork::parse(value).ok_or(DidDeploymentOperationError::Integrity)
}

fn parse_state(value: &str) -> Result<DidDeploymentState, DidDeploymentOperationError> {
    match value {
        "composing" => Ok(DidDeploymentState::Composing),
        "funding" => Ok(DidDeploymentState::Funding),
        "proving" => Ok(DidDeploymentState::Proving),
        "submitting" => Ok(DidDeploymentState::Submitting),
        "confirming" => Ok(DidDeploymentState::Confirming),
        "awaiting_visibility" => Ok(DidDeploymentState::AwaitingVisibility),
        "resolving" => Ok(DidDeploymentState::Resolving),
        "ready" => Ok(DidDeploymentState::Ready),
        "retryable_failure" => Ok(DidDeploymentState::RetryableFailure),
        "outcome_unknown" => Ok(DidDeploymentState::OutcomeUnknown),
        _ => Err(DidDeploymentOperationError::Integrity),
    }
}

fn parse_effect(value: &str) -> Result<DidDeploymentEffect, DidDeploymentOperationError> {
    match value {
        "deploy_contract" => Ok(DidDeploymentEffect::DeployContract),
        "install_verification_method_verifier" => {
            Ok(DidDeploymentEffect::InstallVerificationMethodVerifier)
        }
        "install_jubjub_verifier" => Ok(DidDeploymentEffect::InstallJubjubVerifier),
        "install_relationship_verifier" => Ok(DidDeploymentEffect::InstallRelationshipVerifier),
        "add_authentication_method" => Ok(DidDeploymentEffect::AddAuthenticationMethod),
        "add_authentication_relationship" => Ok(DidDeploymentEffect::AddAuthenticationRelationship),
        "add_assertion_method" => Ok(DidDeploymentEffect::AddAssertionMethod),
        "add_assertion_relationship" => Ok(DidDeploymentEffect::AddAssertionRelationship),
        "resolve_document" => Ok(DidDeploymentEffect::ResolveDocument),
        _ => Err(DidDeploymentOperationError::Integrity),
    }
}

fn parse_failure(value: &str) -> Result<DidDeploymentFailure, DidDeploymentOperationError> {
    match value {
        "composition_unavailable" => Ok(DidDeploymentFailure::CompositionUnavailable),
        "protection_locked" => Ok(DidDeploymentFailure::ProtectionLocked),
        "account_unavailable" => Ok(DidDeploymentFailure::AccountUnavailable),
        "funding_unavailable" => Ok(DidDeploymentFailure::FundingUnavailable),
        "insufficient_night" => Ok(DidDeploymentFailure::InsufficientNight),
        "chain_state_unavailable" => Ok(DidDeploymentFailure::ChainStateUnavailable),
        "unsupported_network" => Ok(DidDeploymentFailure::UnsupportedNetwork),
        "invalid_funding_plan" => Ok(DidDeploymentFailure::InvalidFundingPlan),
        "insufficient_dust" => Ok(DidDeploymentFailure::InsufficientDust),
        "proving_unavailable" => Ok(DidDeploymentFailure::ProvingUnavailable),
        "submission_rejected" => Ok(DidDeploymentFailure::SubmissionRejected),
        "resolution_unavailable" => Ok(DidDeploymentFailure::ResolutionUnavailable),
        "resolution_mismatch" => Ok(DidDeploymentFailure::ResolutionMismatch),
        "persistence_unavailable" => Ok(DidDeploymentFailure::PersistenceUnavailable),
        _ => Err(DidDeploymentOperationError::Integrity),
    }
}

const fn map_store_error(error: store_atomic::AtomicStoreError) -> DidDeploymentOperationError {
    match error {
        store_atomic::AtomicStoreError::Integrity => DidDeploymentOperationError::Integrity,
        store_atomic::AtomicStoreError::Unavailable => DidDeploymentOperationError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    #[test]
    fn parses_actionable_funding_failure_categories() {
        assert_eq!(
            parse_failure("insufficient_night"),
            Ok(DidDeploymentFailure::InsufficientNight)
        );
        assert_eq!(
            parse_failure("chain_state_unavailable"),
            Ok(DidDeploymentFailure::ChainStateUnavailable)
        );
        assert_eq!(
            parse_failure("unsupported_network"),
            Ok(DidDeploymentFailure::UnsupportedNetwork)
        );
        assert_eq!(
            parse_failure("invalid_funding_plan"),
            Ok(DidDeploymentFailure::InvalidFundingPlan)
        );
    }
    use oxid_foundation::UnixTimestampMillis;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Store {
        root: PathBuf,
        repository: JsonDidDeploymentOperationRepository,
    }

    impl Store {
        fn new() -> Self {
            let root = env::temp_dir().join(format!(
                "oxid-did-deployment-store-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            Self {
                repository: JsonDidDeploymentOperationRepository::new(
                    root.join("private").join("did-deployments.json"),
                ),
                root,
            }
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn operation(id: &str, profile: &str) -> DidDeploymentOperation {
        DidDeploymentOperation::new(
            DidDeploymentOperationId::parse(id).expect("operation id"),
            IdentityProfileId::parse(profile).expect("profile id"),
            MidnightNetwork::Undeployed,
            0,
            UnixTimestampMillis::new(1_000),
        )
        .expect("operation")
    }

    #[test]
    fn round_trips_safe_operation_state_and_inclusion_evidence() {
        let store = Store::new();
        let did =
            MidnightDid::parse(format!("did:midnight:undeployed:{}", "a".repeat(64))).expect("did");
        let mut operation = operation("operation-1", "profile-1");
        store
            .repository
            .upsert(operation.clone())
            .expect("save initial");
        operation = operation
            .composed(did, "draft-1".to_owned(), UnixTimestampMillis::new(2_000))
            .expect("composed");
        store
            .repository
            .upsert(operation.clone())
            .expect("save composed");
        operation = operation
            .transition(DidDeploymentState::Proving, UnixTimestampMillis::new(3_000))
            .expect("proving");
        store
            .repository
            .upsert(operation.clone())
            .expect("save proving");
        operation = operation
            .transition(
                DidDeploymentState::Submitting,
                UnixTimestampMillis::new(4_000),
            )
            .expect("submitting");
        store
            .repository
            .upsert(operation.clone())
            .expect("save submitting");
        operation = operation
            .transition(
                DidDeploymentState::Confirming,
                UnixTimestampMillis::new(5_000),
            )
            .expect("confirming");
        store
            .repository
            .upsert(operation.clone())
            .expect("save confirming");
        operation = operation
            .included(
                "1".repeat(64),
                "2".repeat(64),
                17,
                UnixTimestampMillis::new(6_000),
            )
            .expect("included");
        store
            .repository
            .upsert(operation.clone())
            .expect("save finalized");

        assert_eq!(
            store
                .repository
                .get(operation.operation_id())
                .expect("load"),
            operation
        );
        assert_eq!(
            store
                .repository
                .active(operation.profile_id(), MidnightNetwork::Undeployed)
                .expect("active"),
            Some(operation.clone())
        );
        assert_eq!(
            store
                .repository
                .latest(operation.profile_id(), MidnightNetwork::Undeployed)
                .expect("latest"),
            Some(operation)
        );
    }

    #[test]
    fn worker_permit_fences_independent_repository_instances() {
        let store = Store::new();
        let second = JsonDidDeploymentOperationRepository::new(store.repository.configured_path());
        let permit = store.repository.try_acquire_worker().expect("first permit");
        assert!(matches!(
            second.try_acquire_worker(),
            Err(DidDeploymentOperationError::Conflict)
        ));
        drop(permit);
        assert!(second.try_acquire_worker().is_ok());
    }

    #[test]
    fn legacy_receipt_survives_with_a_required_observation_before_protected_work() {
        let store = Store::new();
        let operation = operation("legacy-operation", "profile-1")
            .composed(
                MidnightDid::parse(format!("did:midnight:undeployed:{}", "a".repeat(64))).unwrap(),
                "legacy-deploy".to_owned(),
                UnixTimestampMillis::new(2_000),
            )
            .unwrap()
            .transition(DidDeploymentState::Proving, UnixTimestampMillis::new(3_000))
            .unwrap()
            .transition(
                DidDeploymentState::Submitting,
                UnixTimestampMillis::new(4_000),
            )
            .unwrap()
            .transition(
                DidDeploymentState::Confirming,
                UnixTimestampMillis::new(5_000),
            )
            .unwrap()
            .included(
                "1".repeat(64),
                "2".repeat(64),
                17,
                UnixTimestampMillis::new(6_000),
            )
            .unwrap();
        let mut legacy = serde_json::to_value(StoredOperation::from(&operation)).unwrap();
        legacy["state"] = serde_json::json!("composing");
        legacy["effect"] = serde_json::json!("install_verification_method_verifier");
        for field in [
            "observations",
            "legacyObservationsPending",
            "revision",
            "attempt",
            "attemptStartedAtMillis",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        store_atomic::write_owner_private(
            store.repository.configured_path(),
            &serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"operations":[legacy]}))
                .unwrap(),
        )
        .unwrap();
        let restored = store
            .repository
            .get(operation.operation_id())
            .expect("legacy journal");
        assert!(restored.legacy_observations_pending());
        assert_eq!(restored.receipts(), operation.receipts());
        let observed = restored
            .observed(
                "3".repeat(64),
                "2".repeat(64),
                17,
                UnixTimestampMillis::new(7_000),
            )
            .unwrap();
        assert!(!observed.legacy_observations_pending());
        assert_eq!(
            observed.effect(),
            DidDeploymentEffect::InstallVerificationMethodVerifier
        );
        store
            .repository
            .upsert(observed)
            .expect("migrated checkpoint");
    }

    #[test]
    fn rejects_stale_revision_writes() {
        let store = Store::new();
        let operation = operation("operation-1", "profile-1");
        store
            .repository
            .upsert(operation.clone())
            .expect("initial save");
        assert_eq!(
            store.repository.upsert(operation),
            Err(DidDeploymentOperationError::Conflict),
            "a duplicate/stale worker cannot overwrite the same revision"
        );
    }

    #[test]
    fn rejects_a_second_active_operation_for_the_same_realm() {
        let store = Store::new();
        store
            .repository
            .upsert(operation("operation-1", "profile-1"))
            .expect("first");
        assert_eq!(
            store
                .repository
                .upsert(operation("operation-2", "profile-1")),
            Err(DidDeploymentOperationError::Conflict)
        );
    }

    #[test]
    fn tampered_state_fails_closed() {
        let store = Store::new();
        store
            .repository
            .upsert(operation("operation-1", "profile-1"))
            .expect("save");
        let path = store.repository.configured_path();
        let bytes = fs::read(path).expect("read");
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        json["operations"][0]["state"] = serde_json::Value::String("ready".to_owned());
        fs::write(path, serde_json::to_vec(&json).expect("encode")).expect("tamper");

        assert_eq!(
            store
                .repository
                .get(&DidDeploymentOperationId::parse("operation-1").expect("id")),
            Err(DidDeploymentOperationError::Integrity)
        );
    }
}
