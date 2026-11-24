// SPDX-License-Identifier: Apache-2.0

//! Native Rust composition for the four holder-DID bootstrap writes.
//!
//! The generated Compact runtime executes in-process. Controller and recovery
//! seeds are borrowed only by the custody signer; they never cross a DTO,
//! filesystem, environment, WebView, or child-process boundary.

use std::{future::Future, io::Cursor, pin::Pin, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use midnight_base_crypto::{hash::HashOutput, time::Timestamp};
use midnight_compact_runtime as runtime;
use midnight_did_jubjub_schnorr::{
    derive_public_key_from_seed, field_from_scalar, sign_authorization_digest_from_seed,
};
use midnight_did_runtime::{ledger_contract, pure_circuits, types};
use midnight_ledger::{
    construct::{PreTranscript, partition_transcripts},
    structure::{
        Intent, LedgerParameters, ProofPreimageMarker, Signature, StandardTransaction, Transaction,
    },
};
use midnight_serialize::{Deserializable as _, tagged_deserialize, tagged_serialize};
use midnight_storage::{DefaultDB, storage::HashMap as LedgerHashMap};
use midnight_transient_crypto::{
    commitment::PedersenRandomness, curve::EmbeddedGroupAffine, proofs::ProofPreimage,
};
use oxid_identity_application::DidLifecyclePortError;
use oxid_wallet_application::{
    GenerateProtectedKeyRequest, WalletDerivedSecretUsePort, WalletHdPath, WalletHdPathComponent,
    WalletKeyOperationPort, WalletSecurityPortError,
};
use oxid_wallet_domain::{
    PublicKeyEncoding, WalletKeyAlgorithm, WalletKeyDescriptor, WalletKeyLabel, WalletKeyPurpose,
    WalletProfileId,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    compact_artifacts::{
        MidnightDidBootstrapCircuit, MidnightDidCompactArtifacts, decode_verifier_key,
    },
    custody::{controller_path, recovery_path, replay_randomness_path},
    protected_randomness::{ProtectedDeterministicRng, derive_seed},
};

const MAX_CONTRACT_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ZSWAP_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_LEDGER_PARAMETERS_BYTES: usize = 512 * 1024;
const MAX_TRANSACTION_BYTES: usize = 32 * 1024 * 1024;
const CALL_COMMUNICATION_DOMAIN: &[u8] = b"oxid:did-call:communication-rng:v1";
const CALL_INTENT_DOMAIN: &[u8] = b"oxid:did-call:intent-rng:v1";

type UnprovenTransaction =
    Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MidnightDidCallContext {
    pub contract_state: Vec<u8>,
    pub contract_address: [u8; 32],
    pub observation_transaction_hash: [u8; 32],
    pub observation_block_hash: [u8; 32],
    pub observation_block_height: u64,
    pub zswap_chain_state: Option<Vec<u8>>,
    pub ledger_parameters: Option<Vec<u8>>,
    pub network_id: String,
    pub timestamp_millis: u64,
    pub expires_at_millis: u64,
    pub coin_public_key: [u8; 32],
    pub encryption_public_key: [u8; 32],
}

impl MidnightDidCallContext {
    fn validate(&self) -> Result<(), DidLifecyclePortError> {
        if self.contract_state.is_empty()
            || self.contract_state.len() > MAX_CONTRACT_STATE_BYTES
            || self.contract_address == [0; 32]
            || self.observation_transaction_hash == [0; 32]
            || self.observation_block_hash == [0; 32]
            || self.observation_block_height == 0
            || self.network_id.is_empty()
            || self.network_id.len() > 64
            || !self
                .network_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || self.timestamp_millis == 0
            || self.expires_at_millis <= self.timestamp_millis
            || self.expires_at_millis / 1_000 <= self.timestamp_millis / 1_000
            || self.coin_public_key == [0; 32]
            || self.encryption_public_key == [0; 32]
            || self
                .zswap_chain_state
                .as_ref()
                .is_some_and(|state| state.is_empty() || state.len() > MAX_ZSWAP_STATE_BYTES)
            || self.ledger_parameters.as_ref().is_none_or(|parameters| {
                parameters.is_empty() || parameters.len() > MAX_LEDGER_PARAMETERS_BYTES
            })
        {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        Ok(())
    }

    fn decode_ledger_parameters(&self) -> Result<LedgerParameters, DidLifecyclePortError> {
        let bytes = self
            .ledger_parameters
            .as_deref()
            .ok_or(DidLifecyclePortError::InvalidOperation)?;
        let mut cursor = Cursor::new(bytes);
        let parameters =
            tagged_deserialize(&mut cursor).map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        if usize::try_from(cursor.position()).ok() != Some(bytes.len()) {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        Ok(parameters)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MidnightDidCallOperation {
    Deactivate,
    AddAuthenticationMethod {
        method_id: String,
        x: [u8; 32],
    },
    AddAuthenticationRelationship {
        method_id: String,
    },
    AddAssertionMethod {
        method_id: String,
        x: [u8; 32],
        y: [u8; 32],
    },
    AddAssertionRelationship {
        method_id: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightDidBootstrapCall {
    AddAuthenticationMethod,
    AddAuthenticationRelationship,
    AddAssertionMethod,
    AddAssertionRelationship,
}

impl MidnightDidCallOperation {
    fn circuit(&self) -> MidnightDidBootstrapCircuit {
        match self {
            Self::Deactivate => MidnightDidBootstrapCircuit::Deactivation,
            Self::AddAuthenticationMethod { .. } => MidnightDidBootstrapCircuit::VerificationMethod,
            Self::AddAssertionMethod { .. } => {
                MidnightDidBootstrapCircuit::SchnorrJubjubVerificationMethod
            }
            Self::AddAuthenticationRelationship { .. } | Self::AddAssertionRelationship { .. } => {
                MidnightDidBootstrapCircuit::VerificationMethodRelation
            }
        }
    }

    fn validate(&self) -> Result<(), DidLifecyclePortError> {
        let method_id = match self {
            Self::Deactivate => return Ok(()),
            Self::AddAuthenticationMethod { method_id, x } => {
                if *x == [0; 32] {
                    return Err(DidLifecyclePortError::InvalidOperation);
                }
                method_id
            }
            Self::AddAuthenticationRelationship { method_id }
            | Self::AddAssertionRelationship { method_id } => method_id,
            Self::AddAssertionMethod { method_id, x, y } => {
                if *x == [0; 32] || *y == [0; 32] {
                    return Err(DidLifecyclePortError::InvalidOperation);
                }
                method_id
            }
        };
        if !method_id.starts_with('#')
            || method_id.len() < 2
            || method_id.len() > 65
            || !method_id[1..].bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
            })
        {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        Ok(())
    }

    fn into_runtime(self) -> Result<RuntimeDidOperation, DidLifecyclePortError> {
        Ok(match self {
            Self::Deactivate => RuntimeDidOperation::Deactivate,
            Self::AddAuthenticationMethod { method_id, x } => {
                RuntimeDidOperation::SetVerificationMethod {
                    method: types::VerificationMethod {
                        id: runtime::OpaqueString::from(method_id),
                        typ: types::VerificationMethodType::JsonWebKey,
                        publicKeyJwk: types::PublicKeyJwk {
                            kty: types::KeyType::OKP,
                            crv: types::CurveType::Ed25519,
                            x: runtime::OpaqueString::from(URL_SAFE_NO_PAD.encode(x)),
                            y: runtime::OpaqueString::from(""),
                        },
                    },
                    mutation: types::MapMutation::Insert,
                }
            }
            Self::AddAuthenticationRelationship { method_id } => {
                RuntimeDidOperation::SetVerificationMethodRelation {
                    relation: types::VerificationMethodRelation::Authentication,
                    method_id: runtime::OpaqueString::from(method_id),
                    mutation: types::SetMutation::Insert,
                }
            }
            Self::AddAssertionMethod { method_id, x, y } => {
                RuntimeDidOperation::SetSchnorrJubjubVerificationMethod {
                    method: types::SchnorrJubjubVerificationMethod {
                        id: runtime::OpaqueString::from(method_id),
                        publicKey: jubjub_point(x, y)?,
                    },
                    mutation: types::MapMutation::Insert,
                }
            }
            Self::AddAssertionRelationship { method_id } => {
                RuntimeDidOperation::SetVerificationMethodRelation {
                    relation: types::VerificationMethodRelation::AssertionMethod,
                    method_id: runtime::OpaqueString::from(method_id),
                    mutation: types::SetMutation::Insert,
                }
            }
        })
    }
}

enum RuntimeDidOperation {
    Deactivate,
    SetVerificationMethod {
        method: types::VerificationMethod,
        mutation: types::MapMutation,
    },
    SetSchnorrJubjubVerificationMethod {
        method: types::SchnorrJubjubVerificationMethod,
        mutation: types::MapMutation,
    },
    SetVerificationMethodRelation {
        relation: types::VerificationMethodRelation,
        method_id: runtime::OpaqueString,
        mutation: types::SetMutation,
    },
}

pub struct NativeMidnightDidCallRequest {
    pub profile_id: WalletProfileId,
    pub account_index: u32,
    pub controller_index: u32,
    pub context: MidnightDidCallContext,
    pub operation: MidnightDidCallOperation,
    pub replay_recipe: [u8; 32],
}

pub struct NativeMidnightDidCallPlan {
    pub planning_fingerprint: [u8; 32],
    pub transaction: Zeroizing<Vec<u8>>,
}

pub type MidnightDidCallCompositionFuture<'a> = Pin<
    Box<dyn Future<Output = Result<NativeMidnightDidCallPlan, DidLifecyclePortError>> + Send + 'a>,
>;

pub trait MidnightDidCallCompositionPort: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn compose_bootstrap_call<'a>(
        &'a self,
        profile_id: WalletProfileId,
        account_index: u32,
        controller_index: u32,
        operation_scope: String,
        context: MidnightDidCallContext,
        call: MidnightDidBootstrapCall,
    ) -> MidnightDidCallCompositionFuture<'a>;
}

pub struct NativeMidnightDidCallComposer {
    custody: Arc<dyn WalletDerivedSecretUsePort>,
    keys: Arc<dyn WalletKeyOperationPort>,
    artifacts: MidnightDidCompactArtifacts,
}

impl NativeMidnightDidCallComposer {
    #[must_use]
    pub fn new(
        custody: Arc<dyn WalletDerivedSecretUsePort>,
        keys: Arc<dyn WalletKeyOperationPort>,
        artifacts: MidnightDidCompactArtifacts,
    ) -> Self {
        Self {
            custody,
            keys,
            artifacts,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compose_bootstrap(
        &self,
        profile_id: WalletProfileId,
        account_index: u32,
        controller_index: u32,
        operation_scope: &str,
        context: MidnightDidCallContext,
        call: MidnightDidBootstrapCall,
    ) -> Result<NativeMidnightDidCallPlan, DidLifecyclePortError> {
        if operation_scope.is_empty() || operation_scope.len() > 256 {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        let authentication = matches!(
            call,
            MidnightDidBootstrapCall::AddAuthenticationMethod
                | MidnightDidBootstrapCall::AddAuthenticationRelationship
        )
        .then(|| {
            self.bootstrap_key(
                &profile_id,
                operation_scope,
                "authentication",
                WalletKeyAlgorithm::Ed25519,
                WalletKeyPurpose::Authentication,
                PublicKeyEncoding::Ed25519Compressed,
            )
        })
        .transpose()?;
        let assertion = matches!(
            call,
            MidnightDidBootstrapCall::AddAssertionMethod
                | MidnightDidBootstrapCall::AddAssertionRelationship
        )
        .then(|| {
            self.bootstrap_key(
                &profile_id,
                operation_scope,
                "holder binding",
                WalletKeyAlgorithm::Jubjub,
                WalletKeyPurpose::Assertion,
                PublicKeyEncoding::JubjubCompressed,
            )
        })
        .transpose()?;
        let operation = match call {
            MidnightDidBootstrapCall::AddAuthenticationMethod => {
                MidnightDidCallOperation::AddAuthenticationMethod {
                    method_id: "#key-auth".to_owned(),
                    x: authentication
                        .ok_or(DidLifecyclePortError::InvalidOperation)?
                        .public_key()
                        .bytes()
                        .try_into()
                        .map_err(|_| DidLifecyclePortError::InvalidOperation)?,
                }
            }
            MidnightDidBootstrapCall::AddAuthenticationRelationship => {
                MidnightDidCallOperation::AddAuthenticationRelationship {
                    method_id: "#key-auth".to_owned(),
                }
            }
            MidnightDidBootstrapCall::AddAssertionMethod => {
                let (x, y) =
                    jubjub_coordinates(&assertion.ok_or(DidLifecyclePortError::InvalidOperation)?)?;
                MidnightDidCallOperation::AddAssertionMethod {
                    method_id: "#key-assert".to_owned(),
                    x,
                    y,
                }
            }
            MidnightDidBootstrapCall::AddAssertionRelationship => {
                MidnightDidCallOperation::AddAssertionRelationship {
                    method_id: "#key-assert".to_owned(),
                }
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(b"oxid:did-call:replay:v1");
        hasher.update(operation_scope.as_bytes());
        hasher.update(operation.circuit().artifact_id().as_bytes());
        self.compose(&NativeMidnightDidCallRequest {
            profile_id,
            account_index,
            controller_index,
            context,
            operation,
            replay_recipe: hasher.finalize().into(),
        })
    }

    fn bootstrap_key(
        &self,
        profile_id: &WalletProfileId,
        operation_scope: &str,
        role: &str,
        algorithm: WalletKeyAlgorithm,
        purpose: WalletKeyPurpose,
        encoding: PublicKeyEncoding,
    ) -> Result<WalletKeyDescriptor, DidLifecyclePortError> {
        let digest = Sha256::digest(operation_scope.as_bytes());
        let label = WalletKeyLabel::parse(format!(
            "Midnight DID {role} {}",
            &hex::encode(digest)[..16]
        ))
        .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        let matches = self
            .keys
            .list(profile_id)
            .map_err(map_security_error)?
            .into_iter()
            .filter(|descriptor| descriptor.label() == &label)
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(DidLifecyclePortError::Conflict);
        }
        let descriptor = if let Some(descriptor) = matches.into_iter().next() {
            descriptor
        } else {
            self.keys
                .generate(
                    profile_id,
                    GenerateProtectedKeyRequest {
                        label,
                        algorithm,
                        purpose,
                    },
                )
                .map_err(map_security_error)?
        };
        if descriptor.algorithm() != algorithm
            || descriptor.purpose() != purpose
            || descriptor.public_key().encoding() != encoding
            || descriptor.public_key().bytes().len() != 32
        {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        Ok(descriptor)
    }

    pub fn compose(
        &self,
        request: &NativeMidnightDidCallRequest,
    ) -> Result<NativeMidnightDidCallPlan, DidLifecyclePortError> {
        request.context.validate()?;
        let ledger_parameters = request.context.decode_ledger_parameters()?;
        request.operation.validate()?;
        if request.account_index > WalletHdPathComponent::MAX_INDEX
            || request.controller_index > WalletHdPathComponent::MAX_INDEX
        {
            return Err(DidLifecyclePortError::InvalidOperation);
        }

        let controller = controller_path(request.account_index, request.controller_index)?;
        let recovery = recovery_path(request.account_index)?;
        let replay = replay_randomness_path(request.account_index)?;
        let private_state = NativeDidPrivateState {
            controller_public_key: self.public_key(&request.profile_id, &controller)?,
            recovery_public_key: self.public_key(&request.profile_id, &recovery)?,
            timestamp_millis: request.context.timestamp_millis,
        };
        let signer = CustodyAuthorizationSigner {
            custody: Arc::clone(&self.custody),
            profile_id: request.profile_id.clone(),
            controller_path: controller,
        };
        let observed = runtime::transaction::ObservedContractState::decode_with_limit(
            runtime::ledger::ContractAddress(HashOutput(request.context.contract_address)),
            &request.context.contract_state,
            runtime::transaction::Observation {
                transaction_hash: request.context.observation_transaction_hash,
                block_hash: request.context.observation_block_hash,
                block_height: request.context.observation_block_height,
            },
            runtime::transaction::EncodedSizeLimit::new(MAX_CONTRACT_STATE_BYTES),
        )
        .map_err(|_| DidLifecyclePortError::InvalidOperation)?
        .with_coin_public_key(runtime::context::CoinPublicKey(HashOutput(
            request.context.coin_public_key,
        )));
        let view = ledger_contract::PublicStateView::from(&observed);
        let id = view
            .id()
            .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        let version = view
            .version()
            .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        let circuit = request.operation.circuit();
        let operation = request.operation.clone().into_runtime()?;
        let contract = ledger_contract::Contract::from(NativeDidWitnesses);
        let recorded = match operation {
            RuntimeDidOperation::Deactivate => {
                let digest = pure_circuits::deactivateAuthorizationDigest(id, version)
                    .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
                let signature = signer.sign(&signer.controller_path, digest.0)?;
                contract
                    .recording()
                    .deactivate_call(&observed, private_state, signature, version)
            }
            RuntimeDidOperation::SetVerificationMethod { method, mutation } => {
                let digest = pure_circuits::setVerificationMethodAuthorizationDigest(
                    id.clone(),
                    version,
                    method.clone(),
                    mutation,
                )
                .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
                let signature = signer.sign(&signer.controller_path, digest.0)?;
                contract.recording().setVerificationMethod_call(
                    &observed,
                    private_state,
                    method,
                    mutation,
                    signature,
                    version,
                )
            }
            RuntimeDidOperation::SetSchnorrJubjubVerificationMethod { method, mutation } => {
                let digest = pure_circuits::setSchnorrJubjubVerificationMethodAuthorizationDigest(
                    id.clone(),
                    version,
                    method.clone(),
                    mutation,
                )
                .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
                let signature = signer.sign(&signer.controller_path, digest.0)?;
                contract
                    .recording()
                    .setSchnorrJubjubVerificationMethod_call(
                        &observed,
                        private_state,
                        method,
                        mutation,
                        signature,
                        version,
                    )
            }
            RuntimeDidOperation::SetVerificationMethodRelation {
                relation,
                method_id,
                mutation,
            } => {
                let digest = pure_circuits::setVerificationMethodRelationAuthorizationDigest(
                    id,
                    version,
                    relation,
                    method_id.clone(),
                    mutation,
                )
                .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
                let signature = signer.sign(&signer.controller_path, digest.0)?;
                contract.recording().setVerificationMethodRelation_call(
                    &observed,
                    private_state,
                    relation,
                    method_id,
                    mutation,
                    signature,
                    version,
                )
            }
        }
        .map_err(|_| DidLifecyclePortError::InvalidOperation)?;

        let verifier = self
            .artifacts
            .verifier_key(circuit)
            .map_err(|_| DidLifecyclePortError::ProtectionUnavailable)?;
        let verifier_key = decode_verifier_key(verifier.as_slice())
            .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        let mut seeds = None;
        self.custody
            .use_derived_secret(&request.profile_id, &replay, &mut |secret| {
                seeds = Some((
                    derive_seed(secret, CALL_COMMUNICATION_DOMAIN, &request.replay_recipe)?,
                    derive_seed(secret, CALL_INTENT_DOMAIN, &request.replay_recipe)?,
                ));
                Ok(())
            })
            .map_err(map_security_error)?;
        let (communication_seed, intent_seed) =
            seeds.ok_or(DidLifecyclePortError::ProtectionUnavailable)?;
        let mut communication_bytes = *communication_seed;
        communication_bytes[31] = 0;
        let communication_commitment_rand = runtime::Field::from_le_bytes(&communication_bytes)
            .ok_or(DidLifecyclePortError::InvalidOperation)?;
        communication_bytes.zeroize();
        let public = &recorded.recorded().public;
        let transcript = PreTranscript {
            context: public.initial().clone(),
            program: public.verify_ops().to_vec(),
            comm_comm: None,
        };
        let mut call = recorded
            .prepare(verifier_key, communication_commitment_rand)
            .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        // Compact's checked preparation currently partitions with genesis
        // parameters. Keep its verifier and trace validation, then size the
        // guaranteed/fallible transcripts for the observed finalized ledger
        // before add_call binds them into the proof preimage.
        let mut partitions = partition_transcripts(&[transcript], &ledger_parameters)
            .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        let (guaranteed, fallible) = partitions
            .pop()
            .ok_or(DidLifecyclePortError::InvalidOperation)?;
        let no_effects = Default::default();
        let unchanged = |before: Option<&_>, after: Option<&_>| {
            before.unwrap_or(&no_effects) == after.unwrap_or(&no_effects)
        };
        if (guaranteed.is_none() && fallible.is_none())
            || !unchanged(
                call.guaranteed_public_transcript
                    .as_ref()
                    .map(|trace| &trace.effects),
                guaranteed.as_ref().map(|trace| &trace.effects),
            )
            || !unchanged(
                call.fallible_public_transcript
                    .as_ref()
                    .map(|trace| &trace.effects),
                fallible.as_ref().map(|trace| &trace.effects),
            )
        {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        call.guaranteed_public_transcript = guaranteed;
        call.fallible_public_transcript = fallible;
        let mut intent_rng = ProtectedDeterministicRng::new(intent_seed);
        let intent: Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> =
            Intent::empty(
                &mut intent_rng,
                Timestamp::from_secs(request.context.expires_at_millis / 1_000),
            )
            .add_call::<ProofPreimage>(call);
        let transaction = Transaction::Standard(StandardTransaction::new(
            &request.context.network_id,
            LedgerHashMap::from_iter([(1_u16, intent)]),
            None,
            LedgerHashMap::new(),
        ));
        let mut encoded = Zeroizing::new(Vec::new());
        tagged_serialize(&transaction, &mut *encoded)
            .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
        if encoded.is_empty() || encoded.len() > MAX_TRANSACTION_BYTES {
            return Err(DidLifecyclePortError::InvalidOperation);
        }
        validate_transaction(&encoded, &request.context.network_id)?;
        Ok(NativeMidnightDidCallPlan {
            planning_fingerprint: Sha256::digest(encoded.as_slice()).into(),
            transaction: encoded,
        })
    }

    fn public_key(
        &self,
        profile_id: &WalletProfileId,
        path: &WalletHdPath,
    ) -> Result<EmbeddedGroupAffine, DidLifecyclePortError> {
        let mut public_key = None;
        self.custody
            .use_derived_secret(profile_id, path, &mut |secret| {
                public_key = Some(derive_public_key_from_seed(secret));
                Ok(())
            })
            .map_err(map_security_error)?;
        public_key.ok_or(DidLifecyclePortError::ProtectionUnavailable)
    }
}

impl MidnightDidCallCompositionPort for NativeMidnightDidCallComposer {
    fn compose_bootstrap_call<'a>(
        &'a self,
        profile_id: WalletProfileId,
        account_index: u32,
        controller_index: u32,
        operation_scope: String,
        context: MidnightDidCallContext,
        call: MidnightDidBootstrapCall,
    ) -> MidnightDidCallCompositionFuture<'a> {
        Box::pin(async move {
            self.compose_bootstrap(
                profile_id,
                account_index,
                controller_index,
                &operation_scope,
                context,
                call,
            )
        })
    }
}

#[derive(Clone)]
struct NativeDidPrivateState {
    controller_public_key: EmbeddedGroupAffine,
    recovery_public_key: EmbeddedGroupAffine,
    timestamp_millis: u64,
}

#[derive(Clone, Copy)]
struct NativeDidWitnesses;

impl ledger_contract::Witnesses<NativeDidPrivateState> for NativeDidWitnesses {
    fn getSchnorrReduction(
        &self,
        context: runtime::context::WitnessContext<
            '_,
            NativeDidPrivateState,
            ledger_contract::LedgerView<'_>,
        >,
        challenge_hash: runtime::Field,
    ) -> (
        NativeDidPrivateState,
        (
            runtime::BoundedUint<127>,
            runtime::WideUint<
                1329227995784915872903807060280344575u128,
                340282366920938463463374607431768211455u128,
            >,
        ),
    ) {
        let mut bytes = challenge_hash.as_le_bytes();
        bytes.resize(32, 0);
        let quotient = runtime::BoundedUint::new(bytes[31] as u128)
            .expect("field quotient fits the generated bound");
        bytes[31] = 0;
        let remainder = runtime::WideUint::from_le_bytes(&bytes)
            .expect("field remainder fits the generated bound");
        (context.private_state.clone(), (quotient, remainder))
    }
    fn localControllerPublicKey(
        &self,
        context: runtime::context::WitnessContext<
            '_,
            NativeDidPrivateState,
            ledger_contract::LedgerView<'_>,
        >,
    ) -> (NativeDidPrivateState, runtime::JubjubPoint) {
        (
            context.private_state.clone(),
            context.private_state.controller_public_key.into(),
        )
    }
    fn localRecoveryAuthorityPublicKey(
        &self,
        context: runtime::context::WitnessContext<
            '_,
            NativeDidPrivateState,
            ledger_contract::LedgerView<'_>,
        >,
    ) -> (NativeDidPrivateState, runtime::JubjubPoint) {
        (
            context.private_state.clone(),
            context.private_state.recovery_public_key.into(),
        )
    }
    fn currentTimestamp(
        &self,
        context: runtime::context::WitnessContext<
            '_,
            NativeDidPrivateState,
            ledger_contract::LedgerView<'_>,
        >,
    ) -> (
        NativeDidPrivateState,
        runtime::BoundedUint<18446744073709551615>,
    ) {
        (
            context.private_state.clone(),
            runtime::BoundedUint::new(context.private_state.timestamp_millis as u128)
                .expect("u64 timestamp fits the generated bound"),
        )
    }
}

struct CustodyAuthorizationSigner {
    custody: Arc<dyn WalletDerivedSecretUsePort>,
    profile_id: WalletProfileId,
    controller_path: WalletHdPath,
}
impl CustodyAuthorizationSigner {
    fn sign(
        &self,
        path: &WalletHdPath,
        digest: [runtime::Field; 4],
    ) -> Result<types::SchnorrSignature, DidLifecyclePortError> {
        let mut signature = None;
        self.custody
            .use_derived_secret(&self.profile_id, path, &mut |secret| {
                let signed = sign_authorization_digest_from_seed(secret, &digest)
                    .map_err(|_| WalletSecurityPortError::InvalidOperation)?;
                signature = Some(types::SchnorrSignature {
                    announcement: signed.announcement.into(),
                    response: field_from_scalar(&signed.response),
                });
                Ok(())
            })
            .map_err(map_security_error)?;
        signature.ok_or(DidLifecyclePortError::ProtectionUnavailable)
    }
}

fn jubjub_point(x: [u8; 32], y: [u8; 32]) -> Result<runtime::JubjubPoint, DidLifecyclePortError> {
    let x = runtime::Field::from_le_bytes(&x).ok_or(DidLifecyclePortError::InvalidOperation)?;
    let y = runtime::Field::from_le_bytes(&y).ok_or(DidLifecyclePortError::InvalidOperation)?;
    let point = EmbeddedGroupAffine::new(x, y).ok_or(DidLifecyclePortError::InvalidOperation)?;
    if point.is_identity() {
        return Err(DidLifecyclePortError::InvalidOperation);
    }
    Ok(point.into())
}

fn jubjub_coordinates(
    descriptor: &WalletKeyDescriptor,
) -> Result<([u8; 32], [u8; 32]), DidLifecyclePortError> {
    let mut encoded = descriptor.public_key().bytes();
    let point = EmbeddedGroupAffine::deserialize(&mut encoded, 0)
        .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
    if !encoded.is_empty() || point.is_identity() {
        return Err(DidLifecyclePortError::InvalidOperation);
    }
    let x = point
        .x()
        .ok_or(DidLifecyclePortError::InvalidOperation)?
        .as_le_bytes()
        .try_into()
        .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
    let y = point
        .y()
        .ok_or(DidLifecyclePortError::InvalidOperation)?
        .as_le_bytes()
        .try_into()
        .map_err(|_| DidLifecyclePortError::InvalidOperation)?;
    Ok((x, y))
}

fn validate_transaction(bytes: &[u8], network_id: &str) -> Result<(), DidLifecyclePortError> {
    let mut cursor = Cursor::new(bytes);
    let transaction: UnprovenTransaction =
        tagged_deserialize(&mut cursor).map_err(|_| DidLifecyclePortError::InvalidOperation)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(DidLifecyclePortError::InvalidOperation);
    }
    let Transaction::Standard(standard) = transaction else {
        return Err(DidLifecyclePortError::InvalidOperation);
    };
    if standard.network_id != network_id || standard.intents.iter().count() != 1 {
        return Err(DidLifecyclePortError::InvalidOperation);
    }
    Ok(())
}

const fn map_security_error(error: WalletSecurityPortError) -> DidLifecyclePortError {
    match error {
        WalletSecurityPortError::Locked => DidLifecyclePortError::Locked,
        WalletSecurityPortError::UnsupportedAlgorithm => {
            DidLifecyclePortError::UnsupportedAlgorithm
        }
        WalletSecurityPortError::NotFound => DidLifecyclePortError::NotFound,
        WalletSecurityPortError::Conflict => DidLifecyclePortError::Conflict,
        WalletSecurityPortError::Unavailable | WalletSecurityPortError::NotInitialized => {
            DidLifecyclePortError::ProtectionUnavailable
        }
        WalletSecurityPortError::AlreadyInitialized
        | WalletSecurityPortError::AuthorizationDenied
        | WalletSecurityPortError::InvalidOperation => DidLifecyclePortError::InvalidOperation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::cost_model::CostDuration;
    use midnight_ledger::structure::{ContractAction, INITIAL_PARAMETERS};
    use midnight_onchain_state::state::{
        ContractMaintenanceAuthority, ContractOperation, ContractState, EntryPointBuf,
    };
    use oxid_adapter_platform_system::{OsRandom, SystemClock};
    use oxid_adapter_storage_dev::DevelopmentWalletSecurity;
    use oxid_wallet_application::WalletProtectionPort;

    #[test]
    fn rejects_expired_or_incomplete_chain_contexts() {
        let context = MidnightDidCallContext {
            contract_state: vec![1],
            contract_address: [2; 32],
            observation_transaction_hash: [7; 32],
            observation_block_hash: [8; 32],
            observation_block_height: 1,
            zswap_chain_state: None,
            ledger_parameters: None,
            network_id: "undeployed".to_owned(),
            timestamp_millis: 2_000,
            expires_at_millis: 1_000,
            coin_public_key: [3; 32],
            encryption_public_key: [4; 32],
        };
        assert_eq!(
            context.validate(),
            Err(DidLifecyclePortError::InvalidOperation)
        );
    }
    #[test]
    fn rejects_wrong_network_and_key_contexts() {
        let mut parameter_bytes = Vec::new();
        tagged_serialize(&INITIAL_PARAMETERS, &mut parameter_bytes).unwrap();
        let valid = MidnightDidCallContext {
            contract_state: vec![1],
            contract_address: [2; 32],
            observation_transaction_hash: [7; 32],
            observation_block_hash: [8; 32],
            observation_block_height: 1,
            zswap_chain_state: None,
            ledger_parameters: Some(parameter_bytes.clone()),
            network_id: "undeployed".to_owned(),
            timestamp_millis: 1_000,
            expires_at_millis: 2_000,
            coin_public_key: [3; 32],
            encryption_public_key: [4; 32],
        };
        assert_eq!(valid.validate(), Ok(()));
        assert_eq!(valid.decode_ledger_parameters(), Ok(INITIAL_PARAMETERS));
        for bytes in [
            vec![1],
            parameter_bytes[..parameter_bytes.len() - 1].to_vec(),
            [parameter_bytes, vec![0]].concat(),
        ] {
            let context = MidnightDidCallContext {
                ledger_parameters: Some(bytes),
                ..valid.clone()
            };
            assert_eq!(
                context.decode_ledger_parameters(),
                Err(DidLifecyclePortError::InvalidOperation),
            );
        }

        for context in [
            MidnightDidCallContext {
                network_id: "Undeployed".to_owned(),
                ..valid.clone()
            },
            MidnightDidCallContext {
                coin_public_key: [0; 32],
                ..valid.clone()
            },
            MidnightDidCallContext {
                expires_at_millis: 1_999,
                ..valid
            },
        ] {
            assert_eq!(
                context.validate(),
                Err(DidLifecyclePortError::InvalidOperation)
            );
        }
    }

    #[test]
    fn validates_bootstrap_operations_and_rejects_invalid_curve_points() {
        let operations = [
            MidnightDidCallOperation::AddAuthenticationMethod {
                method_id: "#key-auth".to_owned(),
                x: [7; 32],
            },
            MidnightDidCallOperation::AddAuthenticationRelationship {
                method_id: "#key-auth".to_owned(),
            },
            MidnightDidCallOperation::AddAssertionMethod {
                method_id: "#key-assertion".to_owned(),
                x: [8; 32],
                y: [9; 32],
            },
            MidnightDidCallOperation::AddAssertionRelationship {
                method_id: "#key-assertion".to_owned(),
            },
        ];

        for operation in &operations {
            operation.validate().expect("valid operation");
        }
        assert!(operations[0].clone().into_runtime().is_ok());
        assert!(operations[1].clone().into_runtime().is_ok());
        assert!(matches!(
            operations[2].clone().into_runtime(),
            Err(DidLifecyclePortError::InvalidOperation)
        ));
        assert!(operations[3].clone().into_runtime().is_ok());

        let point = derive_public_key_from_seed(&[11; 32]);
        let coordinate = |value: Option<runtime::Field>| {
            value
                .expect("fixture is not the identity")
                .as_le_bytes()
                .try_into()
                .expect("canonical coordinate")
        };
        let valid_assertion = MidnightDidCallOperation::AddAssertionMethod {
            method_id: "#key-assertion".to_owned(),
            x: coordinate(point.x()),
            y: coordinate(point.y()),
        };
        assert_eq!(valid_assertion.validate(), Ok(()));
        assert!(matches!(
            valid_assertion.into_runtime().expect("valid Jubjub key"),
            RuntimeDidOperation::SetSchnorrJubjubVerificationMethod {
                mutation: types::MapMutation::Insert,
                ..
            }
        ));

        assert_eq!(
            MidnightDidCallOperation::AddAuthenticationMethod {
                method_id: "not-a-fragment".to_owned(),
                x: [7; 32],
            }
            .validate(),
            Err(DidLifecyclePortError::InvalidOperation)
        );
        assert_eq!(
            MidnightDidCallOperation::AddAssertionMethod {
                method_id: "#key-assertion".to_owned(),
                x: [0; 32],
                y: [9; 32],
            }
            .validate(),
            Err(DidLifecyclePortError::InvalidOperation)
        );
    }

    #[test]
    #[ignore = "midnight-did-conformance: requires Nix-packaged DID artifacts"]
    fn composes_a_generated_bootstrap_call_without_an_external_process() {
        let Some(root) = std::env::var_os("OXID_MIDNIGHT_DID_ARTIFACTS_DIR") else {
            return;
        };
        let profile_id =
            WalletProfileId::parse("native-did-call-test".to_owned()).expect("profile id");
        let security = Arc::new(DevelopmentWalletSecurity::new(
            Arc::new(SystemClock),
            Arc::new(OsRandom),
        ));
        security
            .initialize(&profile_id)
            .expect("initialize custody");
        let custody: Arc<dyn WalletDerivedSecretUsePort> = security.clone();
        let keys: Arc<dyn WalletKeyOperationPort> = security;
        let composer = NativeMidnightDidCallComposer::new(
            Arc::clone(&custody),
            keys,
            MidnightDidCompactArtifacts::load(root).expect("authenticated artifacts"),
        );
        let controller = controller_path(0, 7).expect("controller path");
        let recovery = recovery_path(0).expect("recovery path");
        let private_state = NativeDidPrivateState {
            controller_public_key: composer
                .public_key(&profile_id, &controller)
                .expect("controller key"),
            recovery_public_key: composer
                .public_key(&profile_id, &recovery)
                .expect("recovery key"),
            timestamp_millis: 10_000,
        };
        let initial = ledger_contract::initial_state(
            runtime::context::ConstructorContext::new(private_state),
            &NativeDidWitnesses,
        )
        .expect("generated initial state");
        let operations = LedgerHashMap::from_iter(
            [
                MidnightDidBootstrapCircuit::VerificationMethod,
                MidnightDidBootstrapCircuit::SchnorrJubjubVerificationMethod,
            ]
            .into_iter()
            .map(|circuit| {
                let bytes = composer.artifacts.verifier_key(circuit).expect("verifier");
                let verifier = decode_verifier_key(bytes.as_slice()).expect("decode verifier");
                (
                    EntryPointBuf(circuit.artifact_id().as_bytes().to_vec()),
                    ContractOperation::new(Some(verifier), None),
                )
            }),
        );
        let contract = ContractState::new(
            initial.ledger_state.get_ref().clone(),
            operations,
            ContractMaintenanceAuthority::default(),
        );
        let contract_address = [2; 32];
        let mut contract_state = Vec::new();
        tagged_serialize(&contract, &mut contract_state).expect("serialize contract state");

        let compose = |parameters: &LedgerParameters, call| {
            let mut bytes = Vec::new();
            tagged_serialize(parameters, &mut bytes).expect("serialize ledger parameters");
            let plan = composer
                .compose_bootstrap(
                    profile_id.clone(),
                    0,
                    7,
                    "native-bootstrap-call",
                    MidnightDidCallContext {
                        contract_state: contract_state.clone(),
                        contract_address,
                        observation_transaction_hash: [7; 32],
                        observation_block_hash: [8; 32],
                        observation_block_height: 1,
                        zswap_chain_state: None,
                        ledger_parameters: Some(bytes),
                        network_id: "undeployed".to_owned(),
                        timestamp_millis: 11_000,
                        expires_at_millis: 3_611_000,
                        coin_public_key: [3; 32],
                        encryption_public_key: [4; 32],
                    },
                    call,
                )
                .expect("native generated call");
            let transaction: UnprovenTransaction =
                tagged_deserialize(plan.transaction.as_slice()).expect("valid unproven tx");
            let (_, ContractAction::Call(call)) =
                transaction.actions().next().expect("call action")
            else {
                panic!("expected a contract call");
            };
            call
        };
        let mut baseline = INITIAL_PARAMETERS;
        // Exercise model changes separately from the guaranteed/fallible split.
        baseline.limits.min_time_to_dismiss = CostDuration::from_picoseconds(1_000_000_000_000);
        let mut live = baseline.clone();
        live.cost_model.runtime_cost_model.push_cell +=
            CostDuration::from_picoseconds(1_000_000_000);
        let mut fallible_limits = live.clone();
        fallible_limits.limits.min_time_to_dismiss = CostDuration::ZERO;
        fallible_limits.limits.time_to_dismiss_per_byte = CostDuration::ZERO;
        let observed = runtime::transaction::ObservedContractState::new(
            runtime::ledger::ContractAddress(HashOutput(contract_address)),
            contract,
            runtime::transaction::Observation {
                transaction_hash: [7; 32],
                block_hash: [8; 32],
                block_height: 1,
            },
        );
        let query = observed.circuit_context(()).query;
        for kind in [
            MidnightDidBootstrapCall::AddAuthenticationMethod,
            MidnightDidBootstrapCall::AddAssertionMethod,
        ] {
            let genesis = compose(&baseline, kind)
                .guaranteed_transcript
                .clone()
                .expect("genesis guaranteed transcript");
            let exact = compose(&live, kind)
                .guaranteed_transcript
                .clone()
                .expect("live guaranteed transcript");
            assert_eq!(genesis.program, exact.program);
            assert_eq!(genesis.effects, exact.effects);
            assert!(
                exact.gas.compute_time > genesis.gas.compute_time,
                "{kind:?}: default gas {:?}, live gas {:?}",
                genesis.gas,
                exact.gas,
            );
            let program: Vec<_> = exact.program.iter_deref().cloned().collect();
            let model = &live.cost_model.runtime_cost_model;
            assert!(query.query(&program, Some(genesis.gas), model).is_err());
            query
                .query(&program, Some(exact.gas), model)
                .expect("live transcript fits declared gas");

            let fallible = compose(&fallible_limits, kind);
            assert!(fallible.guaranteed_transcript.is_none());
            assert!(fallible.fallible_transcript.is_some());
        }
    }

    #[test]
    #[ignore = "midnight-did-conformance: requires Nix-packaged DID artifacts"]
    fn preinstalled_verifier_deploys_and_composes_native_deactivation() {
        use crate::{
            NativeMidnightDidDeploymentComposer, NativeMidnightDidDeploymentRequest,
            compact_artifacts::NATIVE_DID_CIRCUITS,
        };
        use oxid_identity_domain::MidnightNetwork;

        let root = std::env::var_os("OXID_MIDNIGHT_DID_ARTIFACTS_DIR").expect("DID artifacts");
        let artifacts = MidnightDidCompactArtifacts::load(root).expect("authenticated artifacts");
        let profile_id = WalletProfileId::parse("native-did-deactivation-test").unwrap();
        let security = Arc::new(DevelopmentWalletSecurity::new(
            Arc::new(SystemClock),
            Arc::new(OsRandom),
        ));
        security
            .initialize(&profile_id)
            .expect("initialize custody");
        let custody: Arc<dyn WalletDerivedSecretUsePort> = security.clone();
        let deployment = NativeMidnightDidDeploymentComposer::new_with_initial_verifiers(
            Arc::clone(&custody),
            &artifacts,
        )
        .expect("load initial verifiers");
        let request = NativeMidnightDidDeploymentRequest::new(
            profile_id.clone(),
            MidnightNetwork::Undeployed,
            "undeployed",
            0,
            7,
            10_000,
            3_610_000,
            [5; 32],
            [6; 32],
        )
        .expect("deployment request");
        let plan = deployment.compose(&request).expect("compose deploy");
        let replay = deployment.compose(&request).expect("replay deploy");
        assert_eq!(plan.did(), replay.did());
        assert_eq!(plan.planning_fingerprint(), replay.planning_fingerprint());
        let legacy = NativeMidnightDidDeploymentComposer::new(Arc::clone(&custody))
            .compose(&request)
            .expect("compose deploy for maintenance");
        assert_ne!(plan.did(), legacy.did());
        let transaction: UnprovenTransaction =
            tagged_deserialize(plan.into_transaction().as_slice()).expect("decode deploy");
        let (_, deploy) = transaction.deploys().next().expect("deploy action");
        let contract_address = deploy.address().0.0;
        let contract = deploy.initial_state;
        assert_eq!(
            contract.operations.iter().count(),
            NATIVE_DID_CIRCUITS.len()
        );
        let legacy_tx: UnprovenTransaction =
            tagged_deserialize(legacy.into_transaction().as_slice()).expect("decode legacy deploy");
        let (_, mut pilot_deploy) = legacy_tx.deploys().next().expect("legacy deploy action");
        pilot_deploy.initial_state.operations = contract.operations.clone();
        assert_eq!(pilot_deploy.address().0.0, contract_address);
        let mut contract_state = Vec::new();
        tagged_serialize(&contract, &mut contract_state).expect("serialize contract state");
        let mut ledger_parameters = Vec::new();
        tagged_serialize(&INITIAL_PARAMETERS, &mut ledger_parameters)
            .expect("serialize ledger parameters");
        let plan = NativeMidnightDidCallComposer::new(custody, security, artifacts)
            .compose(&NativeMidnightDidCallRequest {
                profile_id,
                account_index: 0,
                controller_index: 7,
                context: MidnightDidCallContext {
                    contract_state,
                    contract_address,
                    observation_transaction_hash: [7; 32],
                    observation_block_hash: [8; 32],
                    observation_block_height: 1,
                    zswap_chain_state: None,
                    ledger_parameters: Some(ledger_parameters),
                    network_id: "undeployed".to_owned(),
                    timestamp_millis: 11_000,
                    expires_at_millis: 3_611_000,
                    coin_public_key: [3; 32],
                    encryption_public_key: [4; 32],
                },
                operation: MidnightDidCallOperation::Deactivate,
                replay_recipe: [9; 32],
            })
            .expect("compose deactivation against installed verifier");
        let transaction: UnprovenTransaction =
            tagged_deserialize(plan.transaction.as_slice()).expect("decode deactivation");
        let (_, ContractAction::Call(call)) =
            transaction.actions().next().expect("deactivation action")
        else {
            panic!("expected a contract call");
        };
        assert_eq!(call.entry_point.0, b"deactivate");
        let observed = runtime::transaction::ObservedContractState::new(
            runtime::ledger::ContractAddress(HashOutput(contract_address)),
            contract,
            runtime::transaction::Observation {
                transaction_hash: [7; 32],
                block_hash: [8; 32],
                block_height: 1,
            },
        );
        let mut state = observed.circuit_context(()).query;
        for transcript in [
            call.guaranteed_transcript.as_deref(),
            call.fallible_transcript.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let program: Vec<_> = transcript.program.iter_deref().cloned().collect();
            state = state
                .query(
                    &program,
                    Some(transcript.gas),
                    &INITIAL_PARAMETERS.cost_model.runtime_cost_model,
                )
                .expect("replay protected deactivation")
                .context;
        }
        assert!(
            midnight_did_runtime::ledger_slots::deactivated
                .inspect(state.state.get_ref())
                .unwrap()
        );
    }
}
