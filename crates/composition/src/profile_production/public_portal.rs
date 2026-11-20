// SPDX-License-Identifier: Apache-2.0

//! Protected mobile composition for the authenticated Preview Portal profile.

use std::sync::Arc;

use oxid_adapter_backup_complete::FileRecoveryJournal;
use oxid_adapter_did_midnight::StandaloneDidLifecycle;
use oxid_adapter_midnight::{
    MidnightAccountCheckpointConfig, MidnightDustCheckpointConfig,
    MidnightShieldedCheckpointConfig, MidnightSubmissionJournalConfig,
    protected_standalone_midnight_wallet_with_checkpoint_options_and_proving_material,
};
use oxid_adapter_platform_system::{OsRandom, SystemClock};
use oxid_adapter_storage_credential_json::EncryptedJsonCredentialRepository;
use oxid_adapter_storage_identity_json::{
    JsonDidDeploymentOperationRepository, JsonDidRecordRepository,
};
use oxid_adapter_storage_json::JsonWalletProfileRepository;
use oxid_adapter_storage_mobile::MobileWalletSecurity;
use oxid_adapter_vc_midnight::{DigitalPassportDisclosureAdapter, MidnightCredentialVerifier};
use oxid_credential_application::UnavailableCredentialInbox;
use oxid_identity_application::MidnightNetwork;

use super::{AuthenticatedProductionDeployment, public_portal_state_root};
use crate::did_deployment::{native_did_deployment, native_did_proving_material};
use crate::identity::{
    CredentialIssuanceComposition, CredentialPresentationComposition, IdentityAdapters,
    SelfIssuedAuthenticationComposition,
};
use crate::passport_vault::PassportVaultRepositoryComposition;
use crate::portal::PortalIdentityConfiguration;
use crate::services::ApplicationServices;
use crate::wiring::{compose_with_identity_adapters, with_native_wallet_onboarding};

use super::ProductionDeploymentCompositionError as CompositionError;

/// Installs native Portal issuance only after signed profile, chain identity,
/// and exact Portal manifest admission. State and journals belong to that
/// chain's genesis. The wallet uses platform-backed custody for signing.
pub(super) fn compose_authenticated_public_portal(
    deployment: AuthenticatedProductionDeployment,
    portal: PortalIdentityConfiguration,
) -> Result<ApplicationServices, CompositionError> {
    let network = MidnightNetwork::parse(deployment.profile.midnight().network_id())
        .filter(|network| matches!(network, MidnightNetwork::Preview | MidnightNetwork::Preprod))
        .ok_or(CompositionError::InvalidMidnightProfile)?;
    let PortalIdentityConfiguration {
        client_factory,
        issuer_resolver,
        trust_anchor,
        test_ingress,
        did_publisher,
    } = portal;
    let platform_profiles = JsonWalletProfileRepository::at_platform_location();
    let state_root = platform_profiles
        .configured_path()
        .and_then(|path| {
            public_portal_state_root(path, network, deployment.profile.midnight().genesis_hash())
        })
        .ok_or(CompositionError::PlatformStorageUnavailable)?;
    let profiles = Arc::new(JsonWalletProfileRepository::new(
        state_root.join("wallet-profiles.json"),
    ));
    let private = state_root.join("private");
    let account = private.join("midnight-account-checkpoints.json");
    let dust = private.join("midnight-dust-checkpoints.bin");
    let shielded = private.join("midnight-shielded-checkpoints.bin");
    let submissions = private.join("midnight-submissions.json");
    let account = MidnightAccountCheckpointConfig::new(account)
        .map_err(|_| CompositionError::PlatformStorageUnavailable)?;
    let dust = MidnightDustCheckpointConfig::new(dust)
        .map_err(|_| CompositionError::PlatformStorageUnavailable)?;
    let shielded = MidnightShieldedCheckpointConfig::new(shielded)
        .map_err(|_| CompositionError::PlatformStorageUnavailable)?;
    let submissions = MidnightSubmissionJournalConfig::new(submissions)
        .map_err(|_| CompositionError::PlatformStorageUnavailable)?;
    let backup_recovery = FileRecoveryJournal::new(private.join("complete-wallet-recovery.json"))
        .map_err(|_| CompositionError::PlatformStorageUnavailable)?;

    let proving_material =
        native_did_proving_material().ok_or(CompositionError::NativeDidDeploymentUnavailable)?;
    let clock = Arc::new(SystemClock);
    let security = Arc::new(MobileWalletSecurity::native(
        Arc::clone(&clock),
        Arc::new(OsRandom),
    ));
    let midnight = Arc::new(
        protected_standalone_midnight_wallet_with_checkpoint_options_and_proving_material(
            deployment.midnight.clone(),
            Some(account),
            Some(dust),
            Some(shielded),
            Some(submissions),
            Some(proving_material),
            Arc::clone(&clock),
            Arc::clone(&security),
        )
        .with_profile_association_repository(profiles.clone()),
    );
    let lifecycle = Arc::new(
        StandaloneDidLifecycle::with_jubjub_challenge_signing(security.clone(), security.clone())
            .with_ledger9_jubjub_jwk(),
    );
    let verifier = Arc::new(MidnightCredentialVerifier::with_compact_policy(
        Arc::clone(&issuer_resolver),
        Arc::clone(&issuer_resolver),
        clock,
        trust_anchor,
    ));
    let mut services = compose_with_identity_adapters(
        Arc::clone(&profiles),
        Arc::clone(&security),
        Arc::clone(&midnight),
        IdentityAdapters {
            backup_recovery_journal: Some(Arc::new(backup_recovery)),
            did_repository: Arc::new(JsonDidRecordRepository::new(
                private.join("did-records.json"),
            )),
            did_resolver: issuer_resolver,
            did_lifecycle: lifecycle.clone(),
            did_jubjub_challenge_signing: lifecycle,
            did_publisher,
            credential_repository: Arc::new(EncryptedJsonCredentialRepository::new(
                private.join("credentials.enc"),
                private.join("credentials.key"),
            )),
            credential_inbox: Arc::new(UnavailableCredentialInbox),
            credential_verifier: verifier,
            credential_disclosure: Arc::new(DigitalPassportDisclosureAdapter),
            credential_issuance: CredentialIssuanceComposition::Portal(Box::new(client_factory)),
            self_issued_authentication: SelfIssuedAuthenticationComposition::Unavailable,
            credential_presentation: CredentialPresentationComposition::Unavailable,
            portal_test_ingress: test_ingress,
        },
        PassportVaultRepositoryComposition::unavailable(),
        |security| security,
    );
    services.deploy_did = native_did_deployment(
        &deployment.midnight,
        Arc::clone(&security),
        Arc::clone(&midnight),
        Arc::clone(&services.did_resolution_port),
        Arc::new(JsonDidDeploymentOperationRepository::new(
            private.join("did-deployments.json"),
        )),
    )
    .ok_or(CompositionError::NativeDidDeploymentUnavailable)?;
    Ok(with_native_wallet_onboarding(
        services,
        profiles,
        security,
        midnight,
        network.as_str().to_owned(),
    ))
}
