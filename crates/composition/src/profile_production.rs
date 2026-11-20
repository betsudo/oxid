// SPDX-License-Identifier: Apache-2.0

use std::{fmt, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
use oxid_adapter_deployment_profile::AuthenticatedDeploymentProfile;
#[cfg(not(target_arch = "wasm32"))]
use oxid_adapter_did_midnight::{HttpDidResolver, HttpDidResolverConfig};
use oxid_adapter_midnight::unavailable_midnight_wallet;
#[cfg(not(target_arch = "wasm32"))]
use oxid_adapter_midnight::{
    MidnightPreprodCredential, MidnightPreprodPreflightError, MidnightStandaloneConfig,
    authenticate_midnight_chain_identity, protected_standalone_midnight_wallet,
};

use super::identity::{
    CredentialIssuanceComposition, CredentialPresentationComposition, IdentityAdapters,
    SelfIssuedAuthenticationComposition,
};
use super::passport_vault::PassportVaultRepositoryComposition;
use super::services::ApplicationServices;
#[cfg(all(
    feature = "preprod-observation",
    any(target_os = "ios", target_os = "android")
))]
use super::services::WalletRootRecoveryCapability;
use super::wiring::compose_with_identity_adapters;
#[cfg(all(
    feature = "preprod-observation",
    any(target_os = "ios", target_os = "android")
))]
use super::wiring::with_native_wallet_onboarding;
#[cfg(any(target_os = "ios", target_os = "android"))]
use oxid_adapter_platform_system::OsRandom;
use oxid_adapter_platform_system::SystemClock;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use oxid_adapter_storage_dev::UnavailableWalletSecurity;
use oxid_adapter_storage_json::JsonWalletProfileRepository;
#[cfg(any(target_os = "ios", target_os = "android"))]
use oxid_adapter_storage_mobile::MobileWalletSecurity;
use oxid_credential_application::{
    UnavailableCredentialDisclosure, UnavailableCredentialInbox, UnavailableCredentialRepository,
    UnavailableCredentialVerifier,
};
use oxid_identity_application::{
    UnavailableDidLifecycle, UnavailableDidRecordRepository, UnavailableDidResolver,
};
#[cfg(all(
    feature = "preprod-observation",
    any(target_os = "ios", target_os = "android")
))]
use oxid_wallet_application::{RecoverWalletRootUseCase, WalletRootRecoveryService};

/// A signed deployment profile after the configured node has also proven the
/// exact genesis hash bound by that profile.
#[cfg(not(target_arch = "wasm32"))]
pub struct AuthenticatedProductionDeployment {
    pub(super) profile: AuthenticatedDeploymentProfile,
    pub(super) midnight: MidnightStandaloneConfig,
}

#[cfg(all(
    feature = "public-portal",
    not(target_arch = "wasm32"),
    any(test, target_os = "ios", target_os = "android")
))]
mod preview_startup;
#[cfg(all(
    feature = "public-portal",
    any(target_os = "ios", target_os = "android")
))]
mod public_portal;
#[cfg(all(
    feature = "public-portal",
    any(target_os = "ios", target_os = "android")
))]
pub use preview_startup::compose_embedded_preview_portal;
#[cfg(all(feature = "preprod-portal", target_os = "ios"))]
pub use preview_startup::{begin_preprod_project_id_setup, compose_embedded_preprod_portal};

#[cfg(test)]
#[path = "profile_production/tests.rs"]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Debug for AuthenticatedProductionDeployment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedProductionDeployment")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthenticatedProductionDeployment {
    #[must_use]
    pub const fn profile(&self) -> &AuthenticatedDeploymentProfile {
        &self.profile
    }
}

#[cfg(all(
    feature = "public-portal",
    not(target_arch = "wasm32"),
    any(test, target_os = "ios", target_os = "android")
))]
pub(super) fn authenticate_public_portal_manifest(
    profile: &AuthenticatedDeploymentProfile,
    bytes: &[u8],
) -> Result<oxid_adapter_openid4vci::PortalDeploymentManifest, ProductionDeploymentCompositionError>
{
    let ssi = profile.ssi();
    let digest = ssi
        .portal_manifest_sha256()
        .ok_or(ProductionDeploymentCompositionError::InvalidSsiProfile)?;
    let network =
        oxid_identity_application::MidnightNetwork::parse(profile.midnight().network_id())
            .ok_or(ProductionDeploymentCompositionError::InvalidSsiProfile)?;
    oxid_adapter_openid4vci::PortalDeploymentManifest::from_public_bytes(
        bytes,
        digest,
        network,
        ssi.issuer_metadata_url(),
        ssi.did_resolver_url(),
    )
    .map_err(|_| ProductionDeploymentCompositionError::InvalidSsiProfile)
}

/// Public mobile state must never be reopened against a different genesis.
#[cfg(any(
    test,
    all(
        feature = "public-portal",
        any(target_os = "ios", target_os = "android")
    )
))]
pub(super) fn public_portal_state_root(
    platform_profile_path: &std::path::Path,
    network: oxid_identity_application::MidnightNetwork,
    genesis: &[u8; 32],
) -> Option<std::path::PathBuf> {
    platform_profile_path
        .parent()
        .filter(|parent| parent.is_absolute())
        .map(|parent| {
            parent
                .join("public-networks")
                .join(network.as_str())
                .join(hex::encode(genesis))
        })
}

/// Payload-free failures from the production deployment composition gate.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionDeploymentCompositionError {
    InvalidMidnightProfile,
    InvalidPublicPortalTrustPolicy,
    InvalidSignedPublicPortalProfile,
    PublicPortalRuntimeUnavailable,
    ChainIdentityUnavailable,
    ChainIdentityMismatch,
    PreprodCredentialRequired,
    PreprodCredentialUnavailable,
    PreprodIndexerUnavailable,
    PreprodIndexerWebsocketUnavailable,
    PreprodChainViewMismatch,
    PreprodIncompatibleRuntime,
    PublicProofServerUnavailable,
    PublicProofServerIncompatibleVersion,
    InvalidSsiProfile,
    PlatformStorageUnavailable,
    NativeDidDeploymentUnavailable,
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Display for ProductionDeploymentCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMidnightProfile => "authenticated Midnight deployment profile is invalid",
            Self::InvalidPublicPortalTrustPolicy => {
                "embedded public Portal trust policy is invalid"
            }
            Self::InvalidSignedPublicPortalProfile => {
                "embedded signed public Portal profile was rejected"
            }
            Self::PublicPortalRuntimeUnavailable => "public Portal startup runtime is unavailable",
            Self::ChainIdentityUnavailable => {
                "authenticated Midnight chain identity is unavailable"
            }
            Self::ChainIdentityMismatch => {
                "authenticated Midnight chain identity does not match the node"
            }
            Self::PreprodCredentialRequired => {
                "PreProd network access needs a Blockfrost project ID"
            }
            Self::PreprodCredentialUnavailable => {
                "PreProd network access could not be read from the device"
            }
            Self::PreprodIndexerUnavailable => "authenticated PreProd indexer is unavailable",
            Self::PreprodIndexerWebsocketUnavailable => {
                "authenticated PreProd GraphQL WebSocket is unavailable"
            }
            Self::PreprodChainViewMismatch => {
                "PreProd node and indexer disagree on the indexed block"
            }
            Self::PreprodIncompatibleRuntime => {
                "PreProd runtime does not match this Ledger 9 build"
            }
            Self::PublicProofServerUnavailable => {
                "the configured private proof server is unavailable"
            }
            Self::PublicProofServerIncompatibleVersion => {
                "the configured private proof server does not match this Ledger 9 build"
            }
            Self::InvalidSsiProfile => "authenticated SSI deployment profile is invalid",
            Self::PlatformStorageUnavailable => "protected platform storage is unavailable",
            Self::NativeDidDeploymentUnavailable => "native Midnight DID deployment is unavailable",
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::error::Error for ProductionDeploymentCompositionError {}

#[cfg(not(target_arch = "wasm32"))]
fn production_midnight_config(
    profile: &AuthenticatedDeploymentProfile,
) -> Result<MidnightStandaloneConfig, ProductionDeploymentCompositionError> {
    let midnight = profile.midnight();
    MidnightStandaloneConfig::new_without_unshielded_address(
        midnight.network_id(),
        midnight.indexer_websocket_url(),
        midnight.indexer_http_url(),
        midnight.node_websocket_url(),
        midnight.proof_server_url(),
    )
    .map_err(|_| ProductionDeploymentCompositionError::InvalidMidnightProfile)
}

/// Binds a signed deployment profile to the genesis hash returned by its
/// reviewed node route. The caller cannot provide alternate endpoints after
/// this asynchronous gate succeeds.
#[cfg(not(target_arch = "wasm32"))]
pub async fn authenticate_production_deployment(
    profile: AuthenticatedDeploymentProfile,
) -> Result<AuthenticatedProductionDeployment, ProductionDeploymentCompositionError> {
    let config = production_midnight_config(&profile)?;
    let midnight = profile.midnight();
    authenticate_midnight_chain_identity(midnight.node_websocket_url(), midnight.genesis_hash())
        .await
        .map_err(|error| match error {
            oxid_adapter_midnight::MidnightChainIdentityError::GenesisMismatch => {
                ProductionDeploymentCompositionError::ChainIdentityMismatch
            }
            oxid_adapter_midnight::MidnightChainIdentityError::InvalidNodeEndpoint
            | oxid_adapter_midnight::MidnightChainIdentityError::NodeUnavailable => {
                ProductionDeploymentCompositionError::ChainIdentityUnavailable
            }
        })?;
    Ok(AuthenticatedProductionDeployment {
        profile,
        midnight: config,
    })
}

/// Binds the signed PreProd deployment to the authenticated Blockfrost cohort.
#[cfg(not(target_arch = "wasm32"))]
pub async fn authenticate_preprod_deployment(
    profile: AuthenticatedDeploymentProfile,
    credential: MidnightPreprodCredential,
) -> Result<AuthenticatedProductionDeployment, ProductionDeploymentCompositionError> {
    let config = production_midnight_config(&profile)?;
    let midnight = profile.midnight();
    // Validate every wallet route before the provider credential reaches a request.
    let config = config
        .with_preprod_credential(credential)
        .map_err(|_| ProductionDeploymentCompositionError::InvalidMidnightProfile)?;
    config
        .verify_preprod_chain(midnight.genesis_hash())
        .await
        .map_err(|error| match error {
            MidnightPreprodPreflightError::GenesisMismatch => {
                ProductionDeploymentCompositionError::ChainIdentityMismatch
            }
            MidnightPreprodPreflightError::IndexerUnavailable => {
                ProductionDeploymentCompositionError::PreprodIndexerUnavailable
            }
            MidnightPreprodPreflightError::IndexerWebsocketUnavailable => {
                ProductionDeploymentCompositionError::PreprodIndexerWebsocketUnavailable
            }
            MidnightPreprodPreflightError::ChainViewMismatch => {
                ProductionDeploymentCompositionError::PreprodChainViewMismatch
            }
            MidnightPreprodPreflightError::IncompatibleRuntime => {
                ProductionDeploymentCompositionError::PreprodIncompatibleRuntime
            }
            MidnightPreprodPreflightError::NodeUnavailable => {
                ProductionDeploymentCompositionError::ChainIdentityUnavailable
            }
            MidnightPreprodPreflightError::InvalidCredential
            | MidnightPreprodPreflightError::InvalidRoute => {
                ProductionDeploymentCompositionError::InvalidMidnightProfile
            }
        })?;
    Ok(AuthenticatedProductionDeployment {
        profile,
        midnight: config,
    })
}

/// Composes the live Midnight path only after profile-signature and node
/// genesis authentication. The default [`compose`] function remains
/// fail-closed and never calls this opt-in constructor.
///
/// The authenticated DID resolver is enabled from the same signed profile.
/// Issuer and verifier HTTP protocol adapters remain unavailable until their
/// independent metadata/transport implementation is reviewed.
#[cfg(not(target_arch = "wasm32"))]
pub fn compose_authenticated_production(
    deployment: AuthenticatedProductionDeployment,
) -> Result<ApplicationServices, ProductionDeploymentCompositionError> {
    #[cfg(all(
        feature = "preprod-observation",
        any(target_os = "ios", target_os = "android")
    ))]
    let authenticated_network_id = deployment.profile.midnight().network_id().to_owned();
    #[cfg(all(
        feature = "preprod-observation",
        any(target_os = "ios", target_os = "android")
    ))]
    if authenticated_network_id != "preprod" {
        return Err(ProductionDeploymentCompositionError::InvalidMidnightProfile);
    }
    let did_resolver = HttpDidResolverConfig::new(deployment.profile.ssi().did_resolver_url())
        .map(HttpDidResolver::new)
        .map_err(|_| ProductionDeploymentCompositionError::InvalidSsiProfile)?;
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let security = {
        let clock = Arc::new(SystemClock);
        let random = Arc::new(OsRandom);
        Arc::new(MobileWalletSecurity::native(clock, random))
    };
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    let security = Arc::new(UnavailableWalletSecurity);
    let profiles = Arc::new(JsonWalletProfileRepository::at_default_location());
    let clock = Arc::new(SystemClock);
    let midnight = Arc::new(
        protected_standalone_midnight_wallet(
            deployment.midnight,
            Arc::clone(&clock),
            Arc::clone(&security),
        )
        .with_profile_association_repository(profiles.clone()),
    );
    let services = compose_with_identity_adapters(
        Arc::clone(&profiles),
        Arc::clone(&security),
        Arc::clone(&midnight),
        IdentityAdapters {
            backup_recovery_journal: None,
            did_repository: Arc::new(UnavailableDidRecordRepository),
            did_resolver: Arc::new(did_resolver),
            did_lifecycle: Arc::new(UnavailableDidLifecycle),
            did_jubjub_challenge_signing: Arc::new(UnavailableDidLifecycle),
            did_publisher: None,
            credential_repository: Arc::new(UnavailableCredentialRepository),
            credential_inbox: Arc::new(UnavailableCredentialInbox),
            credential_verifier: Arc::new(UnavailableCredentialVerifier),
            credential_disclosure: Arc::new(UnavailableCredentialDisclosure),
            credential_issuance: CredentialIssuanceComposition::Unavailable,
            self_issued_authentication: SelfIssuedAuthenticationComposition::Unavailable,
            credential_presentation: CredentialPresentationComposition::Unavailable,
            portal_test_ingress: None,
        },
        PassportVaultRepositoryComposition::unavailable(),
        |security| security,
    );
    #[cfg(all(
        feature = "preprod-observation",
        any(target_os = "ios", target_os = "android")
    ))]
    {
        let services = with_native_wallet_onboarding(
            services,
            Arc::clone(&profiles),
            Arc::clone(&security),
            Arc::clone(&midnight),
            authenticated_network_id.clone(),
        );
        let recovery: Arc<dyn RecoverWalletRootUseCase> = Arc::new(
            WalletRootRecoveryService::new(
                Arc::clone(&profiles),
                Arc::clone(&security),
                Arc::clone(&midnight),
                authenticated_network_id.clone(),
            )
            .map_err(|_| ProductionDeploymentCompositionError::InvalidMidnightProfile)?,
        );
        Ok(
            services.with_wallet_root_recovery(WalletRootRecoveryCapability::new(
                authenticated_network_id,
                recovery,
            )),
        )
    }
    #[cfg(not(all(
        feature = "preprod-observation",
        any(target_os = "ios", target_os = "android")
    )))]
    {
        Ok(services)
    }
}

/// Wires the application with persistent public-profile metadata storage.
#[must_use]
pub fn compose() -> ApplicationServices {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let security = {
        let clock = Arc::new(SystemClock);
        let random = Arc::new(OsRandom);
        Arc::new(MobileWalletSecurity::native(clock, random))
    };
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    let security = Arc::new(UnavailableWalletSecurity);
    compose_with_identity_adapters(
        Arc::new(JsonWalletProfileRepository::at_default_location()),
        security,
        Arc::new(unavailable_midnight_wallet()),
        IdentityAdapters {
            backup_recovery_journal: None,
            did_repository: Arc::new(UnavailableDidRecordRepository),
            did_resolver: Arc::new(UnavailableDidResolver),
            did_lifecycle: Arc::new(UnavailableDidLifecycle),
            did_jubjub_challenge_signing: Arc::new(UnavailableDidLifecycle),
            did_publisher: None,
            credential_repository: Arc::new(UnavailableCredentialRepository),
            credential_inbox: Arc::new(UnavailableCredentialInbox),
            credential_verifier: Arc::new(UnavailableCredentialVerifier),
            credential_disclosure: Arc::new(UnavailableCredentialDisclosure),
            credential_issuance: CredentialIssuanceComposition::Unavailable,
            self_issued_authentication: SelfIssuedAuthenticationComposition::Unavailable,
            credential_presentation: CredentialPresentationComposition::Unavailable,
            portal_test_ingress: None,
        },
        PassportVaultRepositoryComposition::unavailable(),
        |security| security,
    )
}
