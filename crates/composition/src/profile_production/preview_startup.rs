// SPDX-License-Identifier: Apache-2.0

//! Signed-input admission and startup for public Portal mobile builds.

#[cfg(any(target_os = "ios", target_os = "android"))]
use std::time::{SystemTime, UNIX_EPOCH};

use oxid_adapter_deployment_profile::{
    AuthenticatedDeploymentProfile, DeploymentProfileVerifier, DeploymentTrustRoot,
};

use super::{
    ProductionDeploymentCompositionError as StartupError, authenticate_public_portal_manifest,
};
use crate::portal::PortalIdentityConfiguration;

const APP_AUDIENCE: &str = "io.medianox.oxid";

fn admit_public_inputs(
    reviewed_trust_root: &[u8],
    signed_profile: &[u8],
    portal_manifest: &[u8],
    now: u64,
    expected_network: &str,
) -> Result<(AuthenticatedDeploymentProfile, PortalIdentityConfiguration), StartupError> {
    let root = DeploymentTrustRoot::from_reviewed_json(reviewed_trust_root)
        .map_err(|_| StartupError::InvalidPublicPortalTrustPolicy)?;
    let verifier = DeploymentProfileVerifier::new(APP_AUDIENCE, [root], 1)
        .map_err(|_| StartupError::InvalidPublicPortalTrustPolicy)?;
    let profile = verifier
        .verify(signed_profile, now)
        .map_err(|_| StartupError::InvalidSignedPublicPortalProfile)?;
    if profile.midnight().network_id() != expected_network {
        return Err(StartupError::InvalidMidnightProfile);
    }
    let manifest = authenticate_public_portal_manifest(&profile, portal_manifest)?;
    let portal = PortalIdentityConfiguration::new(manifest, None, None)
        .map_err(|_| StartupError::InvalidSsiProfile)?;
    Ok((profile, portal))
}

/// Startup for three independent, build-pinned public inputs. The signed
/// network and Portal policy are checked before any node request.
#[cfg(any(target_os = "ios", target_os = "android"))]
pub fn compose_embedded_preview_portal(
    reviewed_trust_root: &[u8],
    signed_profile: &[u8],
    portal_manifest: &[u8],
) -> Result<crate::services::ApplicationServices, StartupError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StartupError::InvalidSignedPublicPortalProfile)?
        .as_secs();
    let (profile, portal) = admit_public_inputs(
        reviewed_trust_root,
        signed_profile,
        portal_manifest,
        now,
        "preview",
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| StartupError::PublicPortalRuntimeUnavailable)?;
    let deployment = runtime.block_on(super::authenticate_production_deployment(profile))?;
    runtime.block_on(verify_public_prover(&deployment))?;
    super::public_portal::compose_authenticated_public_portal(deployment, portal)
}

/// Startup for a signed PreProd Portal profile and its device-local access credential.
#[cfg(all(feature = "preprod-portal", target_os = "ios"))]
pub fn compose_embedded_preprod_portal(
    reviewed_trust_root: &[u8],
    signed_profile: &[u8],
    portal_manifest: &[u8],
) -> Result<crate::services::ApplicationServices, StartupError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StartupError::InvalidSignedPublicPortalProfile)?
        .as_secs();
    let (profile, portal) = admit_public_inputs(
        reviewed_trust_root,
        signed_profile,
        portal_manifest,
        now,
        "preprod",
    )?;
    let mut secret = oxid_adapter_mobile_native::read_preprod_project_id()
        .map_err(|_| StartupError::PreprodCredentialUnavailable)?
        .ok_or(StartupError::PreprodCredentialRequired)?;
    let credential =
        oxid_adapter_midnight::MidnightPreprodCredential::new(std::mem::take(&mut *secret))
            .map_err(|_| StartupError::PreprodCredentialUnavailable)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| StartupError::PublicPortalRuntimeUnavailable)?;
    let deployment =
        runtime.block_on(super::authenticate_preprod_deployment(profile, credential))?;
    runtime.block_on(verify_public_prover(&deployment))?;
    super::public_portal::compose_authenticated_public_portal(deployment, portal)
}

#[cfg(any(target_os = "ios", target_os = "android"))]
async fn verify_public_prover(
    deployment: &super::AuthenticatedProductionDeployment,
) -> Result<(), StartupError> {
    use oxid_adapter_midnight::MidnightProofServerVersionError;

    deployment
        .midnight
        .verify_public_proof_server()
        .await
        .map_err(|error| match error {
            MidnightProofServerVersionError::Unavailable => {
                StartupError::PublicProofServerUnavailable
            }
            MidnightProofServerVersionError::IncompatibleVersion => {
                StartupError::PublicProofServerIncompatibleVersion
            }
        })
}

#[cfg(all(feature = "preprod-portal", target_os = "ios"))]
pub fn begin_preprod_project_id_setup() -> Result<(), StartupError> {
    oxid_adapter_mobile_native::begin_preprod_project_id_setup()
        .map_err(|_| StartupError::PreprodCredentialUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUST: &[u8] = include_bytes!("../../tests/fixtures/preview-portal/trust-root.json");
    const PROFILE: &[u8] = include_bytes!("../../tests/fixtures/preview-portal/profile.json");
    const WRONG_NETWORK: &[u8] =
        include_bytes!("../../tests/fixtures/preview-portal/wrong-network.json");
    const MANIFEST: &[u8] = include_bytes!("../../tests/fixtures/preview-portal/portal.json");
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn preview_startup_admits_reviewed_deployment_before_live_authentication() {
        let (profile, portal) = admit_public_inputs(TRUST, PROFILE, MANIFEST, NOW, "preview")
            .expect("valid signed inputs");
        assert_eq!(profile.midnight().network_id(), "preview");
        assert!(portal.client_factory.deployment().is_public_network());
        assert!(portal.test_ingress.is_none());
        assert!(portal.did_publisher.is_none());
    }

    #[test]
    fn preprod_startup_binds_the_preprod_manifest_and_rejects_preview() {
        let trust = include_bytes!("../../tests/fixtures/preprod-portal/trust-root.json");
        let profile = include_bytes!("../../tests/fixtures/preprod-portal/profile.json");
        let manifest = include_bytes!("../../tests/fixtures/preprod-portal/portal.json");
        let (profile, portal) = admit_public_inputs(trust, profile, manifest, NOW, "preprod")
            .expect("reviewed PreProd fixture");
        assert_eq!(profile.midnight().network_id(), "preprod");
        assert!(portal.client_factory.deployment().is_public_network());
        assert!(portal.test_ingress.is_none());
        assert_eq!(
            admit_public_inputs(TRUST, PROFILE, MANIFEST, NOW, "preprod").err(),
            Some(StartupError::InvalidMidnightProfile),
        );
    }

    #[test]
    fn keychain_fixture_is_admitted_but_refuses_to_send_the_project_id() {
        let trust = include_bytes!("../../tests/fixtures/preprod-portal/trust-root.json");
        let profile = include_bytes!("../../tests/fixtures/preprod-portal/keychain-profile.json");
        let manifest = include_bytes!("../../tests/fixtures/preprod-portal/portal.json");
        let (profile, _) = admit_public_inputs(trust, profile, manifest, NOW, "preprod")
            .expect("the keychain fixture must get past signed input admission");
        let credential = oxid_adapter_midnight::MidnightPreprodCredential::new(format!(
            "nightpreprod{}",
            "Z".repeat(32)
        ))
        .expect("synthetic fixture project ID");
        assert_eq!(
            futures::executor::block_on(super::super::authenticate_preprod_deployment(
                profile, credential,
            ))
            .err(),
            Some(StartupError::InvalidMidnightProfile),
        );
    }

    #[test]
    fn preview_startup_rejects_wrong_network_expiry_and_changed_inputs() {
        let check = |trust: &[u8], profile: &[u8], manifest: &[u8], now| {
            admit_public_inputs(trust, profile, manifest, now, "preview").err()
        };
        assert_eq!(
            check(TRUST, WRONG_NETWORK, MANIFEST, NOW),
            Some(StartupError::InvalidMidnightProfile)
        );
        assert_eq!(
            check(TRUST, PROFILE, MANIFEST, 1_900_000_000),
            Some(StartupError::InvalidSignedPublicPortalProfile)
        );
        let trust = std::str::from_utf8(TRUST).unwrap();
        let rolled_back = trust.replace(
            "\"minimumProfileSequence\": 3",
            "\"minimumProfileSequence\": 4",
        );
        assert_ne!(
            rolled_back, trust,
            "the negative case must change the trust root"
        );
        assert_eq!(
            check(rolled_back.as_bytes(), PROFILE, MANIFEST, NOW),
            Some(StartupError::InvalidSignedPublicPortalProfile)
        );
        assert_eq!(
            check(b"{}", PROFILE, MANIFEST, NOW),
            Some(StartupError::InvalidPublicPortalTrustPolicy)
        );
        assert_eq!(
            check(TRUST, PROFILE, b"{}", NOW),
            Some(StartupError::InvalidSsiProfile)
        );
    }
}
