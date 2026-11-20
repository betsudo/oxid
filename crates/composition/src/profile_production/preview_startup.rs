// SPDX-License-Identifier: Apache-2.0

//! Startup for the separately selected Preview Portal mobile build.

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

fn admit_preview_inputs(
    reviewed_trust_root: &[u8],
    signed_profile: &[u8],
    portal_manifest: &[u8],
    now: u64,
) -> Result<(AuthenticatedDeploymentProfile, PortalIdentityConfiguration), StartupError> {
    let root = DeploymentTrustRoot::from_reviewed_json(reviewed_trust_root)
        .map_err(|_| StartupError::InvalidPreviewTrustPolicy)?;
    let verifier = DeploymentProfileVerifier::new(APP_AUDIENCE, [root], 1)
        .map_err(|_| StartupError::InvalidPreviewTrustPolicy)?;
    let profile = verifier
        .verify(signed_profile, now)
        .map_err(|_| StartupError::InvalidSignedPreviewProfile)?;
    if profile.midnight().network_id() != "preview" {
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
        .map_err(|_| StartupError::InvalidSignedPreviewProfile)?
        .as_secs();
    let (profile, portal) =
        admit_preview_inputs(reviewed_trust_root, signed_profile, portal_manifest, now)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| StartupError::PreviewStartupRuntimeUnavailable)?;
    let deployment = runtime.block_on(super::authenticate_production_deployment(profile))?;
    super::public_portal::compose_authenticated_public_portal(deployment, portal)
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
        let (profile, portal) =
            admit_preview_inputs(TRUST, PROFILE, MANIFEST, NOW).expect("valid signed inputs");
        assert_eq!(profile.midnight().network_id(), "preview");
        assert!(portal.client_factory.deployment().is_public_network());
        assert!(portal.test_ingress.is_none());
        assert!(portal.did_publisher.is_none());
    }

    #[test]
    fn preview_startup_rejects_wrong_network_expiry_and_changed_inputs() {
        let check = |trust: &[u8], profile: &[u8], manifest: &[u8], now| {
            admit_preview_inputs(trust, profile, manifest, now).err()
        };
        assert_eq!(
            check(TRUST, WRONG_NETWORK, MANIFEST, NOW),
            Some(StartupError::InvalidMidnightProfile)
        );
        assert_eq!(
            check(TRUST, PROFILE, MANIFEST, 1_900_000_000),
            Some(StartupError::InvalidSignedPreviewProfile)
        );
        let trust = std::str::from_utf8(TRUST).unwrap();
        let rolled_back = trust.replace(
            "\"minimumProfileSequence\":3",
            "\"minimumProfileSequence\":4",
        );
        assert_eq!(
            check(rolled_back.as_bytes(), PROFILE, MANIFEST, NOW),
            Some(StartupError::InvalidSignedPreviewProfile)
        );
        assert_eq!(
            check(b"{}", PROFILE, MANIFEST, NOW),
            Some(StartupError::InvalidPreviewTrustPolicy)
        );
        assert_eq!(
            check(TRUST, PROFILE, b"{}", NOW),
            Some(StartupError::InvalidSsiProfile)
        );
    }
}
