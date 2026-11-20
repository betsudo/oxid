// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::{env, fs, io::Read as _, path::PathBuf};

use sha2::{Digest as _, Sha256};

#[path = "src/portal_profile_authority.rs"]
mod portal_profile_authority;

const PORTAL_MANIFEST_PATH_ENV: &str = "OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_PATH";
const PORTAL_MANIFEST_SHA256_ENV: &str = "OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_SHA256";
const MAX_PORTAL_MANIFEST_BYTES: usize = 65_536;
#[cfg(feature = "preview-portal")]
const PREVIEW_PROFILE_PATH_ENV: &str = "OXID_BUILD_PREVIEW_SIGNED_PROFILE_PATH";
#[cfg(feature = "preview-portal")]
const PREVIEW_PROFILE_SHA256_ENV: &str = "OXID_BUILD_PREVIEW_SIGNED_PROFILE_SHA256";
#[cfg(feature = "preview-portal")]
const PREVIEW_TRUST_ROOT_PATH_ENV: &str = "OXID_BUILD_PREVIEW_TRUST_ROOT_PATH";
#[cfg(feature = "preview-portal")]
const PREVIEW_TRUST_ROOT_SHA256_ENV: &str = "OXID_BUILD_PREVIEW_TRUST_ROOT_SHA256";
const PORTAL_PROFILE_AUTHORITY_PATH_ENV: &str = "OXID_BUILD_PORTAL_PROFILE_AUTHORITY_PATH";
const PORTAL_PROFILE_AUTHORITY_SHA256_ENV: &str = "OXID_BUILD_PORTAL_PROFILE_AUTHORITY_SHA256";
const PORTAL_PUBLIC_ORIGIN_ENV: &str = "OXID_BUILD_PORTAL_PUBLIC_ORIGIN";
const MAX_PORTAL_PROFILE_AUTHORITY_BYTES: usize = 512;

fn active_portal_profile() -> Option<portal_profile_authority::PortalProfile> {
    let local = env::var_os("CARGO_FEATURE_STANDALONE_PORTAL").is_some();
    let tailnet = env::var_os("CARGO_FEATURE_STANDALONE_PORTAL_TAILNET").is_some();
    assert!(
        usize::from(local) + usize::from(tailnet) <= 1,
        "select exactly one standalone Portal profile"
    );
    if local {
        Some(portal_profile_authority::PortalProfile::Local)
    } else if tailnet {
        Some(portal_profile_authority::PortalProfile::AndroidTailnet)
    } else {
        None
    }
}

fn main() {
    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must provide CARGO_MANIFEST_DIR"),
    );
    let repository_root = manifest_directory
        .parent()
        .and_then(|apps| apps.parent())
        .expect("oxid app must remain under apps/");
    let brand_directory = repository_root.join("brands/oxid");
    let output_directory =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR"));
    #[cfg(feature = "preview-portal")]
    authorize_preview_build();
    authorize_portal_profile();
    let brand = oxid_brand_build::load_brand_pack(&brand_directory)
        .unwrap_or_else(|error| panic!("default brand pack is invalid: {error}"));
    oxid_brand_build::validate_app_manifest(&brand, manifest_directory.join("Dioxus.toml"))
        .unwrap_or_else(|error| panic!("thin app manifest does not match its brand: {error}"));
    oxid_brand_build::generate_brand(&brand_directory, output_directory.clone())
        .unwrap_or_else(|error| panic!("default brand generation failed: {error}"));
    embed_portal_manifests(&output_directory);

    println!("cargo:rerun-if-changed={}", brand_directory.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_directory.join("Dioxus.toml").display()
    );
}

fn authorize_portal_profile() {
    println!("cargo:rustc-check-cfg=cfg(oxid_portal_virtual_device_profile_authorized)");
    println!("cargo:rustc-check-cfg=cfg(oxid_portal_android_physical_profile_authorized)");
    println!("cargo:rerun-if-env-changed={PORTAL_PROFILE_AUTHORITY_PATH_ENV}");
    println!("cargo:rerun-if-env-changed={PORTAL_PROFILE_AUTHORITY_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={PORTAL_PUBLIC_ORIGIN_ENV}");
    let Some(profile) = active_portal_profile() else {
        return;
    };
    if profile == portal_profile_authority::PortalProfile::Local
        && (env::var_os("CARGO_FEATURE_STANDALONE_TAILNET").is_some()
            || env::var_os("CARGO_FEATURE_STANDALONE_NATIVE_CUSTODY").is_some())
    {
        panic!("standalone-portal is incompatible with tailnet and native custody");
    }
    if profile == portal_profile_authority::PortalProfile::Local
        && !env::var("CARGO_CFG_TARGET_OS")
            .is_ok_and(|target| matches!(target.as_str(), "ios" | "android"))
    {
        panic!("standalone-portal is available only on iOS and Android");
    }

    let path = PathBuf::from(env::var_os(PORTAL_PROFILE_AUTHORITY_PATH_ENV).unwrap_or_else(|| {
        panic!("standalone Portal requires repository virtual-device profile authority via {PORTAL_PROFILE_AUTHORITY_PATH_ENV}")
    }));
    assert!(
        path.is_absolute(),
        "{PORTAL_PROFILE_AUTHORITY_PATH_ENV} must be absolute"
    );
    let metadata = fs::symlink_metadata(&path).unwrap_or_else(|_| {
        panic!("standalone-portal profile authority must be a readable regular file")
    });
    assert!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "standalone-portal profile authority must be a regular non-symlink file"
    );
    let bytes = fs::read(&path).unwrap_or_else(|_| {
        panic!("standalone-portal profile authority must be a readable regular file")
    });
    assert!(
        !bytes.is_empty() && bytes.len() <= MAX_PORTAL_PROFILE_AUTHORITY_BYTES,
        "standalone-portal profile authority has an invalid size"
    );
    let digest = env::var(PORTAL_PROFILE_AUTHORITY_SHA256_ENV).unwrap_or_else(|_| {
        panic!("standalone-portal requires {PORTAL_PROFILE_AUTHORITY_SHA256_ENV}")
    });
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value)),
        "standalone-portal profile authority digest must be lowercase SHA-256"
    );
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        actual, digest,
        "standalone-portal profile authority digest mismatch"
    );
    let target = env::var("TARGET").expect("Cargo must provide TARGET");
    portal_profile_authority::validate_manifest(&bytes, profile, &target)
        .unwrap_or_else(|error| panic!("{error}"));
    if profile == portal_profile_authority::PortalProfile::AndroidTailnet {
        let public_origin = env::var(PORTAL_PUBLIC_ORIGIN_ENV).unwrap_or_else(|_| {
            panic!("Portal tailnet profile requires {PORTAL_PUBLIC_ORIGIN_ENV}")
        });
        oxid_adapter_identity_ingress::validate_tailnet_public_origin(&public_origin)
            .unwrap_or_else(|error| panic!("{error}"));
        println!("cargo:rustc-env=OXID_EMBEDDED_PORTAL_PUBLIC_ORIGIN={public_origin}");
        println!("cargo:rustc-cfg=oxid_portal_android_physical_profile_authorized");
    } else {
        println!("cargo:rustc-cfg=oxid_portal_virtual_device_profile_authorized");
    }
    println!("cargo:rerun-if-changed={}", path.display());
}

#[cfg(feature = "preview-portal")]
fn authorize_preview_build() {
    assert!(
        env::var("CARGO_CFG_TARGET_OS")
            .is_ok_and(|target| matches!(target.as_str(), "ios" | "android")),
        "preview-portal is available only on iOS and Android"
    );
    let conflicting = [
        "DESKTOP",
        "WEB",
        "STANDALONE_DEVELOPMENT",
        "STANDALONE_NATIVE_CUSTODY",
        "STANDALONE_LOCAL",
        "STANDALONE_TAILNET",
        "STANDALONE_PORTAL",
        "STANDALONE_PORTAL_TAILNET",
        "PREPROD_OBSERVATION",
        "UI_PROFILE_DEV",
        "UI_PROFILE_DEMO",
    ];
    assert!(
        !conflicting
            .iter()
            .any(|feature| env::var_os(format!("CARGO_FEATURE_{feature}")).is_some()),
        "preview-portal is an isolated protected mobile profile"
    );
}

fn embed_portal_manifests(output_directory: &std::path::Path) {
    let mobile_target = env::var("CARGO_CFG_TARGET_OS")
        .is_ok_and(|target| matches!(target.as_str(), "ios" | "android"));
    let preview = cfg!(feature = "preview-portal");
    if !mobile_target || (!preview && active_portal_profile().is_none()) {
        return;
    }
    let (manifest, digest) = read_pinned_input(
        PORTAL_MANIFEST_PATH_ENV,
        PORTAL_MANIFEST_SHA256_ENV,
        MAX_PORTAL_MANIFEST_BYTES,
    );
    #[cfg(feature = "preview-portal")]
    embed_preview_profile(output_directory, &digest);
    fs::write(output_directory.join("portal-deployment.json"), manifest)
        .expect("Portal deployment manifest could not be embedded");
    println!("cargo:rustc-env=OXID_EMBEDDED_PORTAL_DEPLOYMENT_SHA256={digest}");
}

#[cfg(feature = "preview-portal")]
fn embed_preview_profile(output_directory: &std::path::Path, manifest_digest: &str) {
    use oxid_adapter_deployment_profile::{DeploymentProfileVerifier, DeploymentTrustRoot};
    use std::time::{SystemTime, UNIX_EPOCH};

    let (trust_bytes, _) = read_pinned_input(
        PREVIEW_TRUST_ROOT_PATH_ENV,
        PREVIEW_TRUST_ROOT_SHA256_ENV,
        4_096,
    );
    let (profile_bytes, _) =
        read_pinned_input(PREVIEW_PROFILE_PATH_ENV, PREVIEW_PROFILE_SHA256_ENV, 65_536);
    let root = DeploymentTrustRoot::from_reviewed_json(&trust_bytes)
        .expect("embedded Preview trust policy is invalid");
    let verifier = DeploymentProfileVerifier::new("io.medianox.oxid", [root], 1)
        .expect("embedded Preview trust policy is invalid");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("trusted build time is unavailable")
        .as_secs();
    let profile = verifier
        .verify(&profile_bytes, now)
        .expect("embedded signed Preview profile was rejected");
    assert_eq!(
        profile.midnight().network_id(),
        "preview",
        "signed Preview network mismatch"
    );
    assert!(
        profile.ssi().portal_manifest_sha256() == Some(manifest_digest),
        "signed Preview Portal manifest digest mismatch"
    );
    fs::write(
        output_directory.join("preview-trust-root.json"),
        trust_bytes,
    )
    .expect("Preview trust root could not be embedded");
    fs::write(
        output_directory.join("preview-signed-profile.json"),
        profile_bytes,
    )
    .expect("signed Preview profile could not be embedded");
}

fn read_pinned_input(path_env: &str, digest_env: &str, max_bytes: usize) -> (Vec<u8>, String) {
    println!("cargo:rerun-if-env-changed={path_env}");
    println!("cargo:rerun-if-env-changed={digest_env}");
    let path =
        PathBuf::from(env::var_os(path_env).unwrap_or_else(|| panic!("required {path_env}")));
    assert!(path.is_absolute(), "{path_env} must be absolute");
    let metadata = fs::symlink_metadata(&path)
        .unwrap_or_else(|_| panic!("{path_env} must select a readable regular file"));
    assert!(
        metadata.file_type().is_file(),
        "{path_env} must select a regular non-symlink file"
    );
    assert!(
        metadata.len() > 0 && metadata.len() <= max_bytes as u64,
        "{path_env} has an invalid size"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&path)
        .and_then(|file| file.take(max_bytes as u64 + 1).read_to_end(&mut bytes))
        .unwrap_or_else(|_| panic!("{path_env} must select a readable regular file"));
    assert!(
        !bytes.is_empty() && bytes.len() <= max_bytes,
        "{path_env} has an invalid size"
    );
    let digest = env::var(digest_env).unwrap_or_else(|_| panic!("required {digest_env}"));
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value)),
        "{digest_env} must be lowercase SHA-256"
    );
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(actual == digest, "{digest_env} mismatch");
    println!("cargo:rerun-if-changed={}", path.display());
    (bytes, digest)
}
