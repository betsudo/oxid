// SPDX-License-Identifier: Apache-2.0

//! Read-only verification of signed PreProd routes with native Blockfrost authentication.

use std::fmt;

use reqwest::header::{HeaderMap, HeaderValue};
use zeroize::Zeroizing;

use super::submission::{
    MidnightChainIdentityError, authenticate_midnight_chain_identity_with_headers,
    fetch_chain_tip_with_headers,
};

const NODE_ROUTE: &str = "wss://rpc.midnight-preprod.blockfrost.io";
const INDEXER_ROUTE: &str = "https://midnight-preprod.blockfrost.io/api/v0";
const PROJECT_PREFIX: &str = "nightpreprod";

/// A provider credential supplied to native transport at runtime.
pub struct MidnightPreprodCredential(Zeroizing<String>);

impl MidnightPreprodCredential {
    pub fn new(project_id: String) -> Result<Self, MidnightPreprodPreflightError> {
        let project_id = Zeroizing::new(project_id);
        if !project_id.starts_with(PROJECT_PREFIX)
            || !(20..=128).contains(&project_id.len())
            || !project_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(MidnightPreprodPreflightError::InvalidCredential);
        }
        Ok(Self(project_id))
    }

    fn headers(&self) -> Result<HeaderMap, MidnightPreprodPreflightError> {
        let mut value = HeaderValue::from_str(&self.0)
            .map_err(|_| MidnightPreprodPreflightError::InvalidCredential)?;
        value.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("project_id", value);
        Ok(headers)
    }
}

impl fmt::Debug for MidnightPreprodCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MidnightPreprodCredential([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightPreprodPreflightError {
    InvalidCredential,
    InvalidRoute,
    NodeUnavailable,
    GenesisMismatch,
    IndexerUnavailable,
}

impl fmt::Display for MidnightPreprodPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredential => "Blockfrost PreProd project ID is invalid",
            Self::InvalidRoute => "Blockfrost PreProd route is invalid",
            Self::NodeUnavailable => "authenticated PreProd node is unavailable",
            Self::GenesisMismatch => "PreProd node genesis differs from the signed profile",
            Self::IndexerUnavailable => "authenticated PreProd indexer is unavailable",
        })
    }
}

impl std::error::Error for MidnightPreprodPreflightError {}

/// Checks the signed node genesis and reads the indexer tip. The caller
/// supplies the canonical public routes from a verified deployment profile.
pub async fn preflight_blockfrost_preprod(
    node_url: &str,
    indexer_url: &str,
    genesis_hash: &[u8; 32],
    credential: &MidnightPreprodCredential,
) -> Result<u64, MidnightPreprodPreflightError> {
    if ![NODE_ROUTE, "wss://rpc.midnight-preprod.blockfrost.io/"].contains(&node_url)
        || indexer_url != INDEXER_ROUTE
    {
        return Err(MidnightPreprodPreflightError::InvalidRoute);
    }
    authenticate_midnight_chain_identity_with_headers(
        node_url,
        genesis_hash,
        credential.headers()?,
    )
    .await
    .map_err(|error| match error {
        MidnightChainIdentityError::GenesisMismatch => {
            MidnightPreprodPreflightError::GenesisMismatch
        }
        _ => MidnightPreprodPreflightError::NodeUnavailable,
    })?;
    let tip = fetch_chain_tip_with_headers(indexer_url, credential.headers()?)
        .await
        .map_err(|_| MidnightPreprodPreflightError::IndexerUnavailable)?;
    Ok(tip.height)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> MidnightPreprodCredential {
        MidnightPreprodCredential::new(format!("{PROJECT_PREFIX}{}", "A".repeat(32))).unwrap()
    }

    #[test]
    fn synthetic_project_id_is_sensitive_and_absent_from_debug() {
        let credential = credential();
        let headers = credential.headers().unwrap();
        let header = &headers["project_id"];
        assert!(header.is_sensitive());
        assert!(header.as_bytes().starts_with(PROJECT_PREFIX.as_bytes()));
        assert!(!format!("{headers:?} {credential:?}").contains(PROJECT_PREFIX));
    }

    #[test]
    fn malformed_or_cross_network_credentials_are_rejected() {
        for candidate in [
            String::new(),
            format!("nightpreview{}", "A".repeat(32)),
            format!("{PROJECT_PREFIX}{}", "A".repeat(150)),
            format!("{PROJECT_PREFIX}inject\r\nheader"),
        ] {
            assert_eq!(
                MidnightPreprodCredential::new(candidate).unwrap_err(),
                MidnightPreprodPreflightError::InvalidCredential
            );
        }
    }

    #[test]
    fn preflight_refuses_queries_and_unreviewed_hosts_before_network_io() {
        let credential = credential();
        for (node, indexer) in [
            ("wss://rpc.midnight-preview.blockfrost.io", INDEXER_ROUTE),
            (
                NODE_ROUTE,
                "https://midnight-preprod.blockfrost.io/api/v0?key=test",
            ),
            (
                NODE_ROUTE,
                "https://midnight-preprod.blockfrost.io.invalid/api/v0",
            ),
            ("wss://rpc.midnight-preprod.blockfrost.io//", INDEXER_ROUTE),
        ] {
            assert_eq!(
                futures::executor::block_on(preflight_blockfrost_preprod(
                    node,
                    indexer,
                    &[0; 32],
                    &credential,
                )),
                Err(MidnightPreprodPreflightError::InvalidRoute)
            );
        }
    }
}
