// SPDX-License-Identifier: Apache-2.0

//! Public Midnight chain verification and native PreProd Blockfrost authentication.

use std::{fmt, time::Duration};

use tokio_tungstenite::tungstenite::{client::IntoClientRequest, handshake::client::Request};

use reqwest::header::{HeaderMap, HeaderValue};
use zeroize::Zeroizing;

use oxid_adapter_platform_system::connect_json_rpc_websocket_with_headers;
use subxt::{
    SubstrateConfig,
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
};
use tokio::time::timeout;

use super::{indexer::verify_graphql_transport, submission::fetch_identified_chain_tip};

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const NODE_ROUTE: &str = "wss://rpc.midnight-preprod.blockfrost.io";
pub(crate) const INDEXER_ROUTE: &str = "https://midnight-preprod.blockfrost.io/api/v0";
pub(crate) const INDEXER_SOCKET_ROUTE: &str = "wss://midnight-preprod.blockfrost.io/api/v0/ws";
const PROJECT_PREFIX: &str = "nightpreprod";
// Midnight 2.1.101 Ledger 9 runtime, paired with the pinned app cohort.
const LEDGER9_RUNTIME_SPEC: u32 = 2_001_100;

/// A provider credential supplied to native transport at runtime.
#[derive(PartialEq, Eq)]
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

pub(crate) fn is_preprod_node_route(endpoint: &str) -> bool {
    [NODE_ROUTE, "wss://rpc.midnight-preprod.blockfrost.io/"].contains(&endpoint)
}

/// Keeps the public endpoint and optional credential separate until a request is built.
#[derive(Clone, Copy)]
pub(crate) struct MidnightTransportRoute<'a> {
    endpoint: &'a str,
    credential: Option<&'a MidnightPreprodCredential>,
    mixed_eras: bool,
}

impl<'a> MidnightTransportRoute<'a> {
    pub(crate) fn new(
        endpoint: &'a str,
        credential: Option<&'a MidnightPreprodCredential>,
    ) -> Self {
        Self {
            endpoint,
            credential,
            mixed_eras: false,
        }
    }

    pub(crate) fn with_mixed_eras(mut self, mixed_eras: bool) -> Self {
        self.mixed_eras = mixed_eras;
        self
    }

    pub(crate) fn mixed_eras(self) -> bool {
        self.mixed_eras
    }

    pub(crate) fn endpoint(self) -> &'a str {
        self.endpoint
    }

    pub(crate) fn headers(self) -> Result<HeaderMap, MidnightPreprodPreflightError> {
        let preprod = self.endpoint == INDEXER_ROUTE
            || self.endpoint == INDEXER_SOCKET_ROUTE
            || is_preprod_node_route(self.endpoint);
        match (preprod, self.credential) {
            (true, Some(credential)) => credential.headers(),
            (true, None) => Err(MidnightPreprodPreflightError::InvalidCredential),
            (false, Some(_)) => Err(MidnightPreprodPreflightError::InvalidRoute),
            (false, None) => Ok(HeaderMap::new()),
        }
    }

    pub(crate) fn graphql_request(self) -> Result<Request, MidnightPreprodPreflightError> {
        let mut request = self
            .endpoint
            .into_client_request()
            .map_err(|_| MidnightPreprodPreflightError::InvalidRoute)?;
        request.headers_mut().extend(self.headers()?);
        request.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static("graphql-transport-ws"),
        );
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MidnightPublicChainPreflightError {
    InvalidCredential,
    InvalidRoute,
    NodeUnavailable,
    GenesisMismatch,
    IndexerUnavailable,
    IndexerWebsocketUnavailable,
    ChainViewMismatch,
    IncompatibleRuntime,
}

/// Preserves the error type used by the Blockfrost PreProd entry point.
pub type MidnightPreprodPreflightError = MidnightPublicChainPreflightError;

impl fmt::Display for MidnightPublicChainPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredential => "Blockfrost PreProd project ID is invalid",
            Self::InvalidRoute => "authenticated Midnight route is invalid",
            Self::NodeUnavailable => "authenticated Midnight node is unavailable",
            Self::GenesisMismatch => "Midnight node genesis differs from the signed profile",
            Self::IndexerUnavailable => "authenticated Midnight indexer is unavailable",
            Self::IndexerWebsocketUnavailable => {
                "authenticated Midnight GraphQL WebSocket is unavailable"
            }
            Self::ChainViewMismatch => "Midnight node and indexer disagree on the indexed block",
            Self::IncompatibleRuntime => {
                "Midnight runtime does not match the supported Ledger 9 release"
            }
        })
    }
}

impl std::error::Error for MidnightPublicChainPreflightError {}

/// Checks the signed node genesis and compares the indexer tip to the node's
/// canonical hash. The caller supplies public routes from a verified profile.
pub async fn preflight_blockfrost_preprod(
    node_url: &str,
    indexer_url: &str,
    indexer_websocket_url: &str,
    genesis_hash: &[u8; 32],
    credential: &MidnightPreprodCredential,
) -> Result<u64, MidnightPreprodPreflightError> {
    if !is_preprod_node_route(node_url)
        || indexer_url != INDEXER_ROUTE
        || indexer_websocket_url != INDEXER_SOCKET_ROUTE
    {
        return Err(MidnightPreprodPreflightError::InvalidRoute);
    }
    verify_public_chain(
        node_url,
        indexer_url,
        indexer_websocket_url,
        genesis_hash,
        Some(credential),
    )
    .await
}

pub(crate) async fn verify_public_chain(
    node_url: &str,
    indexer_url: &str,
    indexer_websocket_url: &str,
    genesis_hash: &[u8; 32],
    credential: Option<&MidnightPreprodCredential>,
) -> Result<u64, MidnightPublicChainPreflightError> {
    use MidnightPublicChainPreflightError as Error;

    let node_headers = MidnightTransportRoute::new(node_url, credential).headers()?;
    let client = timeout(
        PREFLIGHT_TIMEOUT,
        connect_json_rpc_websocket_with_headers(node_url, node_headers),
    )
    .await
    .map_err(|_| Error::NodeUnavailable)?
    .map_err(|_| Error::NodeUnavailable)?;
    let node = LegacyRpcMethods::<SubstrateConfig>::new(RpcClient::new(client));
    let genesis = timeout(
        PREFLIGHT_TIMEOUT,
        node.chain_get_block_hash(Some(0_u64.into())),
    )
    .await
    .map_err(|_| Error::NodeUnavailable)?
    .map_err(|_| Error::NodeUnavailable)?
    .ok_or(Error::NodeUnavailable)?;
    if genesis.0 != *genesis_hash {
        return Err(Error::GenesisMismatch);
    }
    let (height, indexed_hash, indexed_runtime) =
        fetch_identified_chain_tip(MidnightTransportRoute::new(indexer_url, credential))
            .await
            .map_err(|_| Error::IndexerUnavailable)?;
    let node_hash = timeout(
        PREFLIGHT_TIMEOUT,
        node.chain_get_block_hash(Some(height.into())),
    )
    .await
    .map_err(|_| Error::NodeUnavailable)?
    .map_err(|_| Error::NodeUnavailable)?
    .filter(|hash| hash.0 == indexed_hash)
    .ok_or(Error::ChainViewMismatch)?;
    let node_runtime = timeout(
        PREFLIGHT_TIMEOUT,
        node.state_get_runtime_version(Some(node_hash)),
    )
    .await
    .map_err(|_| Error::NodeUnavailable)?
    .map_err(|_| Error::NodeUnavailable)?;
    if node_runtime.spec_version != LEDGER9_RUNTIME_SPEC || indexed_runtime != LEDGER9_RUNTIME_SPEC
    {
        return Err(Error::IncompatibleRuntime);
    }
    verify_graphql_transport(MidnightTransportRoute::new(
        indexer_websocket_url,
        credential,
    ))
    .await
    .map_err(|_| Error::IndexerWebsocketUnavailable)?;
    Ok(height)
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
    fn exact_graphql_upgrade_carries_a_sensitive_header_and_public_uri() {
        let credential = credential();
        let route = MidnightTransportRoute::new(INDEXER_SOCKET_ROUTE, Some(&credential));
        let request = route.graphql_request().unwrap();
        assert_eq!(request.uri().to_string(), INDEXER_SOCKET_ROUTE);
        assert_eq!(
            request.headers()["sec-websocket-protocol"],
            "graphql-transport-ws"
        );
        assert!(request.headers()["project_id"].is_sensitive());
        assert!(!format!("{request:?}").contains(PROJECT_PREFIX));

        let without = MidnightTransportRoute::new(INDEXER_SOCKET_ROUTE, None);
        assert_eq!(
            without.graphql_request().unwrap_err(),
            MidnightPreprodPreflightError::InvalidCredential
        );
        let unrelated =
            MidnightTransportRoute::new("wss://example.test/api/v0/ws", Some(&credential));
        assert_eq!(
            unrelated.graphql_request().unwrap_err(),
            MidnightPreprodPreflightError::InvalidRoute
        );
        let local = MidnightTransportRoute::new("ws://127.0.0.1:10", None);
        assert!(
            !local
                .graphql_request()
                .unwrap()
                .headers()
                .contains_key("project_id")
        );
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
                    INDEXER_SOCKET_ROUTE,
                    &[0; 32],
                    &credential,
                )),
                Err(MidnightPreprodPreflightError::InvalidRoute)
            );
        }
    }
}
