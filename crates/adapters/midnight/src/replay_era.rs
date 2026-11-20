// SPDX-License-Identifier: Apache-2.0

use midnight_ledger::events::Event;
use midnight_storage::DefaultDB;

#[cfg(feature = "mixed-era-replay")]
use midnight_legacy_ledger::events::Event as LegacyEvent;
#[cfg(feature = "mixed-era-replay")]
use midnight_legacy_storage::DefaultDB as LegacyDb;

use serde_json::Value;

pub(crate) fn has_mixed_history(network_id: &str) -> bool {
    matches!(network_id, "preview" | "preprod")
}

/// Midnight node spec version at the Ledger 9 upgrade.
const LEDGER_9_PROTOCOL_VERSION: u64 = 2_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerEra {
    V8,
    V9,
}

pub(crate) fn replay_era(data: &Value, mixed_eras: bool) -> Option<LedgerEra> {
    match data.get("protocolVersion") {
        None if !mixed_eras => Some(LedgerEra::V9),
        Some(version) => match version.as_u64()? {
            0 => None,
            1..LEDGER_9_PROTOCOL_VERSION if mixed_eras => Some(LedgerEra::V8),
            LEDGER_9_PROTOCOL_VERSION.. => Some(LedgerEra::V9),
            _ => None,
        },
        None => None,
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ReplayEvent {
    Current(Event<DefaultDB>),
    #[cfg(feature = "mixed-era-replay")]
    Legacy(LegacyEvent<LegacyDb>),
}

impl ReplayEvent {
    pub(crate) fn decode(era: LedgerEra, bytes: &[u8]) -> Option<Self> {
        match era {
            LedgerEra::V9 => midnight_serialize::tagged_deserialize(bytes)
                .map(Self::Current)
                .ok(),
            #[cfg(feature = "mixed-era-replay")]
            LedgerEra::V8 => midnight_legacy_serialize::tagged_deserialize(bytes)
                .map(Self::Legacy)
                .ok(),
            #[cfg(not(feature = "mixed-era-replay"))]
            LedgerEra::V8 => None,
        }
    }

    pub(crate) fn era(&self) -> LedgerEra {
        match self {
            Self::Current(_) => LedgerEra::V9,
            #[cfg(feature = "mixed-era-replay")]
            Self::Legacy(_) => LedgerEra::V8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn public_replay_requires_valid_protocol_version() {
        for invalid in [
            json!({}),
            json!({"protocolVersion": 0}),
            json!({"protocolVersion": "2000000"}),
        ] {
            assert_eq!(replay_era(&invalid, true), None);
        }
        assert_eq!(
            replay_era(&json!({"protocolVersion": 1999999}), true),
            Some(LedgerEra::V8)
        );
        assert_eq!(
            replay_era(&json!({"protocolVersion": 2000000}), true),
            Some(LedgerEra::V9)
        );
        assert_eq!(
            replay_era(&json!({"protocolVersion": 1999999}), false),
            None
        );
        assert_eq!(replay_era(&json!({}), false), Some(LedgerEra::V9));
    }
}
