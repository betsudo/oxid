// SPDX-License-Identifier: Apache-2.0

use midnight_ledger::dust::{DustLocalState, DustParameters, DustSecretKey};
use midnight_storage::DefaultDB;
use oxid_wallet_application::WalletTransactionPortError;

use crate::replay_era::{LedgerEra, ReplayEvent};

#[cfg(feature = "mixed-era-replay")]
use midnight_legacy_ledger::{
    dust::{DustLocalState as LegacyState, DustSecretKey as LegacyKey},
    structure::INITIAL_PARAMETERS as LEGACY_INITIAL_PARAMETERS,
};
#[cfg(feature = "mixed-era-replay")]
use midnight_legacy_storage::DefaultDB as LegacyDb;

#[derive(Clone, Debug)]
pub(crate) enum DustReplayState {
    Current(DustLocalState<DefaultDB>),
    #[cfg(feature = "mixed-era-replay")]
    Legacy(LegacyState<LegacyDb>),
}

impl DustReplayState {
    pub(crate) fn current(&self) -> Option<&DustLocalState<DefaultDB>> {
        match self {
            Self::Current(state) => Some(state),
            #[cfg(feature = "mixed-era-replay")]
            Self::Legacy(_) => None,
        }
    }

    pub(crate) fn into_current(
        self,
    ) -> Result<DustLocalState<DefaultDB>, WalletTransactionPortError> {
        match self {
            Self::Current(state) => Ok(state),
            #[cfg(feature = "mixed-era-replay")]
            Self::Legacy(_) => Err(WalletTransactionPortError::Timeout),
        }
    }
}

pub(crate) struct DustReplayKeys<'a> {
    pub(crate) current: &'a DustSecretKey,
    #[cfg(feature = "mixed-era-replay")]
    legacy: Option<LegacyKey>,
}

impl<'a> DustReplayKeys<'a> {
    pub(crate) fn new(current: &'a DustSecretKey, seed: Option<&[u8; 32]>) -> Self {
        #[cfg(not(feature = "mixed-era-replay"))]
        let _ = seed;
        Self {
            current,
            #[cfg(feature = "mixed-era-replay")]
            legacy: seed.map(LegacyKey::derive_secret_key),
        }
    }
}

/// The caller groups events by era and persists the successful replay boundary.
pub(crate) fn replay_dust_batch(
    state: Option<&DustReplayState>,
    keys: &DustReplayKeys<'_>,
    parameters: DustParameters,
    events: &[ReplayEvent],
) -> Result<DustReplayState, WalletTransactionPortError> {
    let invalid = WalletTransactionPortError::InvalidChainState;
    let era = events.first().ok_or(invalid)?.era();
    if events.iter().any(|event| event.era() != era) {
        return Err(invalid);
    }
    match era {
        LedgerEra::V9 => {
            // The Ledger 9 fork resets DUST. The checkpoint cursor stays with
            // the caller, while the previous era's DUST tree is discarded.
            let initial;
            let state = match state.and_then(DustReplayState::current) {
                Some(state) => state,
                None => {
                    initial = DustLocalState::new(parameters);
                    &initial
                }
            };
            state
                .replay_events(
                    keys.current,
                    events.iter().filter_map(|event| match event {
                        ReplayEvent::Current(event) => Some(event),
                        #[cfg(feature = "mixed-era-replay")]
                        ReplayEvent::Legacy(_) => None,
                    }),
                )
                .map(DustReplayState::Current)
                .map_err(|_| invalid)
        }
        #[cfg(feature = "mixed-era-replay")]
        LedgerEra::V8 => {
            let key = keys.legacy.as_ref().ok_or(invalid)?;
            let initial;
            let state = match state {
                Some(DustReplayState::Legacy(state)) => state,
                Some(DustReplayState::Current(_)) => return Err(invalid),
                None => {
                    initial = LegacyState::new(LEGACY_INITIAL_PARAMETERS.dust);
                    &initial
                }
            };
            state
                .replay_events(
                    key,
                    events.iter().filter_map(|event| match event {
                        ReplayEvent::Legacy(event) => Some(event),
                        ReplayEvent::Current(_) => None,
                    }),
                )
                .map(DustReplayState::Legacy)
                .map_err(|_| invalid)
        }
        #[cfg(not(feature = "mixed-era-replay"))]
        LedgerEra::V8 => Err(invalid),
    }
}
