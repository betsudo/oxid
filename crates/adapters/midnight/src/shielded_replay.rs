// SPDX-License-Identifier: Apache-2.0

use midnight_storage::DefaultDB;
use midnight_zswap::{keys::SecretKeys, local::State};

use crate::{
    replay_era::{LedgerEra, ReplayEvent},
    shielded::{ShieldedReplayError, replay_zswap_events},
};

#[cfg(feature = "mixed-era-replay")]
use midnight_legacy_storage::DefaultDB as LegacyDb;
#[cfg(feature = "mixed-era-replay")]
use midnight_legacy_zswap::{keys::SecretKeys as LegacyKeys, local::State as LegacyState};

#[derive(Clone, Debug)]
pub(crate) enum ShieldedReplayState {
    Current(State<DefaultDB>),
    #[cfg(feature = "mixed-era-replay")]
    Legacy(LegacyState<LegacyDb>),
}

impl ShieldedReplayState {
    pub(crate) fn current(&self) -> Option<&State<DefaultDB>> {
        match self {
            Self::Current(state) => Some(state),
            #[cfg(feature = "mixed-era-replay")]
            Self::Legacy(_) => None,
        }
    }

    pub(crate) fn into_current(self) -> Option<State<DefaultDB>> {
        match self {
            Self::Current(state) => Some(state),
            #[cfg(feature = "mixed-era-replay")]
            Self::Legacy(_) => None,
        }
    }
}

pub(crate) struct ShieldedReplayKeys<'a> {
    current: &'a SecretKeys,
    #[cfg(feature = "mixed-era-replay")]
    legacy: Option<LegacyKeys>,
}

impl<'a> ShieldedReplayKeys<'a> {
    pub(crate) fn new(current: &'a SecretKeys, seed: Option<&[u8; 32]>) -> Self {
        #[cfg(not(feature = "mixed-era-replay"))]
        let _ = seed;
        Self {
            current,
            #[cfg(feature = "mixed-era-replay")]
            legacy: seed
                .map(|seed| LegacyKeys::from(midnight_legacy_zswap::keys::Seed::from(*seed))),
        }
    }
}

pub(crate) fn replay_shielded_batch(
    state: Option<ShieldedReplayState>,
    keys: &ShieldedReplayKeys<'_>,
    events: &[ReplayEvent],
) -> Result<ShieldedReplayState, ShieldedReplayError> {
    let invalid = ShieldedReplayError::InvalidEvent;
    let era = events.first().ok_or(invalid)?.era();
    if events.iter().any(|event| event.era() != era) {
        return Err(invalid);
    }
    match era {
        LedgerEra::V9 => {
            let state = match state {
                Some(ShieldedReplayState::Current(state)) => state,
                #[cfg(feature = "mixed-era-replay")]
                Some(ShieldedReplayState::Legacy(state)) => carry_shielded_state(&state)?,
                None => State::new(),
            };
            replay_zswap_events(
                keys.current,
                state,
                events.iter().filter_map(|event| match event {
                    ReplayEvent::Current(event) => Some(event),
                    #[cfg(feature = "mixed-era-replay")]
                    ReplayEvent::Legacy(_) => None,
                }),
            )
            .map(ShieldedReplayState::Current)
        }
        #[cfg(feature = "mixed-era-replay")]
        LedgerEra::V8 => {
            let mut state = match state {
                Some(ShieldedReplayState::Legacy(state)) => state,
                Some(ShieldedReplayState::Current(_)) => return Err(invalid),
                None => LegacyState::new(),
            };
            let keys = keys.legacy.as_ref().ok_or(invalid)?;
            for event in events {
                let ReplayEvent::Legacy(event) = event else {
                    return Err(invalid);
                };
                apply_legacy_event(&mut state, keys, event)?;
            }
            state.merkle_tree = state.merkle_tree.rehash();
            Ok(ShieldedReplayState::Legacy(state))
        }
        #[cfg(not(feature = "mixed-era-replay"))]
        LedgerEra::V8 => Err(invalid),
    }
}

#[cfg(feature = "mixed-era-replay")]
fn carry_shielded_state(
    legacy: &LegacyState<LegacyDb>,
) -> Result<State<DefaultDB>, ShieldedReplayError> {
    const MAX_STATE_BYTES: usize = crate::shielded_checkpoint::MAX_STATE_BYTES;
    let invalid = |_| ShieldedReplayError::InvalidEvent;
    let mut bytes = Vec::new();
    midnight_legacy_serialize::tagged_serialize(legacy, &mut bytes).map_err(invalid)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ShieldedReplayError::InvalidEvent);
    }
    // Both supported ledgers use zswap-local-state[v6]. Inputs reserved
    // by old-era transactions remain owned, but their reservation expires.
    let mut current: State<DefaultDB> =
        midnight_serialize::tagged_deserialize(&bytes[..]).map_err(invalid)?;
    current.pending_spends = Default::default();
    Ok(current)
}

#[cfg(feature = "mixed-era-replay")]
fn apply_legacy_event(
    state: &mut LegacyState<LegacyDb>,
    keys: &LegacyKeys,
    event: &midnight_legacy_ledger::events::Event<LegacyDb>,
) -> Result<(), ShieldedReplayError> {
    use midnight_legacy_coin_structure::transfer::{Recipient, SenderEvidence};
    use midnight_legacy_ledger::events::EventDetails;
    use std::borrow::Cow;

    match &event.content {
        EventDetails::ZswapOutput {
            commitment,
            preimage_evidence,
            mt_index,
            ..
        } => {
            if *mt_index != state.first_free {
                return Err(ShieldedReplayError::NonLinearCommitment);
            }
            state.merkle_tree = state
                .merkle_tree
                .try_update_hash(*mt_index, commitment.0, ())
                .map_err(|_| ShieldedReplayError::InvalidCommitmentTree)?;
            state.first_free = state
                .first_free
                .checked_add(1)
                .ok_or(ShieldedReplayError::InvalidCommitmentTree)?;

            let pending = state.pending_outputs.get(commitment).copied();
            let owned = pending.or_else(|| preimage_evidence.try_with_keys(keys));
            if let Some(coin) = owned.filter(|coin| {
                coin.commitment(&Recipient::User(keys.coin_public_key())) == *commitment
            }) {
                let nullifier =
                    coin.nullifier(&SenderEvidence::User(Cow::Borrowed(&keys.coin_secret_key)));
                state.coins = state.coins.insert(nullifier, coin.qualify(*mt_index));
                state.pending_outputs = state.pending_outputs.remove(commitment);
            } else {
                state.merkle_tree = state.merkle_tree.collapse(*mt_index, *mt_index);
            }
        }
        EventDetails::ZswapInput { nullifier, .. } => {
            state.coins = state.coins.remove(nullifier);
            state.pending_spends = state.pending_spends.remove(nullifier);
        }
        _ => return Err(ShieldedReplayError::InvalidEvent),
    }
    Ok(())
}
