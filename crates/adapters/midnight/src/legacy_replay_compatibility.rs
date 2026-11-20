// SPDX-License-Identifier: Apache-2.0

use midnight_legacy_coin_structure::coin::{Info, Nonce, ShieldedTokenType};
use midnight_legacy_storage::DefaultDB as LegacyDb;
use midnight_legacy_zswap::{
    keys::{SecretKeys, Seed},
    local::State,
};
use midnight_storage::DefaultDB;
use midnight_zswap::local::State as CurrentState;

#[test]
fn shielded_wallet_keeps_coins_tree_and_pending_outputs_at_the_ledger_fork() {
    let keys = SecretKeys::from(Seed::from([0x35; 32]));
    let coin = Info {
        nonce: Nonce(Default::default()),
        type_: ShieldedTokenType(Default::default()),
        value: 37,
    };
    let pending = Info { value: 89, ..coin };
    let legacy = State::<LegacyDb>::new()
        .insert_coin(&keys, coin)
        .expect("Legacy ledger admits the owned fixture output")
        .watch_for(&keys.coin_public_key(), &pending);
    assert_eq!(legacy.coins.iter().count(), 1);
    assert_eq!(legacy.pending_outputs.iter().count(), 1);

    let mut before = Vec::new();
    midnight_legacy_serialize::tagged_serialize(&legacy, &mut before)
        .expect("Ledger 8 emits the shielded wallet checkpoint");
    let current: CurrentState<DefaultDB> = midnight_serialize::tagged_deserialize(&before[..])
        .expect("Ledger 9 reads the original shielded state bytes");
    assert_eq!(current.first_free, 1);
    assert_eq!(current.coins.iter().count(), 1);
    assert_eq!(current.pending_outputs.iter().count(), 1);

    let mut after = Vec::new();
    midnight_serialize::tagged_serialize(&current, &mut after)
        .expect("Ledger 9 serializes the carried shielded wallet");
    assert_eq!(after, before);
}

#[test]
fn legacy_event_codec_is_distinct_from_the_current_ledger() {
    use midnight_legacy_serialize::Tagged as LegacyTagged;
    use midnight_serialize::Tagged as CurrentTagged;
    assert_eq!(
        <midnight_legacy_ledger::events::Event<LegacyDb> as LegacyTagged>::tag(),
        "event[v9]"
    );
    assert_eq!(
        <midnight_ledger::events::Event<DefaultDB> as CurrentTagged>::tag(),
        "event[v14]"
    );
}

pub(crate) fn private_checkpoint_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().expect("a private checkpoint directory")
}
