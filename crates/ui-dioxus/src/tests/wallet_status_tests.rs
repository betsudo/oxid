// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn wallet_status_separates_live_night_dust_balance_and_registration() {
    use oxid_wallet_application::{
        ChainNetworkId, SelectedWalletRealmActionReadiness, SelectedWalletRealmIdentity,
        SelectedWalletRealmObservation, SelectedWalletRealmSpendableNightView,
        WalletDustRegistrationSettlementIdentity, WalletDustRegistrationSettlementState,
        WalletProfileId,
    };
    use selected_realm_sync::{wallet_dust_observed_amount, wallet_dust_status};

    let identity = SelectedWalletRealmIdentity {
        profile: WalletProfileId::parse("profile_wallet_status").unwrap(),
        realm: ChainNetworkId::parse("undeployed").unwrap(),
    };
    let mut dust = dust_status("synced", Some(2), Some(2));
    dust.balance_atomic_units = Some("0".to_owned());
    let mut realm = SelectedWalletRealmProjection {
        generation: 7,
        revision: 2,
        fresh: true,
        consistent: true,
        actionable: SelectedWalletRealmActionReadiness::Ready,
        observation: SelectedWalletRealmObservation::Settled,
        spendable_night: SelectedWalletRealmSpendableNightView::Zero,
        view: selected_realm_status(
            WalletSyncState::Synced,
            dust.clone(),
            shielded_status("synced", Some(2), Some(2)),
        ),
        identity,
    };
    let mut settlement = WalletDustSettlementProjection::default();
    settlement.identity = Some(WalletDustRegistrationSettlementIdentity {
        profile: realm.identity.profile.clone(),
        realm: realm.identity.realm.clone(),
        generation: realm.generation,
    });

    assert_eq!(
        selected_realm_sync::selected_realm_account_state(&realm.view.account),
        "synced"
    );
    if let WalletRealmFamilyView::Ready(account) = &mut realm.view.account {
        account.source = WalletAccountSource::Cached;
    }
    assert_eq!(
        selected_realm_sync::selected_realm_account_state(&realm.view.account),
        "cached",
        "a retained account snapshot must not present as current"
    );
    assert_eq!(selected_realm_sync_state(&realm.view), "cached");
    if let WalletRealmFamilyView::Ready(account) = &mut realm.view.account {
        account.sync.state = WalletSyncState::Stalled;
    }
    assert_eq!(
        selected_realm_sync::selected_realm_account_state(&realm.view.account),
        "stalled",
        "a cached snapshot that stops recovering must remain retryable"
    );
    assert_eq!(selected_realm_sync_state(&realm.view), "stalled");
    if let WalletRealmFamilyView::Ready(account) = &mut realm.view.account {
        account.source = WalletAccountSource::Live;
        account.sync.state = WalletSyncState::Synced;
    }
    assert_eq!(
        wallet_dust_observed_amount(&realm.view.dust).as_deref(),
        Some("0 DUST")
    );
    for (state, expected) in [
        (
            WalletDustRegistrationSettlementState::NotEligible,
            "Waiting for eligible NIGHT",
        ),
        (
            WalletDustRegistrationSettlementState::Submitting,
            "Registering",
        ),
        (
            WalletDustRegistrationSettlementState::Confirming,
            "Waiting for Midnight",
        ),
        (
            WalletDustRegistrationSettlementState::Degraded,
            "Needs attention",
        ),
        (
            WalletDustRegistrationSettlementState::Ready,
            "No spendable DUST",
        ),
    ] {
        settlement.state = state;
        assert_eq!(wallet_dust_status(&realm, &settlement).0, expected);
    }

    dust.balance_atomic_units = None;
    realm.view.dust = WalletRealmFamilyView::Ready(dust.clone());
    assert_eq!(wallet_dust_observed_amount(&realm.view.dust), None);
    assert_eq!(
        wallet_dust_status(&realm, &settlement).0,
        "Updating balance"
    );
    dust.balance_atomic_units = Some("1".to_owned());
    realm.view.dust = WalletRealmFamilyView::Ready(dust.clone());
    assert_eq!(wallet_dust_status(&realm, &settlement).0, "Ready");

    if let WalletRealmFamilyView::Ready(account) = &mut realm.view.account {
        account.source = WalletAccountSource::Cached;
    }
    assert_eq!(selected_realm_sync_state(&realm.view), "cached");
    assert_eq!(
        wallet_dust_status(&realm, &settlement).0,
        "Ready",
        "a fresh DUST observation remains independent from a stale NIGHT snapshot"
    );
    if let WalletRealmFamilyView::Ready(account) = &mut realm.view.account {
        account.source = WalletAccountSource::Live;
    }

    dust.state = "cached".to_owned();
    realm.view.dust = WalletRealmFamilyView::Ready(dust.clone());
    assert_eq!(
        wallet_dust_observed_amount(&realm.view.dust).as_deref(),
        Some("0.000000000000001 DUST · last known")
    );
    assert_eq!(
        wallet_dust_status(&realm, &settlement).0,
        "Updating balance",
        "a retained DUST amount is not spend-ready"
    );

    dust.state = "synced".to_owned();
    realm.view.dust = WalletRealmFamilyView::Ready(dust);
    settlement.state = WalletDustRegistrationSettlementState::Degraded;
    realm.generation += 1;
    assert_eq!(wallet_dust_status(&realm, &settlement).0, "Ready");
    settlement.identity.as_mut().unwrap().generation = realm.generation;
    realm.identity.profile = WalletProfileId::parse("profile_other").unwrap();
    assert_eq!(wallet_dust_status(&realm, &settlement).0, "Ready");
    settlement.identity.as_mut().unwrap().profile = realm.identity.profile.clone();
    realm.identity.realm = ChainNetworkId::parse("preprod").unwrap();
    assert_eq!(wallet_dust_status(&realm, &settlement).0, "Ready");
}
