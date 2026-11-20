// SPDX-License-Identifier: Apache-2.0

pub(super) mod action_watch;
pub(crate) mod dust_authorization;

use super::*;
use oxid_wallet_application::WalletDustRegistrationSettlementState as DustSettlement;

#[component]
pub(super) fn AccountSyncCard(
    profile_id: String,
    secret_mode: SecretModeController,
    can_sync: bool,
    account_unavailable: bool,
    on_account_updated: EventHandler<WalletAccountView>,
) -> Element {
    let services = consume_context::<WalletUiServices>();
    let mut realm_lifecycle_wake = consume_context::<Signal<WalletRealmLifecycleWake>>();
    let WalletRealmProjectionWake(realm_projection_wake) =
        consume_context::<WalletRealmProjectionWake>();
    let dust_settlement_port = services.wallet_dust_settlement();
    let mut dust_settlement = use_signal(|| dust_settlement_port.subscribe().borrow().clone());
    use_future(move || {
        let mut subscription = dust_settlement_port.subscribe();
        async move {
            loop {
                let next = subscription.borrow_and_update().clone();
                if *dust_settlement.peek() != next {
                    dust_settlement.set(next);
                }
                if subscription.changed().await.is_err() {
                    break;
                }
            }
        }
    });
    let state = use_signal(|| AccountSyncCardState::Loading);
    let load_services = services.clone();
    let load_profile = profile_id.clone();
    use_effect(move || {
        let _projection_generation = realm_projection_wake();
        let _settlement_observation = dust_settlement.read();
        begin_account_sync_card_observation(
            load_services.clone(),
            load_profile.clone(),
            state,
            on_account_updated,
        );
    });

    match state.read().clone() {
        AccountSyncCardState::Loading => rsx! {
            article { class: "surface-card account-sync-card", role: "status", aria_busy: "true",
                p { class: "card-eyebrow", "Account sync" }
                h2 { "Loading wallet status…" }
            }
        },
        AccountSyncCardState::Failed(message) => {
            let retry_services = services.clone();
            let retry_profile = profile_id.clone();
            rsx! {
                article { class: "surface-card account-sync-card", role: "alert",
                    div { class: "wallet-sync-row__heading",
                        div {
                            p { class: "card-eyebrow", "Account sync" }
                            h2 { "Status unavailable" }
                        }
                        span { class: "status-pill", "Error" }
                    }
                    p { "{message}" }
                    button {
                        class: "secondary-action",
                        r#type: "button",
                        onclick: move |_| {
                            reload_account_sync_card(
                                retry_services.clone(),
                                retry_profile.clone(),
                                state,
                                on_account_updated,
                            );
                        },
                        "Retry"
                    }
                }
            }
        }
        AccountSyncCardState::Ready {
            realm: projection,
            action_busy,
            operation_error,
        } => {
            let retained_projection = projection.clone();
            let realm = &projection.view;
            let syncing = selected_realm_is_syncing(realm);
            let overall_state = selected_realm_sync_state(realm);
            let lifecycle = selected_realm_lifecycle_presentation(overall_state);
            let account_state = selected_realm_sync::selected_realm_account_state(&realm.account);
            let account_status = selected_realm_lifecycle_presentation(account_state);
            let settlement = dust_settlement.read();
            let review = dust_authorization::protected_review(
                services.wallet_dust_settlement().as_ref(),
                &projection,
                &settlement,
            );
            let (dust_label, dust_tone) = if review.is_some() {
                ("Review needed", "syncing")
            } else {
                wallet_dust_status(&projection, &settlement)
            };
            drop(settlement);
            let observed_dust = selected_realm_sync::wallet_dust_observed_amount(&realm.dust);
            let provenance = selected_realm_provenance(realm);
            let chain_tip = selected_realm_chain_tip(realm);
            let progress = selected_realm_sync_progress(realm);
            let dust_balance = selected_realm_dust_balance(&realm.dust);
            let dust_state = selected_realm_dust_state(&realm.dust);
            let dust_progress = match &realm.dust {
                WalletRealmFamilyView::Ready(status) if dust_state == "syncing" => {
                    dust_progress_percent(status)
                }
                _ => None,
            };
            let dust_note = selected_realm_dust_note(&realm.dust);
            let shielded_night = selected_realm_shielded_balance(&realm.shielded);
            let shielded_state = selected_realm_shielded_state(&realm.shielded);
            let shielded_note = selected_realm_shielded_note(&realm.shielded);
            let owned_notes = match &realm.shielded {
                WalletRealmFamilyView::Ready(status) => status
                    .owned_note_count
                    .map_or_else(|| "—".to_owned(), |count| count.to_string()),
                _ => "—".to_owned(),
            };
            let retained_realm = retained_projection.clone();
            let action_services = services.clone();
            let action_profile = profile_id.clone();
            let mut action_state = state;
            rsx! {
                article { class: "surface-card account-sync-card",
                    div { class: "wallet-sync-row__heading",
                        div {
                            p { class: "card-eyebrow", "Selected realm" }
                            h2 { "Wallet status" }
                        }
                    }
                    div { class: "account-sync-card__rows", "data-testid": "wallet-status-facets",
                        div { class: "account-sync-card__row", "data-testid": "wallet-night-status",
                            strong { "NIGHT sync" }
                            span { class: "{dust_status_pill_class(account_state)}", "{account_status.label}" }
                        }
                        div { class: "account-sync-card__row", "data-testid": "wallet-dust-status",
                            div {
                                strong { "DUST" }
                                if let Some(amount) = observed_dust.as_deref() {
                                    small {
                                        class: "privacy-value",
                                        "data-testid": "wallet-dust-amount",
                                        aria_hidden: if secret_mode.is_masked() { "true" } else { "false" },
                                        "{amount}"
                                    }
                                } else {
                                    small { "Balance unavailable" }
                                }
                            }
                            span {
                                class: "{dust_status_pill_class(dust_tone)}",
                                role: "status",
                                aria_label: "DUST {dust_label}",
                                "{dust_label}"
                            }
                        }
                    }
                    if let Some(review) = review {
                        dust_authorization::ProtectedDustReviewCard {
                            key: "{projection.identity.profile.as_str()}-{projection.identity.realm.as_str()}-{projection.generation}",
                            review,
                        }
                    }
                    if lifecycle.retry {
                        p { class: "account-sync-card__summary", "{lifecycle.note}" }
                    }
                    if let Some(percent) = dust_progress {
                        div { class: "wallet-sync-progress", role: "progressbar",
                            aria_label: "DUST synchronization progress",
                            aria_valuemin: "0", aria_valuemax: "100", aria_valuenow: "{percent}",
                            div { class: "wallet-sync-progress__bar", style: "width: {percent}%" }
                        }
                    }
                    if cfg!(feature = "ui-profile-dev") {
                    details { class: "account-sync-card__details",
                        summary { "Synchronization details" }
                        p { class: "account-sync-card__provenance", "{provenance}" }
                        p { class: "account-sync-card__provenance", "{chain_tip}" }
                        div { class: "account-sync-card__rows",
                            div { class: "account-sync-card__row",
                                div {
                                    strong {
                                        class: "privacy-value",
                                        aria_hidden: if secret_mode.is_masked() { "true" } else { "false" },
                                        "{dust_balance}"
                                    }
                                    small { "{dust_note}" }
                                }
                                span { class: "{dust_status_pill_class(dust_state)}", "{ui::sync_state(dust_state)}" }
                            }
                            div { class: "account-sync-card__row",
                                div {
                                    strong {
                                        class: "privacy-value",
                                        aria_hidden: if secret_mode.is_masked() { "true" } else { "false" },
                                        "{shielded_night}"
                                    }
                                    small {
                                        aria_hidden: if secret_mode.is_masked() { "true" } else { "false" },
                                        "Shielded NIGHT · {owned_notes} protected notes"
                                    }
                                    small { "{shielded_note}" }
                                }
                                span { class: "{dust_status_pill_class(shielded_state)}", "{ui::sync_state(shielded_state)}" }
                            }
                        }
                        if let WalletRealmFamilyView::Ready(shielded) = &realm.shielded {
                            if non_native_shielded_balances(shielded).next().is_some() {
                                div { class: "activity-list", aria_label: "Shielded token balances",
                                    for balance in non_native_shielded_balances(shielded) {
                                        div { class: "activity-row", key: "{balance.token_type_hex}",
                                            span { class: "activity-row__mark", aria_hidden: "true", "◈" }
                                            div {
                                                strong {
                                                    class: "privacy-value",
                                                    aria_hidden: if secret_mode.is_masked() { "true" } else { "false" },
                                                    "{ui::format_shielded_amount(&balance.token_type_hex, &balance.atomic_units)}"
                                                }
                                                small { title: "{balance.token_type_hex}", "Protected token" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    }
                    if let Some(percent) = progress.filter(|_| cfg!(feature = "ui-profile-dev")) {
                        div { class: "wallet-sync-progress", aria_label: "Combined synchronization progress",
                            div { class: "wallet-sync-progress__bar", style: "width: {percent}%" }
                        }
                    }
                    if let Some(message) = operation_error {
                        p { class: "wallet-sync-error", role: "alert", "{message}" }
                    }
                    if lifecycle.retry && !syncing && can_sync && !account_unavailable {
                    button {
                        class: "secondary-action wallet-sync-action",
                        r#type: "button",
                        disabled: action_busy,
                        onclick: move |_| {
                            action_state.set(AccountSyncCardState::Ready {
                                realm: retained_realm.clone(),
                                action_busy: true,
                                operation_error: None,
                            });
                            let services = action_services.clone();
                            let profile_id = action_profile.clone();
                            let retained = retained_realm.clone();
                            spawn(async move {
                                let command = SelectedWalletRealmSyncCommand {
                                    profile_id: profile_id.clone(),
                                };
                                let result = run_ui_future(
                                    wallet_realm_lifecycle::explicit_retry(
                                        services.clone(),
                                        command,
                                    ),
                                )
                                .await;
                                realm_lifecycle_wake.set(
                                    realm_lifecycle_wake().realm_changed(),
                                );
                                match result {
                                    Ok(Ok(updated)) => {
                                        if !account_sync_card_accepts_projection(
                                            &action_state.read(),
                                            &updated,
                                        ) {
                                            finish_account_sync_card_action(action_state, &retained, None);
                                            return;
                                        }
                                        let should_poll = updated.observation.poll_after().is_some();
                                        if let WalletRealmFamilyView::Ready(account) = &updated.view.account {
                                            on_account_updated.call(account.clone());
                                        }
                                        let poll_projection = updated.clone();
                                        action_state.set(AccountSyncCardState::Ready {
                                            realm: Box::new(updated),
                                            action_busy: false,
                                            operation_error: None,
                                        });
                                        if should_poll {
                                            poll_account_sync(
                                                services,
                                                profile_id,
                                                poll_projection,
                                                action_state,
                                                on_account_updated,
                                            );
                                        }
                                    }
                                    Ok(Err(error)) => finish_account_sync_card_action(
                                        action_state,
                                        &retained,
                                        Some(error.to_string()),
                                    ),
                                    Err(error) => finish_account_sync_card_action(
                                        action_state,
                                        &retained,
                                        Some(error.to_string()),
                                    ),
                                }
                            });
                        },
                        if action_busy {
                            "Retrying…"
                        } else {
                            "Retry"
                        }
                    }
                    }
                }
            }
        }
    }
}

pub(super) fn wallet_dust_status(
    realm: &SelectedWalletRealmProjection,
    settlement: &WalletDustSettlementProjection,
) -> (&'static str, &'static str) {
    let state =
        dust_authorization::settlement_matches_realm(realm, settlement).then_some(settlement.state);
    let live_balance = match &realm.view.dust {
        WalletRealmFamilyView::Ready(status)
            if status.state == "synced" && status.failure.is_none() =>
        {
            status
                .balance_atomic_units
                .as_deref()
                .and_then(|value| value.parse::<u128>().ok())
        }
        _ => None,
    };
    match state {
        Some(DustSettlement::NotEligible) if live_balance.unwrap_or(0) == 0 => {
            ("Waiting for eligible NIGHT", "never_synced")
        }
        Some(DustSettlement::ActionRequired) => ("Registration pending", "syncing"),
        Some(DustSettlement::AwaitingAuthorization | DustSettlement::Submitting) => {
            ("Registering", "syncing")
        }
        Some(DustSettlement::Confirming | DustSettlement::Reconciling) => {
            if settlement
                .registration
                .as_ref()
                .is_some_and(|registration| registration.included)
            {
                ("Updating balance", "syncing")
            } else {
                ("Waiting for Midnight", "syncing")
            }
        }
        Some(
            DustSettlement::Cancelled
            | DustSettlement::Offline
            | DustSettlement::TimedOut
            | DustSettlement::Degraded
            | DustSettlement::Suspended,
        ) => ("Needs attention", "stalled"),
        _ => match live_balance {
            Some(1..) => ("Ready", "synced"),
            Some(0) => ("No spendable DUST", "never_synced"),
            None => match selected_realm_dust_state(&realm.view.dust) {
                "synced" if state != Some(DustSettlement::Ready) => {
                    ("Not registered", "never_synced")
                }
                "stalled" | "cancelled" => ("Needs attention", "stalled"),
                "unavailable" | "unsupported" | "invalid_data" => ("Unavailable", "unavailable"),
                _ => ("Updating balance", "syncing"),
            },
        },
    }
}

pub(super) fn wallet_dust_observed_amount(
    family: &WalletRealmFamilyView<WalletDustSyncView>,
) -> Option<String> {
    let WalletRealmFamilyView::Ready(status) = family else {
        return None;
    };
    let value = status.balance_atomic_units.as_deref()?;
    let qualifier = if status.state == "synced" && status.failure.is_none() {
        ""
    } else {
        " · last known"
    };
    Some(format!(
        "{} DUST{qualifier}",
        ui::format_atomic_units(value, ui::DUST_DECIMALS)
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AccountSyncCardState {
    Loading,
    Ready {
        realm: Box<SelectedWalletRealmProjection>,
        action_busy: bool,
        operation_error: Option<String>,
    },
    Failed(String),
}

pub(super) fn load_account_sync_card(
    services: &WalletUiServices,
    profile_id: &str,
) -> AccountSyncCardState {
    services
        .get_selected_wallet_realm_sync()
        .execute(SelectedWalletRealmSyncCommand {
            profile_id: profile_id.to_owned(),
        })
        .map(|realm| AccountSyncCardState::Ready {
            realm: Box::new(realm),
            action_busy: false,
            operation_error: None,
        })
        .unwrap_or_else(|error| AccountSyncCardState::Failed(error.to_string()))
}

pub(super) fn begin_account_sync_card_observation(
    services: WalletUiServices,
    profile_id: String,
    mut state: Signal<AccountSyncCardState>,
    on_account_updated: EventHandler<WalletAccountView>,
) {
    spawn(async move {
        let query_services = services.clone();
        let query_profile = profile_id.clone();
        let loaded =
            run_ui_blocking(move || load_account_sync_card(&query_services, &query_profile))
                .await
                .unwrap_or_else(|error| AccountSyncCardState::Failed(error.to_string()));
        let loaded = match (&*state.peek(), loaded) {
            (
                current @ AccountSyncCardState::Ready { .. },
                AccountSyncCardState::Ready { realm, .. },
            ) => {
                let Some(next) = merge_polled_account_sync_card(current, realm) else {
                    return;
                };
                next
            }
            (AccountSyncCardState::Ready { .. }, AccountSyncCardState::Failed(_)) => return,
            (_, loaded) => loaded,
        };
        let observation = match &loaded {
            AccountSyncCardState::Ready { realm, .. }
                if realm.observation.poll_after().is_some() =>
            {
                Some((**realm).clone())
            }
            _ => None,
        };
        if let AccountSyncCardState::Ready { realm, .. } = &loaded
            && let WalletRealmFamilyView::Ready(account) = &realm.view.account
        {
            on_account_updated.call(account.clone());
        }
        state.set(loaded);
        if let Some(projection) = observation {
            poll_account_sync(services, profile_id, projection, state, on_account_updated);
        }
    });
}

pub(super) fn reload_account_sync_card(
    services: WalletUiServices,
    profile_id: String,
    mut state: Signal<AccountSyncCardState>,
    on_account_updated: EventHandler<WalletAccountView>,
) {
    state.set(AccountSyncCardState::Loading);
    spawn(async move {
        let query_services = services.clone();
        let query_profile = profile_id.clone();
        let loaded =
            run_ui_blocking(move || load_account_sync_card(&query_services, &query_profile))
                .await
                .unwrap_or_else(|error| AccountSyncCardState::Failed(error.to_string()));
        let observation = match &loaded {
            AccountSyncCardState::Ready { realm, .. }
                if realm.observation.poll_after().is_some() =>
            {
                Some((**realm).clone())
            }
            _ => None,
        };
        state.set(loaded);
        if let Some(projection) = observation {
            poll_account_sync(services, profile_id, projection, state, on_account_updated);
        }
    });
}

pub(super) fn poll_account_sync(
    services: WalletUiServices,
    profile_id: String,
    mut expected: SelectedWalletRealmProjection,
    mut state: Signal<AccountSyncCardState>,
    on_account_updated: EventHandler<WalletAccountView>,
) {
    spawn(async move {
        while let Some(delay) = expected.observation.poll_after() {
            tokio::time::sleep(delay).await;
            let worker_services = services.clone();
            let worker_profile = profile_id.clone();
            let result =
                run_ui_blocking(move || load_account_sync_card(&worker_services, &worker_profile))
                    .await;
            match result {
                Ok(AccountSyncCardState::Ready { realm, .. }) => {
                    if !realm.supersedes(&expected) {
                        break;
                    }
                    let next = {
                        let current = state.read();
                        merge_polled_account_sync_card(&current, realm)
                    };
                    let Some(AccountSyncCardState::Ready {
                        realm,
                        action_busy,
                        operation_error,
                    }) = next
                    else {
                        break;
                    };
                    expected = (*realm).clone();
                    let complete = realm.observation.poll_after().is_none();
                    if let WalletRealmFamilyView::Ready(account) = &realm.view.account {
                        on_account_updated.call(account.clone());
                    }
                    state.set(AccountSyncCardState::Ready {
                        realm,
                        action_busy,
                        operation_error,
                    });
                    if complete {
                        break;
                    }
                }
                Ok(AccountSyncCardState::Failed(error)) => {
                    if !poll_still_owns_account_sync_card(&state.read(), &expected) {
                        break;
                    }
                    state.set(AccountSyncCardState::Failed(error));
                    break;
                }
                Ok(AccountSyncCardState::Loading) => {}
                Err(error) => {
                    if !poll_still_owns_account_sync_card(&state.read(), &expected) {
                        break;
                    }
                    state.set(AccountSyncCardState::Failed(error.to_string()));
                    break;
                }
            }
        }
    });
}

fn merge_polled_account_sync_card(
    current: &AccountSyncCardState,
    candidate: Box<SelectedWalletRealmProjection>,
) -> Option<AccountSyncCardState> {
    let AccountSyncCardState::Ready {
        realm,
        action_busy,
        operation_error,
    } = current
    else {
        return None;
    };
    retain_polled_card_feedback(
        candidate.identity == realm.identity,
        (candidate.generation, candidate.revision),
        (realm.generation, realm.revision),
        *action_busy,
        operation_error,
    )
    .map(
        |(action_busy, operation_error)| AccountSyncCardState::Ready {
            realm: candidate,
            action_busy,
            operation_error,
        },
    )
}

pub(super) fn account_sync_card_accepts_projection(
    current: &AccountSyncCardState,
    candidate: &SelectedWalletRealmProjection,
) -> bool {
    matches!(
        current,
        AccountSyncCardState::Ready { realm, .. }
            if candidate.supersedes(realm)
    )
}

pub(super) fn finish_account_sync_card_action(
    mut state: Signal<AccountSyncCardState>,
    expected: &SelectedWalletRealmProjection,
    error: Option<String>,
) {
    let next = match state.read().clone() {
        AccountSyncCardState::Ready {
            realm,
            operation_error,
            ..
        } if realm.generation == expected.generation && realm.supersedes(expected) => {
            Some(AccountSyncCardState::Ready {
                realm,
                action_busy: false,
                operation_error: error.or(operation_error),
            })
        }
        AccountSyncCardState::Loading
        | AccountSyncCardState::Ready { .. }
        | AccountSyncCardState::Failed(_) => None,
    };
    if let Some(next) = next {
        state.set(next);
    }
}

fn retain_polled_card_feedback(
    same_realm: bool,
    candidate_revision: (u64, u64),
    current_revision: (u64, u64),
    action_busy: bool,
    operation_error: &Option<String>,
) -> Option<(bool, Option<String>)> {
    (same_realm && candidate_revision >= current_revision)
        .then(|| (action_busy, operation_error.clone()))
}

fn poll_still_owns_account_sync_card(
    current: &AccountSyncCardState,
    expected: &SelectedWalletRealmProjection,
) -> bool {
    match current {
        AccountSyncCardState::Ready {
            realm, action_busy, ..
        } => poll_owns_current_projection(realm.as_ref() == expected, *action_busy),
        AccountSyncCardState::Loading | AccountSyncCardState::Failed(_) => false,
    }
}

const fn poll_owns_current_projection(same_projection: bool, action_busy: bool) -> bool {
    same_projection && !action_busy
}

pub(super) fn selected_realm_is_syncing(realm: &SelectedWalletRealmSyncView) -> bool {
    selected_realm_dust_state(&realm.dust) == "syncing"
        || selected_realm_shielded_state(&realm.shielded) == "syncing"
}

pub(super) fn selected_realm_sync_state(realm: &SelectedWalletRealmSyncView) -> &str {
    let account = selected_realm_account_state(&realm.account);
    let dust = selected_realm_dust_state(&realm.dust);
    let shielded = selected_realm_shielded_state(&realm.shielded);
    if account == "syncing" || dust == "syncing" || shielded == "syncing" {
        "syncing"
    } else if account == "synced" && dust == "synced" && shielded == "synced" {
        "synced"
    } else if account == "stalled" || dust == "stalled" || shielded == "stalled" {
        "stalled"
    } else if dust == "cancelled" || shielded == "cancelled" {
        "cancelled"
    } else if account == "cached" || dust == "cached" || shielded == "cached" {
        "cached"
    } else if matches!(account, "unsupported" | "unavailable" | "invalid_data")
        || matches!(dust, "unsupported" | "unavailable" | "invalid_data")
        || matches!(shielded, "unsupported" | "unavailable" | "invalid_data")
    {
        "unavailable"
    } else {
        "never_synced"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SelectedRealmLifecyclePresentation {
    pub label: &'static str,
    pub note: &'static str,
    pub retry: bool,
}

/// Product language for the application-owned selected-realm lifecycle.
///
/// Family-specific state remains available to developer diagnostics. The
/// normal wallet surface deliberately presents one aggregate and offers a
/// retry only after automatic recovery has stopped making progress.
pub(super) fn selected_realm_lifecycle_presentation(
    state: &str,
) -> SelectedRealmLifecyclePresentation {
    match state {
        "syncing" | "never_synced" => SelectedRealmLifecyclePresentation {
            label: "Updating",
            note: "Balances and activity update automatically.",
            retry: false,
        },
        "synced" => SelectedRealmLifecyclePresentation {
            label: "Up to date",
            note: "The selected wallet and network are ready.",
            retry: false,
        },
        "cached" => SelectedRealmLifecyclePresentation {
            label: "Updating",
            note: "A saved checkpoint is visible while live state catches up.",
            retry: false,
        },
        "stalled" | "cancelled" => SelectedRealmLifecyclePresentation {
            label: "Needs attention",
            note: "The last consistent state is retained. Try recovery again.",
            retry: true,
        },
        "unavailable" => SelectedRealmLifecyclePresentation {
            label: "Offline",
            note: "The last consistent state is retained until the network returns.",
            retry: true,
        },
        _ => SelectedRealmLifecyclePresentation {
            label: "Action needed",
            note: "Open diagnostics to review the selected wallet and network.",
            retry: true,
        },
    }
}

pub(super) fn selected_realm_provenance(realm: &SelectedWalletRealmSyncView) -> String {
    match &realm.account {
        WalletRealmFamilyView::Ready(account) => format!(
            "{} · {} · {} source",
            account.network_name,
            account.chain,
            ui::account_source(account.source).to_lowercase(),
        ),
        family => format!("Selected realm · {} source", realm_family_source(family)),
    }
}

const fn realm_family_source<T>(family: &WalletRealmFamilyView<T>) -> &'static str {
    match family {
        WalletRealmFamilyView::Ready(_) => "ready",
        WalletRealmFamilyView::Busy => "syncing",
        WalletRealmFamilyView::NotFound => "wallet not active",
        WalletRealmFamilyView::Unsupported => "unsupported",
        WalletRealmFamilyView::ProtectionNotInitialized => "protection not initialized",
        WalletRealmFamilyView::ProtectionLocked => "protection locked",
        WalletRealmFamilyView::Unavailable => "unavailable",
        WalletRealmFamilyView::InvalidData => "invalid data",
    }
}

pub(super) fn selected_realm_chain_tip(realm: &SelectedWalletRealmSyncView) -> String {
    match &realm.account {
        WalletRealmFamilyView::Ready(account) => account.sync.chain_tip_height.map_or_else(
            || "Indexer tip unavailable".to_owned(),
            |height| format!("Indexer tip · block {height}"),
        ),
        _ => "Indexer tip unavailable".to_owned(),
    }
}

pub(super) fn selected_realm_account_state(
    family: &WalletRealmFamilyView<WalletAccountView>,
) -> &str {
    match family {
        WalletRealmFamilyView::Ready(account) => account.sync.state.as_str(),
        WalletRealmFamilyView::Busy => "syncing",
        WalletRealmFamilyView::NotFound => "never_synced",
        _ => "unavailable",
    }
}

pub(super) fn selected_realm_sync_progress(realm: &SelectedWalletRealmSyncView) -> Option<u64> {
    let values = [
        match &realm.dust {
            WalletRealmFamilyView::Ready(status) => dust_progress_percent(status),
            _ => None,
        },
        match &realm.shielded {
            WalletRealmFamilyView::Ready(status) => shielded_progress_percent(status),
            _ => None,
        },
    ];
    let values = values.into_iter().flatten().collect::<Vec<_>>();
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<u64>() / u64::try_from(values.len()).ok()?)
    }
}

pub(super) fn selected_realm_dust_state(
    family: &WalletRealmFamilyView<WalletDustSyncView>,
) -> &str {
    match family {
        WalletRealmFamilyView::Ready(status) => &status.state,
        WalletRealmFamilyView::Busy => "syncing",
        WalletRealmFamilyView::NotFound => "never_synced",
        _ => "unavailable",
    }
}

pub(super) fn selected_realm_shielded_state(
    family: &WalletRealmFamilyView<WalletShieldedSyncView>,
) -> &str {
    match family {
        WalletRealmFamilyView::Ready(status) => &status.state,
        WalletRealmFamilyView::Busy => "syncing",
        WalletRealmFamilyView::NotFound => "never_synced",
        _ => "unavailable",
    }
}

pub(super) fn selected_realm_dust_balance(
    family: &WalletRealmFamilyView<WalletDustSyncView>,
) -> String {
    match family {
        WalletRealmFamilyView::Ready(status) => status.balance_atomic_units.as_deref().map_or_else(
            || {
                if status.state == "synced" {
                    "Not registered".to_owned()
                } else {
                    "Pending".to_owned()
                }
            },
            |value| format!("{} DUST", ui::format_atomic_units(value, ui::DUST_DECIMALS)),
        ),
        _ => "Unavailable".to_owned(),
    }
}

pub(super) fn selected_realm_dust_note(
    family: &WalletRealmFamilyView<WalletDustSyncView>,
) -> String {
    match family {
        WalletRealmFamilyView::Ready(status)
            if status.state == "synced" && status.balance_atomic_units.is_none() =>
        {
            "No registered DUST state was found for this account.".to_owned()
        }
        WalletRealmFamilyView::Ready(status) => dust_sync_note(status),
        WalletRealmFamilyView::Busy => "DUST synchronization is already running.".to_owned(),
        WalletRealmFamilyView::Unsupported => {
            "DUST is not supported by the selected network realm.".to_owned()
        }
        WalletRealmFamilyView::ProtectionNotInitialized => {
            "Set up wallet protection before synchronizing DUST.".to_owned()
        }
        WalletRealmFamilyView::ProtectionLocked => {
            "Unlock this wallet profile before synchronizing DUST.".to_owned()
        }
        WalletRealmFamilyView::NotFound => "No DUST account is active in this realm.".to_owned(),
        WalletRealmFamilyView::Unavailable => {
            "DUST synchronization is unavailable in this composition.".to_owned()
        }
        WalletRealmFamilyView::InvalidData => {
            "The DUST source returned inconsistent state.".to_owned()
        }
    }
}

pub(super) fn selected_realm_shielded_balance(
    family: &WalletRealmFamilyView<WalletShieldedSyncView>,
) -> String {
    match family {
        WalletRealmFamilyView::Ready(status) => home_shielded_value(status),
        _ => "Unavailable".to_owned(),
    }
}

pub(super) fn selected_realm_shielded_note(
    family: &WalletRealmFamilyView<WalletShieldedSyncView>,
) -> String {
    match family {
        WalletRealmFamilyView::Ready(status) => shielded_sync_note(status),
        WalletRealmFamilyView::Busy => "Shielded synchronization is already running.".to_owned(),
        WalletRealmFamilyView::Unsupported => {
            "Shielded assets are not supported by the selected network realm.".to_owned()
        }
        WalletRealmFamilyView::ProtectionNotInitialized => {
            "Set up wallet protection before synchronizing shielded assets.".to_owned()
        }
        WalletRealmFamilyView::ProtectionLocked => {
            "Unlock this wallet profile before synchronizing shielded assets.".to_owned()
        }
        WalletRealmFamilyView::NotFound => {
            "No shielded account is active in this realm.".to_owned()
        }
        WalletRealmFamilyView::Unavailable => {
            "Shielded synchronization is unavailable in this composition.".to_owned()
        }
        WalletRealmFamilyView::InvalidData => {
            "The shielded source returned inconsistent state.".to_owned()
        }
    }
}

pub(super) fn dust_progress_percent(status: &WalletDustSyncView) -> Option<u64> {
    let (current, target) = status.current_cursor.zip(status.target_cursor)?;
    let completed = u128::from(current).checked_add(1)?;
    let total = u128::from(target).checked_add(1)?;
    let percent = completed.checked_mul(100)?.checked_div(total)?.min(100);
    u64::try_from(percent).ok()
}

pub(super) fn dust_sync_note(status: &WalletDustSyncView) -> String {
    let detail = match status.state.as_str() {
        "never_synced" => "DUST has not been indexed for this protected account.".to_owned(),
        "syncing" => "Refreshing the protected DUST balance…".to_owned(),
        "synced" => "DUST is synchronized.".to_owned(),
        "cached" => "Showing a resumable cached DUST checkpoint; spending remains disabled until live catch-up.".to_owned(),
        "cancelled" => "DUST synchronization was cancelled at a consistent checkpoint and can resume.".to_owned(),
        "stalled" => "DUST synchronization stalled; the last consistent checkpoint is retained.".to_owned(),
        _ => "DUST synchronization is not available in this composition.".to_owned(),
    };
    status.failure.as_ref().map_or(detail.clone(), |failure| {
        format!("{detail} ({})", ui::sync_failure(failure))
    })
}

pub(super) fn dust_status_pill_class(state: &str) -> &'static str {
    match state {
        "synced" => "status-pill success",
        "syncing" | "cached" => "status-pill warning",
        _ => "status-pill",
    }
}

pub(super) fn shielded_progress_percent(status: &WalletShieldedSyncView) -> Option<u64> {
    let (current, target) = status.current_cursor.zip(status.target_cursor)?;
    let completed = u128::from(current).checked_add(1)?;
    let total = u128::from(target).checked_add(1)?;
    let percent = completed.checked_mul(100)?.checked_div(total)?.min(100);
    u64::try_from(percent).ok()
}

pub(super) fn shielded_sync_note(status: &WalletShieldedSyncView) -> String {
    let detail = match status.state.as_str() {
        "never_synced" => {
            "Shielded notes have not been indexed for this protected account.".to_owned()
        }
        "syncing" => "Refreshing protected shielded notes…".to_owned(),
        "synced" => "Shielded notes are synchronized.".to_owned(),
        "cached" => {
            "Showing a key-scoped cached shielded checkpoint; live catch-up is still required."
                .to_owned()
        }
        "cancelled" => {
            "Shielded synchronization was cancelled at a consistent checkpoint and can resume."
                .to_owned()
        }
        "stalled" => {
            "Shielded synchronization stalled; the last consistent checkpoint is retained."
                .to_owned()
        }
        _ => "Shielded synchronization is not available in this composition.".to_owned(),
    };
    status.failure.as_ref().map_or(detail.clone(), |failure| {
        format!("{detail} ({})", ui::sync_failure(failure))
    })
}

pub(super) fn non_native_shielded_balances(
    status: &WalletShieldedSyncView,
) -> impl Iterator<Item = &oxid_wallet_application::WalletShieldedTokenBalanceView> {
    status
        .balances
        .iter()
        .filter(|balance| balance.token_type_hex != NATIVE_SHIELDED_NIGHT_TOKEN_TYPE)
}

#[cfg(test)]
mod poll_tests {
    use super::*;

    #[test]
    fn stale_poll_cannot_replace_a_newer_manual_projection() {
        assert!(retain_polled_card_feedback(true, (1, 1), (1, 2), true, &None).is_none());
        assert!(retain_polled_card_feedback(true, (1, 9), (2, 1), true, &None).is_none());
        assert!(retain_polled_card_feedback(false, (2, 2), (1, 1), true, &None).is_none());
        assert!(!poll_owns_current_projection(false, false));
    }

    #[test]
    fn equal_poll_preserves_the_current_action_state() {
        let operation_error = Some("manual action pending".to_owned());
        let (action_busy, retained_error) =
            retain_polled_card_feedback(true, (1, 2), (1, 2), true, &operation_error)
                .expect("equal projection remains admissible");

        assert!(action_busy);
        assert_eq!(retained_error, operation_error);
        assert!(!poll_owns_current_projection(true, true));
    }

    #[test]
    fn lifecycle_presentation_keeps_automatic_states_action_free() {
        for state in ["never_synced", "syncing", "synced", "cached"] {
            assert!(
                !selected_realm_lifecycle_presentation(state).retry,
                "{state} must remain automatic"
            );
        }
        assert_eq!(
            selected_realm_lifecycle_presentation("synced").label,
            "Up to date"
        );
    }

    #[test]
    fn lifecycle_presentation_offers_one_retry_after_recovery_stops() {
        for state in ["stalled", "cancelled", "unavailable", "unknown"] {
            assert!(
                selected_realm_lifecycle_presentation(state).retry,
                "{state} must offer bounded recovery"
            );
        }
        assert_eq!(
            selected_realm_lifecycle_presentation("unavailable").label,
            "Offline"
        );
    }
}
