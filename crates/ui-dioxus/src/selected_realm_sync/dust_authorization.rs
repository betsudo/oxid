// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, pin::Pin, sync::Arc};

use dioxus::prelude::*;
use oxid_wallet_application::{
    SelectedWalletRealmProjection, WalletDustRegistrationSettlementState,
};

pub type WalletDustSettlementProjection =
    oxid_wallet_application::WalletDustRegistrationSettlementProjection;
pub type WalletDustSettlementSubscription =
    tokio::sync::watch::Receiver<WalletDustSettlementProjection>;

type SubmitDecision =
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync;

/// A presentation-safe review carrying the decision for the preview it describes.
#[derive(Clone)]
pub struct WalletDustProtectedReview {
    title: String,
    summary: String,
    submit: Arc<SubmitDecision>,
}

impl WalletDustProtectedReview {
    pub fn new<Submit, Decision>(title: String, summary: String, submit: Submit) -> Self
    where
        Submit: Fn() -> Decision + Send + Sync + 'static,
        Decision: Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            title,
            summary,
            submit: Arc::new(move || Box::pin(submit())),
        }
    }
}

impl PartialEq for WalletDustProtectedReview {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.submit, &other.submit)
    }
}

/// Observes settlement and optionally exposes the composition-owned consent step.
pub trait WalletDustSettlementUiPort: Send + Sync {
    fn projection(&self) -> Result<WalletDustSettlementProjection, String>;

    fn subscribe(&self) -> WalletDustSettlementSubscription;

    fn protected_review(
        &self,
        _settlement: &WalletDustSettlementProjection,
    ) -> Option<WalletDustProtectedReview> {
        None
    }
}

#[derive(Clone)]
pub struct WalletDustSettlementUiServices {
    port: Arc<dyn WalletDustSettlementUiPort>,
}

impl WalletDustSettlementUiServices {
    #[must_use]
    pub const fn new(port: Arc<dyn WalletDustSettlementUiPort>) -> Self {
        Self { port }
    }

    pub(crate) fn port(&self) -> Arc<dyn WalletDustSettlementUiPort> {
        Arc::clone(&self.port)
    }
}

pub(super) fn settlement_matches_realm(
    realm: &SelectedWalletRealmProjection,
    settlement: &WalletDustSettlementProjection,
) -> bool {
    settlement.identity.as_ref().is_some_and(|identity| {
        identity.profile == realm.identity.profile
            && identity.realm == realm.identity.realm
            && identity.generation == realm.generation
    })
}

pub(super) fn protected_review(
    port: &dyn WalletDustSettlementUiPort,
    realm: &SelectedWalletRealmProjection,
    settlement: &WalletDustSettlementProjection,
) -> Option<WalletDustProtectedReview> {
    if settlement.state != WalletDustRegistrationSettlementState::AwaitingAuthorization
        || !settlement_matches_realm(realm, settlement)
    {
        return None;
    }
    port.protected_review(settlement)
}

#[component]
pub(super) fn ProtectedDustReviewCard(review: WalletDustProtectedReview) -> Element {
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let submit = Arc::clone(&review.submit);
    rsx! {
        details { class: "account-sync-card__details", "data-testid": "wallet-dust-protected-review",
            summary { "Review DUST registration" }
            h3 { "{review.title}" }
            p { "{review.summary}" }
            if let Some(message) = error.read().as_ref() {
                p { class: "wallet-sync-error", role: "alert", "{message}" }
            }
            button {
                class: "primary-action wallet-sync-action",
                r#type: "button",
                disabled: busy(),
                onclick: move |_| {
                    if busy() {
                        return;
                    }
                    busy.set(true);
                    error.set(None);
                    let submit = Arc::clone(&submit);
                    spawn(async move {
                        let result = crate::run_ui_future(async move { submit().await }).await;
                        busy.set(false);
                        error.set(match result {
                            Ok(Ok(())) => None,
                            Ok(Err(message)) => Some(message),
                            Err(worker) => Some(worker.to_string()),
                        });
                    });
                },
                if busy() { "Confirming…" } else { "Confirm registration" }
            }
        }
    }
}
