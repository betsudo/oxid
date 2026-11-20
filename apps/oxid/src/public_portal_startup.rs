// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use dioxus::{mobile::tao::event::Event, prelude::*};
use oxid_composition::{
    ApplicationServices, ProductionDeploymentCompositionError as StartupError,
    PublicPortalStartupLinks,
};

#[cfg(feature = "preview-portal")]
const NETWORK: &str = "Preview";
#[cfg(feature = "preprod-portal")]
const NETWORK: &str = "PreProd";

#[derive(Clone, Default)]
struct Startup(Arc<Mutex<PublicPortalStartupLinks<Arc<ApplicationServices>>>>);

fn forward_link(application: &Arc<ApplicationServices>, link: String) {
    let _ = application.identity_link_ingress().capture(link);
}

#[derive(Clone)]
struct ReadyWallet(Arc<ApplicationServices>);

impl PartialEq for ReadyWallet {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

enum StartupState {
    Connecting,
    ConnectionFailed(StartupError),
    Ready(ReadyWallet),
}

pub(super) fn launch() {
    let startup = Startup::default();
    let events = startup.clone();
    let config = dioxus::mobile::Config::new()
        .with_custom_index(include_str!("../assets/index.html").to_owned())
        .with_custom_event_handler(move |event, _target| {
            if let Event::Opened { urls } = event {
                if let Ok(mut links) = events.0.lock() {
                    for url in urls {
                        links.receive(url.as_str(), forward_link);
                    }
                }
                return;
            }
            let Some(application) = events
                .0
                .lock()
                .ok()
                .and_then(|links| links.application().cloned())
            else {
                return;
            };
            match event {
                Event::Suspended => {
                    let _ = application
                        .set_credential_presentation_foreground()
                        .execute(false);
                }
                Event::Resumed => {
                    let _ = application
                        .set_credential_presentation_foreground()
                        .execute(true);
                }
                _ => {}
            }
        });
    dioxus::LaunchBuilder::new()
        .with_context(startup)
        .with_context(super::generated_brand::BRAND_PROFILE)
        .with_cfg(config)
        .launch(PublicPortalStartup);
}

async fn connect(startup: Startup) -> StartupState {
    let (done, result) = futures::channel::oneshot::channel();
    let worker = std::thread::Builder::new()
        .name("oxid-public-portal-startup".to_owned())
        .spawn(move || {
            let application = compose_from_embedded_profile().and_then(|application| {
                let ready = Arc::new(application);
                startup
                    .0
                    .lock()
                    .map_err(|_| StartupError::PublicPortalRuntimeUnavailable)?
                    .publish(Arc::clone(&ready), forward_link);
                Ok(ready)
            });
            let _ = done.send(application);
        });
    if worker.is_err() {
        return StartupState::ConnectionFailed(StartupError::PublicPortalRuntimeUnavailable);
    }
    match result.await {
        Ok(Ok(application)) => StartupState::Ready(ReadyWallet(application)),
        Ok(Err(error)) => StartupState::ConnectionFailed(error),
        Err(_) => StartupState::ConnectionFailed(StartupError::PublicPortalRuntimeUnavailable),
    }
}

#[cfg(feature = "preview-portal")]
fn compose_from_embedded_profile() -> Result<ApplicationServices, StartupError> {
    oxid_composition::compose_embedded_preview_portal(
        include_bytes!(concat!(env!("OUT_DIR"), "/preview-trust-root.json")),
        include_bytes!(concat!(env!("OUT_DIR"), "/preview-signed-profile.json")),
        include_bytes!(concat!(env!("OUT_DIR"), "/portal-deployment.json")),
    )
}

#[cfg(feature = "preprod-portal")]
fn compose_from_embedded_profile() -> Result<ApplicationServices, StartupError> {
    oxid_composition::compose_embedded_preprod_portal(
        include_bytes!(concat!(env!("OUT_DIR"), "/preprod-trust-root.json")),
        include_bytes!(concat!(env!("OUT_DIR"), "/preprod-signed-profile.json")),
        include_bytes!(concat!(env!("OUT_DIR"), "/portal-deployment.json")),
    )
}

#[component]
fn PublicPortalStartup() -> Element {
    let startup = consume_context::<Startup>();
    let mut state = use_signal(|| StartupState::Connecting);
    let initial = startup.clone();
    use_future(move || {
        let initial = initial.clone();
        async move { state.set(connect(initial).await) }
    });

    match &*state.read() {
        StartupState::Ready(wallet) => rsx! { ActiveWallet { wallet: wallet.clone() } },
        StartupState::Connecting => rsx! {
            main { style: "padding: 24px", role: "status", "Connecting to Midnight {NETWORK}…" }
        },
        StartupState::ConnectionFailed(error) => rsx! {
            main { style: "padding: 24px",
                h1 { "{NETWORK} access" }
                p { role: "status", "{error}" }
                {access_setup(*error)}
                button {
                    onclick: move |_| {
                        if matches!(*state.peek(), StartupState::Connecting) {
                            return;
                        }
                        state.set(StartupState::Connecting);
                        let startup = startup.clone();
                        spawn(async move { state.set(connect(startup).await) });
                    },
                    "Retry connection"
                }
            }
        },
    }
}

#[cfg(feature = "preview-portal")]
fn access_setup(_error: StartupError) -> Element {
    rsx! {}
}

#[cfg(feature = "preprod-portal")]
fn access_setup(error: StartupError) -> Element {
    if matches!(
        error,
        StartupError::PreprodCredentialRequired
            | StartupError::PreprodCredentialUnavailable
            | StartupError::ChainIdentityUnavailable
            | StartupError::PreprodIndexerUnavailable
            | StartupError::PreprodIndexerWebsocketUnavailable
    ) {
        rsx! { PreprodAccessSetup {} }
    } else {
        rsx! {}
    }
}

#[cfg(feature = "preprod-portal")]
#[component]
fn PreprodAccessSetup() -> Element {
    let mut setup_error = use_signal(|| false);
    rsx! {
        button {
            onclick: move |_| {
                setup_error.set(oxid_composition::begin_preprod_project_id_setup().is_err());
            },
            "Enter project ID"
        }
        if setup_error() {
            p { role: "alert", "The secure input could not be opened. Try again." }
        }
    }
}

#[component]
fn ActiveWallet(wallet: ReadyWallet) -> Element {
    use_context_provider(|| super::wallet_ui(&wallet.0));
    rsx! { oxid_ui_dioxus::App {} }
}
