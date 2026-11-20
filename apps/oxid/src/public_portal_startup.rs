// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, OnceLock};

use dioxus::{mobile::tao::event::Event, prelude::*};
use oxid_composition::{ApplicationServices, ProductionDeploymentCompositionError as StartupError};

#[cfg(feature = "preview-portal")]
const NETWORK: &str = "Preview";
#[cfg(feature = "preprod-portal")]
const NETWORK: &str = "PreProd";

#[derive(Clone, Default)]
struct Startup(Arc<OnceLock<Arc<ApplicationServices>>>);

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
            let Some(application) = events.0.get() else {
                return;
            };
            match event {
                Event::Opened { urls } => {
                    let ingress = application.identity_link_ingress();
                    for url in urls {
                        let _ = ingress.capture(url.as_str().to_owned());
                    }
                }
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
            let application = compose_from_embedded_profile().map(Arc::new);
            if let Ok(ready) = &application {
                let _ = startup.0.set(Arc::clone(ready));
            }
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
