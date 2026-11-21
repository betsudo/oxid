// SPDX-License-Identifier: Apache-2.0

use oxid_adapter_identity_ingress::StrictIdentityRequestRouter;
use oxid_platform_ports::InboundIdentityLink;
use oxid_protocol_application::{IdentityRequestKind, IdentityRequestRouterPort};

/// Holds the first validated OS link while the public wallet is connecting.
pub enum PublicPortalStartupLinks<T> {
    Connecting(Option<InboundIdentityLink>),
    Ready(T),
}

impl<T> Default for PublicPortalStartupLinks<T> {
    fn default() -> Self {
        Self::Connecting(None)
    }
}

impl<T> PublicPortalStartupLinks<T> {
    pub fn receive(&mut self, value: &str, forward: impl FnOnce(&T, String)) {
        let Ok(link) = InboundIdentityLink::new(value.to_owned()) else {
            return;
        };
        match self {
            Self::Connecting(pending) => {
                if pending.is_none()
                    && StrictIdentityRequestRouter::credential_offers_only()
                        .route(value)
                        .is_ok_and(|kind| kind == IdentityRequestKind::CredentialIssuance)
                {
                    *pending = Some(link);
                }
            }
            Self::Ready(application) => forward(application, link.into_inner()),
        }
    }

    pub fn publish(&mut self, application: T, forward: impl FnOnce(&T, String)) {
        if let Self::Connecting(pending) = self {
            if let Some(link) = pending.take() {
                forward(&application, link.into_inner());
            }
            *self = Self::Ready(application);
        }
    }

    #[must_use]
    pub fn application(&self) -> Option<&T> {
        match self {
            Self::Connecting(_) => None,
            Self::Ready(application) => Some(application),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_ignores_malformed_and_unsupported_links_before_reserving_the_offer_slot() {
        let malformed = "openid-credential-offer://?credential_offer=";
        let unsupported = "https://issuer.example/offer";
        let cold = "openid-credential-offer://?credential_offer=fixture";
        let contender = "openid-credential-offer://?credential_offer=contender";
        let warm = "openid-credential-offer://?credential_offer=another-fixture";
        let mut startup = PublicPortalStartupLinks::default();
        let mut captured = Vec::new();
        let mut forward = |_: &(), link| captured.push(link);

        startup.receive(malformed, &mut forward);
        startup.receive(unsupported, &mut forward);
        startup.receive(cold, &mut forward);
        startup.receive(contender, &mut forward);
        assert!(startup.application().is_none());

        startup.publish((), &mut forward);
        assert!(startup.application().is_some());
        startup.publish((), &mut forward);
        startup.receive(warm, &mut forward);
        assert_eq!(captured, [cold, warm]);
    }

    #[test]
    fn warm_ingress_remains_unclassified() {
        let unsupported = "https://issuer.example/offer";
        let mut startup = PublicPortalStartupLinks::Ready(());
        let mut captured = Vec::new();
        startup.receive(unsupported, |_: &(), link| captured.push(link));
        assert_eq!(captured, [unsupported]);
    }
}
