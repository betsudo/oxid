// SPDX-License-Identifier: Apache-2.0

use oxid_platform_ports::InboundIdentityLink;

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
                if pending.is_none() {
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
    fn forwards_one_cold_open_offer_after_connection_and_keeps_ingress_live() {
        let cold = "openid-credential-offer://?credential_offer=fixture";
        let warm = "openid-credential-offer://?credential_offer=another-fixture";
        let mut startup = PublicPortalStartupLinks::default();
        let mut captured = Vec::new();
        let mut forward = |_: &(), link| captured.push(link);
        startup.receive("", &mut forward);
        startup.receive(cold, &mut forward);
        startup.receive(warm, &mut forward);
        assert!(startup.application().is_none());
        startup.publish((), &mut forward);
        assert!(startup.application().is_some());
        startup.publish((), &mut forward);
        startup.receive(warm, &mut forward);
        assert_eq!(captured, [cold, warm]);
    }
}
