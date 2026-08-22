// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Exact-origin relying-party policy.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Immutable relying-party policy for one deployed Fabric public domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebauthnPolicy {
    rp_domain: DomainName,
    origin: Url,
}

impl WebauthnPolicy {
    /// Creates strict HTTPS relying-party policy for one canonical Fabric domain.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnServiceError::InvalidPolicy`] unless the origin uses
    /// HTTPS, has no credentials/query/fragment, uses `/`, and its host exactly
    /// equals the canonical RP domain. Subdomain and any-port relaxation are not
    /// enabled.
    pub fn new(rp_domain: DomainName, origin: Url) -> Result<Self, WebauthnServiceError> {
        if origin.scheme() != "https"
            || origin.host_str() != Some(rp_domain.as_str())
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.port().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            return Err(WebauthnServiceError::InvalidPolicy);
        }
        Ok(Self { rp_domain, origin })
    }

    /// Returns the only local tenant domain eligible for this RP deployment.
    #[must_use]
    pub const fn rp_domain(&self) -> &DomainName {
        &self.rp_domain
    }

    /// Returns the exact HTTPS `WebAuthn` origin.
    #[must_use]
    pub const fn origin(&self) -> &Url {
        &self.origin
    }
}
