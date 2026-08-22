// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Application-owned CFR participant to FCP endpoint bindings.

use alloc::collections::BTreeMap;
use cfr_protocol::SigPublic;
use libfcp_core::EndpointIdentity;

/// Application-approved bindings from remote CFR identity keys to complete FCP endpoint identities.
///
/// This map is a trust-policy input, not a discovery mechanism. It must contain
/// only remote CFR members and must be replaced or removed when application
/// identity policy changes. A matching entry proves no human identity by itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CfrEndpointBindings(BTreeMap<SigPublic, EndpointIdentity>);

impl CfrEndpointBindings {
    /// Creates an empty application-owned identity-binding policy.
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Inserts or replaces the explicit binding for one remote CFR participant.
    pub fn bind(
        &mut self,
        identity: SigPublic,
        endpoint: EndpointIdentity,
    ) -> Option<EndpointIdentity> {
        self.0.insert(identity, endpoint)
    }

    /// Removes an application-approved binding when its identity policy changes.
    pub fn unbind(&mut self, identity: &SigPublic) -> Option<EndpointIdentity> {
        self.0.remove(identity)
    }

    pub(crate) fn endpoint(&self, identity: &SigPublic) -> Option<&EndpointIdentity> {
        self.0.get(identity)
    }

    pub(crate) fn identities(&self) -> impl Iterator<Item = SigPublic> + '_ {
        self.0.keys().copied()
    }
}
