// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Federation-pinned established FCP peer directory.

use alloc::collections::BTreeMap;
use libfcp_core::{Connection, EndpointIdentity, FederationId};

use crate::Error;

/// Established FCP connections pinned to one local endpoint identity and federation.
///
/// The directory prevents a caller from accidentally routing a CFR message
/// through a connection for another federation, attempt namespace or local key.
#[derive(Debug)]
pub struct PeerConnections {
    federation: FederationId,
    local: EndpointIdentity,
    entries: BTreeMap<EndpointIdentity, Connection>,
}

impl PeerConnections {
    /// Creates an empty directory pinned to the local endpoint and federation.
    pub const fn new(federation: FederationId, local: EndpointIdentity) -> Self {
        Self {
            federation,
            local,
            entries: BTreeMap::new(),
        }
    }

    /// Inserts or replaces a verified connection for its pinned remote endpoint.
    pub fn insert(&mut self, connection: Connection) -> Result<Option<Connection>, Error> {
        if connection.federation() != self.federation || connection.local_endpoint() != self.local {
            return Err(Error::MismatchedConnection);
        }
        Ok(self
            .entries
            .insert(connection.remote_endpoint(), connection))
    }

    /// Removes one remote endpoint connection from the directory.
    pub fn remove(&mut self, endpoint: &EndpointIdentity) -> Option<Connection> {
        self.entries.remove(endpoint)
    }

    pub(crate) fn get(&self, endpoint: &EndpointIdentity) -> Option<&Connection> {
        self.entries.get(endpoint)
    }
}
