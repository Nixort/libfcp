// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Verified federation configuration and local client state.

use alloc::vec::Vec;

use cfr_protocol::{Conference, Message, SigPublic};
use libfcp_core::{
    Action, Connection, EndpointIdentity, EndpointSigner, FederationId,
    SignedFederationConfiguration,
};

use crate::{deliver_inbound, route_outbound, CfrEndpointBindings, Error, PeerConnections};

/// Pinned local policy needed to accept one federation server configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfiguration {
    /// Immutable federation namespace the client intends to join.
    pub federation: FederationId,
    /// Server authority identity authenticated by the application out of band.
    pub authority: EndpointIdentity,
    /// This client's CFR participant identity.
    pub local_cfr_identity: SigPublic,
    /// This client's complete FCP endpoint identity.
    pub local_endpoint: EndpointIdentity,
}

/// Local client state for one configured federation.
///
/// A client accepts a signed authority snapshot before binding any remote CFR
/// identity to an FCP endpoint. It keeps its own established peer connections:
/// the authority is not placed on the CFR path and does not relay FCP signaling.
#[derive(Debug)]
pub struct FederationClient {
    policy: ClientConfiguration,
    accepted_epoch: Option<u64>,
    bindings: CfrEndpointBindings,
    connections: PeerConnections,
}

impl FederationClient {
    /// Creates a client with no accepted federation configuration or peer connections.
    pub const fn new(policy: ClientConfiguration) -> Self {
        Self {
            bindings: CfrEndpointBindings::new(),
            connections: PeerConnections::new(policy.federation, policy.local_endpoint),
            policy,
            accepted_epoch: None,
        }
    }

    /// Returns the client policy pinned by the integrating application.
    pub const fn policy(&self) -> ClientConfiguration {
        self.policy
    }

    /// Returns the latest accepted server configuration epoch, if any.
    pub const fn accepted_epoch(&self) -> Option<u64> {
        self.accepted_epoch
    }

    /// Returns the active explicit remote CFR-to-FCP endpoint bindings.
    pub const fn bindings(&self) -> &CfrEndpointBindings {
        &self.bindings
    }

    /// Returns the active federation-pinned peer directory.
    pub const fn connections(&self) -> &PeerConnections {
        &self.connections
    }

    /// Verifies and atomically applies a strictly newer signed server snapshot.
    ///
    /// The authority identity is pinned in [`ClientConfiguration`] before this method
    /// is called. Delivery of the snapshot may use HTTPS, a relay, a file, an
    /// invite or another application mechanism; the carrier does not become
    /// trusted by this method.
    pub fn apply_configuration(
        &mut self,
        signed: SignedFederationConfiguration,
    ) -> Result<(), Error> {
        signed.verify()?;
        let configuration = signed.configuration;
        if configuration.federation != self.policy.federation {
            return Err(Error::WrongFederation);
        }
        if configuration.authority != self.policy.authority {
            return Err(Error::WrongAuthority);
        }
        if self
            .accepted_epoch
            .is_some_and(|accepted| configuration.epoch <= accepted)
        {
            return Err(Error::StaleConfiguration);
        }

        let mut next_bindings = CfrEndpointBindings::new();
        let mut local_member_seen = false;
        for member in configuration.members {
            let identity = SigPublic::from_bytes(member.cfr_identity);
            if identity == self.policy.local_cfr_identity {
                if member.endpoint != self.policy.local_endpoint {
                    return Err(Error::WrongLocalEndpoint);
                }
                local_member_seen = true;
            } else {
                let _ = next_bindings.bind(identity, member.endpoint);
            }
        }
        if !local_member_seen {
            return Err(Error::MissingLocalMember);
        }

        self.bindings = next_bindings;
        self.accepted_epoch = Some(configuration.epoch);
        Ok(())
    }

    /// Inserts one established FCP peer connection after federation/local-key validation.
    pub fn insert_connection(
        &mut self,
        connection: Connection,
    ) -> Result<Option<Connection>, Error> {
        self.connections.insert(connection)
    }

    /// Removes a remote endpoint's established FCP connection.
    pub fn remove_connection(&mut self, endpoint: &EndpointIdentity) -> Option<Connection> {
        self.connections.remove(endpoint)
    }

    /// Converts one local CFR message into exact FCP control send actions.
    pub fn route_outbound<S: EndpointSigner>(
        &self,
        message: &Message,
        signer: &S,
    ) -> Result<Vec<Action>, Error> {
        route_outbound(message, signer, &self.bindings, &self.connections)
    }

    /// Delivers exact FCP control bytes into this client's CFR conference.
    pub fn deliver_inbound(
        &self,
        conference: &mut Conference,
        payload: &[u8],
    ) -> cfr_protocol::Result<(Vec<cfr_protocol::Event>, Vec<Message>)> {
        deliver_inbound(conference, payload)
    }
}
