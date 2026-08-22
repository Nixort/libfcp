// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Exact CFR message routing over established FCP connections.

use alloc::vec::Vec;
use cfr_protocol::{Conference, Message, Recipient, SigPublic};
use libfcp_core::{Action, EndpointSigner};

use crate::{CfrEndpointBindings, Error, PeerConnections};

/// Converts one outbound CFR message into FCP send actions.
///
/// `Recipient::Everyone` expands only across remote entries in the
/// application-provided bindings. It must not be treated as a second FCP or CFR
/// membership roster, and it does not include the local sender.
pub fn route_outbound<S: EndpointSigner>(
    message: &Message,
    signer: &S,
    bindings: &CfrEndpointBindings,
    connections: &PeerConnections,
) -> Result<Vec<Action>, Error> {
    match message.to {
        Recipient::Peer(identity) => route_one(message, signer, bindings, connections, identity),
        Recipient::Everyone => {
            let mut actions = Vec::new();
            for identity in bindings.identities() {
                actions.extend(route_one(message, signer, bindings, connections, identity)?);
            }
            Ok(actions)
        }
    }
}

fn route_one<S: EndpointSigner>(
    message: &Message,
    signer: &S,
    bindings: &CfrEndpointBindings,
    connections: &PeerConnections,
    identity: SigPublic,
) -> Result<Vec<Action>, Error> {
    let endpoint = bindings.endpoint(&identity).ok_or(Error::MissingBinding)?;
    let connection = connections.get(endpoint).ok_or(Error::MissingConnection)?;
    Ok(alloc::vec![
        connection.cfr_control(signer, message.payload.clone())?
    ])
}

/// Delivers exact FCP-carried CFR bytes into the application-facing CFR API.
///
/// Returned CFR messages must be routed again through [`route_outbound`]. A
/// `RepairNeeded` event remains CFR's responsibility and leads to
/// `Conference::resync`; FCP does not synthesize repair traffic.
pub fn deliver_inbound(
    conference: &mut Conference,
    payload: &[u8],
) -> cfr_protocol::Result<(Vec<cfr_protocol::Event>, Vec<Message>)> {
    conference.handle(payload)
}
