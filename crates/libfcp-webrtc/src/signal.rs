// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Application-owned signaling events emitted by the concrete WebRTC.rs session.

use libfcp_core::Envelope;
use std::vec::Vec;

/// A signed FCP envelope ready for the application's selected signaling path.
///
/// The concrete engine never opens an unauthenticated HTTP or WebSocket server.
/// An application transports this envelope through its own authenticated relay,
/// direct path or store-and-forward mechanism, then gives the exact received
/// bytes to [`crate::WebRtcRsSession::accept_signal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalEvent {
    envelope: Envelope,
}

impl SignalEvent {
    /// Creates an application-facing event from a locally signed envelope.
    pub(crate) const fn new(envelope: Envelope) -> Self {
        Self { envelope }
    }

    /// Returns the canonical signed FCP envelope.
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Serializes the exact canonical signed envelope for a signaling transport.
    pub fn encode(&self) -> Result<Vec<u8>, libfcp_core::Error> {
        self.envelope.encode()
    }
}
