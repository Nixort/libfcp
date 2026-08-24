// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Engine-neutral FCP-to-WebRTC adapter contract and event dispatcher.

use alloc::boxed::Box;
use alloc::vec::Vec;
use libfcp_core::{
    Action, CloseCode, Connection, ControlChannelConfig, EndpointIdentity, Envelope, EnvelopeId,
    Error as FcpError, WebRtcBinding,
};

/// A platform adapter for one native WebRTC engine instance.
pub trait WebRtcAdapter {
    /// Platform-specific error type.
    type Error;

    /// Applies the exact opaque offer description after FCP signature/binding checks.
    fn apply_offer(
        &mut self,
        binding: WebRtcBinding,
        description: &[u8],
    ) -> Result<(), Self::Error>;

    /// Applies the exact opaque answer description after FCP signature/binding checks.
    fn apply_answer(
        &mut self,
        binding: WebRtcBinding,
        description: &[u8],
    ) -> Result<(), Self::Error>;

    /// Adds one bounded opaque ICE candidate to the engine.
    fn add_candidate(&mut self, sequence: u32, candidate: &[u8]) -> Result<(), Self::Error>;

    /// Configures the initiator-side reliable ordered binary FCP control channel.
    fn open_control_channel(
        &mut self,
        configuration: ControlChannelConfig,
    ) -> Result<(), Self::Error>;

    /// Closes the platform peer connection for the supplied FCP reason.
    fn close(&mut self, reason: CloseCode) -> Result<(), Self::Error>;
}

/// One event that a platform adapter reports to its FCP owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterEvent {
    /// DTLS/ICE/SCTP and the FCP control channel became usable.
    Connected,
    /// One binary message read from the fixed FCP control data channel.
    ControlBinary(Vec<u8>),
    /// The platform engine failed without a valid remote FCP close envelope.
    Failed,
    /// The engine closed after an external transport condition.
    Closed,
}

/// A non-platform action intentionally returned to the application dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationAction {
    /// Send this signed FCP envelope through the chosen signaling/data path.
    Send(Box<Envelope>),
    /// Deliver exact raw bytes and their verified FCP transport origin to the application bridge.
    DeliverCfr {
        /// Stable identifier of the signed FCP envelope carrying this payload.
        envelope_id: EnvelopeId,
        /// Complete remote FCP endpoint identity that signed the carrying envelope.
        remote_endpoint: EndpointIdentity,
        /// Unmodified CFR control bytes.
        payload: Vec<u8>,
    },
}

/// Applies a platform event to one FCP connection.
///
/// `ControlBinary` is parsed as exactly one FCP envelope. The call performs
/// binding, signature, replay and state validation in `libfcp-core` before any
/// platform or CFR action can be emitted.
pub fn apply_event(
    connection: &mut Connection,
    event: AdapterEvent,
) -> Result<Vec<Action>, FcpError> {
    match event {
        AdapterEvent::Connected => connection.transport_connected(),
        AdapterEvent::ControlBinary(wire) => connection.receive(Envelope::decode_verified(&wire)?),
        AdapterEvent::Failed | AdapterEvent::Closed => {
            connection.transport_failed()?;
            Ok(Vec::new())
        }
    }
}

/// Applies a platform-owned FCP action or returns an application-owned action.
pub fn dispatch<A: WebRtcAdapter>(
    adapter: &mut A,
    action: Action,
) -> Result<Option<ApplicationAction>, A::Error> {
    match action {
        Action::Send(envelope) => Ok(Some(ApplicationAction::Send(envelope))),
        Action::ApplyOffer {
            binding,
            description,
        } => {
            adapter.apply_offer(binding, &description)?;
            Ok(None)
        }
        Action::ApplyAnswer {
            binding,
            description,
        } => {
            adapter.apply_answer(binding, &description)?;
            Ok(None)
        }
        Action::AddCandidate {
            sequence,
            candidate,
        } => {
            adapter.add_candidate(sequence, &candidate)?;
            Ok(None)
        }
        Action::OpenControlChannel => {
            adapter.open_control_channel(libfcp_core::CONTROL_CHANNEL)?;
            Ok(None)
        }
        Action::DeliverCfr {
            envelope_id,
            remote_endpoint,
            payload,
        } => Ok(Some(ApplicationAction::DeliverCfr {
            envelope_id,
            remote_endpoint,
            payload,
        })),
        Action::CloseTransport { reason } => {
            adapter.close(reason)?;
            Ok(None)
        }
    }
}
