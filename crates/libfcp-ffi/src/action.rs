// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    status::{status_from_core, FcpStatus},
    types::FcpOwnedBuffer,
    ENVELOPE_ID_BYTES, WEBRTC_BINDING_BYTES,
};
use libfcp_core::{Action, EndpointIdentity, Phase};
use std::collections::VecDeque;
/// An action kind emitted by the signer-backed FCP connection state machine.
pub const FCP_ACTION_SEND_ENVELOPE: u32 = 1;
/// An action directing the host WebRTC engine to apply an offer.
pub const FCP_ACTION_APPLY_OFFER: u32 = 2;
/// An action directing the host WebRTC engine to apply an answer.
pub const FCP_ACTION_APPLY_ANSWER: u32 = 3;
/// An action directing the host WebRTC engine to add one ICE candidate.
pub const FCP_ACTION_ADD_CANDIDATE: u32 = 4;
/// An action directing the host WebRTC engine to create the required control channel.
pub const FCP_ACTION_OPEN_CONTROL_CHANNEL: u32 = 5;
/// An action containing exact CFR bytes for the application bridge.
pub const FCP_ACTION_DELIVER_CFR: u32 = 6;
/// An action directing the host WebRTC engine to close the peer transport.
pub const FCP_ACTION_CLOSE_TRANSPORT: u32 = 7;

/// One FIFO action transferred from an FCP connection to the foreign host.
#[repr(C)]
#[derive(Debug)]
pub struct FcpAction {
    /// One `FCP_ACTION_*` value.
    pub kind: u32,
    /// A WebRTC binding for offer/answer actions; all zero for other actions.
    pub binding: [u8; WEBRTC_BINDING_BYTES],
    /// ICE diagnostic sequence number for candidate actions; zero otherwise.
    pub sequence: u32,
    /// Signed application close code for close actions; zero otherwise.
    pub close_code: u16,
    /// Signed envelope identifier for `FCP_ACTION_DELIVER_CFR`; zero otherwise.
    pub envelope_id: [u8; ENVELOPE_ID_BYTES],
    /// FCP-owned complete remote endpoint identity for `FCP_ACTION_DELIVER_CFR`; empty otherwise.
    pub remote_endpoint: FcpOwnedBuffer,
    /// FCP-owned signed envelope, opaque engine bytes or exact CFR payload.
    pub payload: FcpOwnedBuffer,
}

impl Default for FcpAction {
    fn default() -> Self {
        Self {
            kind: 0,
            binding: [0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: FcpOwnedBuffer::default(),
            payload: FcpOwnedBuffer::default(),
        }
    }
}
#[derive(Debug)]
pub(crate) struct QueuedAction {
    pub(crate) kind: u32,
    pub(crate) binding: [u8; WEBRTC_BINDING_BYTES],
    pub(crate) sequence: u32,
    pub(crate) close_code: u16,
    pub(crate) envelope_id: [u8; ENVELOPE_ID_BYTES],
    pub(crate) remote_endpoint: Option<EndpointIdentity>,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn queue_actions(
    queue: &mut VecDeque<QueuedAction>,
    actions: impl IntoIterator<Item = Action>,
) -> Result<(), FcpStatus> {
    for action in actions {
        queue.push_back(queued_action(action)?);
    }
    Ok(())
}

pub(crate) fn queued_action(action: Action) -> Result<QueuedAction, FcpStatus> {
    match action {
        Action::Send(envelope) => Ok(QueuedAction {
            kind: FCP_ACTION_SEND_ENVELOPE,
            binding: [0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: None,
            payload: envelope.encode().map_err(status_from_core)?,
        }),
        Action::ApplyOffer {
            binding,
            description,
        } => Ok(QueuedAction {
            kind: FCP_ACTION_APPLY_OFFER,
            binding: *binding.as_bytes(),
            sequence: 0,
            close_code: 0,
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: None,
            payload: description,
        }),
        Action::ApplyAnswer {
            binding,
            description,
        } => Ok(QueuedAction {
            kind: FCP_ACTION_APPLY_ANSWER,
            binding: *binding.as_bytes(),
            sequence: 0,
            close_code: 0,
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: None,
            payload: description,
        }),
        Action::AddCandidate {
            sequence,
            candidate,
        } => Ok(QueuedAction {
            kind: FCP_ACTION_ADD_CANDIDATE,
            binding: [0; WEBRTC_BINDING_BYTES],
            sequence,
            close_code: 0,
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: None,
            payload: candidate,
        }),
        Action::OpenControlChannel => Ok(QueuedAction {
            kind: FCP_ACTION_OPEN_CONTROL_CHANNEL,
            binding: [0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: None,
            payload: Vec::new(),
        }),
        Action::DeliverCfr {
            envelope_id,
            remote_endpoint,
            payload,
        } => Ok(QueuedAction {
            kind: FCP_ACTION_DELIVER_CFR,
            binding: [0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: *envelope_id.as_bytes(),
            remote_endpoint: Some(remote_endpoint),
            payload,
        }),
        Action::CloseTransport { reason } => Ok(QueuedAction {
            kind: FCP_ACTION_CLOSE_TRANSPORT,
            binding: [0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: reason.as_u16(),
            envelope_id: [0; ENVELOPE_ID_BYTES],
            remote_endpoint: None,
            payload: Vec::new(),
        }),
    }
}

pub(crate) fn phase_code(phase: Phase) -> u32 {
    match phase {
        Phase::Idle => 0,
        Phase::OfferSent => 1,
        Phase::OfferReceived => 2,
        Phase::AnswerSent => 3,
        Phase::AnswerReceived => 4,
        Phase::Established => 5,
        Phase::Closed => 6,
    }
}
