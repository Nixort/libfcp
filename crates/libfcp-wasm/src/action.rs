// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use libfcp_core::Action;
use wasm_bindgen::prelude::*;

use crate::{error::core_error, ENVELOPE_ID_BYTES, WEBRTC_BINDING_BYTES};

/// FCP action kind: deliver the payload as a complete signed envelope.
pub(crate) const ACTION_SEND_ENVELOPE: u8 = 1;
/// FCP action kind: apply an offer through the browser's WebRTC engine.
pub(crate) const ACTION_APPLY_OFFER: u8 = 2;
/// FCP action kind: apply an answer through the browser's WebRTC engine.
pub(crate) const ACTION_APPLY_ANSWER: u8 = 3;
/// FCP action kind: add one candidate through the browser's WebRTC engine.
pub(crate) const ACTION_ADD_CANDIDATE: u8 = 4;
/// FCP action kind: open the required reliable ordered binary control channel.
pub(crate) const ACTION_OPEN_CONTROL_CHANNEL: u8 = 5;
/// FCP action kind: deliver exact opaque CFR payload bytes to JavaScript.
pub(crate) const ACTION_DELIVER_CFR: u8 = 6;
/// FCP action kind: close the browser's WebRTC peer transport.
pub(crate) const ACTION_CLOSE_TRANSPORT: u8 = 7;

/// An ordered FCP action copied into JavaScript-owned byte arrays.
#[wasm_bindgen]
pub struct FcpAction {
    kind: u8,
    binding: Vec<u8>,
    sequence: u32,
    close_code: u16,
    envelope_id: Vec<u8>,
    remote_endpoint: Vec<u8>,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl FcpAction {
    /// Returns stable action kind values 1 through 7.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// Returns the exact 32-byte offer/answer binding or zeroes for unrelated actions.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn binding(&self) -> Vec<u8> {
        self.binding.clone()
    }

    /// Returns the candidate sequence number or zero for unrelated actions.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Returns the signed application close code or zero for unrelated actions.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn close_code(&self) -> u16 {
        self.close_code
    }

    /// Returns the verified signed FCP envelope ID for a CFR delivery, or zeroes otherwise.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn envelope_id(&self) -> Vec<u8> {
        self.envelope_id.clone()
    }

    /// Returns the verified remote FCP endpoint identity for a CFR delivery, or empty otherwise.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn remote_endpoint(&self) -> Vec<u8> {
        self.remote_endpoint.clone()
    }

    /// Returns exact signed envelope, opaque engine or opaque CFR payload bytes.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

fn endpoint_bytes(endpoint: &libfcp_core::EndpointIdentity) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(crate::ENDPOINT_IDENTITY_BYTES);
    bytes.extend_from_slice(endpoint.classical.as_bytes());
    bytes.extend_from_slice(&endpoint.post_quantum);
    bytes
}

pub(crate) fn convert_action(action: Action) -> Result<FcpAction, JsError> {
    match action {
        Action::Send(envelope) => Ok(FcpAction {
            kind: ACTION_SEND_ENVELOPE,
            binding: vec![0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: vec![0; ENVELOPE_ID_BYTES],
            remote_endpoint: Vec::new(),
            payload: envelope.encode().map_err(core_error)?,
        }),
        Action::ApplyOffer {
            binding,
            description,
        } => Ok(FcpAction {
            kind: ACTION_APPLY_OFFER,
            binding: binding.as_bytes().to_vec(),
            sequence: 0,
            close_code: 0,
            envelope_id: vec![0; ENVELOPE_ID_BYTES],
            remote_endpoint: Vec::new(),
            payload: description,
        }),
        Action::ApplyAnswer {
            binding,
            description,
        } => Ok(FcpAction {
            kind: ACTION_APPLY_ANSWER,
            binding: binding.as_bytes().to_vec(),
            sequence: 0,
            close_code: 0,
            envelope_id: vec![0; ENVELOPE_ID_BYTES],
            remote_endpoint: Vec::new(),
            payload: description,
        }),
        Action::AddCandidate {
            sequence,
            candidate,
        } => Ok(FcpAction {
            kind: ACTION_ADD_CANDIDATE,
            binding: vec![0; WEBRTC_BINDING_BYTES],
            sequence,
            close_code: 0,
            envelope_id: vec![0; ENVELOPE_ID_BYTES],
            remote_endpoint: Vec::new(),
            payload: candidate,
        }),
        Action::OpenControlChannel => Ok(FcpAction {
            kind: ACTION_OPEN_CONTROL_CHANNEL,
            binding: vec![0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: vec![0; ENVELOPE_ID_BYTES],
            remote_endpoint: Vec::new(),
            payload: Vec::new(),
        }),
        Action::DeliverCfr {
            envelope_id,
            remote_endpoint,
            payload,
        } => Ok(FcpAction {
            kind: ACTION_DELIVER_CFR,
            binding: vec![0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: 0,
            envelope_id: envelope_id.as_bytes().to_vec(),
            remote_endpoint: endpoint_bytes(&remote_endpoint),
            payload,
        }),
        Action::CloseTransport { reason } => Ok(FcpAction {
            kind: ACTION_CLOSE_TRANSPORT,
            binding: vec![0; WEBRTC_BINDING_BYTES],
            sequence: 0,
            close_code: reason.as_u16(),
            envelope_id: vec![0; ENVELOPE_ID_BYTES],
            remote_endpoint: Vec::new(),
            payload: Vec::new(),
        }),
    }
}
