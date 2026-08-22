// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use std::{collections::VecDeque, rc::Rc};

use libfcp_core::{
    Action, AttemptId, CloseCode, Connection, Envelope, FederationId, Phase, SigningIdentity,
    WebRtcBinding, MAX_CANDIDATE_BYTES, MAX_CFR_CONTROL_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_ENVELOPE_BYTES,
};
use wasm_bindgen::prelude::*;

use crate::{
    action::{convert_action, FcpAction},
    error::{bounded, core_error, endpoint_identity, fixed},
    signer::Signer,
};

/// Browser-session state for one signer-backed federation/attempt/peer-pinned FCP connection.
#[wasm_bindgen]
pub struct FcpConnection {
    inner: ConnectionState,
}

struct ConnectionState {
    connection: Connection,
    signer: Rc<SigningIdentity>,
    actions: VecDeque<FcpAction>,
}

#[wasm_bindgen]
impl FcpConnection {
    /// Creates one FCP connection. The signer fixes the local endpoint identity.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for invalid fixed-width identities or rejected peer bindings.
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        federation: &[u8],
        attempt: &[u8],
        remote_endpoint: &[u8],
    ) -> Result<FcpConnection, JsError> {
        let federation = FederationId::from_bytes(fixed(federation)?);
        let attempt = AttemptId::from_bytes(fixed(attempt)?);
        let remote = endpoint_identity(remote_endpoint)?;
        let signer = Rc::clone(&signer.inner);
        let connection =
            Connection::new(federation, attempt, signer.endpoint(), remote).map_err(core_error)?;
        Ok(Self {
            inner: ConnectionState {
                connection,
                signer,
                actions: VecDeque::new(),
            },
        })
    }

    /// Starts a local offer and queues all resulting host actions in FCP order.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for oversized input or an invalid FCP state transition.
    pub fn begin_offer(&mut self, binding: &[u8], description: &[u8]) -> Result<(), JsError> {
        bounded(description, MAX_DESCRIPTION_BYTES)?;
        let binding = WebRtcBinding::from_bytes(fixed(binding)?);
        let signer = Rc::clone(&self.inner.signer);
        let actions = self
            .inner
            .connection
            .begin_offer(signer.as_ref(), binding, description.to_vec())
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, actions)
    }

    /// Answers an accepted offer and queues the signed signaling envelope.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for oversized input or an invalid FCP state transition.
    pub fn answer(&mut self, binding: &[u8], description: &[u8]) -> Result<(), JsError> {
        bounded(description, MAX_DESCRIPTION_BYTES)?;
        let binding = WebRtcBinding::from_bytes(fixed(binding)?);
        let signer = Rc::clone(&self.inner.signer);
        let action = self
            .inner
            .connection
            .answer(signer.as_ref(), binding, description.to_vec())
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, [action])
    }

    /// Creates a signed candidate envelope for the active attempt.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for oversized input or an invalid FCP state transition.
    pub fn add_candidate(&mut self, sequence: u32, candidate: &[u8]) -> Result<(), JsError> {
        bounded(candidate, MAX_CANDIDATE_BYTES)?;
        let signer = Rc::clone(&self.inner.signer);
        let action = self
            .inner
            .connection
            .candidate(signer.as_ref(), sequence, candidate.to_vec())
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, [action])
    }

    /// Creates a signed CFR control envelope only after an engine-connected transition.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for oversized input or delivery before engine connection.
    pub fn cfr_control(&mut self, payload: &[u8]) -> Result<(), JsError> {
        bounded(payload, MAX_CFR_CONTROL_BYTES)?;
        let signer = Rc::clone(&self.inner.signer);
        let action = self
            .inner
            .connection
            .cfr_control(signer.as_ref(), payload.to_vec())
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, [action])
    }

    /// Queues a signed local close envelope.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error when the connection is not in a closable FCP phase.
    pub fn close_with_code(&mut self, close_code: u16) -> Result<(), JsError> {
        let signer = Rc::clone(&self.inner.signer);
        let action = self
            .inner
            .connection
            .close(signer.as_ref(), CloseCode::from_u16(close_code))
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, [action])
    }

    /// Verifies one received FCP envelope and queues exact ordered host actions.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error for invalid canonical bytes, signature/binding failures or invalid state.
    pub fn receive(&mut self, envelope: &[u8]) -> Result<(), JsError> {
        bounded(envelope, MAX_ENVELOPE_BYTES)?;
        let envelope = Envelope::decode_verified(envelope).map_err(core_error)?;
        let actions = self
            .inner
            .connection
            .receive(envelope)
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, actions)
    }

    /// Records the real browser WebRTC control-channel connection transition.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error unless FCP is awaiting a real control-channel connection.
    pub fn transport_connected(&mut self) -> Result<(), JsError> {
        let actions = self
            .inner
            .connection
            .transport_connected()
            .map_err(core_error)?;
        enqueue(&mut self.inner.actions, actions)
    }

    /// Records terminal local browser WebRTC failure without manufacturing a remote close.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error when no active FCP attempt can be failed.
    pub fn transport_failed(&mut self) -> Result<(), JsError> {
        self.inner.connection.transport_failed().map_err(core_error)
    }

    /// Returns the next FCP host action or `undefined` after the FIFO is drained.
    pub fn take_action(&mut self) -> Option<FcpAction> {
        self.inner.actions.pop_front()
    }

    /// Returns phase 0 idle through 6 closed.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn phase(&self) -> u8 {
        match self.inner.connection.phase() {
            Phase::Idle => 0,
            Phase::OfferSent => 1,
            Phase::OfferReceived => 2,
            Phase::AnswerSent => 3,
            Phase::AnswerReceived => 4,
            Phase::Established => 5,
            Phase::Closed => 6,
        }
    }
}

fn enqueue(
    queue: &mut VecDeque<FcpAction>,
    actions: impl IntoIterator<Item = Action>,
) -> Result<(), JsError> {
    for action in actions {
        queue.push_back(convert_action(action)?);
    }
    Ok(())
}
