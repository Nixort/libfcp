// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Concrete WebRTC.rs FCP session and live control-channel integration.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use libfcp::transport::{apply_event, AdapterEvent};
use libfcp_core::{
    Action, AttemptId, CloseCode, Connection, EndpointIdentity, Envelope, FederationId,
    SigningIdentity, WebRtcBinding, CONTROL_CHANNEL,
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceCandidateInit, RTCIceServer, RTCPeerConnectionIceEvent, RTCPeerConnectionState,
    RTCSessionDescription,
};

use crate::{Error, SignalEvent};

mod control;
mod engine;
mod sdp;

use control::{
    emit_or_stage_candidate, emit_terminal, install_local_control_channel,
    install_remote_control_channel,
};
use engine::{
    EngineHandler, Shared, CONTROL_SEND_BUFFER_BYTES, ENGINE_EVENT_CAPACITY,
    MAX_STAGED_LOCAL_CANDIDATES, SIGNAL_EVENT_CAPACITY,
};
pub use engine::{SessionConfig, SessionEvent};
use sdp::dtls_fingerprint;

/// A real WebRTC.rs peer session bound to one FCP connection attempt.
///
/// The session emits signed [`SignalEvent`] values for an application-owned
/// signaling path. Incoming signaling is verified by FCP before its opaque SDP
/// or candidate bytes are given to the engine. The session sends/receives CFR
/// payloads only through the exact ordered reliable FCP control channel.
pub struct WebRtcRsSession {
    peer: Arc<dyn PeerConnection>,
    shared: Arc<Shared>,
    signals: Receiver<SignalEvent>,
    events: Receiver<SessionEvent>,
}

impl WebRtcRsSession {
    /// Builds a real WebRTC.rs peer connection for an already-created FCP attempt.
    pub async fn new(
        configuration: SessionConfig,
        federation: FederationId,
        attempt: AttemptId,
        signer: SigningIdentity,
        remote: EndpointIdentity,
    ) -> Result<Self, Error> {
        let (signal_tx, signal_rx) = mpsc::channel(SIGNAL_EVENT_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(ENGINE_EVENT_CAPACITY);
        let local = signer.endpoint();
        let shared = Arc::new(Shared {
            connection: Mutex::new(Connection::new(federation, attempt, local, remote)?),
            signer,
            signals: Mutex::new(signal_tx),
            events: event_tx,
            control: tokio::sync::Mutex::new(None),
            candidate_sequence: AtomicU32::new(0),
            staged_candidates: Mutex::new(VecDeque::new()),
            terminal: AtomicBool::new(false),
        });
        let handler = EngineHandler {
            shared: shared.clone(),
        };
        let peer = Box::pin(
            PeerConnectionBuilder::new()
                .with_configuration(
                    RTCConfigurationBuilder::default()
                        .with_ice_servers(configuration.ice_servers)
                        .build(),
                )
                .with_handler(Arc::new(handler))
                .with_udp_addrs(configuration.udp_addresses)
                .with_data_channel_send_buffer_limit(CONTROL_SEND_BUFFER_BYTES)
                .build(),
        )
        .await?;
        Ok(Self {
            peer: Arc::new(peer),
            shared,
            signals: signal_rx,
            events: event_rx,
        })
    }

    /// Starts an initiator offer and returns the first signed signaling envelope.
    ///
    /// Further local candidates can be retrieved with [`Self::try_take_signal`].
    pub async fn begin_offer(&mut self) -> Result<SignalEvent, Error> {
        let channel = self
            .peer
            .create_data_channel(
                CONTROL_CHANNEL.label,
                Some(RTCDataChannelInit {
                    ordered: CONTROL_CHANNEL.ordered,
                    max_packet_life_time: None,
                    max_retransmits: None,
                    protocol: CONTROL_CHANNEL.protocol.to_owned(),
                    negotiated: None,
                }),
            )
            .await?;
        install_local_control_channel(self.shared.clone(), channel).await;

        let offer = self.peer.create_offer(None).await?;
        self.peer.set_local_description(offer).await?;
        let description = self
            .peer
            .local_description()
            .await
            .ok_or(Error::InvalidAction("local offer unavailable"))?;
        let description_bytes = description.sdp.into_bytes();
        let binding =
            WebRtcBinding::derive(&description_bytes, &dtls_fingerprint(&description_bytes)?);
        let action = {
            let mut connection = self.shared.connection.lock().map_err(|_| Error::Poisoned)?;
            connection.begin_offer(&self.shared.signer, binding, description_bytes)?
        };
        self.process_actions(action).await?;
        self.flush_staged_candidates()?;
        self.try_take_signal()
            .ok_or(Error::InvalidAction("local offer was not emitted"))
    }

    /// Accepts one exact signed FCP envelope received through the application's signaling path.
    ///
    /// The envelope is verified and bound by FCP before the selected WebRTC.rs operation executes.
    pub async fn accept_signal(&self, wire: &[u8]) -> Result<(), Error> {
        let envelope = Envelope::decode_verified(wire)?;
        let actions = {
            let mut connection = self.shared.connection.lock().map_err(|_| Error::Poisoned)?;
            connection.receive(envelope)?
        };
        self.process_actions(actions).await
    }

    /// Answers a verified remote offer after [`Self::accept_signal`] applied it to the engine.
    pub async fn answer(&mut self) -> Result<SignalEvent, Error> {
        let answer = self.peer.create_answer(None).await?;
        self.peer.set_local_description(answer).await?;
        let description = self
            .peer
            .local_description()
            .await
            .ok_or(Error::InvalidAction("local answer unavailable"))?;
        let description_bytes = description.sdp.into_bytes();
        let binding =
            WebRtcBinding::derive(&description_bytes, &dtls_fingerprint(&description_bytes)?);
        let action = {
            let mut connection = self.shared.connection.lock().map_err(|_| Error::Poisoned)?;
            connection.answer(&self.shared.signer, binding, description_bytes)?
        };
        self.process_actions(vec![action]).await?;
        self.flush_staged_candidates()?;
        self.try_take_signal()
            .ok_or(Error::InvalidAction("local answer was not emitted"))
    }

    /// Sends exact CFR control bytes over the established FCP data channel.
    pub async fn send_cfr(&self, payload: Vec<u8>) -> Result<(), Error> {
        let action = {
            let connection = self.shared.connection.lock().map_err(|_| Error::Poisoned)?;
            connection.cfr_control(&self.shared.signer, payload)?
        };
        let Action::Send(envelope) = action else {
            return Err(Error::InvalidAction(
                "CFR control must be a signed envelope",
            ));
        };
        let control = self
            .shared
            .control
            .lock()
            .await
            .clone()
            .ok_or(Error::ControlChannelUnavailable)?;
        control
            .send(BytesMut::from(envelope.encode()?.as_slice()))
            .await?;
        Ok(())
    }

    /// Takes one locally generated signed signaling envelope without waiting.
    pub fn try_take_signal(&mut self) -> Option<SignalEvent> {
        let signal = self.signals.try_recv().ok();
        if signal.is_some() {
            let _ = self.flush_staged_candidates();
        }
        signal
    }

    /// Takes one live engine/FCP/CFR event without waiting.
    pub fn try_take_event(&mut self) -> Option<SessionEvent> {
        self.events.try_recv().ok()
    }

    /// Starts a signed graceful close through the application-owned signaling path.
    ///
    /// The caller must deliver the returned envelope, then invoke [`Self::close`]
    /// after its signaling policy determines that the local engine may be closed.
    pub fn begin_close(&self, reason: CloseCode) -> Result<SignalEvent, Error> {
        let action = {
            let mut connection = self.shared.connection.lock().map_err(|_| Error::Poisoned)?;
            connection.close(&self.shared.signer, reason)?
        };
        let Action::Send(envelope) = action else {
            return Err(Error::InvalidAction(
                "FCP close must produce a signaling envelope",
            ));
        };
        Ok(SignalEvent::new(*envelope))
    }

    /// Forcefully closes the underlying concrete WebRTC peer connection.
    ///
    /// Prefer [`Self::begin_close`] when a remote peer must receive a signed FCP
    /// close reason before the engine session is torn down.
    pub async fn close(&self) -> Result<(), Error> {
        self.peer.close().await?;
        Ok(())
    }

    fn flush_staged_candidates(&self) -> Result<(), Error> {
        let staged = {
            let mut candidates = self
                .shared
                .staged_candidates
                .lock()
                .map_err(|_| Error::Poisoned)?;
            core::mem::take(&mut *candidates)
        };
        for (sequence, candidate) in staged {
            emit_or_stage_candidate(&self.shared, sequence, candidate);
        }
        Ok(())
    }

    async fn process_actions(&self, actions: Vec<Action>) -> Result<(), Error> {
        let mut pending: VecDeque<Action> = actions.into();
        while let Some(action) = pending.pop_front() {
            match action {
                Action::Send(envelope) => {
                    let signal = SignalEvent::new(*envelope);
                    let sender = self.shared.signals.lock().map_err(|_| Error::Poisoned)?;
                    sender.try_send(signal).map_err(|_| {
                        Error::InvalidAction("signaling consumer is not draining events")
                    })?;
                }
                Action::ApplyOffer {
                    binding,
                    description,
                } => {
                    let expected =
                        WebRtcBinding::derive(&description, &dtls_fingerprint(&description)?);
                    if binding != expected {
                        return Err(Error::InvalidAction(
                            "offer binding does not match engine description",
                        ));
                    }
                    let sdp =
                        String::from_utf8(description).map_err(|_| Error::DescriptionEncoding)?;
                    self.peer
                        .set_remote_description(RTCSessionDescription::offer(sdp)?)
                        .await?;
                }
                Action::ApplyAnswer {
                    binding,
                    description,
                } => {
                    let expected =
                        WebRtcBinding::derive(&description, &dtls_fingerprint(&description)?);
                    if binding != expected {
                        return Err(Error::InvalidAction(
                            "answer binding does not match engine description",
                        ));
                    }
                    let sdp =
                        String::from_utf8(description).map_err(|_| Error::DescriptionEncoding)?;
                    self.peer
                        .set_remote_description(RTCSessionDescription::answer(sdp)?)
                        .await?;
                }
                Action::AddCandidate {
                    sequence: _,
                    candidate,
                } => {
                    let candidate: RTCIceCandidateInit =
                        serde_json::from_slice(&candidate).map_err(|_| Error::CandidateEncoding)?;
                    self.peer.add_ice_candidate(candidate).await?;
                }
                Action::OpenControlChannel => {}
                Action::DeliverCfr {
                    envelope_id,
                    remote_endpoint,
                    payload,
                } => {
                    self.shared
                        .events
                        .send(SessionEvent::DeliverCfr {
                            envelope_id,
                            remote_endpoint,
                            payload,
                        })
                        .await
                        .map_err(|_| Error::Closed)?;
                }
                Action::CloseTransport { reason } => {
                    if !emit_terminal(&self.shared, SessionEvent::Closed { reason }).await {
                        return Err(Error::Closed);
                    }
                    self.peer.close().await?;
                }
            }
        }
        Ok(())
    }
}
