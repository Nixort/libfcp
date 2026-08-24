// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Per-peer FCP connection state machine and engine actions.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::envelope::{Body, Envelope};
use crate::error::Error;
use crate::identity::{EndpointIdentity, EndpointSigner};
use crate::types::{
    AttemptId, CloseCode, EnvelopeId, FederationId, WebRtcBinding, MAX_SEEN_ENVELOPES, PROTOCOL_ID,
};

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No offer or answer exists.
    Idle,
    /// This endpoint has sent an offer.
    OfferSent,
    /// A valid offer from the configured peer awaits a local answer.
    OfferReceived,
    /// This endpoint has sent an answer and awaits transport connection.
    AnswerSent,
    /// This endpoint has received an answer and awaits transport connection.
    AnswerReceived,
    /// The platform adapter reported the WebRTC control channel connected.
    Established,
    /// A local or remote close finished this attempt.
    Closed,
}

#[derive(Debug, Clone, Copy)]
struct NegotiationIds {
    offer: EnvelopeId,
    answer: Option<EnvelopeId>,
}

/// An action emitted by the core for an untrusted transport or platform adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a signed envelope through any configured signaling or data path.
    Send(Box<Envelope>),
    /// Give an opaque offer description to the selected WebRTC engine.
    ApplyOffer {
        /// Signed digest binding exact description and DTLS fingerprint bytes.
        binding: WebRtcBinding,
        /// Exact bounded opaque description to give the platform engine.
        description: Vec<u8>,
    },
    /// Give an opaque answer description to the selected WebRTC engine.
    ApplyAnswer {
        /// Signed digest binding exact description and DTLS fingerprint bytes.
        binding: WebRtcBinding,
        /// Exact bounded opaque description to give the platform engine.
        description: Vec<u8>,
    },
    /// Add one opaque ICE candidate to the selected WebRTC engine.
    AddCandidate {
        /// Sender-local diagnostic sequence number.
        sequence: u32,
        /// Exact bounded opaque candidate to give the platform engine.
        candidate: Vec<u8>,
    },
    /// Ask the adapter to configure/open the fixed reliable ordered FCP control channel.
    OpenControlChannel,
    /// Deliver an exact raw CFR payload with its verified FCP transport origin.
    DeliverCfr {
        /// Stable identifier of the verified signed FCP envelope carrying this payload.
        envelope_id: EnvelopeId,
        /// Complete FCP endpoint identity that signed the carrying envelope.
        remote_endpoint: EndpointIdentity,
        /// Unmodified CFR wire payload.
        payload: Vec<u8>,
    },
    /// Close the selected platform connection.
    CloseTransport {
        /// Application close code from a signed remote envelope.
        reason: CloseCode,
    },
}

/// Fixed FCP data-channel configuration that platform adapters must enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlChannelConfig {
    /// Stable data channel label.
    pub label: &'static str,
    /// Stable subprotocol string.
    pub protocol: &'static str,
    /// FCP control is ordered.
    pub ordered: bool,
    /// FCP control is fully reliable.
    pub reliable: bool,
    /// FCP control uses binary messages.
    pub binary: bool,
}

/// Required FCP data-channel configuration.
pub const CONTROL_CHANNEL: ControlChannelConfig = ControlChannelConfig {
    label: "org.nixort.cfr.fcp.control/1",
    protocol: PROTOCOL_ID,
    ordered: true,
    reliable: true,
    binary: true,
};

/// Per-peer state machine for one FCP connection attempt.
#[derive(Debug)]
pub struct Connection {
    federation: FederationId,
    attempt: AttemptId,
    local: EndpointIdentity,
    remote: EndpointIdentity,
    phase: Phase,
    negotiation: Option<NegotiationIds>,
    seen: VecDeque<EnvelopeId>,
}

impl Connection {
    /// Creates an idle connection pinned to one federation, attempt and complete remote identity.
    pub fn new(
        federation: FederationId,
        attempt: AttemptId,
        local: EndpointIdentity,
        remote: EndpointIdentity,
    ) -> Result<Self, Error> {
        if local == remote {
            return Err(Error::SameEndpoint);
        }
        Ok(Self {
            federation,
            attempt,
            local,
            remote,
            phase: Phase::Idle,
            negotiation: None,
            seen: VecDeque::new(),
        })
    }

    /// Returns the federation namespace pinned for this attempt.
    pub const fn federation(&self) -> FederationId {
        self.federation
    }

    /// Returns the application-provided attempt identifier pinned for this connection.
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the complete local FCP endpoint identity pinned for this connection.
    pub const fn local_endpoint(&self) -> EndpointIdentity {
        self.local
    }

    /// Returns the complete remote FCP endpoint identity pinned for this connection.
    pub const fn remote_endpoint(&self) -> EndpointIdentity {
        self.remote
    }

    /// Returns the current lifecycle state.
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Starts a local offer from `Idle`.
    pub fn begin_offer<S: EndpointSigner>(
        &mut self,
        signer: &S,
        binding: WebRtcBinding,
        description: Vec<u8>,
    ) -> Result<Vec<Action>, Error> {
        self.require_local_signer(signer)?;
        if self.phase != Phase::Idle {
            return Err(Error::InvalidState);
        }
        let offer = Envelope::sign(
            signer,
            self.federation,
            self.attempt,
            self.remote,
            Body::Offer {
                binding,
                description,
            },
        )?;
        self.negotiation = Some(NegotiationIds {
            offer: offer.id()?,
            answer: None,
        });
        self.phase = Phase::OfferSent;
        Ok(vec![
            Action::OpenControlChannel,
            Action::Send(Box::new(offer)),
        ])
    }

    /// Answers one accepted remote offer.
    pub fn answer<S: EndpointSigner>(
        &mut self,
        signer: &S,
        binding: WebRtcBinding,
        description: Vec<u8>,
    ) -> Result<Action, Error> {
        self.require_local_signer(signer)?;
        if self.phase != Phase::OfferReceived {
            return Err(Error::InvalidState);
        }
        let offer_id = self.negotiation.ok_or(Error::InvalidState)?.offer;
        let answer = Envelope::sign(
            signer,
            self.federation,
            self.attempt,
            self.remote,
            Body::Answer {
                offer_id,
                binding,
                description,
            },
        )?;
        self.negotiation = Some(NegotiationIds {
            offer: offer_id,
            answer: Some(answer.id()?),
        });
        self.phase = Phase::AnswerSent;
        Ok(Action::Send(Box::new(answer)))
    }

    /// Creates a candidate bound to the active negotiation.
    pub fn candidate<S: EndpointSigner>(
        &self,
        signer: &S,
        sequence: u32,
        candidate: Vec<u8>,
    ) -> Result<Action, Error> {
        self.require_local_signer(signer)?;
        if !matches!(
            self.phase,
            Phase::OfferSent
                | Phase::OfferReceived
                | Phase::AnswerSent
                | Phase::AnswerReceived
                | Phase::Established
        ) {
            return Err(Error::InvalidState);
        }
        let ids = self.negotiation.ok_or(Error::InvalidState)?;
        let parent_id = ids.answer.unwrap_or(ids.offer);
        let envelope = Envelope::sign(
            signer,
            self.federation,
            self.attempt,
            self.remote,
            Body::Candidate {
                parent_id,
                sequence,
                candidate,
            },
        )?;
        Ok(Action::Send(Box::new(envelope)))
    }

    /// Emits one bounded raw CFR control envelope after WebRTC connection is established.
    pub fn cfr_control<S: EndpointSigner>(
        &self,
        signer: &S,
        payload: Vec<u8>,
    ) -> Result<Action, Error> {
        self.require_local_signer(signer)?;
        if self.phase != Phase::Established {
            return Err(Error::InvalidState);
        }
        Ok(Action::Send(Box::new(Envelope::sign(
            signer,
            self.federation,
            self.attempt,
            self.remote,
            Body::CfrControl { payload },
        )?)))
    }

    /// Emits a local close and closes the core attempt.
    pub fn close<S: EndpointSigner>(
        &mut self,
        signer: &S,
        reason: CloseCode,
    ) -> Result<Action, Error> {
        self.require_local_signer(signer)?;
        if matches!(self.phase, Phase::Idle | Phase::Closed) {
            return Err(Error::InvalidState);
        }
        self.phase = Phase::Closed;
        Ok(Action::Send(Box::new(Envelope::sign(
            signer,
            self.federation,
            self.attempt,
            self.remote,
            Body::Close { reason },
        )?)))
    }

    /// Processes a received envelope only after exact binding and signature validation.
    pub fn receive(&mut self, envelope: Envelope) -> Result<Vec<Action>, Error> {
        self.validate_inbound(&envelope)?;
        let id = envelope.id()?;
        let remote_endpoint = envelope.sender;
        if self.seen.iter().any(|known| known == &id) {
            return Ok(Vec::new());
        }
        let actions = match envelope.body {
            Body::Offer {
                binding,
                description,
            } => {
                if self.phase == Phase::OfferSent {
                    return Err(Error::Glare);
                }
                if self.phase != Phase::Idle {
                    return Err(Error::InvalidState);
                }
                self.negotiation = Some(NegotiationIds {
                    offer: id,
                    answer: None,
                });
                self.phase = Phase::OfferReceived;
                vec![Action::ApplyOffer {
                    binding,
                    description,
                }]
            }
            Body::Answer {
                offer_id,
                binding,
                description,
            } => {
                if self.phase != Phase::OfferSent
                    || self.negotiation.ok_or(Error::InvalidState)?.offer != offer_id
                {
                    return Err(Error::InvalidState);
                }
                let offer = self.negotiation.ok_or(Error::InvalidState)?.offer;
                self.negotiation = Some(NegotiationIds {
                    offer,
                    answer: Some(id),
                });
                self.phase = Phase::AnswerReceived;
                vec![Action::ApplyAnswer {
                    binding,
                    description,
                }]
            }
            Body::Candidate {
                parent_id,
                sequence,
                candidate,
            } => {
                self.validate_candidate_parent(parent_id)?;
                vec![Action::AddCandidate {
                    sequence,
                    candidate,
                }]
            }
            Body::Close { reason } => {
                if matches!(self.phase, Phase::Idle | Phase::Closed) {
                    return Err(Error::InvalidState);
                }
                self.phase = Phase::Closed;
                vec![Action::CloseTransport { reason }]
            }
            Body::CfrControl { payload } => {
                if self.phase != Phase::Established {
                    return Err(Error::InvalidState);
                }
                vec![Action::DeliverCfr {
                    envelope_id: id,
                    remote_endpoint,
                    payload,
                }]
            }
        };
        self.note_seen(id);
        Ok(actions)
    }

    /// Records that the platform adapter reached a connected WebRTC control channel.
    pub fn transport_connected(&mut self) -> Result<Vec<Action>, Error> {
        if !matches!(self.phase, Phase::AnswerSent | Phase::AnswerReceived) {
            return Err(Error::InvalidState);
        }
        self.phase = Phase::Established;
        Ok(Vec::new())
    }

    /// Records a local platform failure and stops this attempt without manufacturing a remote close.
    pub fn transport_failed(&mut self) -> Result<(), Error> {
        if matches!(self.phase, Phase::Idle | Phase::Closed) {
            return Err(Error::InvalidState);
        }
        self.phase = Phase::Closed;
        Ok(())
    }

    fn require_local_signer<S: EndpointSigner>(&self, signer: &S) -> Result<(), Error> {
        if signer.endpoint() != self.local {
            return Err(Error::WrongLocalSigner);
        }
        Ok(())
    }

    fn validate_inbound(&self, envelope: &Envelope) -> Result<(), Error> {
        if envelope.federation != self.federation {
            return Err(Error::WrongFederation);
        }
        if envelope.attempt != self.attempt {
            return Err(Error::WrongAttempt);
        }
        if envelope.sender != self.remote {
            return Err(Error::WrongSender);
        }
        if envelope.recipient != self.local {
            return Err(Error::WrongRecipient);
        }
        envelope.verify()
    }

    fn validate_candidate_parent(&self, parent: EnvelopeId) -> Result<(), Error> {
        let ids = self.negotiation.ok_or(Error::InvalidState)?;
        if !matches!(
            self.phase,
            Phase::OfferSent
                | Phase::OfferReceived
                | Phase::AnswerSent
                | Phase::AnswerReceived
                | Phase::Established
        ) {
            return Err(Error::InvalidState);
        }
        if parent != ids.offer && ids.answer != Some(parent) {
            return Err(Error::WrongCandidateParent);
        }
        Ok(())
    }

    fn note_seen(&mut self, id: EnvelopeId) {
        if self.seen.len() == MAX_SEEN_ENVELOPES {
            let _ = self.seen.pop_front();
        }
        self.seen.push_back(id);
    }
}
