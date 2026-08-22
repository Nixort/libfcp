// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! WebRTC.rs session configuration, shared engine state and peer callbacks.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) const ENGINE_EVENT_CAPACITY: usize = 128;
pub(super) const SIGNAL_EVENT_CAPACITY: usize = 128;
pub(super) const CONTROL_SEND_BUFFER_BYTES: usize = 512 * 1024;
pub(super) const MAX_STAGED_LOCAL_CANDIDATES: usize = 64;

/// Configuration for a concrete WebRTC.rs FCP session.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionConfig {
    /// Locally bound UDP addresses, such as `127.0.0.1:0` for loopback tests.
    pub udp_addresses: Vec<String>,
    /// Application-approved STUN or TURN servers used by the selected engine.
    pub ice_servers: Vec<RTCIceServer>,
}

impl SessionConfig {
    /// Creates a localhost-only configuration suitable for deterministic local integration tests.
    pub fn loopback() -> Self {
        Self {
            udp_addresses: vec!["127.0.0.1:0".to_owned()],
            ice_servers: Vec::new(),
        }
    }
}

/// Application-facing live event from a concrete FCP WebRTC.rs session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The fixed FCP data channel opened after real WebRTC transport establishment.
    Connected,
    /// Exact CFR bytes delivered from a verified FCP control envelope.
    DeliverCfr {
        /// Unmodified payload for `cfr_protocol::Conference::handle`.
        payload: Vec<u8>,
    },
    /// A verified remote FCP close caused the local engine session to close.
    Closed {
        /// Signed application-defined remote close reason.
        reason: CloseCode,
    },
    /// The selected engine or control channel failed without a verified FCP close.
    Failed,
}

pub(super) struct Shared {
    pub(super) connection: Mutex<Connection>,
    pub(super) signer: SigningIdentity,
    pub(super) signals: Mutex<Sender<SignalEvent>>,
    pub(super) events: Sender<SessionEvent>,
    pub(super) control: tokio::sync::Mutex<Option<Arc<dyn DataChannel>>>,
    pub(super) candidate_sequence: AtomicU32,
    pub(super) staged_candidates: Mutex<VecDeque<(u32, Vec<u8>)>>,
    pub(super) terminal: AtomicBool,
}

#[derive(Clone)]
pub(super) struct EngineHandler {
    pub(super) shared: Arc<Shared>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for EngineHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let Ok(candidate) = event.candidate.to_json() else {
            return;
        };
        let Ok(candidate) = serde_json::to_vec(&candidate) else {
            return;
        };
        let sequence = self
            .shared
            .candidate_sequence
            .fetch_add(1, Ordering::Relaxed);
        emit_or_stage_candidate(&self.shared, sequence, candidate);
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        if state == RTCPeerConnectionState::Failed {
            let _ = emit_terminal(&self.shared, SessionEvent::Failed).await;
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        install_remote_control_channel(self.shared.clone(), channel).await;
    }
}
