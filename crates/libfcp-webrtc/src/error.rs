// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Concrete WebRTC.rs transport errors.

/// Concrete engine, signaling-session or FCP transition failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// FCP core rejected a local or remote envelope/state transition.
    #[error("fcp core error: {0}")]
    Fcp(#[from] libfcp_core::Error),
    /// The selected WebRTC.rs engine rejected a peer-connection operation.
    #[error("webrtc engine error: {0}")]
    WebRtc(#[from] webrtc::error::Error),
    /// An FCP action was not valid for this concrete engine session.
    #[error("invalid engine action: {0}")]
    InvalidAction(&'static str),
    /// A signed opaque offer or answer was not UTF-8 SDP text for this engine.
    #[error("engine description is not valid UTF-8 SDP")]
    DescriptionEncoding,
    /// An ICE candidate was not the expected WebRTC.rs JSON candidate-init encoding.
    #[error("engine candidate encoding is invalid")]
    CandidateEncoding,
    /// A synchronized session state lock was poisoned by a prior unexpected panic.
    #[error("session state lock poisoned")]
    Poisoned,
    /// The exact configured FCP control data channel did not become available.
    #[error("fcp control data channel unavailable")]
    ControlChannelUnavailable,
    /// The engine emitted an event after the local session had been closed.
    #[error("session closed")]
    Closed,
}
