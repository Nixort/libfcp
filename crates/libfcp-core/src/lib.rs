// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Transport-agnostic FCP federation connection-control core.
//!
//! Applications use [`Connection`] to bind one WebRTC negotiation attempt to a
//! federation and endpoint keys. The core neither parses SDP/ICE nor CFR
//! payloads; platform adapters and the CFR bridge own those separate concerns.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

extern crate alloc;

mod configuration;
mod connection;
mod envelope;
mod error;
mod identity;
mod types;

pub use configuration::{
    FederationConfiguration, FederationMember, SignedFederationConfiguration,
    FEDERATION_CONFIG_MARKER, FEDERATION_CONFIG_VERSION, MAX_FEDERATION_MEMBERS,
};
pub use connection::{Action, Connection, ControlChannelConfig, Phase, CONTROL_CHANNEL};
pub use envelope::{Body, Envelope, Kind};
pub use error::Error;
pub use identity::{
    EndpointIdentity, EndpointSigner, SigningIdentity, ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
};
pub use types::{
    AttemptId, CloseCode, EndpointKey, EnvelopeId, FederationId, WebRtcBinding, FCP_WIRE_MARKER,
    FCP_WIRE_VERSION, MAX_CANDIDATE_BYTES, MAX_CFR_CONTROL_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_ENVELOPE_BYTES, MAX_SEEN_ENVELOPES, PROTOCOL_ID,
};
