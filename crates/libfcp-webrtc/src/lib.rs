// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Concrete Tokio/WebRTC.rs transport engine for FCP.
//!
//! This crate drives a real Rust WebRTC peer connection while preserving
//! `libfcp-core` as the sole authority for FCP wire validation and state changes.
//! Signaling transport and deployment identity policy remain application-owned.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

mod error;
mod session;
mod signal;

pub use error::Error;
pub use session::{SessionConfig, SessionEvent, WebRtcRsSession};
pub use signal::SignalEvent;
