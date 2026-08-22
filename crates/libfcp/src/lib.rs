// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Primary federation client SDK for FCP.
//!
//! An application pins a federation authority key out of band, verifies its
//! signed configuration, owns established peer connections, and routes exact CFR
//! payload bytes. Optional engines implement [`transport`]; this crate itself
//! does not run a server, relay signaling or implement a WebRTC socket stack.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

extern crate alloc;

mod bindings;
mod bridge;
mod client;
mod directory;
mod error;

/// Engine-neutral action and event contract for optional FCP transport adapters.
pub mod transport;

pub use bindings::CfrEndpointBindings;
pub use bridge::{deliver_inbound, route_outbound};
pub use client::{ClientConfiguration, FederationClient};
pub use directory::PeerConnections;
pub use error::Error;
