// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Engine-neutral transport contract for FCP connection actions and events.
//!
//! This module is implemented by optional engine adapters such as `libfcp-webrtc`.
//! It does not select an I/O runtime, parse SDP/ICE as trusted core data, or own
//! federation policy.

mod adapter;
mod queue;

pub use adapter::{apply_event, dispatch, AdapterEvent, ApplicationAction, WebRtcAdapter};
pub use queue::{CommandQueue, NativeCommand};
