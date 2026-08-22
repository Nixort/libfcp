// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Server-side federation configuration authority for FCP.
//!
//! This crate publishes signed snapshots of application-selected federation
//! membership and endpoint bindings. It does not relay FCP signaling, terminate
//! WebRTC, become a CFR member or replace application identity/admission policy.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

extern crate alloc;

mod error;
mod server;

pub use error::Error;
pub use server::FederationServer;
