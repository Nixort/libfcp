// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Browser-oriented `wasm-bindgen` façade over the portable FCP core.
//!
//! JavaScript owns WebRTC, signaling delivery and browser lifetime. This crate
//! only exposes canonical FCP verification, opaque signers, one connection
//! state machine and ordered action records. It never exposes Fabric or key
//! persistence APIs.

use libfcp_core::{Envelope, SignedFederationConfiguration, MAX_ENVELOPE_BYTES};
use wasm_bindgen::prelude::*;

const ENDPOINT_IDENTITY_BYTES: usize = 32 + libfcp_core::ML_DSA_65_PUBLIC_KEY_BYTES;
const ENVELOPE_ID_BYTES: usize = 32;
const WEBRTC_BINDING_BYTES: usize = 32;

mod action;
mod connection;
mod error;
mod signer;

pub use action::FcpAction;
pub use connection::FcpConnection;
pub use signer::Signer;

use error::{bounded, core_error};

/// Returns the browser façade ABI major version.
#[must_use]
#[wasm_bindgen]
pub fn abi_version() -> u32 {
    2
}

/// Returns the FCP wire version embedded in this browser façade.
#[must_use]
#[wasm_bindgen]
pub fn wire_version() -> u32 {
    u32::from(libfcp_core::FCP_WIRE_VERSION)
}

/// Verifies a complete canonical dual-signed FCP envelope without changing state.
///
/// # Errors
///
/// Returns a JavaScript error for oversized, malformed, non-canonical or incorrectly signed bytes.
#[wasm_bindgen]
pub fn verify_envelope(envelope: &[u8]) -> Result<(), JsError> {
    bounded(envelope, MAX_ENVELOPE_BYTES)?;
    Envelope::decode_verified(envelope)
        .map(|_| ())
        .map_err(core_error)
}

/// Verifies a complete canonical dual-signed FCP configuration without changing state.
///
/// # Errors
///
/// Returns a JavaScript error for malformed, non-canonical or incorrectly signed configuration bytes.
#[wasm_bindgen]
pub fn verify_configuration(configuration: &[u8]) -> Result<(), JsError> {
    SignedFederationConfiguration::decode_verified(configuration)
        .map(|_| ())
        .map_err(core_error)
}

#[cfg(test)]
mod tests;
