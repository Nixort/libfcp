// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Stable C ABI for the FCP Rust protocol core.
//!
//! This crate is the only intentionally `unsafe` boundary in the client SDK.
//! It validates all FFI records, copies foreign input before returning, catches
//! Rust panics and exposes opaque handles instead of Rust layout or secrets.

const ABI_VERSION: u32 = 1;
const FEDERATION_ID_BYTES: usize = 32;
const ATTEMPT_ID_BYTES: usize = 16;
const CFR_IDENTITY_BYTES: usize = 32;
const WEBRTC_BINDING_BYTES: usize = 32;
const ENDPOINT_IDENTITY_BYTES: usize = 32 + libfcp_core::ML_DSA_65_PUBLIC_KEY_BYTES;

mod action;
mod client;
mod connection;
mod memory;
mod signer;
mod status;
mod types;
mod verify;

pub use action::{
    FcpAction, FCP_ACTION_ADD_CANDIDATE, FCP_ACTION_APPLY_ANSWER, FCP_ACTION_APPLY_OFFER,
    FCP_ACTION_CLOSE_TRANSPORT, FCP_ACTION_DELIVER_CFR, FCP_ACTION_OPEN_CONTROL_CHANNEL,
    FCP_ACTION_SEND_ENVELOPE,
};
pub use client::{
    fcp_client_accepted_epoch, fcp_client_apply_configuration, fcp_client_create, fcp_client_free,
};
pub use connection::{
    fcp_connection_answer, fcp_connection_begin_offer, fcp_connection_candidate,
    fcp_connection_cfr_control, fcp_connection_close, fcp_connection_create, fcp_connection_free,
    fcp_connection_phase, fcp_connection_receive, fcp_connection_take_action,
    fcp_connection_transport_connected, fcp_connection_transport_failed,
};
pub use memory::{fcp_action_free, fcp_buffer_free};
pub use signer::{fcp_signer_free, fcp_signer_generate, fcp_signer_public_identity};
pub use status::{
    FcpStatus, FCP_STATUS_ABI_MISMATCH, FCP_STATUS_CLOSED, FCP_STATUS_CONFIGURATION,
    FCP_STATUS_INTERNAL, FCP_STATUS_INVALID_ARGUMENT, FCP_STATUS_NO_ACTION, FCP_STATUS_OK,
    FCP_STATUS_PANIC, FCP_STATUS_PROTOCOL, FCP_STATUS_TOO_LARGE,
};
pub use types::{
    FcpByteSlice, FcpClient, FcpClientOptions, FcpConnection, FcpConnectionOptions, FcpOwnedBuffer,
    FcpSigner,
};
pub use verify::{fcp_configuration_verify, fcp_envelope_verify};

/// Returns the ABI major version required by all stateful FCP calls.
#[unsafe(no_mangle)]
pub extern "C" fn fcp_ffi_abi_version() -> u32 {
    ABI_VERSION
}

/// Returns the FCP wire-format version embedded in this native library.
#[unsafe(no_mangle)]
pub extern "C" fn fcp_ffi_wire_version() -> u32 {
    u32::from(libfcp_core::FCP_WIRE_VERSION)
}

#[cfg(test)]
mod tests;
