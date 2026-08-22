// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    memory::{borrowed_bytes, copy_bounded},
    status::{ffi_status, status_from_core, FcpStatus},
    types::FcpByteSlice,
};
use libfcp_core::{Envelope, SignedFederationConfiguration, MAX_ENVELOPE_BYTES};
/// Verifies a complete canonical FCP envelope without constructing state.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_envelope_verify(envelope: FcpByteSlice) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: Copies bounded caller bytes before parsing.
        let envelope = unsafe { copy_bounded(envelope, MAX_ENVELOPE_BYTES)? };
        Envelope::decode_verified(&envelope)
            .map(|_| ())
            .map_err(status_from_core)
    })
}

/// Verifies a complete canonical signed FCP federation configuration without changing state.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_configuration_verify(configuration: FcpByteSlice) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The configuration parser performs the authoritative bounded decode.
        let configuration = unsafe { borrowed_bytes(configuration)? };
        SignedFederationConfiguration::decode_verified(configuration)
            .map(|_| ())
            .map_err(status_from_core)
    })
}
