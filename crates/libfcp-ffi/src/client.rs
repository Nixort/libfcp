// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    memory::{
        copy_bounded, endpoint_identity, federation_id, fixed, free_handle, required_handle,
        required_out,
    },
    status::{ffi_status, status_from_client, status_from_core, FcpStatus, FCP_STATUS_CLOSED},
    types::{FcpByteSlice, FcpClient, FcpClientOptions},
    CFR_IDENTITY_BYTES,
};
use libfcp::{ClientConfiguration, FederationClient};
use libfcp_core::{SignedFederationConfiguration, MAX_ENVELOPE_BYTES};
use std::sync::Mutex;
/// Creates a configuration-validation client pinned to the supplied public policy.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_client_create(
    options: FcpClientOptions,
    out: *mut *mut FcpClient,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let federation = unsafe { federation_id(options.federation)? };
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let authority = unsafe { endpoint_identity(options.authority)? };
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let local_cfr_identity =
            unsafe { fixed::<CFR_IDENTITY_BYTES>(options.local_cfr_identity)? };
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let local_endpoint = unsafe { endpoint_identity(options.local_endpoint)? };
        // SAFETY: The output pointer is caller-owned writable storage.
        let out = unsafe { required_out(out)? };
        let policy = ClientConfiguration {
            federation,
            authority,
            local_cfr_identity: cfr_protocol::SigPublic::from_bytes(local_cfr_identity),
            local_endpoint,
        };
        *out = Box::into_raw(Box::new(FcpClient {
            inner: Mutex::new(FederationClient::new(policy)),
        }));
        Ok(())
    })
}

/// Verifies and atomically applies a strictly newer canonical signed `FCFG` snapshot.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_client_apply_configuration(
    client: *const FcpClient,
    configuration: FcpByteSlice,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let client = unsafe { required_handle(client)? };
        // SAFETY: Input is copied before the parser returns and bounded before allocation.
        let configuration = unsafe { copy_bounded(configuration, MAX_ENVELOPE_BYTES)? };
        let configuration = SignedFederationConfiguration::decode_verified(&configuration)
            .map_err(status_from_core)?;
        let mut client = client.inner.lock().map_err(|_| FCP_STATUS_CLOSED)?;
        client
            .apply_configuration(configuration)
            .map_err(status_from_client)
    })
}

/// Returns whether a configuration epoch has been accepted and, if so, its value.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_client_accepted_epoch(
    client: *const FcpClient,
    out_epoch: *mut u64,
    out_present: *mut u8,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let client = unsafe { required_handle(client)? };
        // SAFETY: Both output slots are caller-owned writable storage.
        let out_epoch = unsafe { required_out(out_epoch)? };
        // SAFETY: Both output slots are caller-owned writable storage.
        let out_present = unsafe { required_out(out_present)? };
        let client = client.inner.lock().map_err(|_| FCP_STATUS_CLOSED)?;
        if let Some(epoch) = client.accepted_epoch() {
            *out_epoch = epoch;
            *out_present = 1;
        } else {
            *out_epoch = 0;
            *out_present = 0;
        }
        Ok(())
    })
}

/// Releases a configuration client and sets its caller-owned handle slot to null.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_client_free(client: *mut *mut FcpClient) {
    // SAFETY: The caller owns the pointer slot and may pass null for a no-op release.
    unsafe { free_handle(client) };
}
