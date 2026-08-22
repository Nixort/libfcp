// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    action::{phase_code, queue_actions},
    memory::{
        attempt_id, copy_bounded, endpoint_identity, federation_id, free_handle, lock_connection,
        owned_buffer, required_handle, required_out, webrtc_binding,
    },
    status::{ffi_status, status_from_core, FcpStatus, FCP_STATUS_NO_ACTION},
    types::{ConnectionState, FcpByteSlice, FcpConnection, FcpConnectionOptions, FcpSigner},
    FcpAction,
};
use libfcp_core::{
    CloseCode, Connection, Envelope, MAX_CANDIDATE_BYTES, MAX_CFR_CONTROL_BYTES,
    MAX_DESCRIPTION_BYTES, MAX_ENVELOPE_BYTES,
};
use std::{collections::VecDeque, sync::Mutex};
/// Creates a signer-backed per-peer connection with fixed federation, attempt and remote identity.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_create(
    signer: *const FcpSigner,
    options: FcpConnectionOptions,
    out: *mut *mut FcpConnection,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let signer = unsafe { required_handle(signer)? };
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let federation = unsafe { federation_id(options.federation)? };
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let attempt = unsafe { attempt_id(options.attempt)? };
        // SAFETY: Parses only borrowed input ranges for the duration of this call.
        let remote = unsafe { endpoint_identity(options.remote_endpoint)? };
        // SAFETY: The output pointer is caller-owned writable storage.
        let out = unsafe { required_out(out)? };
        let signer = signer.inner.clone();
        let connection = Connection::new(federation, attempt, signer.endpoint(), remote)
            .map_err(status_from_core)?;
        *out = Box::into_raw(Box::new(FcpConnection {
            inner: Mutex::new(ConnectionState {
                connection,
                signer,
                actions: VecDeque::new(),
            }),
        }));
        Ok(())
    })
}

/// Starts a local offer and queues ordered actions for the foreign signaling/WebRTC host.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_begin_offer(
    connection: *const FcpConnection,
    binding: FcpByteSlice,
    description: FcpByteSlice,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        // SAFETY: Parses exact fixed bytes during this call.
        let binding = unsafe { webrtc_binding(binding)? };
        // SAFETY: Copies bounded caller bytes before state mutation.
        let description = unsafe { copy_bounded(description, MAX_DESCRIPTION_BYTES)? };
        let signer = state.signer.clone();
        let actions = state
            .connection
            .begin_offer(signer.as_ref(), binding, description)
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, actions)
    })
}

/// Answers an accepted remote offer and queues the signed answer envelope.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_answer(
    connection: *const FcpConnection,
    binding: FcpByteSlice,
    description: FcpByteSlice,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        // SAFETY: Parses exact fixed bytes during this call.
        let binding = unsafe { webrtc_binding(binding)? };
        // SAFETY: Copies bounded caller bytes before state mutation.
        let description = unsafe { copy_bounded(description, MAX_DESCRIPTION_BYTES)? };
        let signer = state.signer.clone();
        let action = state
            .connection
            .answer(signer.as_ref(), binding, description)
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, [action])
    })
}

/// Creates a signed candidate for the active attempt and queues its envelope.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_candidate(
    connection: *const FcpConnection,
    sequence: u32,
    candidate: FcpByteSlice,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        // SAFETY: Copies bounded caller bytes before state mutation.
        let candidate = unsafe { copy_bounded(candidate, MAX_CANDIDATE_BYTES)? };
        let action = state
            .connection
            .candidate(state.signer.as_ref(), sequence, candidate)
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, [action])
    })
}

/// Creates a signed CFR control envelope after a real engine-connected transition.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_cfr_control(
    connection: *const FcpConnection,
    payload: FcpByteSlice,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        // SAFETY: Copies bounded caller bytes before state mutation.
        let payload = unsafe { copy_bounded(payload, MAX_CFR_CONTROL_BYTES)? };
        let action = state
            .connection
            .cfr_control(state.signer.as_ref(), payload)
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, [action])
    })
}

/// Creates a signed local close envelope and queues it for signaling.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_close(
    connection: *const FcpConnection,
    close_code: u16,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        let signer = state.signer.clone();
        let action = state
            .connection
            .close(signer.as_ref(), CloseCode::from_u16(close_code))
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, [action])
    })
}

/// Verifies a received canonical FCP envelope and queues its resulting host actions.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_receive(
    connection: *const FcpConnection,
    envelope: FcpByteSlice,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        // SAFETY: Copies bounded caller bytes before protocol parsing.
        let envelope = unsafe { copy_bounded(envelope, MAX_ENVELOPE_BYTES)? };
        let envelope = Envelope::decode_verified(&envelope).map_err(status_from_core)?;
        let actions = state
            .connection
            .receive(envelope)
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, actions)
    })
}

/// Records that the platform WebRTC engine connected FCP's required control channel.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_transport_connected(
    connection: *const FcpConnection,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        let actions = state
            .connection
            .transport_connected()
            .map_err(status_from_core)?;
        queue_actions(&mut state.actions, actions)
    })
}

/// Records terminal local transport failure without inventing a remote close envelope.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_transport_failed(
    connection: *const FcpConnection,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        state
            .connection
            .transport_failed()
            .map_err(status_from_core)
    })
}

/// Returns the next ordered action, or `FCP_STATUS_NO_ACTION` after the queue is drained.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_take_action(
    connection: *const FcpConnection,
    out: *mut FcpAction,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The output record is caller-owned writable storage.
        let out = unsafe { required_out(out)? };
        // SAFETY: The handle must remain live during this call.
        let mut state = unsafe { lock_connection(connection)? };
        let action = state.actions.pop_front().ok_or(FCP_STATUS_NO_ACTION)?;
        *out = FcpAction {
            kind: action.kind,
            binding: action.binding,
            sequence: action.sequence,
            close_code: action.close_code,
            payload: owned_buffer(action.payload),
        };
        Ok(())
    })
}

/// Returns the connection lifecycle phase as the stable numeric values `0..=6`.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_phase(
    connection: *const FcpConnection,
    out: *mut u32,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The output slot is caller-owned writable storage.
        let out = unsafe { required_out(out)? };
        // SAFETY: The handle must remain live during this call.
        let state = unsafe { lock_connection(connection)? };
        *out = phase_code(state.connection.phase());
        Ok(())
    })
}

/// Releases a connection and sets its caller-owned handle slot to null.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_connection_free(connection: *mut *mut FcpConnection) {
    // SAFETY: The caller owns the pointer slot and may pass null for a no-op release.
    unsafe { free_handle(connection) };
}
