// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    action::FcpAction,
    status::{FcpStatus, FCP_STATUS_CLOSED, FCP_STATUS_INVALID_ARGUMENT, FCP_STATUS_TOO_LARGE},
    types::{ConnectionState, FcpByteSlice, FcpConnection, FcpOwnedBuffer},
    ATTEMPT_ID_BYTES, ENDPOINT_IDENTITY_BYTES, FEDERATION_ID_BYTES, WEBRTC_BINDING_BYTES,
};
use core::{mem, ptr, slice};
use libfcp_core::{
    AttemptId, EndpointIdentity, EndpointKey, FederationId, WebRtcBinding,
    ML_DSA_65_PUBLIC_KEY_BYTES,
};
use std::sync::MutexGuard;
/// Releases an FCP-owned byte buffer and resets the record to an empty buffer.
///
/// The caller must pass only a record previously returned by FCP. The operation
/// is a no-op for a null record pointer or an already-reset record.
///
/// # Safety
/// The caller must provide a valid writable `FcpOwnedBuffer` record returned by FCP.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_buffer_free(buffer: *mut FcpOwnedBuffer) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: The ABI requires a valid writable FcpOwnedBuffer pointer. The function
    // resets it before releasing the allocation to make repeated release idempotent.
    let buffer = unsafe { &mut *buffer };
    let old = mem::take(buffer);
    if old.len == 0 || old.data.is_null() {
        return;
    }
    // SAFETY: FCP creates nonempty returned buffers from Box<[u8]> with exactly this
    // data pointer and length. Foreign callers must not forge or mutate FCP buffers.
    let bytes = unsafe { slice::from_raw_parts_mut(old.data, old.len) };
    // SAFETY: The slice originated from Box<[u8]> in owned_buffer and is released once.
    unsafe { drop(Box::from_raw(bytes)) };
}

/// Releases a returned action's owned endpoint and payload buffers and resets the whole action record.
///
/// # Safety
/// The caller must provide a valid writable `FcpAction` record returned by FCP.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_action_free(action: *mut FcpAction) {
    if action.is_null() {
        return;
    }
    // SAFETY: The ABI requires a valid writable FcpAction output record.
    let action = unsafe { &mut *action };
    // SAFETY: Both buffers follow the FCP-owned buffer contract.
    unsafe { fcp_buffer_free(&raw mut action.remote_endpoint) };
    // SAFETY: Both buffers follow the FCP-owned buffer contract.
    unsafe { fcp_buffer_free(&raw mut action.payload) };
    *action = FcpAction::default();
}

pub(crate) fn owned_buffer(bytes: Vec<u8>) -> FcpOwnedBuffer {
    if bytes.is_empty() {
        return FcpOwnedBuffer::default();
    }
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let data = Box::into_raw(boxed).cast::<u8>();
    FcpOwnedBuffer { data, len }
}

pub(crate) fn endpoint_buffer(endpoint: &EndpointIdentity) -> FcpOwnedBuffer {
    let mut bytes = Vec::with_capacity(ENDPOINT_IDENTITY_BYTES);
    bytes.extend_from_slice(endpoint.classical.as_bytes());
    bytes.extend_from_slice(&endpoint.post_quantum);
    owned_buffer(bytes)
}

pub(crate) unsafe fn required_handle<'a, T>(handle: *const T) -> Result<&'a T, FcpStatus> {
    if handle.is_null() {
        return Err(FCP_STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: A non-null opaque handle is valid for the current call by ABI contract.
    Ok(unsafe { &*handle })
}

pub(crate) unsafe fn required_out<'a, T>(out: *mut T) -> Result<&'a mut T, FcpStatus> {
    if out.is_null() {
        return Err(FCP_STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: A non-null output pointer is valid writable storage by ABI contract.
    Ok(unsafe { &mut *out })
}

pub(crate) unsafe fn free_handle<T>(slot: *mut *mut T) {
    if slot.is_null() {
        return;
    }
    // SAFETY: The caller owns the handle slot and it is writable for this call.
    let slot = unsafe { &mut *slot };
    let handle = mem::replace(slot, ptr::null_mut());
    if handle.is_null() {
        return;
    }
    // SAFETY: FCP creates handles with Box::into_raw and this slot-based release is once-only.
    unsafe { drop(Box::from_raw(handle)) };
}

pub(crate) unsafe fn borrowed_bytes<'a>(input: FcpByteSlice) -> Result<&'a [u8], FcpStatus> {
    if input.len == 0 {
        return Ok(&[]);
    }
    if input.data.is_null() {
        return Err(FCP_STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: The caller guarantees the immutable range is readable for this FFI call.
    Ok(unsafe { slice::from_raw_parts(input.data, input.len) })
}

pub(crate) unsafe fn copy_bounded(
    input: FcpByteSlice,
    maximum: usize,
) -> Result<Vec<u8>, FcpStatus> {
    if input.len > maximum {
        return Err(FCP_STATUS_TOO_LARGE);
    }
    // SAFETY: The returned borrow is copied before this function returns.
    Ok(unsafe { borrowed_bytes(input)? }.to_vec())
}

pub(crate) unsafe fn fixed<const N: usize>(input: FcpByteSlice) -> Result<[u8; N], FcpStatus> {
    // SAFETY: The returned borrow is copied into a fixed local array before returning.
    let bytes = unsafe { borrowed_bytes(input)? };
    if bytes.len() != N {
        return Err(FCP_STATUS_INVALID_ARGUMENT);
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    Ok(output)
}

pub(crate) unsafe fn federation_id(input: FcpByteSlice) -> Result<FederationId, FcpStatus> {
    // SAFETY: fixed performs exact-width pointer validation and copies the bytes.
    Ok(FederationId::from_bytes(unsafe {
        fixed::<FEDERATION_ID_BYTES>(input)?
    }))
}

pub(crate) unsafe fn attempt_id(input: FcpByteSlice) -> Result<AttemptId, FcpStatus> {
    // SAFETY: fixed performs exact-width pointer validation and copies the bytes.
    Ok(AttemptId::from_bytes(unsafe {
        fixed::<ATTEMPT_ID_BYTES>(input)?
    }))
}

pub(crate) unsafe fn webrtc_binding(input: FcpByteSlice) -> Result<WebRtcBinding, FcpStatus> {
    // SAFETY: fixed performs exact-width pointer validation and copies the bytes.
    Ok(WebRtcBinding::from_bytes(unsafe {
        fixed::<WEBRTC_BINDING_BYTES>(input)?
    }))
}

pub(crate) unsafe fn endpoint_identity(input: FcpByteSlice) -> Result<EndpointIdentity, FcpStatus> {
    // SAFETY: fixed performs exact-width pointer validation and copies the bytes.
    let bytes = unsafe { fixed::<ENDPOINT_IDENTITY_BYTES>(input)? };
    let mut classical = [0_u8; 32];
    classical.copy_from_slice(&bytes[..32]);
    let mut post_quantum = [0_u8; ML_DSA_65_PUBLIC_KEY_BYTES];
    post_quantum.copy_from_slice(&bytes[32..]);
    Ok(EndpointIdentity::new(
        EndpointKey::from_bytes(classical),
        post_quantum,
    ))
}

pub(crate) unsafe fn lock_connection<'a>(
    connection: *const FcpConnection,
) -> Result<MutexGuard<'a, ConnectionState>, FcpStatus> {
    // SAFETY: required_handle validates the opaque connection handle for this call.
    let connection = unsafe { required_handle(connection)? };
    connection.inner.lock().map_err(|_| FCP_STATUS_CLOSED)
}
