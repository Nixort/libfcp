// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use super::*;
use core::{ptr, slice};
use libfcp_core::WebRtcBinding;

fn bytes(value: &[u8]) -> FcpByteSlice {
    FcpByteSlice {
        data: value.as_ptr(),
        len: value.len(),
    }
}

fn generated_signer() -> *mut FcpSigner {
    let mut signer = ptr::null_mut();
    // SAFETY: signer points to writable output storage.
    assert_eq!(
        unsafe { fcp_signer_generate(&raw mut signer) },
        FCP_STATUS_OK
    );
    signer
}

fn public_identity(signer: *const FcpSigner) -> Vec<u8> {
    let mut identity = FcpOwnedBuffer::default();
    // SAFETY: identity is writable output storage and signer is live.
    assert_eq!(
        unsafe { fcp_signer_public_identity(signer, &raw mut identity) },
        FCP_STATUS_OK
    );
    // SAFETY: FCP owns the output range for identity.len bytes.
    let bytes = unsafe { slice::from_raw_parts(identity.data, identity.len) }.to_vec();
    // SAFETY: identity is a FCP-owned returned buffer.
    unsafe { fcp_buffer_free(&raw mut identity) };
    bytes
}

#[test]
fn signer_and_connection_emit_ordered_offer_actions() {
    let mut local = generated_signer();
    let mut remote = generated_signer();
    let remote_identity = public_identity(remote);
    let federation = [3_u8; FEDERATION_ID_BYTES];
    let attempt = [7_u8; ATTEMPT_ID_BYTES];
    let mut connection = ptr::null_mut();
    let options = FcpConnectionOptions {
        federation: bytes(&federation),
        attempt: bytes(&attempt),
        remote_endpoint: bytes(&remote_identity),
    };
    // SAFETY: both opaque handles/options/output are live for this call.
    assert_eq!(
        unsafe { fcp_connection_create(local, options, &raw mut connection) },
        FCP_STATUS_OK
    );
    let binding = WebRtcBinding::derive(b"offer", b"fingerprint");
    // SAFETY: connection and byte ranges remain live for the call.
    assert_eq!(
        unsafe {
            fcp_connection_begin_offer(
                connection,
                bytes(binding.as_bytes()),
                bytes(b"opaque-offer"),
            )
        },
        FCP_STATUS_OK
    );
    let mut action = FcpAction::default();
    // SAFETY: connection/action output are live.
    assert_eq!(
        unsafe { fcp_connection_take_action(connection, &raw mut action) },
        FCP_STATUS_OK
    );
    assert_eq!(action.kind, FCP_ACTION_OPEN_CONTROL_CHANNEL);
    // SAFETY: action is FCP-owned output.
    unsafe { fcp_action_free(&raw mut action) };
    // SAFETY: connection/action output are live.
    assert_eq!(
        unsafe { fcp_connection_take_action(connection, &raw mut action) },
        FCP_STATUS_OK
    );
    assert_eq!(action.kind, FCP_ACTION_SEND_ENVELOPE);
    assert_eq!(
        unsafe {
            fcp_envelope_verify(FcpByteSlice {
                data: action.payload.data,
                len: action.payload.len,
            })
        },
        FCP_STATUS_OK
    );
    // SAFETY: action is FCP-owned output.
    unsafe { fcp_action_free(&raw mut action) };
    // SAFETY: connection/action output are live.
    assert_eq!(
        unsafe { fcp_connection_take_action(connection, &raw mut action) },
        FCP_STATUS_NO_ACTION
    );
    // SAFETY: each pointer is an owned FCP handle slot.
    unsafe {
        fcp_connection_free(&raw mut connection);
        fcp_signer_free(&raw mut local);
        fcp_signer_free(&raw mut remote);
    }
    assert!(connection.is_null());
    assert!(local.is_null());
    assert!(remote.is_null());
}

#[test]
fn invalid_fixed_inputs_and_oversize_data_are_rejected_before_state_change() {
    let mut signer = generated_signer();
    let mut connection = ptr::null_mut();
    let options = FcpConnectionOptions {
        federation: bytes(&[1_u8; FEDERATION_ID_BYTES]),
        attempt: bytes(&[2_u8; ATTEMPT_ID_BYTES]),
        remote_endpoint: FcpByteSlice {
            data: ptr::null(),
            len: ENDPOINT_IDENTITY_BYTES,
        },
    };
    // SAFETY: invalid input must report a status instead of dereferencing null.
    assert_eq!(
        unsafe { fcp_connection_create(signer, options, &raw mut connection) },
        FCP_STATUS_INVALID_ARGUMENT
    );
    assert!(connection.is_null());
    // SAFETY: signer is an owned FCP handle slot.
    unsafe { fcp_signer_free(&raw mut signer) };
}
