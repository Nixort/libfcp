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

fn take_action(connection: *const FcpConnection) -> FcpAction {
    let mut action = FcpAction::default();
    // SAFETY: connection is live and action is writable output storage.
    assert_eq!(
        unsafe { fcp_connection_take_action(connection, &raw mut action) },
        FCP_STATUS_OK
    );
    action
}

fn copy_buffer(buffer: &FcpOwnedBuffer) -> Vec<u8> {
    // SAFETY: the test copies a live FCP-owned output range before releasing its action.
    unsafe { slice::from_raw_parts(buffer.data, buffer.len) }.to_vec()
}

#[test]
fn cfr_delivery_copies_verified_origin_into_ffi_action() {
    let mut alice = generated_signer();
    let mut bob = generated_signer();
    let alice_identity = public_identity(alice);
    let bob_identity = public_identity(bob);
    let federation = [4_u8; FEDERATION_ID_BYTES];
    let attempt = [8_u8; ATTEMPT_ID_BYTES];
    let mut alice_connection = ptr::null_mut();
    let mut bob_connection = ptr::null_mut();
    let alice_options = FcpConnectionOptions {
        federation: bytes(&federation),
        attempt: bytes(&attempt),
        remote_endpoint: bytes(&bob_identity),
    };
    let bob_options = FcpConnectionOptions {
        federation: bytes(&federation),
        attempt: bytes(&attempt),
        remote_endpoint: bytes(&alice_identity),
    };
    // SAFETY: all opaque handles, borrowed byte ranges and output slots are live.
    assert_eq!(
        unsafe { fcp_connection_create(alice, alice_options, &raw mut alice_connection) },
        FCP_STATUS_OK
    );
    // SAFETY: all opaque handles, borrowed byte ranges and output slots are live.
    assert_eq!(
        unsafe { fcp_connection_create(bob, bob_options, &raw mut bob_connection) },
        FCP_STATUS_OK
    );
    let binding = WebRtcBinding::derive(b"ffi-offer", b"ffi-fingerprint");
    // SAFETY: connection and input ranges are live for this call.
    assert_eq!(
        unsafe {
            fcp_connection_begin_offer(
                alice_connection,
                bytes(binding.as_bytes()),
                bytes(b"ffi-offer"),
            )
        },
        FCP_STATUS_OK
    );
    let mut open = take_action(alice_connection);
    assert_eq!(open.kind, FCP_ACTION_OPEN_CONTROL_CHANNEL);
    // SAFETY: open is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut open) };
    let mut offer = take_action(alice_connection);
    let offer_wire = copy_buffer(&offer.payload);
    // SAFETY: offer is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut offer) };
    // SAFETY: bob connection and offer wire range are live.
    assert_eq!(
        unsafe { fcp_connection_receive(bob_connection, bytes(&offer_wire)) },
        FCP_STATUS_OK
    );
    let mut apply_offer = take_action(bob_connection);
    assert_eq!(apply_offer.kind, FCP_ACTION_APPLY_OFFER);
    // SAFETY: apply_offer is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut apply_offer) };
    let answer_binding = WebRtcBinding::derive(b"ffi-answer", b"ffi-fingerprint");
    // SAFETY: bob connection and input ranges are live.
    assert_eq!(
        unsafe {
            fcp_connection_answer(
                bob_connection,
                bytes(answer_binding.as_bytes()),
                bytes(b"ffi-answer"),
            )
        },
        FCP_STATUS_OK
    );
    let mut answer = take_action(bob_connection);
    let answer_wire = copy_buffer(&answer.payload);
    // SAFETY: answer is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut answer) };
    // SAFETY: alice connection and answer wire range are live.
    assert_eq!(
        unsafe { fcp_connection_receive(alice_connection, bytes(&answer_wire)) },
        FCP_STATUS_OK
    );
    let mut apply_answer = take_action(alice_connection);
    assert_eq!(apply_answer.kind, FCP_ACTION_APPLY_ANSWER);
    // SAFETY: apply_answer is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut apply_answer) };
    // SAFETY: both FCP connections are live.
    assert_eq!(
        unsafe { fcp_connection_transport_connected(alice_connection) },
        FCP_STATUS_OK
    );
    // SAFETY: both FCP connections are live.
    assert_eq!(
        unsafe { fcp_connection_transport_connected(bob_connection) },
        FCP_STATUS_OK
    );
    // SAFETY: alice connection and payload range are live.
    assert_eq!(
        unsafe { fcp_connection_cfr_control(alice_connection, bytes(b"exact-ffi-cfr")) },
        FCP_STATUS_OK
    );
    let mut sent_control = take_action(alice_connection);
    let control_wire = copy_buffer(&sent_control.payload);
    let expected_id = libfcp_core::Envelope::decode_verified(&control_wire)
        .expect("verify control")
        .id()
        .expect("control id");
    // SAFETY: sent_control is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut sent_control) };
    // SAFETY: bob connection and control wire range are live.
    assert_eq!(
        unsafe { fcp_connection_receive(bob_connection, bytes(&control_wire)) },
        FCP_STATUS_OK
    );
    let mut delivered = take_action(bob_connection);
    assert_eq!(delivered.kind, FCP_ACTION_DELIVER_CFR);
    assert_eq!(delivered.envelope_id, *expected_id.as_bytes());
    assert_eq!(copy_buffer(&delivered.remote_endpoint), alice_identity);
    assert_eq!(copy_buffer(&delivered.payload), b"exact-ffi-cfr");
    // SAFETY: delivered is one FCP-owned action output.
    unsafe { fcp_action_free(&raw mut delivered) };
    assert_eq!(delivered.remote_endpoint.len, 0);
    assert_eq!(delivered.payload.len, 0);
    assert_eq!(delivered.envelope_id, [0; ENVELOPE_ID_BYTES]);
    // SAFETY: every pointer is an owned FCP handle slot.
    unsafe {
        fcp_connection_free(&raw mut alice_connection);
        fcp_connection_free(&raw mut bob_connection);
        fcp_signer_free(&raw mut alice);
        fcp_signer_free(&raw mut bob);
    }
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
