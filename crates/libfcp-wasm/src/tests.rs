// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    action::{convert_action, ACTION_OPEN_CONTROL_CHANNEL, ACTION_SEND_ENVELOPE},
    verify_envelope, FcpConnection, Signer, WEBRTC_BINDING_BYTES,
};
use libfcp_core::{Action, EndpointIdentity, EndpointKey, EnvelopeId, ML_DSA_65_PUBLIC_KEY_BYTES};

#[test]
fn wasm_facade_preserves_offer_action_order_and_signed_envelope() {
    let local = Signer::new().expect("signer");
    let remote = Signer::new().expect("signer");
    let mut connection = FcpConnection::new(&local, &[3; 32], &[7; 16], &remote.public_identity())
        .expect("connection");
    connection
        .begin_offer(&[9; WEBRTC_BINDING_BYTES], b"opaque-offer")
        .expect("offer");
    assert_eq!(
        connection.take_action().expect("channel").kind(),
        ACTION_OPEN_CONTROL_CHANNEL
    );
    let envelope = connection.take_action().expect("envelope");
    assert_eq!(envelope.kind(), ACTION_SEND_ENVELOPE);
    verify_envelope(&envelope.payload()).expect("signed envelope");
    assert!(connection.take_action().is_none());
}

#[test]
fn wasm_action_preserves_verified_cfr_origin() {
    let endpoint = EndpointIdentity::new(
        EndpointKey::from_bytes([5; 32]),
        [6; ML_DSA_65_PUBLIC_KEY_BYTES],
    );
    let action = convert_action(Action::DeliverCfr {
        envelope_id: EnvelopeId::from_bytes([7; 32]),
        remote_endpoint: endpoint,
        payload: b"exact-wasm-cfr".to_vec(),
    })
    .expect("convert CFR action");
    assert_eq!(action.envelope_id(), vec![7; 32]);
    assert_eq!(
        action.remote_endpoint().len(),
        crate::ENDPOINT_IDENTITY_BYTES
    );
    assert_eq!(
        &action.remote_endpoint()[..32],
        endpoint.classical.as_bytes()
    );
    assert_eq!(action.payload(), b"exact-wasm-cfr");
}
