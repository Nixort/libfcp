// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! CFR recipient-to-FCP connection bridge tests.

use cfr_protocol::{Message, Recipient, SigPublic};
use ed25519_dalek::SigningKey;
use libfcp::{route_outbound, CfrEndpointBindings, Error, PeerConnections};
use libfcp_core::{
    Action, AttemptId, Body, Connection, FederationId, SigningIdentity, WebRtcBinding,
};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

fn established_local_connection(
    local: &SigningIdentity,
    remote: &SigningIdentity,
    attempt_byte: u8,
) -> Connection {
    let federation = FederationId::from_bytes([1; 32]);
    let attempt = AttemptId::from_bytes([attempt_byte; 16]);
    let mut local_connection =
        Connection::new(federation, attempt, local.endpoint(), remote.endpoint())
            .expect("distinct identities");
    let mut remote_connection =
        Connection::new(federation, attempt, remote.endpoint(), local.endpoint())
            .expect("distinct identities");
    let offer = local_connection
        .begin_offer(
            local,
            WebRtcBinding::derive(b"offer", b"fp-a"),
            b"offer".to_vec(),
        )
        .expect("offer")
        .into_iter()
        .find_map(|action| match action {
            Action::Send(envelope) => Some(*envelope),
            _ => None,
        })
        .expect("signal");
    remote_connection.receive(offer).expect("apply offer");
    let answer = match remote_connection
        .answer(
            remote,
            WebRtcBinding::derive(b"answer", b"fp-b"),
            b"answer".to_vec(),
        )
        .expect("answer")
    {
        Action::Send(envelope) => *envelope,
        _ => panic!("answer must signal"),
    };
    local_connection.receive(answer).expect("apply answer");
    local_connection
        .transport_connected()
        .expect("connect local");
    remote_connection
        .transport_connected()
        .expect("connect remote");
    local_connection
}

fn sent_payload(action: Action) -> Vec<u8> {
    let Action::Send(envelope) = action else {
        panic!("bridge must emit FCP signal")
    };
    let Body::CfrControl { payload } = envelope.body else {
        panic!("bridge must preserve cfr control kind")
    };
    payload
}

#[test]
fn targeted_cfr_recipient_uses_explicit_binding_and_preserves_exact_payload() {
    let local = signer(31);
    let remote = signer(32);
    let cfr_remote = SigPublic::from_bytes([77; 32]);
    let mut bindings = CfrEndpointBindings::new();
    bindings.bind(cfr_remote, remote.endpoint());
    let mut connections = PeerConnections::new(FederationId::from_bytes([1; 32]), local.endpoint());
    connections
        .insert(established_local_connection(&local, &remote, 1))
        .expect("insert");
    let message = Message {
        to: Recipient::Peer(cfr_remote),
        payload: b"cfr-wire-unchanged".to_vec(),
    };

    let actions = route_outbound(&message, &local, &bindings, &connections).expect("route");
    assert_eq!(actions.len(), 1);
    assert_eq!(
        sent_payload(actions.into_iter().next().expect("action")),
        b"cfr-wire-unchanged".to_vec()
    );
}

#[test]
fn everyone_expands_only_application_provided_remote_bindings() {
    let local = signer(41);
    let remote_a = signer(42);
    let remote_b = signer(43);
    let cfr_a = SigPublic::from_bytes([88; 32]);
    let cfr_b = SigPublic::from_bytes([89; 32]);
    let mut bindings = CfrEndpointBindings::new();
    bindings.bind(cfr_a, remote_a.endpoint());
    bindings.bind(cfr_b, remote_b.endpoint());
    let mut connections = PeerConnections::new(FederationId::from_bytes([1; 32]), local.endpoint());
    connections
        .insert(established_local_connection(&local, &remote_a, 2))
        .expect("insert remote a");
    connections
        .insert(established_local_connection(&local, &remote_b, 3))
        .expect("insert remote b");
    let message = Message {
        to: Recipient::Everyone,
        payload: b"broadcast-exact".to_vec(),
    };

    let actions = route_outbound(&message, &local, &bindings, &connections).expect("route");
    assert_eq!(actions.len(), 2);
    for action in actions {
        assert_eq!(sent_payload(action), b"broadcast-exact".to_vec());
    }
}

#[test]
fn absent_binding_fails_without_guessing_from_cfr_key_bytes() {
    let local = signer(51);
    let cfr_remote = SigPublic::from_bytes([90; 32]);
    let message = Message {
        to: Recipient::Peer(cfr_remote),
        payload: b"payload".to_vec(),
    };
    assert_eq!(
        route_outbound(
            &message,
            &local,
            &CfrEndpointBindings::new(),
            &PeerConnections::new(FederationId::from_bytes([1; 32]), local.endpoint()),
        ),
        Err(Error::MissingBinding)
    );
}

#[test]
fn directory_rejects_connection_from_another_federation() {
    let local = signer(61);
    let remote = signer(62);
    let mut connections = PeerConnections::new(FederationId::from_bytes([1; 32]), local.endpoint());
    let wrong_federation = Connection::new(
        FederationId::from_bytes([2; 32]),
        AttemptId::from_bytes([4; 16]),
        local.endpoint(),
        remote.endpoint(),
    )
    .expect("connection");

    assert!(matches!(
        connections.insert(wrong_federation),
        Err(Error::MismatchedConnection)
    ));
}
