// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! In-memory FCP-to-WebRTC adapter boundary tests without native sockets.

use ed25519_dalek::SigningKey;
use libfcp::transport::{
    apply_event, dispatch, AdapterEvent, ApplicationAction, CommandQueue, NativeCommand,
};
use libfcp_core::{
    Action, AttemptId, Connection, FederationId, Phase, SigningIdentity, WebRtcBinding,
};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

fn deliver_send(actions: Vec<Action>) -> libfcp_core::Envelope {
    actions
        .into_iter()
        .find_map(|action| match action {
            Action::Send(envelope) => Some(*envelope),
            _ => None,
        })
        .expect("signaling action")
}

#[test]
#[allow(clippy::too_many_lines)]
fn command_queue_and_events_preserve_negotiation_order_and_control_gate() {
    let alice = signer(21);
    let bob = signer(22);
    let federation = FederationId::from_bytes([1; 32]);
    let attempt = AttemptId::from_bytes([2; 16]);
    let mut local =
        Connection::new(federation, attempt, alice.endpoint(), bob.endpoint()).expect("connection");
    let mut remote =
        Connection::new(federation, attempt, bob.endpoint(), alice.endpoint()).expect("connection");
    let mut local_engine = CommandQueue::default();
    let mut remote_engine = CommandQueue::default();

    let offer_actions = local
        .begin_offer(
            &alice,
            WebRtcBinding::derive(b"offer", b"fp-a"),
            b"offer".to_vec(),
        )
        .expect("offer");
    let offer = deliver_send(offer_actions.clone());
    let app_actions: Vec<_> = offer_actions
        .into_iter()
        .filter_map(|action| dispatch(&mut local_engine, action).expect("dispatch"))
        .collect();
    assert_eq!(
        app_actions,
        vec![ApplicationAction::Send(Box::new(offer.clone()))]
    );
    assert_eq!(
        local_engine.take_commands(),
        vec![NativeCommand::OpenControlChannel {
            configuration: libfcp_core::CONTROL_CHANNEL
        }]
    );

    let responder_actions = apply_event(
        &mut remote,
        AdapterEvent::ControlBinary(offer.encode().expect("encode")),
    )
    .expect("apply offer");
    assert_eq!(responder_actions.len(), 1);
    for action in responder_actions {
        assert!(dispatch(&mut remote_engine, action)
            .expect("dispatch")
            .is_none());
    }
    assert_eq!(
        remote_engine.take_commands(),
        vec![NativeCommand::ApplyOffer {
            binding: WebRtcBinding::derive(b"offer", b"fp-a"),
            description: b"offer".to_vec(),
        }]
    );

    let answer = match remote
        .answer(
            &bob,
            WebRtcBinding::derive(b"answer", b"fp-b"),
            b"answer".to_vec(),
        )
        .expect("answer")
    {
        Action::Send(envelope) => *envelope,
        _ => panic!("answer is signaling"),
    };
    let initiator_actions = apply_event(
        &mut local,
        AdapterEvent::ControlBinary(answer.encode().expect("encode")),
    )
    .expect("apply answer");
    for action in initiator_actions {
        assert!(dispatch(&mut local_engine, action)
            .expect("dispatch")
            .is_none());
    }
    assert_eq!(
        local_engine.take_commands(),
        vec![NativeCommand::ApplyAnswer {
            binding: WebRtcBinding::derive(b"answer", b"fp-b"),
            description: b"answer".to_vec(),
        }]
    );
    assert_eq!(local.phase(), Phase::AnswerReceived);
    assert_eq!(remote.phase(), Phase::AnswerSent);

    apply_event(&mut local, AdapterEvent::Connected).expect("connect local");
    apply_event(&mut remote, AdapterEvent::Connected).expect("connect remote");
    assert_eq!(local.phase(), Phase::Established);
    assert_eq!(remote.phase(), Phase::Established);

    let control = match local
        .cfr_control(&alice, b"raw-cfr".to_vec())
        .expect("control")
    {
        Action::Send(envelope) => *envelope,
        _ => panic!("control is sent"),
    };
    let delivered = apply_event(
        &mut remote,
        AdapterEvent::ControlBinary(control.encode().expect("encode")),
    )
    .expect("deliver");
    assert_eq!(
        delivered,
        vec![Action::DeliverCfr {
            payload: b"raw-cfr".to_vec()
        }]
    );
}
