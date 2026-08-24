// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! FCP core wire, authentication and state-machine conformance tests.

use ed25519_dalek::SigningKey;
use libfcp_core::{
    Action, AttemptId, Body, CloseCode, Connection, Envelope, Error, FederationConfiguration,
    FederationId, FederationMember, Phase, SignedFederationConfiguration, SigningIdentity,
    WebRtcBinding, FCP_WIRE_MARKER, FCP_WIRE_VERSION, MAX_DESCRIPTION_BYTES, PROTOCOL_ID,
};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

fn federation() -> FederationId {
    FederationId::from_bytes([9; 32])
}

fn attempt() -> AttemptId {
    AttemptId::from_bytes([7; 16])
}

fn send_action(actions: Vec<Action>) -> Envelope {
    actions
        .into_iter()
        .find_map(|action| match action {
            Action::Send(envelope) => Some(*envelope),
            _ => None,
        })
        .expect("one send action")
}

fn establish() -> (Connection, Connection, SigningIdentity, SigningIdentity) {
    let alice = signer(1);
    let bob = signer(2);
    let mut initiator = Connection::new(federation(), attempt(), alice.endpoint(), bob.endpoint())
        .expect("distinct identities");
    let mut responder = Connection::new(federation(), attempt(), bob.endpoint(), alice.endpoint())
        .expect("distinct identities");
    let offer = send_action(
        initiator
            .begin_offer(
                &alice,
                WebRtcBinding::derive(b"offer", b"fingerprint-a"),
                b"offer".to_vec(),
            )
            .expect("offer"),
    );
    assert!(matches!(
        responder.receive(offer),
        Ok(actions) if matches!(actions.as_slice(), [Action::ApplyOffer { .. }])
    ));
    let answer = match responder
        .answer(
            &bob,
            WebRtcBinding::derive(b"answer", b"fingerprint-b"),
            b"answer".to_vec(),
        )
        .expect("answer")
    {
        Action::Send(envelope) => *envelope,
        _ => panic!("answer must be signaled"),
    };
    assert!(matches!(
        initiator.receive(answer),
        Ok(actions) if matches!(actions.as_slice(), [Action::ApplyAnswer { .. }])
    ));
    initiator.transport_connected().expect("connect initiator");
    responder.transport_connected().expect("connect responder");
    assert_eq!(initiator.phase(), Phase::Established);
    assert_eq!(responder.phase(), Phase::Established);
    (initiator, responder, alice, bob)
}

#[test]
fn canonical_envelope_round_trip_requires_both_signatures() {
    let local = signer(3);
    let remote = signer(4);
    let envelope = Envelope::sign(
        &local,
        federation(),
        attempt(),
        remote.endpoint(),
        Body::Offer {
            binding: WebRtcBinding::derive(b"opaque-sdp", b"dtls"),
            description: b"opaque-sdp".to_vec(),
        },
    )
    .expect("sign");
    let wire = envelope.encode().expect("encode");
    assert_eq!(Envelope::decode(&wire).expect("parse"), envelope);
    assert_eq!(Envelope::decode_verified(&wire).expect("verify"), envelope);

    let mut classical_tamper = wire.clone();
    let classical_signature = classical_tamper.len() - 3_309 - 64;
    classical_tamper[classical_signature] ^= 0x80;
    assert_eq!(
        Envelope::decode_verified(&classical_tamper),
        Err(Error::BadSignature)
    );

    let mut post_quantum_tamper = wire;
    let final_byte = post_quantum_tamper.len() - 1;
    post_quantum_tamper[final_byte] ^= 0x01;
    assert!(matches!(
        Envelope::decode_verified(&post_quantum_tamper),
        Err(Error::BadPostQuantumSignature | Error::BadPostQuantumSignatureEncoding)
    ));
}

#[test]
fn state_machine_accepts_valid_negotiation_and_deduplicates_control() {
    let (initiator, mut responder, alice, bob) = establish();
    let candidate = match initiator
        .candidate(&alice, 11, b"candidate".to_vec())
        .expect("candidate")
    {
        Action::Send(envelope) => *envelope,
        _ => panic!("candidate must be signaled"),
    };
    assert!(matches!(
        responder.receive(candidate),
        Ok(actions) if matches!(actions.as_slice(), [Action::AddCandidate { .. }])
    ));

    let control = match initiator
        .cfr_control(&alice, b"exact-cfr-payload".to_vec())
        .expect("control")
    {
        Action::Send(envelope) => *envelope,
        _ => panic!("control must be signaled"),
    };
    let expected_id = control.id().expect("control id");
    let actions = responder.receive(control.clone()).expect("deliver control");
    let [Action::DeliverCfr {
        envelope_id,
        remote_endpoint,
        payload,
    }] = actions.as_slice()
    else {
        panic!("control must produce one CFR delivery")
    };
    assert_eq!(*envelope_id, expected_id);
    assert_eq!(*remote_endpoint, alice.endpoint());
    assert_eq!(payload, b"exact-cfr-payload");
    assert_ne!(*remote_endpoint, bob.endpoint());
    assert!(responder.receive(control).expect("deduplicate").is_empty());
}

#[test]
fn full_identity_and_routing_binding_are_enforced_before_state_change() {
    let alice = signer(5);
    let bob = signer(6);
    let eve = signer(7);
    let mut receiver = Connection::new(federation(), attempt(), bob.endpoint(), alice.endpoint())
        .expect("distinct identities");

    let wrong_federation = Envelope::sign(
        &alice,
        FederationId::from_bytes([1; 32]),
        attempt(),
        bob.endpoint(),
        Body::Offer {
            binding: WebRtcBinding::derive(b"o", b"d"),
            description: b"o".to_vec(),
        },
    )
    .expect("sign");
    assert_eq!(
        receiver.receive(wrong_federation),
        Err(Error::WrongFederation)
    );
    assert_eq!(receiver.phase(), Phase::Idle);

    let wrong_recipient = Envelope::sign(
        &alice,
        federation(),
        attempt(),
        eve.endpoint(),
        Body::Offer {
            binding: WebRtcBinding::derive(b"o", b"d"),
            description: b"o".to_vec(),
        },
    )
    .expect("sign");
    assert_eq!(
        receiver.receive(wrong_recipient),
        Err(Error::WrongRecipient)
    );

    let wrong_sender = Envelope::sign(
        &eve,
        federation(),
        attempt(),
        bob.endpoint(),
        Body::Offer {
            binding: WebRtcBinding::derive(b"o", b"d"),
            description: b"o".to_vec(),
        },
    )
    .expect("sign");
    assert_eq!(receiver.receive(wrong_sender), Err(Error::WrongSender));
}

#[test]
fn configuration_round_trip_requires_both_authority_signatures() {
    let authority = signer(8);
    let member = signer(9);
    let configuration = FederationConfiguration::new(
        federation(),
        authority.endpoint(),
        11,
        vec![FederationMember {
            cfr_identity: [12; 32],
            endpoint: member.endpoint(),
        }],
    )
    .expect("configuration");
    let signed = SignedFederationConfiguration::sign(configuration, &authority).expect("sign");
    let wire = signed.encode().expect("encode");
    assert_eq!(
        SignedFederationConfiguration::decode_verified(&wire).expect("verify"),
        signed
    );

    let mut tampered = wire;
    let final_byte = tampered.len() - 1;
    tampered[final_byte] ^= 0x01;
    assert_eq!(
        SignedFederationConfiguration::decode_verified(&tampered),
        Err(Error::BadConfigurationSignature)
    );
}

#[test]
fn variable_limits_and_hostile_input_remain_bounded() {
    let local = signer(10);
    let remote = signer(11);
    assert_eq!(
        Envelope::sign(
            &local,
            federation(),
            attempt(),
            remote.endpoint(),
            Body::Offer {
                binding: WebRtcBinding::derive(b"x", b"y"),
                description: vec![0_u8; MAX_DESCRIPTION_BYTES + 1],
            },
        ),
        Err(Error::FieldTooLarge)
    );

    let mut state = 0x6a09_e667_f3bc_c909_u64;
    for length in 0..1_024_usize {
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            input.push(state.to_le_bytes()[0]);
        }
        assert!(std::panic::catch_unwind(|| Envelope::decode(&input)).is_ok());
    }
    assert_eq!(
        Envelope::decode(&vec![0_u8; libfcp_core::MAX_ENVELOPE_BYTES + 1]),
        Err(Error::TooLarge)
    );
}

#[test]
fn protocol_identity_is_neutral_and_close_codes_remain_forward_compatible() {
    assert_eq!(FCP_WIRE_MARKER, *b"FCP");
    assert_eq!(FCP_WIRE_VERSION, 1);
    assert_eq!(PROTOCOL_ID, "org.nixort.cfr.fcp");

    let local = signer(12);
    let remote = signer(13);
    let envelope = Envelope::sign(
        &local,
        federation(),
        attempt(),
        remote.endpoint(),
        Body::Close {
            reason: CloseCode::from_u16(u16::MAX),
        },
    )
    .expect("sign");
    let parsed = Envelope::decode_verified(&envelope.encode().expect("encode")).expect("verify");
    assert_eq!(
        parsed.body,
        Body::Close {
            reason: CloseCode::from_u16(u16::MAX)
        }
    );
}
