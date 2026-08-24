// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Real localhost ICE/DTLS/SCTP FCP control-channel integration test.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use libfcp_core::{AttemptId, CloseCode, FederationId, SigningIdentity};
use libfcp_webrtc::{SessionConfig, SessionEvent, WebRtcRsSession};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

async fn forward_signals(
    source: &mut WebRtcRsSession,
    destination: &WebRtcRsSession,
) -> Result<(), libfcp_webrtc::Error> {
    while let Some(signal) = source.try_take_signal() {
        destination.accept_signal(&signal.encode()?).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_peers_establish_real_webrtc_and_deliver_exact_cfr_control() {
    let alice_key = signer(91);
    let bob_key = signer(92);
    let federation = FederationId::from_bytes([7; 32]);
    let attempt = AttemptId::from_bytes([8; 16]);
    let alice_endpoint = alice_key.endpoint();
    let bob_endpoint = bob_key.endpoint();
    let mut alice = WebRtcRsSession::new(
        SessionConfig::loopback(),
        federation,
        attempt,
        alice_key,
        bob_endpoint,
    )
    .await
    .expect("alice session");
    let mut bob = WebRtcRsSession::new(
        SessionConfig::loopback(),
        federation,
        attempt,
        bob_key,
        alice_endpoint,
    )
    .await
    .expect("bob session");

    let offer = alice.begin_offer().await.expect("offer");
    bob.accept_signal(&offer.encode().expect("encode offer"))
        .await
        .expect("accept offer");
    let answer = bob.answer().await.expect("answer");
    alice
        .accept_signal(&answer.encode().expect("encode answer"))
        .await
        .expect("accept answer");

    let payload = b"exact-cfr-control-over-real-sctp".to_vec();
    let delivered = tokio::time::timeout(Duration::from_secs(20), async {
        let mut alice_connected = false;
        let mut bob_connected = false;
        let mut sent = false;
        loop {
            forward_signals(&mut alice, &bob)
                .await
                .expect("alice signals");
            forward_signals(&mut bob, &alice)
                .await
                .expect("bob signals");

            while let Some(event) = alice.try_take_event() {
                if matches!(event, SessionEvent::Connected) {
                    alice_connected = true;
                }
            }
            while let Some(event) = bob.try_take_event() {
                match event {
                    SessionEvent::Connected => bob_connected = true,
                    SessionEvent::DeliverCfr {
                        envelope_id,
                        remote_endpoint,
                        payload: received,
                    } => return (envelope_id, remote_endpoint, received),
                    SessionEvent::Closed { reason } => {
                        panic!("Bob WebRTC/FCP control channel closed early: {reason:?}")
                    }
                    SessionEvent::Failed => panic!("Bob WebRTC/FCP control channel failed"),
                }
            }
            if alice_connected && bob_connected && !sent {
                alice.send_cfr(payload.clone()).await.expect("send cfr");
                sent = true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("localhost WebRTC/FCP loopback timed out");

    assert_ne!(delivered.0.as_bytes(), &[0; 32]);
    assert_eq!(delivered.1, alice_endpoint);
    assert_eq!(delivered.2, payload);

    let close = alice.begin_close(CloseCode::NORMAL).expect("close");
    bob.accept_signal(&close.encode().expect("encode close"))
        .await
        .expect("accept close");
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = bob.try_take_event() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("verified FCP close was not surfaced by the remote session");
    assert_eq!(
        closed,
        SessionEvent::Closed {
            reason: CloseCode::NORMAL
        }
    );

    alice.close().await.expect("close alice");
    bob.close().await.expect("close bob");
}
