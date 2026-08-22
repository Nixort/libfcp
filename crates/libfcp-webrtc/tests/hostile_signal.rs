// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Concrete session hostile-signaling rejection tests.

use ed25519_dalek::SigningKey;
use libfcp_core::{
    AttemptId, Error as FcpError, FederationId, SigningIdentity, MAX_ENVELOPE_BYTES,
};
use libfcp_webrtc::{Error, SessionConfig, WebRtcRsSession};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_signaling_is_rejected_before_engine_application() {
    let local = signer(101);
    let remote = signer(102);
    let session = WebRtcRsSession::new(
        SessionConfig::loopback(),
        FederationId::from_bytes([11; 32]),
        AttemptId::from_bytes([12; 16]),
        local,
        remote.endpoint(),
    )
    .await
    .expect("session");

    assert!(matches!(
        session.accept_signal(&[0xAA; 17]).await,
        Err(Error::Fcp(FcpError::BadMarker))
    ));
    let oversized = vec![0_u8; MAX_ENVELOPE_BYTES + 1];
    assert!(matches!(
        session.accept_signal(&oversized).await,
        Err(Error::Fcp(FcpError::TooLarge))
    ));
    session.close().await.expect("close");
}
