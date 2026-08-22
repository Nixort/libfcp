// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Deterministic verified-wire decode benchmark for FCP.
//!
//! Run with `cargo run --release -p libfcp-core --example wire_benchmark`.
//! This measures only local canonical parsing plus mandatory Ed25519 and ML-DSA-65 verification; it does
//! not measure ICE, DTLS, SCTP, signaling, media, a WebRTC engine or network I/O.

use std::hint::black_box;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use libfcp_core::{AttemptId, Body, Envelope, FederationId, SigningIdentity, WebRtcBinding};
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

const SAMPLES: usize = 20_000;

fn signed_wire(body: Body) -> Vec<u8> {
    let signer = SigningIdentity::new(
        SigningKey::from_bytes(&[41; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([41; 32])),
    );
    let recipient = SigningIdentity::new(
        SigningKey::from_bytes(&[42; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([42; 32])),
    );
    Envelope::sign(
        &signer,
        FederationId::from_bytes([1; 32]),
        AttemptId::from_bytes([2; 16]),
        recipient.endpoint(),
        body,
    )
    .expect("bounded test envelope")
    .encode()
    .expect("canonical wire")
}

fn measure(name: &str, wire: &[u8]) {
    let samples = u32::try_from(SAMPLES).expect("fixed sample count fits u32");
    let start = Instant::now();
    let mut total = 0_u32;
    for _ in 0..samples {
        let envelope = Envelope::decode_verified(black_box(wire)).expect("verified fixture");
        let encoded = envelope.encode().expect("canonical re-encode");
        let bytes = u32::try_from(encoded.len()).expect("bounded envelope fits u32");
        total = total
            .checked_add(bytes)
            .expect("fixed benchmark byte count fits u32");
        black_box(envelope);
    }
    let seconds = start.elapsed().as_secs_f64();
    let envelopes_per_second = f64::from(samples) / seconds;
    let mebibytes_per_second = f64::from(total) / (1024.0 * 1024.0) / seconds;
    println!(
        "{name}\twire_bytes={}\tsamples={SAMPLES}\tenvelopes_per_second={envelopes_per_second:.0}\tMiB_per_second={mebibytes_per_second:.2}",
        wire.len()
    );
}

fn main() {
    let offer = signed_wire(Body::Offer {
        binding: WebRtcBinding::derive(b"deterministic-offer", b"fingerprint"),
        description: vec![0xA5; 1024],
    });
    let cfr_control = signed_wire(Body::CfrControl {
        payload: vec![0x5A; 4096],
    });

    println!("fcp_wire_benchmark\tversion=1\tmode=release_expected");
    measure("verified_offer", &offer);
    measure("verified_cfr_control", &cfr_control);
}
