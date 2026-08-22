// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Generates reproducible public FCP foreign-binding verification fixtures.

use ed25519_dalek::SigningKey;
use libfcp_core::{
    Action, AttemptId, Connection, FederationId, FederationMember, SigningIdentity, WebRtcBinding,
};
use libfcp_server::FederationServer;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn main() {
    let federation = FederationId::from_bytes([9; 32]);
    let attempt = AttemptId::from_bytes([7; 16]);
    let local = signer(1);
    let remote = signer(2);
    let mut connection = Connection::new(federation, attempt, local.endpoint(), remote.endpoint())
        .expect("test identities are distinct");
    let actions = connection
        .begin_offer(
            &local,
            WebRtcBinding::derive(b"opaque-offer", b"test-fingerprint"),
            b"opaque-offer".to_vec(),
        )
        .expect("reference offer");
    let envelope = actions
        .into_iter()
        .find_map(|action| match action {
            Action::Send(envelope) => Some(*envelope),
            _ => None,
        })
        .expect("send action");
    let envelope = envelope.encode().expect("canonical envelope");
    let mut envelope_bad_signature = envelope.clone();
    let last = envelope_bad_signature.len() - 1;
    envelope_bad_signature[last] ^= 1;

    let authority = signer(3);
    let member = FederationMember {
        cfr_identity: [4; 32],
        endpoint: remote.endpoint(),
    };
    let mut server = FederationServer::new(federation, authority).expect("server");
    server.replace_members(1, vec![member]).expect("members");
    let configuration = server
        .publish()
        .and_then(|signed| signed.encode().map_err(Into::into))
        .expect("canonical configuration");
    let mut configuration_bad_signature = configuration.clone();
    let config_last = configuration_bad_signature.len() - 1;
    configuration_bad_signature[config_last] ^= 1;

    println!("{{");
    println!("  \"schema\": \"org.nixort.fcp.vectors/1\",");
    println!("  \"envelope_valid_hex\": \"{}\",", hex(&envelope));
    println!(
        "  \"envelope_bad_signature_hex\": \"{}\",",
        hex(&envelope_bad_signature)
    );
    println!(
        "  \"configuration_valid_hex\": \"{}\",",
        hex(&configuration)
    );
    println!(
        "  \"configuration_bad_signature_hex\": \"{}\"",
        hex(&configuration_bad_signature)
    );
    println!("}}");
}
