// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Client/server federation configuration integration tests.

use cfr_protocol::SigPublic;
use ed25519_dalek::SigningKey;
use libfcp::{ClientConfiguration, Error, FederationClient};
use libfcp_core::{FederationId, FederationMember, SignedFederationConfiguration, SigningIdentity};
use libfcp_server::FederationServer;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};

fn signer(seed: u8) -> SigningIdentity {
    SigningIdentity::new(
        SigningKey::from_bytes(&[seed; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
    )
}

#[test]
fn client_accepts_verified_fresh_server_configuration() {
    let federation = FederationId::from_bytes([1; 32]);
    let authority = signer(2);
    let local_identity = SigPublic::from_bytes([3; 32]);
    let local_endpoint = signer(4).endpoint();
    let remote_identity = SigPublic::from_bytes([5; 32]);
    let remote_endpoint = signer(6).endpoint();

    let mut server = FederationServer::new(federation, authority).expect("server");
    server
        .replace_members(
            1,
            vec![
                FederationMember {
                    cfr_identity: *local_identity.as_bytes(),
                    endpoint: local_endpoint,
                },
                FederationMember {
                    cfr_identity: *remote_identity.as_bytes(),
                    endpoint: remote_endpoint,
                },
            ],
        )
        .expect("members");

    let wire = server.publish().expect("publish").encode().expect("encode");
    let signed = SignedFederationConfiguration::decode_verified(&wire).expect("verify");
    let mut client = FederationClient::new(ClientConfiguration {
        federation,
        authority: server.authority(),
        local_cfr_identity: local_identity,
        local_endpoint,
    });
    client.apply_configuration(signed).expect("apply");
    assert_eq!(client.accepted_epoch(), Some(1));
    assert_eq!(client.policy().federation, federation);
    assert!(matches!(
        client.apply_configuration(server.publish().expect("publish")),
        Err(Error::StaleConfiguration)
    ));
}

#[test]
fn client_rejects_configuration_from_unpinned_authority() {
    let federation = FederationId::from_bytes([11; 32]);
    let mut server = FederationServer::new(federation, signer(12)).expect("server");
    let local_identity = SigPublic::from_bytes([13; 32]);
    let local_endpoint = signer(14).endpoint();
    server
        .replace_members(
            1,
            vec![FederationMember {
                cfr_identity: *local_identity.as_bytes(),
                endpoint: local_endpoint,
            }],
        )
        .expect("members");
    let mut client = FederationClient::new(ClientConfiguration {
        federation,
        authority: signer(15).endpoint(),
        local_cfr_identity: local_identity,
        local_endpoint,
    });
    assert!(matches!(
        client.apply_configuration(server.publish().expect("publish")),
        Err(Error::WrongAuthority)
    ));
}

#[test]
fn tampered_configuration_fails_before_client_policy_application() {
    let federation = FederationId::from_bytes([21; 32]);
    let local_identity = SigPublic::from_bytes([22; 32]);
    let local_endpoint = signer(23).endpoint();
    let mut server = FederationServer::new(federation, signer(24)).expect("server");
    server
        .replace_members(
            1,
            vec![FederationMember {
                cfr_identity: *local_identity.as_bytes(),
                endpoint: local_endpoint,
            }],
        )
        .expect("members");
    let mut wire = server.publish().expect("publish").encode().expect("encode");
    let final_byte = wire.len() - 1;
    wire[final_byte] ^= 0x80;
    assert!(matches!(
        SignedFederationConfiguration::decode_verified(&wire),
        Err(libfcp_core::Error::BadConfigurationSignature)
    ));
}
