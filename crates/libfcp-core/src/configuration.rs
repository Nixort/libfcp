// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Canonical signed federation configuration shared by FCP clients and servers.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{
    EndpointIdentity, EndpointSigner, Error, FederationId, ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
};

/// Stable marker for a signed FCP federation configuration.
pub const FEDERATION_CONFIG_MARKER: [u8; 4] = *b"FCFG";
/// Current signed federation configuration format version.
pub const FEDERATION_CONFIG_VERSION: u8 = 1;
/// Maximum members in one configuration snapshot.
pub const MAX_FEDERATION_MEMBERS: usize = 1_024;

const IDENTITY_BYTES: usize = 32 + ML_DSA_65_PUBLIC_KEY_BYTES;
const MEMBER_BYTES: usize = 32 + IDENTITY_BYTES;
const FIXED_HEADER_BYTES: usize = 4 + 1 + 32 + IDENTITY_BYTES + 8 + 2;
const SIGNATURE_BYTES: usize = 64 + ML_DSA_65_SIGNATURE_BYTES;

/// Explicit association between a CFR participant identity and an FCP endpoint identity.
///
/// The CFR identity bytes are a `cfr_protocol::SigPublic` encoding. The core
/// deliberately remains independent of CFR; `libfcp` validates and converts
/// them through the pinned CFR API before routing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FederationMember {
    /// Canonical 32-byte CFR participant identity key.
    pub cfr_identity: [u8; 32],
    /// Complete dual-algorithm FCP endpoint identity bound to that participant.
    pub endpoint: EndpointIdentity,
}

/// Immutable federation policy snapshot published by its selected authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationConfiguration {
    /// Federation namespace to which every member binding applies.
    pub federation: FederationId,
    /// Pinned authority identity authorized to sign this snapshot.
    pub authority: EndpointIdentity,
    /// Monotonic application-defined configuration epoch.
    pub epoch: u64,
    /// Explicit participant-to-endpoint bindings for this epoch.
    pub members: Vec<FederationMember>,
}

impl FederationConfiguration {
    /// Creates a configuration after checking its bounded canonical member set.
    pub fn new(
        federation: FederationId,
        authority: EndpointIdentity,
        epoch: u64,
        members: Vec<FederationMember>,
    ) -> Result<Self, Error> {
        let configuration = Self {
            federation,
            authority,
            epoch,
            members,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.members.len() > MAX_FEDERATION_MEMBERS {
            return Err(Error::TooManyFederationMembers);
        }
        let mut identities = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for member in &self.members {
            if !identities.insert(member.cfr_identity) || !endpoints.insert(member.endpoint) {
                return Err(Error::DuplicateFederationMember);
            }
        }
        Ok(())
    }

    fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let member_count =
            u16::try_from(self.members.len()).map_err(|_| Error::TooManyFederationMembers)?;
        let mut bytes = Vec::with_capacity(FIXED_HEADER_BYTES + self.members.len() * MEMBER_BYTES);
        bytes.extend_from_slice(&FEDERATION_CONFIG_MARKER);
        bytes.push(FEDERATION_CONFIG_VERSION);
        bytes.extend_from_slice(self.federation.as_bytes());
        write_identity(&mut bytes, &self.authority);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&member_count.to_be_bytes());
        for member in &self.members {
            bytes.extend_from_slice(&member.cfr_identity);
            write_identity(&mut bytes, &member.endpoint);
        }
        Ok(bytes)
    }
}

/// A federation configuration signed by its configured authority identity.
///
/// Both signatures are mandatory and verify the exact same canonical snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFederationConfiguration {
    /// Public policy values authorized by the signatures.
    pub configuration: FederationConfiguration,
    classical_signature: [u8; 64],
    post_quantum_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl SignedFederationConfiguration {
    /// Signs a canonical configuration with exactly its pinned authority identity.
    pub fn sign<S: EndpointSigner>(
        configuration: FederationConfiguration,
        signer: &S,
    ) -> Result<Self, Error> {
        if configuration.authority != signer.endpoint() {
            return Err(Error::WrongConfigurationAuthority);
        }
        let transcript = configuration.signed_bytes()?;
        Ok(Self {
            configuration,
            classical_signature: signer.sign_classical(&transcript),
            post_quantum_signature: signer.sign_post_quantum(&transcript),
        })
    }

    /// Verifies both snapshot signatures against the embedded pinned authority.
    pub fn verify(&self) -> Result<(), Error> {
        let transcript = self.configuration.signed_bytes()?;
        self.configuration
            .authority
            .verify_classical(&transcript, &self.classical_signature)
            .map_err(map_configuration_classical_error)?;
        self.configuration
            .authority
            .verify_post_quantum(&transcript, &self.post_quantum_signature)
            .map_err(map_configuration_pq_error)
    }

    /// Encodes the exact canonical signed configuration for application-selected delivery.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut wire = self.configuration.signed_bytes()?;
        wire.extend_from_slice(&self.classical_signature);
        wire.extend_from_slice(&self.post_quantum_signature);
        Ok(wire)
    }

    /// Verifies a bounded canonical wire snapshot before materialising member records.
    pub fn decode_verified(wire: &[u8]) -> Result<Self, Error> {
        let parsed = parse_wire(wire)?;
        let authority = parsed.authority;
        let classical_signature = wire[parsed.signature_offset..parsed.signature_offset + 64]
            .try_into()
            .map_err(|_| Error::Truncated)?;
        let post_quantum_signature = wire[parsed.signature_offset + 64..]
            .try_into()
            .map_err(|_| Error::Truncated)?;
        authority
            .verify_classical(&wire[..parsed.signature_offset], &classical_signature)
            .map_err(map_configuration_classical_error)?;
        authority
            .verify_post_quantum(&wire[..parsed.signature_offset], &post_quantum_signature)
            .map_err(map_configuration_pq_error)?;
        let members = parsed
            .member_bytes
            .chunks_exact(MEMBER_BYTES)
            .map(parse_member)
            .collect::<Result<Vec<_>, _>>()?;
        let configuration =
            FederationConfiguration::new(parsed.federation, authority, parsed.epoch, members)?;
        Ok(Self {
            configuration,
            classical_signature,
            post_quantum_signature,
        })
    }
}

fn map_configuration_classical_error(error: Error) -> Error {
    match error {
        Error::BadSenderKey => Error::BadConfigurationAuthority,
        Error::BadSignature => Error::BadConfigurationSignature,
        other => other,
    }
}

fn map_configuration_pq_error(error: Error) -> Error {
    match error {
        Error::BadPostQuantumKey => Error::BadConfigurationAuthority,
        Error::BadPostQuantumSignature | Error::BadPostQuantumSignatureEncoding => {
            Error::BadConfigurationSignature
        }
        other => other,
    }
}

fn write_identity(bytes: &mut Vec<u8>, identity: &EndpointIdentity) {
    bytes.extend_from_slice(identity.classical.as_bytes());
    bytes.extend_from_slice(&identity.post_quantum);
}

fn read_identity(bytes: &[u8]) -> Result<EndpointIdentity, Error> {
    if bytes.len() != IDENTITY_BYTES {
        return Err(Error::Truncated);
    }
    Ok(EndpointIdentity::new(
        crate::EndpointKey::from_bytes(bytes[..32].try_into().map_err(|_| Error::Truncated)?),
        bytes[32..].try_into().map_err(|_| Error::Truncated)?,
    ))
}

fn parse_member(bytes: &[u8]) -> Result<FederationMember, Error> {
    if bytes.len() != MEMBER_BYTES {
        return Err(Error::Truncated);
    }
    Ok(FederationMember {
        cfr_identity: bytes[..32].try_into().map_err(|_| Error::Truncated)?,
        endpoint: read_identity(&bytes[32..])?,
    })
}

struct ParsedConfiguration<'a> {
    federation: FederationId,
    authority: EndpointIdentity,
    epoch: u64,
    member_bytes: &'a [u8],
    signature_offset: usize,
}

fn parse_wire(wire: &[u8]) -> Result<ParsedConfiguration<'_>, Error> {
    if wire.len() < FIXED_HEADER_BYTES + SIGNATURE_BYTES {
        return Err(Error::Truncated);
    }
    if wire[..4] != FEDERATION_CONFIG_MARKER {
        return Err(Error::BadConfigurationMarker);
    }
    if wire[4] != FEDERATION_CONFIG_VERSION {
        return Err(Error::UnsupportedConfigurationVersion);
    }
    let federation =
        FederationId::from_bytes(wire[5..37].try_into().map_err(|_| Error::Truncated)?);
    let authority = read_identity(&wire[37..37 + IDENTITY_BYTES])?;
    let epoch_start = 37 + IDENTITY_BYTES;
    let epoch = u64::from_be_bytes(
        wire[epoch_start..epoch_start + 8]
            .try_into()
            .map_err(|_| Error::Truncated)?,
    );
    let count_start = epoch_start + 8;
    let count = usize::from(u16::from_be_bytes(
        wire[count_start..count_start + 2]
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ));
    if count > MAX_FEDERATION_MEMBERS {
        return Err(Error::TooManyFederationMembers);
    }
    let member_bytes_len = count
        .checked_mul(MEMBER_BYTES)
        .ok_or(Error::TooManyFederationMembers)?;
    let signature_offset = FIXED_HEADER_BYTES
        .checked_add(member_bytes_len)
        .ok_or(Error::TooManyFederationMembers)?;
    let expected = signature_offset
        .checked_add(SIGNATURE_BYTES)
        .ok_or(Error::TooManyFederationMembers)?;
    if wire.len() < expected {
        return Err(Error::Truncated);
    }
    if wire.len() > expected {
        return Err(Error::TrailingBytes);
    }
    Ok(ParsedConfiguration {
        federation,
        authority,
        epoch,
        member_bytes: &wire[FIXED_HEADER_BYTES..signature_offset],
        signature_offset,
    })
}
