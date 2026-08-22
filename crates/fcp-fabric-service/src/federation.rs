// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Signed, domain-bound server-to-server federation delivery records.
//!
//! The authenticated human user is never represented by a password, session or
//! MFA assertion here. A source authority first authenticates its own account,
//! then signs a narrowly scoped delivery for a destination authority.

use fcp_fabric_domain::{DomainName, FederationTrustState, UserAddress};
use libfcp_core::{
    EndpointIdentity, EndpointSigner, Error as CoreError, ML_DSA_65_SIGNATURE_BYTES,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

const DOMAIN_TAG: &[u8] = b"fcp-fabric/federation/delivery/v1";
const MAX_PAYLOAD_BYTES: usize = 65_536;
const MAX_DELIVERY_LIFETIME_SECONDS: i64 = 300;
const MAX_CLOCK_SKEW_SECONDS: i64 = 60;

/// A source-authority assertion that may carry one bounded application payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationDelivery {
    /// Domain of the authority making the assertion.
    pub source_domain: DomainName,
    /// Domain of the authority expected to accept the assertion.
    pub destination_domain: DomainName,
    /// Local user principal asserted by the source authority.
    pub sender: UserAddress,
    /// Local user principal at the destination authority.
    pub recipient: UserAddress,
    /// Globally unique request identity used for replay protection.
    pub request_id: Uuid,
    /// First issuance time according to the source authority.
    pub issued_at: OffsetDateTime,
    /// Strict expiry time after which the request is invalid.
    pub expires_at: OffsetDateTime,
    /// Bounded opaque application bytes, such as an already authenticated FCP signal.
    pub payload: Vec<u8>,
}

impl FederationDelivery {
    /// Validates fabric/user-domain bindings, size and lifetime independent of signatures.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] for source/recipient domain mismatches,
    /// oversized payloads or invalid bounded lifetime.
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.sender.domain() != &self.source_domain {
            return Err(FederationError::SenderDomainMismatch);
        }
        if self.recipient.domain() != &self.destination_domain {
            return Err(FederationError::RecipientDomainMismatch);
        }
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(FederationError::PayloadTooLarge);
        }
        let issued = self.issued_at.unix_timestamp();
        let expires = self.expires_at.unix_timestamp();
        if expires <= issued || expires - issued > MAX_DELIVERY_LIFETIME_SECONDS {
            return Err(FederationError::InvalidLifetime);
        }
        Ok(())
    }

    fn transcript(&self) -> Result<Vec<u8>, FederationError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(DOMAIN_TAG.len() + 1024 + self.payload.len());
        bytes.extend_from_slice(DOMAIN_TAG);
        write_u8_bytes(&mut bytes, self.source_domain.as_str().as_bytes())?;
        write_u8_bytes(&mut bytes, self.destination_domain.as_str().as_bytes())?;
        write_u16_bytes(&mut bytes, self.sender.to_string().as_bytes())?;
        write_u16_bytes(&mut bytes, self.recipient.to_string().as_bytes())?;
        bytes.extend_from_slice(self.request_id.as_bytes());
        bytes.extend_from_slice(&self.issued_at.unix_timestamp().to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.unix_timestamp().to_be_bytes());
        let payload_length =
            u32::try_from(self.payload.len()).map_err(|_| FederationError::PayloadTooLarge)?;
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

/// A complete authority-signed federation delivery record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedFederationDelivery {
    /// Delivery fields authenticated by both signatures.
    pub delivery: FederationDelivery,
    /// Complete public identity of the source authority signing key.
    pub authority_identity: EndpointIdentity,
    /// Mandatory Ed25519 transcript signature.
    pub classical_signature: [u8; 64],
    /// Mandatory ML-DSA-65 transcript signature.
    pub post_quantum_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl SignedFederationDelivery {
    /// Signs one canonical delivery with the existing complete FCP authority identity.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if delivery validation or canonical transcript
    /// construction rejects its fields before signing.
    pub fn sign(
        signer: &impl EndpointSigner,
        delivery: FederationDelivery,
    ) -> Result<Self, FederationError> {
        let transcript = delivery.transcript()?;
        Ok(Self {
            authority_identity: signer.endpoint(),
            classical_signature: signer.sign_classical(&transcript),
            post_quantum_signature: signer.sign_post_quantum(&transcript),
            delivery,
        })
    }

    /// Returns a SHA-256 digest of the exact canonical signed-delivery transcript.
    ///
    /// The digest is suitable only for replay-evidence persistence; mandatory
    /// signature verification still covers the complete canonical transcript.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the delivery cannot form a canonical transcript.
    pub fn canonical_body_digest(&self) -> Result<[u8; 32], FederationError> {
        Ok(Sha256::digest(self.delivery.transcript()?).into())
    }

    /// Verifies both mandatory signatures against an independently pinned authority identity.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::UnexpectedAuthorityIdentity`] for key
    /// substitution or [`FederationError::Core`] when either mandatory FCP
    /// signature does not verify over the canonical transcript.
    pub fn verify(&self, expected_identity: EndpointIdentity) -> Result<(), FederationError> {
        if self.authority_identity != expected_identity {
            return Err(FederationError::UnexpectedAuthorityIdentity);
        }
        let transcript = self.delivery.transcript()?;
        expected_identity
            .verify_classical(&transcript, &self.classical_signature)
            .map_err(FederationError::Core)?;
        expected_identity
            .verify_post_quantum(&transcript, &self.post_quantum_signature)
            .map_err(FederationError::Core)
    }
}

/// Persisted local policy for admitting requests from one remote authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemotePeerPolicy {
    /// The local tenant domain that may receive deliveries.
    pub local_domain: DomainName,
    /// The only remote source domain this policy applies to.
    pub remote_domain: DomainName,
    /// Local administrator-controlled peer state.
    pub trust_state: FederationTrustState,
    /// Pinned active remote authority identity for this key-validity period.
    pub active_authority_identity: EndpointIdentity,
}

impl RemotePeerPolicy {
    /// Validates a signed delivery before the store atomically records its request ID.
    ///
    /// This method performs no replay persistence itself. The store must insert
    /// `(tenant, peer, request_id)` under a unique constraint in the same
    /// transaction as delivery acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if local trust is inactive, source or
    /// destination binding differs, freshness fails, identity is substituted or
    /// either mandatory signature is invalid.
    pub fn admit(
        &self,
        now: OffsetDateTime,
        signed: &SignedFederationDelivery,
    ) -> Result<(), FederationError> {
        if !self.trust_state.accepts_requests() {
            return Err(FederationError::PeerNotActive);
        }
        if signed.delivery.destination_domain != self.local_domain {
            return Err(FederationError::WrongDestination);
        }
        if signed.delivery.source_domain != self.remote_domain {
            return Err(FederationError::WrongSource);
        }
        let now_seconds = now.unix_timestamp();
        let issued_seconds = signed.delivery.issued_at.unix_timestamp();
        let expires_seconds = signed.delivery.expires_at.unix_timestamp();
        if issued_seconds > now_seconds + MAX_CLOCK_SKEW_SECONDS
            || expires_seconds < now_seconds - MAX_CLOCK_SKEW_SECONDS
        {
            return Err(FederationError::ExpiredOrNotYetValid);
        }
        signed.verify(self.active_authority_identity)
    }
}

fn write_u8_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), FederationError> {
    let length = u8::try_from(value.len()).map_err(|_| FederationError::InvalidCanonicalField)?;
    bytes.push(length);
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_u16_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), FederationError> {
    let length = u16::try_from(value.len()).map_err(|_| FederationError::InvalidCanonicalField)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

/// Federation delivery validation or signature admission failure.
#[derive(Debug, Error)]
pub enum FederationError {
    /// Source user address is not owned by declared source authority.
    #[error("federation sender is not owned by declared source domain")]
    SenderDomainMismatch,
    /// Recipient user address is not owned by declared destination authority.
    #[error("federation recipient is not owned by declared destination domain")]
    RecipientDomainMismatch,
    /// Payload exceeds bounded delivery limit.
    #[error("federation payload exceeds configured limit")]
    PayloadTooLarge,
    /// Lifetime is reversed or exceeds the five-minute maximum.
    #[error("federation request lifetime is invalid")]
    InvalidLifetime,
    /// A canonical field cannot be represented in its bounded wire encoding.
    #[error("federation canonical field is invalid")]
    InvalidCanonicalField,
    /// Remote peer has not reached explicit active trust state.
    #[error("remote federation peer is not active")]
    PeerNotActive,
    /// Request targets a domain other than local policy domain.
    #[error("federation request has wrong destination domain")]
    WrongDestination,
    /// Request source does not equal policy peer domain.
    #[error("federation request has wrong source domain")]
    WrongSource,
    /// Timestamp falls outside the accepted skew/expiry window.
    #[error("federation request is expired or not yet valid")]
    ExpiredOrNotYetValid,
    /// Embedded identity did not match independently pinned peer identity.
    #[error("federation request used an unexpected authority identity")]
    UnexpectedAuthorityIdentity,
    /// Existing FCP complete-identity signature verification failed.
    #[error("federation signature verification failed: {0}")]
    Core(#[source] CoreError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use fcp_fabric_domain::{DomainName, FederationTrustState, UserAddress};
    use libfcp_core::SigningIdentity;
    use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::{FederationDelivery, RemotePeerPolicy, SignedFederationDelivery};

    fn signer(seed: u8) -> SigningIdentity {
        SigningIdentity::new(
            SigningKey::from_bytes(&[seed; 32]),
            MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([seed; 32])),
        )
    }

    #[test]
    fn active_pinned_peer_accepts_only_fresh_bound_delivery() {
        let remote = signer(1);
        let now = OffsetDateTime::now_utc();
        let delivery = FederationDelivery {
            source_domain: DomainName::parse("nextfcp.io").expect("source"),
            destination_domain: DomainName::parse("parley.io").expect("destination"),
            sender: UserAddress::parse("alice@nextfcp.io").expect("sender"),
            recipient: UserAddress::parse("benjamin@parley.io").expect("recipient"),
            request_id: Uuid::now_v7(),
            issued_at: now,
            expires_at: now + Duration::minutes(2),
            payload: b"verified FCP application signal".to_vec(),
        };
        let signed = SignedFederationDelivery::sign(&remote, delivery).expect("sign");
        let policy = RemotePeerPolicy {
            local_domain: DomainName::parse("parley.io").expect("local"),
            remote_domain: DomainName::parse("nextfcp.io").expect("remote"),
            trust_state: FederationTrustState::Active,
            active_authority_identity: remote.endpoint(),
        };
        assert!(policy.admit(now, &signed).is_ok());
    }

    #[test]
    fn delivery_rejects_identity_substitution() {
        let remote = signer(1);
        let substitute = signer(2);
        let now = OffsetDateTime::now_utc();
        let signed = SignedFederationDelivery::sign(
            &remote,
            FederationDelivery {
                source_domain: DomainName::parse("nextfcp.io").expect("source"),
                destination_domain: DomainName::parse("parley.io").expect("destination"),
                sender: UserAddress::parse("alice@nextfcp.io").expect("sender"),
                recipient: UserAddress::parse("benjamin@parley.io").expect("recipient"),
                request_id: Uuid::now_v7(),
                issued_at: now,
                expires_at: now + Duration::minutes(1),
                payload: vec![1, 2, 3],
            },
        )
        .expect("sign");
        assert!(signed.verify(substitute.endpoint()).is_err());
    }
}
