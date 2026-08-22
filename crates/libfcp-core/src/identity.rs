// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Endpoint identities and mandatory dual-signature authentication.

use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey};
use ml_dsa::{
    Keypair, MlDsa65, Signature, SigningKey as MlDsaSigningKey, Verifier,
    VerifyingKey as MlDsaVerifyingKey,
};

use crate::{EndpointKey, Error};

/// FIPS 204 ML-DSA-65 encoded public-key width.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
/// FIPS 204 ML-DSA-65 encoded signature width.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;

/// An immutable FCP endpoint identity.
///
/// The identity is the atomic binding of the classical and post-quantum
/// verification keys. Configurations, connections, and envelope addressing
/// always carry the complete binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointIdentity {
    /// Ed25519 verification key.
    pub classical: EndpointKey,
    /// ML-DSA-65 verification key in fixed FIPS 204 encoding.
    pub post_quantum: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}

impl EndpointIdentity {
    /// Constructs a complete endpoint identity from canonical key encodings.
    #[must_use]
    pub const fn new(
        classical: EndpointKey,
        post_quantum: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    ) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }

    /// Verifies the mandatory Ed25519 signature over `message`.
    pub fn verify_classical(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
        let key =
            VerifyingKey::from_bytes(self.classical.as_bytes()).map_err(|_| Error::BadSenderKey)?;
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| Error::BadSignature)
    }

    /// Verifies the mandatory ML-DSA-65 signature over `message`.
    pub fn verify_post_quantum(
        &self,
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
    ) -> Result<(), Error> {
        let key_bytes =
            ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(self.post_quantum.as_slice())
                .map_err(|_| Error::BadPostQuantumKey)?;
        let key = MlDsaVerifyingKey::<MlDsa65>::decode(&key_bytes);
        let signature = Signature::<MlDsa65>::try_from(signature.as_slice())
            .map_err(|_| Error::BadPostQuantumSignatureEncoding)?;
        key.verify(message, &signature)
            .map_err(|_| Error::BadPostQuantumSignature)
    }
}

/// An implementation-owned signing identity with both required private keys.
///
/// No runtime randomness is needed to use this type. Applications may derive
/// or securely load the two signing keys according to their own key-management
/// policy before constructing the identity.
pub struct SigningIdentity {
    classical: SigningKey,
    post_quantum: MlDsaSigningKey<MlDsa65>,
}

impl SigningIdentity {
    /// Combines application-managed Ed25519 and ML-DSA-65 signing keys.
    #[must_use]
    pub fn new(classical: SigningKey, post_quantum: MlDsaSigningKey<MlDsa65>) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }

    /// Returns the stable public endpoint identity corresponding to these keys.
    #[must_use]
    pub fn endpoint(&self) -> EndpointIdentity {
        let encoded = self.post_quantum.verifying_key().encode();
        let mut post_quantum = [0_u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        post_quantum.copy_from_slice(encoded.as_ref());
        EndpointIdentity::new(
            EndpointKey::from_bytes(self.classical.verifying_key().to_bytes()),
            post_quantum,
        )
    }
}

/// An endpoint capable of producing both mandatory FCP signatures.
pub trait EndpointSigner {
    /// Returns the complete identity used to address and authenticate envelopes.
    fn endpoint(&self) -> EndpointIdentity;
    /// Produces the canonical Ed25519 signature for the supplied transcript.
    fn sign_classical(&self, message: &[u8]) -> [u8; 64];
    /// Produces the canonical ML-DSA-65 signature for the supplied transcript.
    fn sign_post_quantum(&self, message: &[u8]) -> [u8; ML_DSA_65_SIGNATURE_BYTES];
}

impl EndpointSigner for SigningIdentity {
    fn endpoint(&self) -> EndpointIdentity {
        self.endpoint()
    }

    fn sign_classical(&self, message: &[u8]) -> [u8; 64] {
        Ed25519Signer::sign(&self.classical, message).to_bytes()
    }

    fn sign_post_quantum(&self, message: &[u8]) -> [u8; ML_DSA_65_SIGNATURE_BYTES] {
        let encoded = self.post_quantum.sign(message).encode();
        let mut signature = [0_u8; ML_DSA_65_SIGNATURE_BYTES];
        signature.copy_from_slice(encoded.as_ref());
        signature
    }
}
