// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Opaque session and refresh-token issuance/verification primitives.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const TOKEN_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;

/// An in-memory HMAC key used to derive database-safe opaque-token digests.
#[derive(Clone)]
pub struct TokenDigestKey(Zeroizing<[u8; DIGEST_BYTES]>);

impl TokenDigestKey {
    /// Creates a digest key from KMS/HSM unwrapped key material.
    #[must_use]
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// A keyed digest that may be stored in the session database.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct OpaqueTokenDigest([u8; DIGEST_BYTES]);

impl OpaqueTokenDigest {
    /// Returns raw digest bytes for binary database storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

/// A newly issued opaque credential. The raw value must be returned once only.
#[derive(Clone)]
pub struct IssuedOpaqueToken {
    /// Sensitive bearer credential; do not log or persist plaintext.
    pub raw: SecretString,
    /// Keyed digest stored by the server.
    pub digest: OpaqueTokenDigest,
}

/// Issues a 256-bit opaque random token and its keyed storage digest.
#[must_use]
pub fn issue_opaque_token(key: &TokenDigestKey) -> IssuedOpaqueToken {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    OsRng.fill_bytes(&mut *bytes);
    let raw = SecretString::from(URL_SAFE_NO_PAD.encode(&bytes[..]));
    let digest = token_digest(key, &raw);
    bytes.fill(0);
    IssuedOpaqueToken { raw, digest }
}

/// Derives the keyed fixed-width digest for an opaque credential.
///
/// Callers may persist this result, but must never persist or log `raw`.
#[must_use]
pub fn derive_opaque_token_digest(key: &TokenDigestKey, raw: &SecretString) -> OpaqueTokenDigest {
    token_digest(key, raw)
}

/// Verifies a supplied opaque token against a stored keyed digest.
#[must_use]
pub fn verify_opaque_token(
    key: &TokenDigestKey,
    supplied: &SecretString,
    stored: &OpaqueTokenDigest,
) -> bool {
    derive_opaque_token_digest(key, supplied)
        .0
        .ct_eq(&stored.0)
        .into()
}

fn token_digest(key: &TokenDigestKey, raw: &SecretString) -> OpaqueTokenDigest {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.0.as_ref())
        .expect("HMAC accepts every fixed-length key");
    mac.update(raw.expose_secret().as_bytes());
    let bytes: [u8; DIGEST_BYTES] = mac
        .finalize()
        .into_bytes()
        .into_iter()
        .collect::<Vec<u8>>()
        .try_into()
        .expect("SHA-256 output has fixed length");
    OpaqueTokenDigest(bytes)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{issue_opaque_token, verify_opaque_token, TokenDigestKey};

    #[test]
    fn issued_token_verifies_but_other_token_does_not() {
        let key = TokenDigestKey::from_bytes([3; 32]);
        let issued = issue_opaque_token(&key);
        assert!(verify_opaque_token(&key, &issued.raw, &issued.digest));
        assert!(!verify_opaque_token(
            &key,
            &SecretString::from("wrong-token"),
            &issued.digest,
        ));
    }
}
