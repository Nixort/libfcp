// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! RFC 6238 TOTP enrollment, encrypted storage and code verification primitives.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use fcp_fabric_domain::{AccountId, TenantId, UserAddress};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const SEED_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const PERIOD_SECONDS: i64 = 30;
const DIGITS: u32 = 6;

/// A reference to the externally managed key that encrypts a TOTP seed.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TotpKeyReference(String);

impl TotpKeyReference {
    /// Creates a bounded opaque KMS/HSM key reference.
    ///
    /// # Errors
    ///
    /// Returns [`TotpError::InvalidKeyReference`] for empty, oversized or
    /// control-character-bearing references.
    pub fn new(value: String) -> Result<Self, TotpError> {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(TotpError::InvalidKeyReference);
        }
        Ok(Self(value))
    }

    /// Returns the opaque storage key reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// In-memory symmetric data-encryption key supplied by a KMS/HSM adapter.
#[derive(Clone)]
pub struct TotpDataEncryptionKey(Zeroizing<[u8; SEED_BYTES]>);

impl TotpDataEncryptionKey {
    /// Creates a data-encryption key from KMS/HSM unwrapped material.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SEED_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Identity binding authenticated into a TOTP seed ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpBinding {
    /// Tenant that owns the factor.
    pub tenant_id: TenantId,
    /// Account that owns the factor.
    pub account_id: AccountId,
    /// Factor identity.
    pub factor_id: Uuid,
}

impl TotpBinding {
    fn associated_data(&self) -> Vec<u8> {
        format!(
            "fcp-fabric/totp/v1/{}/{}/{}",
            self.tenant_id, self.account_id, self.factor_id
        )
        .into_bytes()
    }
}

/// A persisted encrypted TOTP seed and non-secret metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedTotpSeed {
    /// AEAD ciphertext containing the 32-byte seed.
    pub ciphertext: Vec<u8>,
    /// Unique AES-GCM nonce stored with ciphertext.
    pub nonce: [u8; NONCE_BYTES],
    /// KMS/HSM reference used to obtain the data-encryption key.
    pub key_reference: TotpKeyReference,
    /// Number of decimal digits emitted by this factor.
    pub digits: u32,
    /// Seconds in one TOTP moving-factor period.
    pub period_seconds: i64,
}

/// One-time TOTP provisioning material returned only during enrollment.
#[derive(Clone)]
pub struct TotpProvisioning {
    /// Base32 seed for an authenticator app; never persist or log it.
    pub secret_base32: SecretString,
    /// `otpauth://` URI for QR rendering; contains the secret and is sensitive.
    pub uri: SecretString,
}

/// A completed enrollment result.
#[derive(Clone)]
pub struct TotpEnrollment {
    /// Encrypted database record for the pending factor.
    pub encrypted_seed: EncryptedTotpSeed,
    /// Sensitive one-display provisioning data.
    pub provisioning: TotpProvisioning,
}

/// Creates a new encrypted TOTP enrollment and one-display provisioning URI.
///
/// # Errors
///
/// Returns [`TotpError`] for invalid issuer/key metadata or AEAD encryption
/// failure. The returned provisioning fields are sensitive and must be shown
/// exactly once over an authenticated channel.
pub fn begin_totp_enrollment(
    key: &TotpDataEncryptionKey,
    key_reference: TotpKeyReference,
    binding: &TotpBinding,
    address: &UserAddress,
    issuer: &str,
) -> Result<TotpEnrollment, TotpError> {
    if issuer.is_empty() || issuer.len() > 64 || issuer.chars().any(char::is_control) {
        return Err(TotpError::InvalidIssuer);
    }
    let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
    OsRng.fill_bytes(&mut *seed);
    let encrypted_seed = encrypt_seed(key, key_reference, binding, &seed)?;
    let secret_base32 = Zeroizing::new(base32_no_padding(&seed[..]));
    let label = format!("{}:{}%40{}", issuer, address.localpart(), address.domain());
    let uri = format!(
        "otpauth://totp/{label}?secret={}&issuer={issuer}&algorithm=SHA256&digits={DIGITS}&period={PERIOD_SECONDS}",
        secret_base32.as_str()
    );
    seed.zeroize();
    Ok(TotpEnrollment {
        encrypted_seed,
        provisioning: TotpProvisioning {
            secret_base32: SecretString::from((*secret_base32).clone()),
            uri: SecretString::from(uri),
        },
    })
}

/// Encrypts a TOTP seed using AES-256-GCM with tenant/account/factor AAD.
///
/// # Errors
///
/// Returns [`TotpError::EncryptionFailed`] if AES-GCM construction or sealing
/// cannot complete.
pub fn encrypt_seed(
    key: &TotpDataEncryptionKey,
    key_reference: TotpKeyReference,
    binding: &TotpBinding,
    seed: &[u8; SEED_BYTES],
) -> Result<EncryptedTotpSeed, TotpError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| TotpError::EncryptionFailed)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: &binding.associated_data(),
            },
        )
        .map_err(|_| TotpError::EncryptionFailed)?;
    Ok(EncryptedTotpSeed {
        ciphertext,
        nonce,
        key_reference,
        digits: DIGITS,
        period_seconds: PERIOD_SECONDS,
    })
}

/// Verifies a six-digit TOTP code under the encrypted factor's declared parameters.
///
/// Returned [`AcceptedTotpStep`] must be recorded atomically by the store; a
/// factor accepts each moving time step at most once.
///
/// # Errors
///
/// Returns [`TotpError`] for unsupported factor parameters, malformed code,
/// decryption/binding failure, invalid time or failed verification.
pub fn verify_totp(
    key: &TotpDataEncryptionKey,
    encrypted: &EncryptedTotpSeed,
    binding: &TotpBinding,
    code: &str,
    now: OffsetDateTime,
    last_accepted_step: Option<i64>,
) -> Result<AcceptedTotpStep, TotpError> {
    if encrypted.digits != DIGITS || encrypted.period_seconds != PERIOD_SECONDS {
        return Err(TotpError::UnsupportedParameters);
    }
    if code.len() != usize::try_from(DIGITS).map_err(|_| TotpError::UnsupportedParameters)?
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TotpError::InvalidCodeFormat);
    }
    let mut seed = decrypt_seed(key, encrypted, binding)?;
    let current_step = now
        .unix_timestamp()
        .checked_div(PERIOD_SECONDS)
        .ok_or(TotpError::InvalidTime)?;
    for step in [
        current_step,
        current_step.checked_sub(1).ok_or(TotpError::InvalidTime)?,
    ] {
        if Some(step) == last_accepted_step {
            continue;
        }
        let expected = code_for_step(&seed, step)?;
        let supplied = code
            .parse::<u32>()
            .map_err(|_| TotpError::InvalidCodeFormat)?;
        if expected.ct_eq(&supplied).into() {
            seed.zeroize();
            return Ok(AcceptedTotpStep(step));
        }
    }
    seed.zeroize();
    Err(TotpError::VerificationFailed)
}

fn decrypt_seed(
    key: &TotpDataEncryptionKey,
    encrypted: &EncryptedTotpSeed,
    binding: &TotpBinding,
) -> Result<Zeroizing<[u8; SEED_BYTES]>, TotpError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| TotpError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            Payload {
                msg: &encrypted.ciphertext,
                aad: &binding.associated_data(),
            },
        )
        .map_err(|_| TotpError::DecryptionFailed)?;
    let seed: [u8; SEED_BYTES] = plaintext
        .try_into()
        .map_err(|_| TotpError::DecryptionFailed)?;
    Ok(Zeroizing::new(seed))
}

fn code_for_step(seed: &[u8; SEED_BYTES], step: i64) -> Result<u32, TotpError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(seed).map_err(|_| TotpError::VerificationFailed)?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let window = digest
        .get(offset..offset + 4)
        .ok_or(TotpError::VerificationFailed)?;
    let truncated = u32::from_be_bytes([window[0], window[1], window[2], window[3]]) & 0x7fff_ffff;
    Ok(truncated % 10_u32.pow(DIGITS))
}

fn base32_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = usize::from((buffer >> (bits - 5)) & 0x1f);
            output.push(char::from(ALPHABET[index]));
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = usize::from((buffer << (5 - bits)) & 0x1f);
        output.push(char::from(ALPHABET[index]));
    }
    output
}

/// An accepted TOTP moving time step for atomic persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AcceptedTotpStep(i64);

impl AcceptedTotpStep {
    /// Returns the successfully verified time-step counter.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// TOTP enrollment, encryption or verification failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TotpError {
    /// Key reference is empty, oversized or contains control characters.
    #[error("TOTP key reference is invalid")]
    InvalidKeyReference,
    /// Issuer label is empty, oversized or contains control characters.
    #[error("TOTP issuer is invalid")]
    InvalidIssuer,
    /// AES-GCM encryption failed.
    #[error("TOTP seed encryption failed")]
    EncryptionFailed,
    /// AES-GCM decryption or factor binding validation failed.
    #[error("TOTP seed decryption failed")]
    DecryptionFailed,
    /// Persisted factor parameters differ from this strict profile.
    #[error("TOTP factor parameters are unsupported")]
    UnsupportedParameters,
    /// Code format is not the configured fixed-width decimal value.
    #[error("TOTP code format is invalid")]
    InvalidCodeFormat,
    /// System time cannot yield a valid moving factor.
    #[error("TOTP time value is invalid")]
    InvalidTime,
    /// No code in the allowed time window verified.
    #[error("TOTP verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use fcp_fabric_domain::{AccountId, DomainName, Localpart, TenantId, UserAddress};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        begin_totp_enrollment, verify_totp, TotpBinding, TotpDataEncryptionKey, TotpKeyReference,
    };

    #[test]
    fn encrypted_seed_is_bound_to_one_tenant_account_and_factor() {
        let key = TotpDataEncryptionKey::from_bytes([7; 32]);
        let binding = TotpBinding {
            tenant_id: TenantId::new(),
            account_id: AccountId::new(),
            factor_id: Uuid::now_v7(),
        };
        let address = UserAddress::parse("benjamin@parley.io").expect("address");
        let enrollment = begin_totp_enrollment(
            &key,
            TotpKeyReference::new("dev-kms-key".to_owned()).expect("key reference"),
            &binding,
            &address,
            "FCP",
        )
        .expect("enrollment");
        let wrong_binding = TotpBinding {
            tenant_id: TenantId::new(),
            ..binding.clone()
        };
        assert!(verify_totp(
            &key,
            &enrollment.encrypted_seed,
            &wrong_binding,
            "000000",
            OffsetDateTime::now_utc(),
            None,
        )
        .is_err());
    }

    #[test]
    fn user_address_fixture_remains_valid_for_totp_label() {
        assert!(UserAddress::parse("alice@nextfcp.io").is_ok());
        assert!(DomainName::parse("nextfcp.io").is_ok());
        assert!(Localpart::parse("alice").is_ok());
    }
}
