// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Argon2id password validation and PHC verifier handling.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand_core::OsRng;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// A policy source that rejects compromised or otherwise prohibited passwords.
pub trait PasswordBlocklist: Send + Sync {
    /// Returns whether the normalized candidate must be rejected.
    fn contains(&self, normalized_candidate: &str) -> bool;
}

/// A blocklist implementation intended only for isolated development tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPasswordBlocklist;

impl PasswordBlocklist for NoPasswordBlocklist {
    fn contains(&self, _normalized_candidate: &str) -> bool {
        false
    }
}

/// Tunable password acceptance and Argon2id parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    minimum_characters: usize,
    maximum_bytes: usize,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl PasswordPolicy {
    /// Creates a policy after validating KDF and input bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::InvalidPolicy`] if input bounds or Argon2id
    /// parameters cannot form a safe bounded configuration.
    pub fn new(
        minimum_characters: usize,
        maximum_bytes: usize,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, PasswordError> {
        if !(8..=1024).contains(&minimum_characters)
            || maximum_bytes < minimum_characters
            || maximum_bytes > 16_384
        {
            return Err(PasswordError::InvalidPolicy);
        }
        Params::new(memory_kib, iterations, parallelism, Some(32))
            .map_err(|_| PasswordError::InvalidPolicy)?;
        Ok(Self {
            minimum_characters,
            maximum_bytes,
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Returns the initial password-only baseline: 15 characters and 19 MiB Argon2id.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::InvalidPolicy`] only if this compiled-in
    /// baseline becomes invalid for the underlying Argon2 implementation.
    pub fn password_only_baseline() -> Result<Self, PasswordError> {
        Self::new(15, 1024, 19 * 1024, 2, 1)
    }

    /// Returns the minimum accepted Unicode scalar count.
    #[must_use]
    pub const fn minimum_characters(&self) -> usize {
        self.minimum_characters
    }

    fn argon2(&self) -> Result<Argon2<'static>, PasswordError> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| PasswordError::InvalidPolicy)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// A serialized PHC password verifier safe to persist in the credential table.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct PasswordVerifierString(String);

impl PasswordVerifierString {
    /// Parses a persisted Argon2id PHC verifier without verifying a candidate.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::MalformedVerifier`] for invalid PHC syntax and
    /// [`PasswordError::UnsupportedVerifier`] unless the record is Argon2id v19.
    pub fn from_persisted(value: String) -> Result<Self, PasswordError> {
        let parsed = PasswordHash::new(&value).map_err(|_| PasswordError::MalformedVerifier)?;
        if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(Version::V0x13.into())
        {
            return Err(PasswordError::UnsupportedVerifier);
        }
        Ok(Self(value))
    }

    /// Returns the PHC serialization intended for protected database storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validates and hashes a password with a new random salt.
///
/// # Errors
///
/// Returns [`PasswordError`] when input length, the supplied blocklist, KDF
/// configuration or Argon2id hashing prevents verifier creation.
pub fn hash_password(
    candidate: &SecretString,
    policy: &PasswordPolicy,
    blocklist: &dyn PasswordBlocklist,
) -> Result<PasswordVerifierString, PasswordError> {
    let normalized = normalize_candidate(candidate, policy, blocklist)?;
    let salt = SaltString::generate(&mut OsRng);
    let verifier = policy
        .argon2()?
        .hash_password(normalized.as_bytes(), &salt)
        .map_err(|_| PasswordError::HashingFailed)?
        .to_string();
    Ok(PasswordVerifierString(verifier))
}

/// Verifies a candidate against a persisted Argon2id PHC verifier.
///
/// The verifier's stored cost parameters are used for comparison. Callers may
/// rehash successful login input under the current policy afterwards.
///
/// # Errors
///
/// Returns [`PasswordError`] when candidate input is invalid, the persisted
/// verifier is malformed/unsupported, or verification does not match.
pub fn verify_password(
    candidate: &SecretString,
    verifier: &PasswordVerifierString,
    maximum_bytes: usize,
) -> Result<(), PasswordError> {
    let normalized = normalize_for_verification(candidate, maximum_bytes)?;
    let parsed =
        PasswordHash::new(verifier.as_str()).map_err(|_| PasswordError::MalformedVerifier)?;
    if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(Version::V0x13.into()) {
        return Err(PasswordError::UnsupportedVerifier);
    }
    Argon2::default()
        .verify_password(normalized.as_bytes(), &parsed)
        .map_err(|_| PasswordError::VerificationFailed)
}

fn normalize_candidate(
    candidate: &SecretString,
    policy: &PasswordPolicy,
    blocklist: &dyn PasswordBlocklist,
) -> Result<Zeroizing<String>, PasswordError> {
    let normalized = normalize_for_verification(candidate, policy.maximum_bytes)?;
    if normalized.chars().count() < policy.minimum_characters {
        return Err(PasswordError::TooShort);
    }
    if blocklist.contains(&normalized) {
        return Err(PasswordError::Blocked);
    }
    Ok(normalized)
}

fn normalize_for_verification(
    candidate: &SecretString,
    maximum_bytes: usize,
) -> Result<Zeroizing<String>, PasswordError> {
    let normalized = Zeroizing::new(candidate.expose_secret().nfc().collect::<String>());
    if normalized.is_empty() || normalized.len() > maximum_bytes {
        return Err(PasswordError::InvalidLength);
    }
    Ok(normalized)
}

/// Password validation, hashing or verification failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PasswordError {
    /// Policy parameters cannot form a safe bounded KDF policy.
    #[error("password policy is invalid")]
    InvalidPolicy,
    /// Candidate is shorter than policy allows.
    #[error("password is shorter than policy allows")]
    TooShort,
    /// Candidate is empty or exceeds the operational input bound.
    #[error("password length is invalid")]
    InvalidLength,
    /// Candidate appears in the supplied compromised-password blocklist.
    #[error("password is blocked by policy")]
    Blocked,
    /// Argon2id did not create a verifier.
    #[error("password hashing failed")]
    HashingFailed,
    /// Persisted PHC verifier cannot be parsed.
    #[error("stored password verifier is malformed")]
    MalformedVerifier,
    /// Persisted verifier does not use the allowed Argon2id version.
    #[error("stored password verifier uses an unsupported algorithm")]
    UnsupportedVerifier,
    /// Candidate did not match the persisted verifier.
    #[error("password verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{hash_password, verify_password, NoPasswordBlocklist, PasswordPolicy};

    #[test]
    fn argon2id_round_trip_rejects_wrong_password() {
        let policy = PasswordPolicy::password_only_baseline().expect("policy");
        let password = SecretString::from("correct horse battery staple");
        let verifier = hash_password(&password, &policy, &NoPasswordBlocklist).expect("hash");
        assert!(verify_password(&password, &verifier, 1024).is_ok());
        assert!(verify_password(&SecretString::from("not the password"), &verifier, 1024).is_err());
    }

    #[test]
    fn password_only_baseline_rejects_short_candidate() {
        let policy = PasswordPolicy::password_only_baseline().expect("policy");
        assert!(hash_password(
            &SecretString::from("short password"),
            &policy,
            &NoPasswordBlocklist,
        )
        .is_err());
    }
}
