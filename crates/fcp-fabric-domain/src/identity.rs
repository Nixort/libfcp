// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Canonical tenant-domain and local-principal identity types.

use core::fmt;
use core::str::FromStr;

use idna::domain_to_ascii;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// An RFC 5890/IDNA canonicalized tenant domain without port or scheme.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DomainName(String);

impl DomainName {
    /// Parses and canonicalizes a tenant or federation domain.
    ///
    /// Domains are serialized as lower-case ASCII A-labels. IP literals,
    /// schemes, ports, trailing dots and whitespace are intentionally rejected.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidDomain`] when `input` is not a canonical
    /// DNS tenant domain under this authority policy.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        if input.is_empty() || input.trim() != input {
            return Err(DomainError::InvalidDomain);
        }
        if input.contains(['/', ':', '@']) || input.ends_with('.') {
            return Err(DomainError::InvalidDomain);
        }
        let ascii = domain_to_ascii(input).map_err(|_| DomainError::InvalidDomain)?;
        let canonical = ascii.to_ascii_lowercase();
        if canonical.len() > 253 || !canonical.contains('.') {
            return Err(DomainError::InvalidDomain);
        }
        for label in canonical.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(DomainError::InvalidDomain);
            }
        }
        Ok(Self(canonical))
    }

    /// Returns the canonical lower-case ASCII representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for DomainName {
    type Err = DomainError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// A canonical tenant-local login component.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Localpart(String);

impl Localpart {
    /// Parses the deliberately narrow first-release login grammar.
    ///
    /// The input is NFC-normalized, then constrained to lower-case ASCII to
    /// avoid cross-client Unicode case-folding and confusable-identifier bugs.
    ///
    /// # Errors
    ///
    /// Returns [`LocalpartError::InvalidLocalpart`] for a noncanonical or
    /// unsupported login component.
    pub fn parse(input: &str) -> Result<Self, LocalpartError> {
        let normalized: String = input.nfc().collect();
        if normalized.is_empty()
            || normalized.len() > 64
            || normalized != input
            || !normalized.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            || normalized.starts_with('.')
            || normalized.ends_with('.')
            || normalized.contains("..")
        {
            return Err(LocalpartError::InvalidLocalpart);
        }
        Ok(Self(normalized))
    }

    /// Returns the canonical localpart.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Localpart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Localpart {
    type Err = LocalpartError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// A tenant-scoped local user address such as `benjamin@parley.io`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UserAddress {
    localpart: Localpart,
    domain: DomainName,
}

impl UserAddress {
    /// Parses a canonical local user address.
    ///
    /// # Errors
    ///
    /// Returns [`UserAddressError`] when the address lacks one separator or
    /// either canonical component is invalid.
    pub fn parse(input: &str) -> Result<Self, UserAddressError> {
        let (localpart, domain) = input
            .split_once('@')
            .filter(|(_, remainder)| !remainder.contains('@'))
            .ok_or(UserAddressError::InvalidAddress)?;
        Ok(Self {
            localpart: Localpart::parse(localpart).map_err(UserAddressError::Localpart)?,
            domain: DomainName::parse(domain).map_err(UserAddressError::Domain)?,
        })
    }

    /// Returns the canonical localpart.
    #[must_use]
    pub fn localpart(&self) -> &Localpart {
        &self.localpart
    }

    /// Returns the authority domain that owns this account name.
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }
}

impl fmt::Display for UserAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.localpart, self.domain)
    }
}

impl FromStr for UserAddress {
    type Err = UserAddressError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// Domain canonicalization failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    /// Input is not an acceptable canonical tenant domain.
    #[error("domain must be a canonical DNS name without scheme, port or trailing dot")]
    InvalidDomain,
}

/// Localpart validation failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LocalpartError {
    /// Input is outside the first-release stable login grammar.
    #[error("localpart must be 1-64 lower-case ASCII characters from [a-z0-9._-]")]
    InvalidLocalpart,
}

/// User-address parsing failed.
#[derive(Debug, Error)]
pub enum UserAddressError {
    /// Address has no single localpart/domain separator.
    #[error("user address must contain exactly one @ separator")]
    InvalidAddress,
    /// Localpart is invalid.
    #[error("invalid localpart: {0}")]
    Localpart(#[source] LocalpartError),
    /// Domain is invalid.
    #[error("invalid domain: {0}")]
    Domain(#[source] DomainError),
}
