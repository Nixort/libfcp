// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Stable authority-domain identifiers and monotonic revisions.

use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A stable tenant identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Creates an identifier from a persisted UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Generates a new time-sortable tenant identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A stable account identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct AccountId(Uuid);

impl AccountId {
    /// Creates an identifier from a persisted UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Generates a new time-sortable account identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for AccountId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A monotonic tenant policy revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    /// Creates a persisted policy version.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying monotonic value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Produces the next policy version or reports integer exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyVersionError::Exhausted`] when the revision cannot be
    /// incremented without overflow.
    pub fn next(self) -> Result<Self, PolicyVersionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(PolicyVersionError::Exhausted)
    }
}

/// A redacted immutable audit-event identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    /// Generates a new time-sortable audit event identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

/// Tenant policy revision cannot advance.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyVersionError {
    /// Monotonic policy version reached the numeric limit.
    #[error("policy version is exhausted")]
    Exhausted,
}
