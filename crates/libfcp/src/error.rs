// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Client policy, configuration and CFR routing errors.

use libfcp_core::Error as FcpError;

/// Client-side configuration or routing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A CFR recipient had no application-approved FCP endpoint binding.
    MissingBinding,
    /// A bound FCP endpoint had no established connection in the supplied directory.
    MissingConnection,
    /// A supplied connection did not belong to this directory's federation or local endpoint.
    MismatchedConnection,
    /// An FCP connection or signed configuration rejected an operation.
    Fcp(FcpError),
    /// A signed configuration was for a different federation namespace.
    WrongFederation,
    /// A signed configuration was not issued by the pinned authority key.
    WrongAuthority,
    /// A configuration did not strictly advance the accepted epoch.
    StaleConfiguration,
    /// The configuration did not contain the local CFR participant identity.
    MissingLocalMember,
    /// The local participant was bound to a different FCP endpoint key.
    WrongLocalEndpoint,
}

impl From<FcpError> for Error {
    fn from(error: FcpError) -> Self {
        Self::Fcp(error)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "fcp client error: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
