// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Server-side federation configuration errors.

use core::fmt;

/// Configuration authority failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A replacement did not advance the configuration epoch.
    NonIncreasingEpoch,
    /// The shared canonical configuration rejected the requested member set.
    Core(libfcp_core::Error),
}

impl From<libfcp_core::Error> for Error {
    fn from(error: libfcp_core::Error) -> Self {
        Self::Core(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fcp server error: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
