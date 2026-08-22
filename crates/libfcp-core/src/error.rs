// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! FCP parse, validation and state-machine errors.

use core::fmt;

/// FCP parse, validation and state-machine failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The envelope exceeded a fixed allocation bound.
    TooLarge,
    /// A variable field exceeded its kind-specific bound.
    FieldTooLarge,
    /// The envelope was truncated.
    Truncated,
    /// Bytes followed an otherwise complete envelope.
    TrailingBytes,
    /// Marker did not identify the FCP wire format.
    BadMarker,
    /// Version is not supported.
    UnsupportedVersion,
    /// Envelope kind is not known.
    UnknownKind,
    /// The endpoint public key did not parse strictly.
    BadSenderKey,
    /// The Ed25519 signature did not verify.
    BadSignature,
    /// Input was not the one canonical encoding of its parsed form.
    NonCanonical,
    /// Remote input did not bind to this federation.
    WrongFederation,
    /// Remote input did not bind to this attempt.
    WrongAttempt,
    /// Remote input was not authored by the configured peer endpoint.
    WrongSender,
    /// Remote input was not addressed to this local endpoint.
    WrongRecipient,
    /// The configured local and remote endpoint keys were identical.
    SameEndpoint,
    /// A local operation used a signer for another endpoint.
    WrongLocalSigner,
    /// Operation is not permitted in the current state.
    InvalidState,
    /// Both peers tried to offer while a local offer was outstanding.
    Glare,
    /// Candidate did not bind to an active offer or answer.
    WrongCandidateParent,
    /// Configuration marker did not identify the FCP configuration format.
    BadConfigurationMarker,
    /// Configuration version is not supported.
    UnsupportedConfigurationVersion,
    /// Configuration authority public key did not parse strictly.
    BadConfigurationAuthority,
    /// Configuration signer did not match the configuration's pinned authority.
    WrongConfigurationAuthority,
    /// Configuration signature did not verify.
    BadConfigurationSignature,
    /// Configuration declared more than the fixed member bound.
    TooManyFederationMembers,
    /// Configuration contains a duplicate CFR identity or endpoint binding.
    DuplicateFederationMember,
    /// ML-DSA-65 public-key bytes did not parse as canonical FCP identity material.
    BadPostQuantumKey,
    /// ML-DSA-65 signature encoding was not canonical.
    BadPostQuantumSignatureEncoding,
    /// ML-DSA-65 signature did not verify.
    BadPostQuantumSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fcp error: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
