// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Password, authenticator and session primitives for the FCP Fabric service.
//!
//! This crate does not expose SQL, HTTP or tenant-role mutation APIs. Its
//! outputs are deliberately opaque values for the transactional store layer.

mod password;
mod session;
mod totp;

pub use password::{
    hash_password, verify_password, NoPasswordBlocklist, PasswordBlocklist, PasswordError,
    PasswordPolicy, PasswordVerifierString,
};
pub use session::{
    derive_opaque_token_digest, issue_opaque_token, verify_opaque_token, IssuedOpaqueToken,
    OpaqueTokenDigest, TokenDigestKey,
};
pub use totp::{
    begin_totp_enrollment, encrypt_seed, verify_totp, AcceptedTotpStep, EncryptedTotpSeed,
    TotpBinding, TotpDataEncryptionKey, TotpEnrollment, TotpError, TotpKeyReference,
    TotpProvisioning,
};
