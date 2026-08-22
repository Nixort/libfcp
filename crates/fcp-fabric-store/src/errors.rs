// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Closed error taxonomy for PostgreSQL persistence operations.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Persistent authority store failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// PostgreSQL connection or query failed.
    #[error("authority database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    /// Embedded migration application failed.
    #[error("authority schema migration failed: {0}")]
    Migration(#[source] sqlx::migrate::MigrateError),
    /// Domain administration policy rejected a command before persistence.
    #[error("authority administration command rejected: {0}")]
    Administration(#[source] AdministrationError),
    /// Password credential retrieved from storage is malformed or unsupported.
    #[error("stored password credential is invalid: {0}")]
    Credential(#[source] fcp_fabric_auth::PasswordError),
    /// Stored encrypted TOTP metadata violates the strict MFA profile.
    #[error("stored TOTP factor is invalid: {0}")]
    Totp(#[source] TotpError),
    /// Stored encrypted TOTP metadata has invalid nonce or parameters.
    #[error("stored TOTP factor metadata is invalid")]
    InvalidStoredTotp,
    /// Stored KMS/HSM data-key envelope metadata violates the bounded provider contract.
    #[error("stored TOTP data-key envelope is invalid")]
    InvalidTotpDataKeyEnvelope,
    /// Database account state does not map to the closed authority state set.
    #[error("stored account state is invalid")]
    CorruptAccountState,
    /// Persisted federation peer trust state is outside the closed Fabric set.
    #[error("stored federation trust state is invalid")]
    CorruptFederationTrustState,
    /// Store-facing audit correlation metadata violates the bounded safe-text policy.
    #[error("audit correlation ID is invalid")]
    InvalidCorrelationId,
    /// Database role value is outside the closed authority role set.
    #[error("stored account role is invalid")]
    CorruptRole,
    /// Stored normalized local address cannot form a canonical Fabric address.
    #[error("stored account address is invalid")]
    InvalidStoredAddress,
    /// Policy version cannot be represented by signed PostgreSQL bigint storage.
    #[error("policy version exceeds PostgreSQL bigint range")]
    PolicyVersionOverflow,
    /// Target account was outside tenant scope or mutation would be a no-op.
    #[error("target account was not found in tenant or role assignment was unchanged")]
    TargetNotFoundOrUnchanged,
    /// Login transaction expiry did not lie after issuance time.
    #[error("login transaction expiry is invalid")]
    InvalidLoginTransactionExpiry,
    /// Recovery code verifier set does not satisfy bounded storage policy.
    #[error("recovery code verifier set is invalid")]
    InvalidRecoveryCodeSet,
    /// Step-up grant expiry did not lie after issuance time.
    #[error("step-up grant expiry is invalid")]
    InvalidStepUpGrantExpiry,
    /// Inbound federation replay expiry did not lie after acceptance time.
    #[error("federation replay expiry is invalid")]
    InvalidFederationReplayExpiry,
    /// `WebAuthn` ceremony expiry did not lie after creation time.
    #[error("WebAuthn ceremony expiry is invalid")]
    InvalidWebauthnCeremonyExpiry,
    /// Opaque `WebAuthn` ceremony handle, browser binding, expiry or consumption state is invalid.
    #[error("WebAuthn ceremony is invalid or expired")]
    InvalidOrExpiredWebauthnCeremony,
    /// Stored `WebAuthn` ceremony kind is outside the closed Fabric set.
    #[error("stored WebAuthn ceremony kind is invalid")]
    CorruptWebauthnCeremonyKind,
    /// Canonical `WebAuthn` credential identifier violates bounded storage policy.
    #[error("WebAuthn credential identifier is invalid")]
    InvalidWebauthnCredentialId,
    /// User-selected `WebAuthn` credential label violates bounded safe-text policy.
    #[error("WebAuthn passkey label is invalid")]
    InvalidWebauthnPasskeyLabel,
    /// Login transaction was invalid, expired, already used, wrong-stage or incorrectly bound.
    #[error("login transaction is invalid or expired")]
    InvalidOrExpiredLoginTransaction,
    /// Session expiry did not lie after the service issuance time.
    #[error("session expiry is invalid")]
    InvalidSessionExpiry,
}
