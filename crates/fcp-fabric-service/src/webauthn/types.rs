// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Ceremony state, public outcomes and closed error contracts.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize, Serialize)]
pub(super) struct RegistrationCeremonyState {
    pub(super) state: PasskeyRegistration,
    pub(super) label: Option<String>,
}

/// Sensitive opaque browser references to one server-side ceremony.
#[derive(Clone)]
pub struct IssuedWebauthnCeremony {
    /// Raw opaque one-use ceremony reference; deliver only in an `HttpOnly` cookie.
    pub token: SecretString,
    /// Independent opaque browser-binding reference; deliver only in an `HttpOnly` cookie.
    pub binding: SecretString,
    /// Absolute short-lived ceremony expiry.
    pub expires_at: OffsetDateTime,
}

/// Generic begin outcome carrying browser challenge data only on an eligible account.
#[derive(Clone)]
pub enum WebauthnBeginOutcome<T> {
    /// Generic denial for unavailable or non-enrolled accounts.
    Denied,
    /// Browser challenge and opaque references to server-side ceremony state.
    Challenge {
        /// Sensitive opaque server-state references.
        ceremony: IssuedWebauthnCeremony,
        /// Browser `WebAuthn` creation or request challenge.
        challenge: T,
        /// Optional non-secret credential label retained for registration completion.
        label: Option<String>,
    },
}

/// Generic completion outcome for a consumed ceremony.
#[derive(Clone, Debug)]
pub enum WebauthnFinishOutcome {
    /// Generic denial for invalid/replayed ceremony or invalid authenticator result.
    Denied,
    /// A new passkey was durably registered.
    Registered,
    /// Verified passkey authentication produced fresh tenant-local authorization.
    Authenticated(AuthorizationContext),
}

/// `WebAuthn` service failure distinct from generic credential denial.
#[derive(Debug, Error)]
pub enum WebauthnServiceError {
    /// RP origin and canonical domain violate strict Fabric policy.
    #[error("WebAuthn policy is invalid")]
    InvalidPolicy,
    /// Upstream `WebAuthn` verification or challenge construction failed.
    #[error("WebAuthn processing failed: {0}")]
    Webauthn(#[source] WebauthnError),
    /// JSON serialization or deserialization of server-only state failed.
    #[error("WebAuthn state serialization failed: {0}")]
    Serialization(#[source] serde_json::Error),
    /// Ceremony, credential or authorization persistence failed.
    #[error("WebAuthn store operation failed: {0}")]
    Store(#[from] StoreError),
    /// Ceremony authentication succeeded but account state no longer allows session issuance.
    #[error("WebAuthn session authorization is unavailable")]
    SessionUnavailable,
    /// Stored library credential ID failed to serialize as canonical base64url text.
    #[error("WebAuthn credential identifier serialization is invalid")]
    InvalidCredentialId,
}

pub(super) fn canonical_credential_id(passkey: &Passkey) -> Result<String, WebauthnServiceError> {
    serde_json::to_value(passkey.cred_id())
        .map_err(WebauthnServiceError::Serialization)
        .and_then(json_string)
}

pub(super) fn json_string(value: Value) -> Result<String, WebauthnServiceError> {
    match value {
        Value::String(value) if !value.is_empty() && value.len() <= 2048 => Ok(value),
        _ => Err(WebauthnServiceError::InvalidCredentialId),
    }
}
