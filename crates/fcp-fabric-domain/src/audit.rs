// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Secret-free immutable audit-event types.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{AccountId, AuditEventId, TenantId};

/// A durable, secret-free security audit event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    /// Immutable event ID.
    pub id: AuditEventId,
    /// Tenant in which the event occurred.
    pub tenant_id: TenantId,
    /// Local actor if authenticated.
    pub actor_id: Option<AccountId>,
    /// Stable category, never containing a secret.
    pub action: AuditAction,
    /// Caller-controlled correlation ID, bounded at the transport edge.
    pub correlation_id: String,
    /// Timestamp of committed state change.
    pub occurred_at: OffsetDateTime,
}

/// A redacted audit action category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Tenant bootstrap was committed.
    TenantBootstrapped,
    /// An account invitation or creation was committed.
    AccountCreated,
    /// An account role changed.
    RoleChanged,
    /// A password was set or changed.
    PasswordChanged,
    /// A multi-factor authenticator changed.
    MfaChanged,
    /// A short-lived login transaction was issued after password verification.
    LoginTransactionIssued,
    /// A short-lived login transaction was consumed for its expected next step.
    LoginTransactionConsumed,
    /// A session family was issued.
    SessionIssued,
    /// A session family was revoked.
    SessionRevoked,
    /// An action-bound MFA step-up grant was issued.
    StepUpGranted,
    /// An action-bound MFA step-up grant was consumed.
    StepUpConsumed,
    /// A server-side `WebAuthn` ceremony was issued.
    WebauthnCeremonyIssued,
    /// A server-side `WebAuthn` ceremony was consumed.
    WebauthnCeremonyConsumed,
    /// A phishing-resistant passkey was registered or materially updated.
    PasskeyChanged,
    /// Federation trust state changed.
    FederationTrustChanged,
    /// A federation request was accepted or rejected.
    FederationRequestEvaluated,
}
