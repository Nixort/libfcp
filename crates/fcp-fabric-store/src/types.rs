// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Shared Fabric PostgreSQL command, record and outcome contracts.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Input required to create one short-lived opaque Fabric login transaction.
#[derive(Clone, Copy, Debug)]
pub struct CreateLoginTransaction<'a> {
    /// Tenant owning the verified account.
    pub tenant_id: TenantId,
    /// Account whose next local authentication step is bound server-side.
    pub account_id: AccountId,
    /// Keyed digest of the raw one-use transaction credential.
    pub token_digest: &'a OpaqueTokenDigest,
    /// The only step permitted when the credential is presented.
    pub stage: LoginTransactionStage,
    /// HMAC-derived browser/native client binding digest.
    pub binding_digest: &'a [u8; 32],
    /// Pending TOTP factor selected entirely by the server, when applicable.
    pub factor_id: Option<Uuid>,
    /// Short absolute expiry for this one-use credential.
    pub expires_at: OffsetDateTime,
    /// Redacted audit correlation identifier.
    pub correlation_id: &'a str,
}

/// Expected next step for a short-lived opaque Fabric login transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginTransactionStage {
    /// Password verified for an account that must enroll first MFA factor.
    MfaEnrollment,
    /// Password verified for an account with active TOTP factor.
    MfaChallenge,
    /// Password and required MFA verified; session may now be issued once.
    SessionIssuance,
}

impl LoginTransactionStage {
    pub(super) const fn database_value(self) -> &'static str {
        match self {
            Self::MfaEnrollment => "mfa_enrollment",
            Self::MfaChallenge => "mfa_challenge",
            Self::SessionIssuance => "session_issuance",
        }
    }
}

/// Durable transaction carrying an opaque login credential between local auth steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoginTransactionRecord {
    /// Durable transaction ID for redacted audit correlation.
    pub transaction_id: Uuid,
    /// Tenant owning the authenticated account.
    pub tenant_id: TenantId,
    /// Account bound to this transaction only on the server side.
    pub account_id: AccountId,
    /// Expected next authentication or session-issuance step.
    pub stage: LoginTransactionStage,
    /// Absolute one-use credential expiration.
    pub expires_at: OffsetDateTime,
    /// Pending TOTP factor selected only for an enrollment-confirmation step.
    pub factor_id: Option<Uuid>,
}

/// Supported server-side `WebAuthn` ceremony purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebauthnCeremonyKind {
    /// Register a new verified passkey for one local account.
    Registration,
    /// Authenticate using currently active account passkeys.
    Authentication,
}

impl WebauthnCeremonyKind {
    pub(super) const fn database_value(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Authentication => "authentication",
        }
    }
}

/// Input required to persist one server-side `WebAuthn` ceremony.
#[derive(Clone, Copy, Debug)]
pub struct CreateWebauthnCeremony<'a> {
    /// Tenant owning the local account.
    pub tenant_id: TenantId,
    /// Account for which the ceremony may complete.
    pub account_id: AccountId,
    /// Registration or authentication purpose.
    pub kind: WebauthnCeremonyKind,
    /// Serialised library-generated server-side challenge state.
    pub state: &'a serde_json::Value,
    /// Keyed digest of the raw opaque browser ceremony handle.
    pub token_digest: &'a OpaqueTokenDigest,
    /// Keyed digest of the independent opaque browser binding handle.
    pub binding_digest: &'a OpaqueTokenDigest,
    /// Absolute short-lived ceremony expiry.
    pub expires_at: OffsetDateTime,
    /// Bounded redacted operation correlation identifier.
    pub correlation_id: &'a str,
}

/// Secret-free consumed `WebAuthn` ceremony record.
#[derive(Clone, Debug)]
pub struct WebauthnCeremonyRecord {
    /// Tenant owning the ceremony account.
    pub tenant_id: TenantId,
    /// Account whose passkey action is authorized by this ceremony.
    pub account_id: AccountId,
    /// Registration or authentication purpose.
    pub kind: WebauthnCeremonyKind,
    /// Library-generated server-side challenge state to use once.
    pub state: serde_json::Value,
}

/// One active serialized passkey record.
#[derive(Clone, Debug)]
pub struct StoredWebauthnPasskey {
    /// Canonical base64url credential identifier, globally unique across accounts.
    pub credential_id: String,
    /// Serialized `webauthn-rs` passkey state retained only server side.
    pub passkey: serde_json::Value,
}

/// Input required to register one verified `WebAuthn` passkey.
#[derive(Clone, Copy, Debug)]
pub struct RegisterWebauthnPasskey<'a> {
    /// Tenant owning the local account.
    pub tenant_id: TenantId,
    /// Account that completed the verified registration ceremony.
    pub account_id: AccountId,
    /// Canonical base64url identifier returned by the verified passkey.
    pub credential_id: &'a str,
    /// Complete opaque library-managed passkey state.
    pub passkey: &'a serde_json::Value,
    /// Optional user-selected non-secret credential label.
    pub label: Option<&'a str>,
    /// Bounded redacted operation correlation identifier.
    pub correlation_id: &'a str,
}

/// Persisted explicit remote federation peer policy and active key documents.
#[derive(Clone, Debug)]
pub struct StoredFederationPeerMaterial {
    /// Local tenant that owns this peer policy.
    pub tenant_id: TenantId,
    /// Durable remote peer record ID.
    pub peer_id: Uuid,
    /// Local owner-controlled remote trust state.
    pub trust_state: FederationTrustState,
    /// SHA-256 fingerprint expected for the accepted complete identity.
    pub expected_key_fingerprint: Vec<u8>,
    /// Currently valid non-retired remote public key documents.
    pub keys: Vec<StoredFederationKeyMaterial>,
}

/// One current remote federation public key document.
#[derive(Clone, Debug)]
pub struct StoredFederationKeyMaterial {
    /// Stable peer-local key identifier.
    pub key_id: String,
    /// Structured public key document owned by explicit peer administration.
    pub public_key_document: serde_json::Value,
    /// Maximum acceptance time of this key document.
    pub valid_until: OffsetDateTime,
}

/// Input for one atomically replay-protected inbound federation delivery.
#[derive(Clone, Copy, Debug)]
pub struct RecordFederationReplay<'a> {
    /// Local tenant that owns the destination federation domain.
    pub tenant_id: TenantId,
    /// Explicitly pinned remote peer identity.
    pub peer_id: Uuid,
    /// Remote source-generated globally unique request ID.
    pub request_id: Uuid,
    /// SHA-256 digest of the exact verified canonical delivery transcript.
    pub body_digest: &'a [u8; 32],
    /// Delivery expiry copied from the verified signed record.
    pub expires_at: OffsetDateTime,
    /// Bounded redacted ingress correlation identifier.
    pub correlation_id: &'a str,
}

/// Supported action protected by one action-bound step-up grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepUpAction {
    /// Changes a tenant-local account role assignment.
    ChangeAccountRole,
}

impl StepUpAction {
    pub(super) const fn database_value(self) -> &'static str {
        match self {
            Self::ChangeAccountRole => "change_account_role",
        }
    }
}

/// Input required to create one action-bound step-up grant.
#[derive(Clone, Copy, Debug)]
pub struct CreateStepUpGrant<'a> {
    /// Tenant-local actor scope.
    pub tenant_id: TenantId,
    /// Authenticated local actor.
    pub account_id: AccountId,
    /// Current server-side session family.
    pub family_id: Uuid,
    /// Action authorized by this grant.
    pub action: StepUpAction,
    /// Fixed-length server-derived target binding digest.
    pub target_digest: &'a [u8; 32],
    /// Keyed digest of the raw opaque grant token.
    pub token_digest: &'a OpaqueTokenDigest,
    /// Absolute one-use grant expiry.
    pub expires_at: OffsetDateTime,
    /// Bounded redacted operation correlation identifier.
    pub correlation_id: &'a str,
}

/// Input required to consume one action-bound step-up grant.
#[derive(Clone, Copy, Debug)]
pub struct ConsumeStepUpGrant<'a> {
    /// Tenant-local actor scope.
    pub tenant_id: TenantId,
    /// Authenticated local actor.
    pub account_id: AccountId,
    /// Current server-side session family.
    pub family_id: Uuid,
    /// Action authorized by this grant.
    pub action: StepUpAction,
    /// Fixed-length server-derived target binding digest.
    pub target_digest: &'a [u8; 32],
    /// Keyed digest of the raw opaque grant token.
    pub token_digest: &'a OpaqueTokenDigest,
    /// Bounded redacted operation correlation identifier.
    pub correlation_id: &'a str,
}

/// Non-secret result of a newly issued action-bound grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepUpGrantRecord {
    /// Durable grant identity retained only server side.
    pub grant_id: Uuid,
    /// Absolute one-use expiry.
    pub expires_at: OffsetDateTime,
}

/// Input required to create a refresh family and its paired opaque access session.
#[derive(Clone, Copy, Debug)]
pub struct CreateRefreshSession<'a> {
    /// Tenant that owns the new session family.
    pub tenant_id: TenantId,
    /// Account that owns the new session family.
    pub account_id: AccountId,
    /// Keyed digest of the raw refresh credential.
    pub refresh_digest: &'a OpaqueTokenDigest,
    /// Keyed digest of the paired raw access credential.
    pub access_digest: &'a OpaqueTokenDigest,
    /// Absolute expiry of the refresh credential.
    pub refresh_expires_at: OffsetDateTime,
    /// Absolute expiry of the paired access credential.
    pub access_expires_at: OffsetDateTime,
    /// Bounded redacted operation correlation identifier.
    pub correlation_id: &'a str,
}

/// Result of one server-side refresh credential presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshRotation {
    /// The credential was consumed and replaced with a successor in its family.
    Rotated(RefreshRotationRecord),
    /// A consumed credential was presented again; its entire family was revoked.
    ReuseDetected,
    /// Credential was absent, invalid, expired, revoked or linked to a disabled account.
    Denied,
}

/// Non-secret result of a successfully rotated refresh credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshRotationRecord {
    /// Tenant which owns the rotated session family.
    pub tenant_id: TenantId,
    /// Account which owns the rotated session family.
    pub account_id: AccountId,
    /// Existing family retained by the successor credential.
    pub family_id: Uuid,
    /// Newly issued credential identifier.
    pub credential_id: Uuid,
    /// Successor credential expiry.
    pub expires_at: OffsetDateTime,
    /// Paired short-lived opaque access-session record identifier.
    pub access_session_id: Uuid,
    /// Paired access-session expiry.
    pub access_expires_at: OffsetDateTime,
}

/// Opaque refresh credential record persisted with one session family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshSessionRecord {
    /// Session family identity revoked together on refresh-token reuse.
    pub family_id: Uuid,
    /// Concrete one-time refresh credential record identity.
    pub credential_id: Uuid,
    /// Absolute expiry at which this credential cannot be refreshed.
    pub expires_at: OffsetDateTime,
    /// Paired short-lived opaque access-session record identifier.
    pub access_session_id: Uuid,
    /// Absolute expiry of the paired opaque access session.
    pub access_expires_at: OffsetDateTime,
}

/// Current authorization material derived from a valid opaque access session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessSessionAuthorization {
    /// Current tenant-local authorization context for the access session owner.
    pub context: AuthorizationContext,
    /// Session family associated with this access session.
    pub family_id: Uuid,
}

/// One current recovery-code set with non-secret count metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCodeSetRecord {
    /// Current recovery-code set identifier for internal management/audit use.
    pub set_id: Uuid,
    /// Number of one-use codes in the replacement set.
    pub code_count: usize,
    /// Time at which the current set was committed.
    pub created_at: OffsetDateTime,
}

/// Login data required for generic local credential verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginAccount {
    /// Tenant-local account identity.
    pub account_id: AccountId,
    /// Tenant in which the account exists.
    pub tenant_id: TenantId,
    /// Current account lifecycle state.
    pub state: AccountState,
    /// Persisted Argon2id verifier, absent before initial password setup.
    pub verifier: Option<PasswordVerifierString>,
}

/// Active encrypted TOTP factor retrieved from persistent store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedTotpFactor {
    /// Factor identity for atomic activation and time-step consumption.
    pub factor_id: Uuid,
    /// Encrypted seed and fixed TOTP metadata.
    pub encrypted_seed: EncryptedTotpSeed,
    /// Most recently accepted moving time step, if any.
    pub last_accepted_step: Option<i64>,
}

/// Non-secret KMS/HSM envelope persisted for one TOTP AES-256 data key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredTotpDataKeyEnvelope {
    /// Opaque reference stored with encrypted TOTP factors.
    pub key_reference: TotpKeyReference,
    /// Closed provider identifier used to select the resolver.
    pub provider: String,
    /// Explicit wrapping-key ARN or provider-specific key reference.
    pub wrapping_key_reference: String,
    /// KMS/HSM ciphertext blob; this is not plaintext key material.
    pub encrypted_data_key: Vec<u8>,
}

/// Input for atomically storing a newly generated KMS/HSM-wrapped data key.
#[derive(Clone, Copy, Debug)]
pub struct CreateTotpDataKeyEnvelope<'a> {
    /// Opaque reference that will be persisted on future encrypted factors.
    pub key_reference: &'a TotpKeyReference,
    /// Closed provider identifier, such as `aws_kms`.
    pub provider: &'a str,
    /// Explicit wrapping-key ARN or provider-specific key reference.
    pub wrapping_key_reference: &'a str,
    /// Provider ciphertext blob only; plaintext never reaches this contract.
    pub encrypted_data_key: &'a [u8],
    /// Durable creation time for lifecycle and rotation visibility.
    pub created_at: OffsetDateTime,
}

impl PersistedTotpFactor {
    pub(super) fn try_from_row(
        row: (Uuid, Vec<u8>, Vec<u8>, String, i16, i16, Option<i64>),
    ) -> Result<Self, StoreError> {
        let (
            factor_id,
            ciphertext,
            nonce,
            key_reference,
            digits,
            period_seconds,
            last_accepted_step,
        ) = row;
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| StoreError::InvalidStoredTotp)?;
        let digits = u32::try_from(digits).map_err(|_| StoreError::InvalidStoredTotp)?;
        let period_seconds = i64::from(period_seconds);
        if digits != 6 || period_seconds != 30 {
            return Err(StoreError::InvalidStoredTotp);
        }
        Ok(Self {
            factor_id,
            encrypted_seed: EncryptedTotpSeed {
                ciphertext,
                nonce,
                key_reference: TotpKeyReference::new(key_reference).map_err(StoreError::Totp)?,
                digits,
                period_seconds,
            },
            last_accepted_step,
        })
    }
}
