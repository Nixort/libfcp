// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Opaque refresh-session issuance after completed local authentication.

use fcp_fabric_auth::{derive_opaque_token_digest, issue_opaque_token, TokenDigestKey};
use fcp_fabric_domain::AuthorizationContext;
use fcp_fabric_store::{CreateRefreshSession, PostgresAuthorityStore, RefreshRotation, StoreError};
use secrecy::SecretString;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Policy for server-issued opaque refresh-session lifetimes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    refresh_lifetime: Duration,
    access_lifetime: Duration,
}

impl SessionPolicy {
    /// Creates a policy with one positive bounded refresh lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`SessionIssueError::InvalidPolicy`] for zero, negative or more
    /// than 30-day refresh lifetimes.
    pub fn new(refresh_lifetime: Duration) -> Result<Self, SessionIssueError> {
        if refresh_lifetime <= Duration::ZERO || refresh_lifetime > Duration::days(30) {
            return Err(SessionIssueError::InvalidPolicy);
        }
        Ok(Self {
            refresh_lifetime,
            access_lifetime: Duration::minutes(15),
        })
    }

    /// Returns the bounded lifetime used for a newly issued refresh credential.
    #[must_use]
    pub const fn refresh_lifetime(&self) -> Duration {
        self.refresh_lifetime
    }

    /// Returns the short-lived opaque access-session lifetime.
    #[must_use]
    pub const fn access_lifetime(&self) -> Duration {
        self.access_lifetime
    }
}

/// Issues durable opaque refresh sessions after password/MFA authentication succeeds.
#[derive(Clone)]
pub struct SessionIssuer {
    store: PostgresAuthorityStore,
    digest_key: TokenDigestKey,
    policy: SessionPolicy,
}

impl SessionIssuer {
    /// Creates the issuer from a KMS/HSM-provided digest key and explicit policy.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        digest_key: TokenDigestKey,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            store,
            digest_key,
            policy,
        }
    }

    /// Issues one refresh bearer credential and stores its digest in a new family.
    ///
    /// The transport layer must deliver the raw credential only through an
    /// HttpOnly/Secure cookie or OS-protected native credential store. It must
    /// never serialize this value into audit, logs or database records.
    ///
    /// # Errors
    ///
    /// Returns [`SessionIssueError::Store`] when persistent session issuance
    /// fails; it does not return a raw credential on failure.
    pub async fn issue(
        &self,
        context: &AuthorizationContext,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<IssuedRefreshSession, SessionIssueError> {
        let issued = issue_opaque_token(&self.digest_key);
        let access = issue_opaque_token(&self.digest_key);
        let expires_at = now + self.policy.refresh_lifetime;
        let access_expires_at = now + self.policy.access_lifetime;
        let record = self
            .store
            .create_refresh_session(CreateRefreshSession {
                tenant_id: context.tenant_id(),
                account_id: context.account_id(),
                refresh_digest: &issued.digest,
                access_digest: &access.digest,
                refresh_expires_at: expires_at,
                access_expires_at,
                correlation_id,
            })
            .await?;
        Ok(IssuedRefreshSession {
            refresh_token: issued.raw,
            access_token: access.raw,
            family_id: record.family_id,
            credential_id: record.credential_id,
            expires_at: record.expires_at,
            access_expires_at: record.access_expires_at,
        })
    }
}

/// Rotates already issued refresh credentials and detects credential-family reuse.
#[derive(Clone)]
pub struct SessionRotator {
    store: PostgresAuthorityStore,
    digest_key: TokenDigestKey,
    policy: SessionPolicy,
}

impl SessionRotator {
    /// Creates the rotator with the same dedicated digest key and lifetime policy
    /// used by the local session issuer.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        digest_key: TokenDigestKey,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            store,
            digest_key,
            policy,
        }
    }

    /// Atomically exchanges one current refresh credential for its successor.
    ///
    /// The raw successor is returned only for [`SessionRotationOutcome::Rotated`].
    /// Reusing an already consumed credential revokes the whole server-side family;
    /// transport code must clear the browser/native credential and return the same
    /// public denial as any other unavailable refresh credential.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRotationError::Store`] for an infrastructure failure.
    /// Invalid, expired, revoked and reused credentials remain normal outcomes.
    pub async fn rotate(
        &self,
        presented_token: &SecretString,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<SessionRotationOutcome, SessionRotationError> {
        let presented_digest = derive_opaque_token_digest(&self.digest_key, presented_token);
        let successor = issue_opaque_token(&self.digest_key);
        let successor_access = issue_opaque_token(&self.digest_key);
        let rotation = self
            .store
            .rotate_refresh_credential(
                &presented_digest,
                &successor.digest,
                &successor_access.digest,
                now + self.policy.refresh_lifetime(),
                now + self.policy.access_lifetime(),
                correlation_id,
            )
            .await?;
        Ok(match rotation {
            RefreshRotation::Rotated(record) => {
                SessionRotationOutcome::Rotated(IssuedRefreshSession {
                    refresh_token: successor.raw,
                    access_token: successor_access.raw,
                    family_id: record.family_id,
                    credential_id: record.credential_id,
                    expires_at: record.expires_at,
                    access_expires_at: record.access_expires_at,
                })
            }
            RefreshRotation::ReuseDetected => SessionRotationOutcome::ReuseDetected,
            RefreshRotation::Denied => SessionRotationOutcome::Denied,
        })
    }
}

/// Internal result of one refresh-credential presentation.
#[derive(Clone)]
pub enum SessionRotationOutcome {
    /// A new opaque refresh credential replaces the presented credential.
    Rotated(IssuedRefreshSession),
    /// A previously consumed credential was presented and its family was revoked.
    ReuseDetected,
    /// Credential was absent, expired, revoked or otherwise unavailable.
    Denied,
}

/// Refresh rotation failure distinct from normal unavailable-credential outcomes.
#[derive(Debug, Error)]
pub enum SessionRotationError {
    /// Atomic refresh persistence or audit operation failed.
    #[error("session rotation storage failed: {0}")]
    Store(#[from] StoreError),
}

/// Authenticates opaque short-lived access credentials for request authorization.
#[derive(Clone)]
pub struct AccessSessionAuthenticator {
    store: PostgresAuthorityStore,
    digest_key: TokenDigestKey,
}

impl AccessSessionAuthenticator {
    /// Creates an access-session authenticator with the session digest key.
    #[must_use]
    pub fn new(store: PostgresAuthorityStore, digest_key: TokenDigestKey) -> Self {
        Self { store, digest_key }
    }

    /// Resolves one raw browser/native access credential into current server-side
    /// tenant-local authorization attributes.
    ///
    /// # Errors
    ///
    /// Returns [`AccessSessionAuthenticationError::Store`] only for a persistent
    /// state failure. Unknown, expired, revoked and unavailable-account sessions
    /// return `Ok(None)` for one generic transport denial.
    pub async fn authenticate(
        &self,
        raw_access_token: &SecretString,
    ) -> Result<Option<AuthenticatedAccessSession>, AccessSessionAuthenticationError> {
        let digest = derive_opaque_token_digest(&self.digest_key, raw_access_token);
        let authorization = self
            .store
            .access_session_authorization_context(&digest)
            .await?;
        Ok(
            authorization.map(|authorization| AuthenticatedAccessSession {
                context: authorization.context,
                family_id: authorization.family_id,
            }),
        )
    }
}

/// Current request authorization derived from a verified opaque access session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAccessSession {
    /// Current tenant-local authorization context.
    pub context: AuthorizationContext,
    /// Family holding the access/refresh credentials.
    pub family_id: uuid::Uuid,
}

/// Access-session authentication infrastructure failure.
#[derive(Debug, Error)]
pub enum AccessSessionAuthenticationError {
    /// Current access-session, family, account or role lookup failed.
    #[error("access session authentication storage failed: {0}")]
    Store(#[from] StoreError),
}

/// Revokes one tenant-local session family for security response or administration.
#[derive(Clone, Debug)]
pub struct SessionRevoker {
    store: PostgresAuthorityStore,
}

impl SessionRevoker {
    /// Creates a session-family revoker over the tenant-scoped persistence boundary.
    #[must_use]
    pub const fn new(store: PostgresAuthorityStore) -> Self {
        Self { store }
    }

    /// Revokes one session family without disclosing whether it existed or was
    /// already revoked to a future HTTP caller.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRevocationError::Store`] when the revocation/audit
    /// transaction cannot commit.
    pub async fn revoke(
        &self,
        tenant_id: fcp_fabric_domain::TenantId,
        account_id: fcp_fabric_domain::AccountId,
        family_id: uuid::Uuid,
        correlation_id: &str,
    ) -> Result<bool, SessionRevocationError> {
        self.store
            .revoke_refresh_session_family(tenant_id, account_id, family_id, correlation_id)
            .await
            .map_err(SessionRevocationError::Store)
    }
}

/// Explicit session-family revocation failure.
#[derive(Debug, Error)]
pub enum SessionRevocationError {
    /// Durable revocation/audit state could not commit.
    #[error("session family revocation storage failed: {0}")]
    Store(#[source] StoreError),
}

/// One-time raw refresh credential and non-secret session metadata.
#[derive(Clone)]
pub struct IssuedRefreshSession {
    /// Raw one-use opaque refresh credential; show/set once only.
    pub refresh_token: SecretString,
    /// Raw short-lived opaque access credential; set only in a Secure/HttpOnly cookie.
    pub access_token: SecretString,
    /// Session family identity for user/device revocation UI.
    pub family_id: uuid::Uuid,
    /// Current refresh credential record identity.
    pub credential_id: uuid::Uuid,
    /// Absolute refresh credential expiry.
    pub expires_at: OffsetDateTime,
    /// Absolute short-lived access credential expiry.
    pub access_expires_at: OffsetDateTime,
}

/// Session issuance failure distinct from normal credential denial.
#[derive(Debug, Error)]
pub enum SessionIssueError {
    /// Session configuration violates the supported FCP Fabric security limits.
    #[error("session issuance policy is invalid")]
    InvalidPolicy,
    /// Persistent refresh-session transaction failed.
    #[error("session issuance storage failed: {0}")]
    Store(#[from] StoreError),
}
