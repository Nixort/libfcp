// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Authenticator-app verification service backed by encrypted TOTP factors.

use std::sync::Arc;

use async_trait::async_trait;
use fcp_fabric_auth::{
    begin_totp_enrollment, verify_totp, TotpBinding, TotpDataEncryptionKey, TotpError,
    TotpKeyReference,
};
use fcp_fabric_domain::{AccountId, AuthorizationContext, TenantId};
use fcp_fabric_store::{PostgresAuthorityStore, StoreError};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Asynchronous adapter that unwraps TOTP data-encryption keys from a KMS/HSM.
#[async_trait]
pub trait TotpKeyResolver: Send + Sync {
    /// Resolves the current data-encryption key for the opaque reference.
    async fn resolve(
        &self,
        reference: &TotpKeyReference,
    ) -> Result<TotpDataEncryptionKey, TotpKeyResolutionError>;
}

/// KMS/HSM key-resolution failure.
#[derive(Debug, Error)]
pub enum TotpKeyResolutionError {
    /// Referenced key is unavailable, disabled or unknown to the configured secret provider.
    #[error("TOTP encryption key is unavailable")]
    Unavailable,
    /// Secret provider failed without exposing secret material.
    #[error("TOTP encryption key provider failed")]
    ProviderFailure,
}

/// Completes an already password-verified local TOTP login transaction.
#[derive(Clone)]
pub struct TotpLoginService {
    store: PostgresAuthorityStore,
    key_resolver: Arc<dyn TotpKeyResolver>,
}

impl TotpLoginService {
    /// Creates the MFA completion service with an external key resolver.
    #[must_use]
    pub fn new(store: PostgresAuthorityStore, key_resolver: Arc<dyn TotpKeyResolver>) -> Self {
        Self {
            store,
            key_resolver,
        }
    }

    /// Verifies and atomically consumes a submitted code for a password-verified account.
    ///
    /// The HTTP boundary must look up tenant/account identity from a short-lived,
    /// single-use opaque login transaction; it must never take them from a client
    /// request body. All verification failures return [`TotpLoginOutcome::Denied`]
    /// for a generic public response.
    ///
    /// # Errors
    ///
    /// Returns [`TotpLoginError`] only for durable-store or KMS/HSM failure.
    /// Invalid/expired/replayed authenticator responses return
    /// [`TotpLoginOutcome::Denied`].
    pub async fn complete(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<TotpLoginOutcome, TotpLoginError> {
        let Some(factor) = self.store.active_totp_factor(tenant_id, account_id).await? else {
            return Ok(TotpLoginOutcome::Denied);
        };
        let key = self
            .key_resolver
            .resolve(&factor.encrypted_seed.key_reference)
            .await
            .map_err(TotpLoginError::KeyResolution)?;
        let binding = TotpBinding {
            tenant_id,
            account_id,
            factor_id: factor.factor_id,
        };
        let accepted = match verify_totp(
            &key,
            &factor.encrypted_seed,
            &binding,
            code,
            now,
            factor.last_accepted_step,
        ) {
            Ok(step) => step,
            Err(TotpError::VerificationFailed | TotpError::InvalidCodeFormat) => {
                return Ok(TotpLoginOutcome::Denied)
            }
            Err(error) => return Err(TotpLoginError::Totp(error)),
        };
        match self
            .store
            .consume_totp_step(tenant_id, account_id, factor.factor_id, accepted.get())
            .await
        {
            Ok(()) => {}
            Err(StoreError::TargetNotFoundOrUnchanged) => return Ok(TotpLoginOutcome::Denied),
            Err(error) => return Err(TotpLoginError::Store(error)),
        }
        let Some(context) = self
            .store
            .session_authorization_context(tenant_id, account_id)
            .await?
        else {
            return Ok(TotpLoginOutcome::Denied);
        };
        Ok(TotpLoginOutcome::Authenticated(context))
    }
}

/// Internal result after TOTP completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TotpLoginOutcome {
    /// Generic denial for invalid, expired, unknown or replayed authenticator response.
    Denied,
    /// Fresh tenant-local authorization context ready for opaque session issuance.
    Authenticated(AuthorizationContext),
}

/// TOTP completion service failure distinct from generic authentication denial.
#[derive(Debug, Error)]
pub enum TotpLoginError {
    /// Active-factor persistence or replay recording failed.
    #[error("TOTP authority-state operation failed: {0}")]
    Store(#[from] StoreError),
    /// External KMS/HSM failed to unwrap the configured factor key.
    #[error("TOTP key resolution failed: {0}")]
    KeyResolution(#[source] TotpKeyResolutionError),
    /// Encrypted factor data failed a non-user-correctable cryptographic check.
    #[error("TOTP factor processing failed: {0}")]
    Totp(#[source] TotpError),
}

/// Active KMS/HSM material selected for new TOTP factor encryption.
#[derive(Clone)]
pub struct ActiveTotpEncryptionKey {
    /// Opaque KMS/HSM key reference persisted alongside the encrypted seed.
    pub reference: TotpKeyReference,
    /// In-memory unwrapped AES-256 data-encryption key.
    pub key: TotpDataEncryptionKey,
}

/// KMS/HSM adapter that both resolves existing keys and selects the active key
/// used for newly enrolled TOTP factors.
#[async_trait]
pub trait TotpEnrollmentKeyProvider: TotpKeyResolver {
    /// Selects the active encryption key for a newly pending factor.
    async fn active_key(&self) -> Result<ActiveTotpEncryptionKey, TotpKeyResolutionError>;
}

/// Creates and confirms encrypted authenticator-app factors.
#[derive(Clone)]
pub struct TotpEnrollmentService {
    store: PostgresAuthorityStore,
    key_provider: Arc<dyn TotpEnrollmentKeyProvider>,
    issuer: String,
}

impl TotpEnrollmentService {
    /// Creates an enrollment service using a deployment-configured issuer label.
    ///
    /// The issuer is validated by the cryptographic enrollment primitive before
    /// any seed is generated or persisted.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        key_provider: Arc<dyn TotpEnrollmentKeyProvider>,
        issuer: String,
    ) -> Self {
        Self {
            store,
            key_provider,
            issuer,
        }
    }

    /// Generates and stores one pending encrypted TOTP factor.
    ///
    /// The returned URI contains the seed and must be transmitted exactly once
    /// on the authenticated HTTPS response. It must never be logged, persisted
    /// in application state, or returned by any later endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TotpEnrollmentError`] for KMS/HSM, cryptographic or store
    /// failures. It returns no provisioning material on failure.
    pub async fn begin(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        correlation_id: &str,
    ) -> Result<PendingTotpEnrollment, TotpEnrollmentError> {
        let Some(address) = self
            .store
            .user_address_for_account(tenant_id, account_id)
            .await?
        else {
            return Err(TotpEnrollmentError::Store(
                StoreError::TargetNotFoundOrUnchanged,
            ));
        };
        let active_key = self.key_provider.active_key().await?;
        let factor_id = Uuid::now_v7();
        let binding = TotpBinding {
            tenant_id,
            account_id,
            factor_id,
        };
        let enrollment = begin_totp_enrollment(
            &active_key.key,
            active_key.reference,
            &binding,
            &address,
            &self.issuer,
        )?;
        self.store
            .create_pending_totp_factor(
                tenant_id,
                account_id,
                factor_id,
                &enrollment.encrypted_seed,
                correlation_id,
            )
            .await?;
        Ok(PendingTotpEnrollment {
            factor_id,
            provisioning_uri: enrollment.provisioning.uri,
        })
    }

    /// Verifies a pending factor and atomically activates it.
    ///
    /// The caller obtains `factor_id` solely from a consumed opaque enrollment
    /// transaction. Invalid, stale or replayed codes return
    /// [`TotpEnrollmentOutcome::Denied`] for generic public handling.
    ///
    /// # Errors
    ///
    /// Returns [`TotpEnrollmentError`] only for infrastructure, persistent state
    /// or encrypted-factor failures.
    pub async fn confirm(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        factor_id: Uuid,
        code: &str,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<TotpEnrollmentOutcome, TotpEnrollmentError> {
        let Some(factor) = self
            .store
            .pending_totp_factor(tenant_id, account_id, factor_id)
            .await?
        else {
            return Ok(TotpEnrollmentOutcome::Denied);
        };
        let key = self
            .key_provider
            .resolve(&factor.encrypted_seed.key_reference)
            .await?;
        let binding = TotpBinding {
            tenant_id,
            account_id,
            factor_id: factor.factor_id,
        };
        let accepted = match verify_totp(
            &key,
            &factor.encrypted_seed,
            &binding,
            code,
            now,
            factor.last_accepted_step,
        ) {
            Ok(step) => step,
            Err(TotpError::VerificationFailed | TotpError::InvalidCodeFormat) => {
                return Ok(TotpEnrollmentOutcome::Denied)
            }
            Err(error) => return Err(TotpEnrollmentError::Totp(error)),
        };
        match self
            .store
            .activate_totp_factor(
                tenant_id,
                account_id,
                factor.factor_id,
                accepted.get(),
                correlation_id,
            )
            .await
        {
            Ok(()) => {}
            Err(StoreError::TargetNotFoundOrUnchanged) => return Ok(TotpEnrollmentOutcome::Denied),
            Err(error) => return Err(TotpEnrollmentError::Store(error)),
        }
        let Some(context) = self
            .store
            .session_authorization_context(tenant_id, account_id)
            .await?
        else {
            return Ok(TotpEnrollmentOutcome::Denied);
        };
        Ok(TotpEnrollmentOutcome::Authenticated(context))
    }
}

/// Sensitive one-display material for the enrollment-confirmation transition.
#[derive(Clone)]
pub struct PendingTotpEnrollment {
    /// Pending factor bound server-side into the next opaque transaction.
    pub factor_id: Uuid,
    /// Sensitive `otpauth://` provisioning URI; never log or persist this value.
    pub provisioning_uri: secrecy::SecretString,
}

/// Internal result after TOTP enrollment confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TotpEnrollmentOutcome {
    /// Generic denial for an invalid, expired or replayed enrollment proof.
    Denied,
    /// Fresh tenant-local context after the factor was atomically activated.
    Authenticated(AuthorizationContext),
}

/// Enrollment service failure distinct from generic public proof denial.
#[derive(Debug, Error)]
pub enum TotpEnrollmentError {
    /// Account/factor persistence or current authorization lookup failed.
    #[error("TOTP enrollment storage failed: {0}")]
    Store(#[from] StoreError),
    /// External KMS/HSM did not provide encryption material.
    #[error("TOTP enrollment key resolution failed: {0}")]
    KeyResolution(#[from] TotpKeyResolutionError),
    /// Enrollment encryption or factor verification failed unexpectedly.
    #[error("TOTP enrollment cryptographic processing failed: {0}")]
    Totp(#[from] TotpError),
}
