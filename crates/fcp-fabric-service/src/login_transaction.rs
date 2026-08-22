// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Durable opaque transitions from local password verification to MFA or session issuance.

use fcp_fabric_auth::{derive_opaque_token_digest, issue_opaque_token, TokenDigestKey};
use fcp_fabric_domain::{AccountId, AuthorizationContext, TenantId};
use fcp_fabric_store::{
    CreateLoginTransaction, LoginTransactionRecord, LoginTransactionStage, PostgresAuthorityStore,
    StoreError,
};
use secrecy::SecretString;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::PasswordLoginOutcome;

/// Immutable timing policy for one-use Fabric login transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoginTransactionPolicy {
    lifetime: Duration,
}

impl LoginTransactionPolicy {
    /// Creates a bounded login-transaction lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`LoginTransactionServiceError::InvalidPolicy`] for non-positive
    /// lifetimes or a value above the five-minute maximum.
    pub fn new(lifetime: Duration) -> Result<Self, LoginTransactionServiceError> {
        if lifetime <= Duration::ZERO || lifetime > Duration::minutes(5) {
            return Err(LoginTransactionServiceError::InvalidPolicy);
        }
        Ok(Self { lifetime })
    }

    /// Returns the standard five-minute transaction policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            lifetime: Duration::minutes(5),
        }
    }
}

/// Starts durable local login transactions from password verification outcomes.
#[derive(Clone)]
pub struct LoginTransactionService {
    store: PostgresAuthorityStore,
    digest_key: TokenDigestKey,
    policy: LoginTransactionPolicy,
}

impl LoginTransactionService {
    /// Creates a Fabric login transaction service with an operator-managed digest key.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        digest_key: TokenDigestKey,
        policy: LoginTransactionPolicy,
    ) -> Self {
        Self {
            store,
            digest_key,
            policy,
        }
    }

    /// Persists an opaque next-step credential after local password verification.
    ///
    /// `binding_digest` must be derived by the HTTPS transport from a separate,
    /// Secure/HttpOnly login-flow cookie or native secure-device binding. It must
    /// not be a raw IP address, User-Agent value, or a client-supplied digest.
    ///
    /// # Errors
    ///
    /// Returns [`LoginTransactionServiceError::Store`] for durable transaction
    /// failures. Invalid username/password outcomes return
    /// [`LoginTransactionStart::Denied`] without writing a transaction.
    pub async fn begin(
        &self,
        password_outcome: PasswordLoginOutcome,
        binding_digest: &[u8; 32],
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<LoginTransactionStart, LoginTransactionServiceError> {
        let Some((tenant_id, account_id, stage, context)) = stage_for(password_outcome) else {
            return Ok(LoginTransactionStart::Denied);
        };
        let issued = issue_opaque_token(&self.digest_key);
        let record = self
            .store
            .create_login_transaction(CreateLoginTransaction {
                tenant_id,
                account_id,
                token_digest: &issued.digest,
                stage,
                binding_digest,
                factor_id: None,
                expires_at: now + self.policy.lifetime,
                correlation_id,
            })
            .await?;
        Ok(LoginTransactionStart::Pending(IssuedLoginTransaction {
            token: issued.raw,
            record,
            context,
        }))
    }

    /// Issues a confirmation transaction bound to one newly pending TOTP factor.
    ///
    /// The factor identifier is persisted only in the server transaction record.
    /// The browser receives the resulting opaque credential but never an account,
    /// tenant, role or factor selector.
    ///
    /// # Errors
    ///
    /// Returns [`LoginTransactionServiceError`] if the transaction cannot be
    /// persisted in the account's tenant scope.
    pub async fn begin_totp_enrollment_confirmation(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        factor_id: Uuid,
        binding_digest: &[u8; 32],
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<IssuedLoginTransaction, LoginTransactionServiceError> {
        let issued = issue_opaque_token(&self.digest_key);
        let record = self
            .store
            .create_login_transaction(CreateLoginTransaction {
                tenant_id,
                account_id,
                token_digest: &issued.digest,
                stage: LoginTransactionStage::MfaEnrollment,
                binding_digest,
                factor_id: Some(factor_id),
                expires_at: now + self.policy.lifetime,
                correlation_id,
            })
            .await?;
        Ok(IssuedLoginTransaction {
            token: issued.raw,
            record,
            context: None,
        })
    }

    /// Atomically consumes a one-use transaction for its only permitted next step.
    ///
    /// # Errors
    ///
    /// Returns [`LoginTransactionServiceError::Store`] for persistence failures.
    /// Invalid, expired, replayed, wrong-stage or wrong-binding credentials are
    /// represented by the store's generic transaction error for HTTP mapping.
    pub async fn consume(
        &self,
        token: &SecretString,
        expected_stage: LoginTransactionStage,
        binding_digest: &[u8; 32],
        correlation_id: &str,
    ) -> Result<LoginTransactionRecord, LoginTransactionServiceError> {
        let token_digest = derive_opaque_token_digest(&self.digest_key, token);
        self.store
            .consume_login_transaction(
                &token_digest,
                expected_stage,
                binding_digest,
                correlation_id,
            )
            .await
            .map_err(LoginTransactionServiceError::Store)
    }
}

fn stage_for(
    outcome: PasswordLoginOutcome,
) -> Option<(
    TenantId,
    AccountId,
    LoginTransactionStage,
    Option<AuthorizationContext>,
)> {
    match outcome {
        PasswordLoginOutcome::Denied => None,
        PasswordLoginOutcome::MfaEnrollmentRequired {
            tenant_id,
            account_id,
        } => Some((
            tenant_id,
            account_id,
            LoginTransactionStage::MfaEnrollment,
            None,
        )),
        PasswordLoginOutcome::TotpChallenge {
            tenant_id,
            account_id,
        } => Some((
            tenant_id,
            account_id,
            LoginTransactionStage::MfaChallenge,
            None,
        )),
        PasswordLoginOutcome::Authenticated(context) => Some((
            context.tenant_id(),
            context.account_id(),
            LoginTransactionStage::SessionIssuance,
            Some(context),
        )),
    }
}

/// Result of a password-stage transition into the durable Fabric flow.
#[derive(Clone)]
pub enum LoginTransactionStart {
    /// Generic public denial; no account or transaction information is leaked.
    Denied,
    /// A one-use raw credential that selects one server-side next step.
    Pending(IssuedLoginTransaction),
}

/// One-time raw transaction credential and non-secret server-side record.
#[derive(Clone)]
pub struct IssuedLoginTransaction {
    /// Raw opaque credential; transport must deliver it only in a secure login-flow cookie or native secure storage.
    pub token: SecretString,
    /// Server-side tenant/account/stage record; never serialize it to the client.
    pub record: LoginTransactionRecord,
    /// Present only for a password-only account ready for session issuance.
    pub context: Option<AuthorizationContext>,
}

/// Login transaction service failure distinct from generic credential denial.
#[derive(Debug, Error)]
pub enum LoginTransactionServiceError {
    /// Requested transaction lifetime violates the Fabric security bounds.
    #[error("login transaction policy is invalid")]
    InvalidPolicy,
    /// Durable login transaction persistence failed.
    #[error("login transaction persistence failed: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use fcp_fabric_domain::{AccountId, AccountState, AuthorizationContext, Role, TenantId};

    use super::{stage_for, LoginTransactionStage};
    use crate::PasswordLoginOutcome;

    #[test]
    fn password_outcomes_map_to_only_one_server_side_next_step() {
        let tenant_id = TenantId::new();
        let account_id = AccountId::new();
        let mfa = stage_for(PasswordLoginOutcome::TotpChallenge {
            tenant_id,
            account_id,
        })
        .expect("mfa stage");
        assert_eq!(mfa.2, LoginTransactionStage::MfaChallenge);
        assert!(mfa.3.is_none());

        let context = AuthorizationContext::new(
            tenant_id,
            account_id,
            AccountState::Active,
            vec![Role::Member],
            false,
        );
        let session =
            stage_for(PasswordLoginOutcome::Authenticated(context)).expect("session stage");
        assert_eq!(session.2, LoginTransactionStage::SessionIssuance);
        assert!(session.3.is_some());
        assert!(stage_for(PasswordLoginOutcome::Denied).is_none());
    }
}
