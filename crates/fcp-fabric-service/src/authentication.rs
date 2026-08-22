// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Local password-login policy before session issuance or TOTP verification.

use fcp_fabric_auth::{verify_password, PasswordVerifierString};
use fcp_fabric_domain::{
    AccountId, AccountState, AuthorizationContext, Role, TenantId, UserAddress,
};
use fcp_fabric_store::{PostgresAuthorityStore, StoreError};
use secrecy::SecretString;
use thiserror::Error;

/// Password login policy with an unknown-account timing equalization verifier.
#[derive(Clone, Debug)]
pub struct PasswordLoginService {
    store: PostgresAuthorityStore,
    dummy_verifier: PasswordVerifierString,
    maximum_password_bytes: usize,
}

impl PasswordLoginService {
    /// Creates the local-password authentication service.
    ///
    /// `dummy_verifier` must be a valid Argon2id record generated under the
    /// current deployment policy and rotated with that policy; it is used only
    /// to perform representative work for an unknown/no-password account.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        dummy_verifier: PasswordVerifierString,
        maximum_password_bytes: usize,
    ) -> Self {
        Self {
            store,
            dummy_verifier,
            maximum_password_bytes,
        }
    }

    /// Performs password verification and returns an internal next-step decision.
    ///
    /// Handlers must map every [`PasswordLoginOutcome::Denied`] case to one
    /// public generic response. This method does not issue browser/API sessions:
    /// TOTP challenge issuance and session rotation require durable transaction
    /// records implemented at the HTTP service boundary.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordLoginError::Store`] only for an authority database
    /// failure. Invalid credentials and unavailable account state deliberately
    /// return [`PasswordLoginOutcome::Denied`].
    pub async fn authenticate(
        &self,
        address: &UserAddress,
        password: &SecretString,
    ) -> Result<PasswordLoginOutcome, PasswordLoginError> {
        let Some(account) = self.store.login_account(address).await? else {
            let _ = verify_password(password, &self.dummy_verifier, self.maximum_password_bytes);
            return Ok(PasswordLoginOutcome::Denied);
        };
        let verifier = account.verifier.as_ref().unwrap_or(&self.dummy_verifier);
        if verify_password(password, verifier, self.maximum_password_bytes).is_err() {
            return Ok(PasswordLoginOutcome::Denied);
        }
        if !account.state.permits_session() {
            return Ok(if account.state == AccountState::MfaEnrollmentRequired {
                PasswordLoginOutcome::MfaEnrollmentRequired {
                    tenant_id: account.tenant_id,
                    account_id: account.account_id,
                }
            } else {
                PasswordLoginOutcome::Denied
            });
        }
        let roles = self
            .store
            .roles_for_account(account.tenant_id, account.account_id)
            .await?;
        let privileged = roles
            .iter()
            .any(|role| matches!(role, Role::Owner | Role::Admin));
        let has_totp = self
            .store
            .has_active_totp_factor(account.tenant_id, account.account_id)
            .await?;
        if privileged || has_totp {
            if !has_totp {
                return Ok(PasswordLoginOutcome::Denied);
            }
            return Ok(PasswordLoginOutcome::TotpChallenge {
                tenant_id: account.tenant_id,
                account_id: account.account_id,
            });
        }
        Ok(PasswordLoginOutcome::Authenticated(
            AuthorizationContext::new(
                account.tenant_id,
                account.account_id,
                account.state,
                roles,
                false,
            ),
        ))
    }
}

/// Internal next step after password verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PasswordLoginOutcome {
    /// Generic failure; never distinguish unknown user, invalid password or denial at HTTP edge.
    Denied,
    /// Bootstrap account must enroll a first MFA factor under a restricted transaction.
    MfaEnrollmentRequired {
        /// Tenant that owns the account.
        tenant_id: TenantId,
        /// Account allowed to complete restricted enrollment.
        account_id: AccountId,
    },
    /// Existing MFA factor must verify before a normal session is issued.
    TotpChallenge {
        /// Tenant that owns the account.
        tenant_id: TenantId,
        /// Account for which a short-lived login transaction is created.
        account_id: AccountId,
    },
    /// Non-privileged account may receive a normal authenticated session.
    Authenticated(AuthorizationContext),
}

/// Password-login service failure distinct from generic credential denial.
#[derive(Debug, Error)]
pub enum PasswordLoginError {
    /// Persistent account/role/factor lookup failed.
    #[error("password login authority-state lookup failed: {0}")]
    Store(#[from] StoreError),
}
