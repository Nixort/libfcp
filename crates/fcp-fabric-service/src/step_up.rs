// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Action-bound, one-use TOTP step-up grants for privileged local administration.

use std::sync::Arc;

use fcp_fabric_auth::{derive_opaque_token_digest, issue_opaque_token, TokenDigestKey};
use fcp_fabric_domain::{AccountId, Role, TenantId};
use fcp_fabric_store::{
    ConsumeStepUpGrant, CreateStepUpGrant, PostgresAuthorityStore, StepUpAction, StoreError,
};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{TotpLoginError, TotpLoginOutcome, TotpLoginService};

/// Immutable policy for an action-bound step-up grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepUpPolicy {
    grant_lifetime: Duration,
}

impl StepUpPolicy {
    /// Creates a bounded step-up policy.
    ///
    /// # Errors
    ///
    /// Returns [`StepUpError::InvalidPolicy`] unless the lifetime is positive and
    /// no greater than five minutes.
    pub fn new(grant_lifetime: Duration) -> Result<Self, StepUpError> {
        if grant_lifetime <= Duration::ZERO || grant_lifetime > Duration::minutes(5) {
            return Err(StepUpError::InvalidPolicy);
        }
        Ok(Self { grant_lifetime })
    }

    /// Returns the standard five-minute action-bound grant policy.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            grant_lifetime: Duration::minutes(5),
        }
    }
}

/// Issues and consumes role-change step-up grants.
#[derive(Clone)]
pub struct StepUpService {
    store: PostgresAuthorityStore,
    totp_login: Arc<TotpLoginService>,
    digest_key: TokenDigestKey,
    policy: StepUpPolicy,
}

impl StepUpService {
    /// Creates a service with a dedicated opaque grant digest key.
    ///
    /// The key must be separate from login transaction, refresh, recovery-code,
    /// and access-session digest keys.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        totp_login: Arc<TotpLoginService>,
        digest_key: TokenDigestKey,
        policy: StepUpPolicy,
    ) -> Self {
        Self {
            store,
            totp_login,
            digest_key,
            policy,
        }
    }

    /// Verifies fresh TOTP proof and issues one role-change-target-bound grant.
    ///
    /// The caller must supply tenant, account and family only from a verified
    /// server-side access session. The raw grant must be delivered only in a
    /// `Secure; HttpOnly; SameSite=Strict` cookie and is never logged or stored.
    ///
    /// # Errors
    ///
    /// Invalid, absent, expired or replayed authenticator proof returns
    /// [`StepUpIssueOutcome::Denied`]. Infrastructure and durable-state failures
    /// return [`StepUpError`].
    pub async fn issue_role_change(
        &self,
        request: IssueRoleChangeStepUp<'_>,
    ) -> Result<StepUpIssueOutcome, StepUpError> {
        let IssueRoleChangeStepUp {
            tenant_id,
            account_id,
            family_id,
            target,
            code,
            correlation_id,
            now,
        } = request;
        match self
            .totp_login
            .complete(tenant_id, account_id, code, now)
            .await?
        {
            TotpLoginOutcome::Denied => Ok(StepUpIssueOutcome::Denied),
            TotpLoginOutcome::Authenticated(context) => {
                if context.tenant_id() != tenant_id || context.account_id() != account_id {
                    return Ok(StepUpIssueOutcome::Denied);
                }
                let issued = issue_opaque_token(&self.digest_key);
                let target_digest = role_change_target_digest(target);
                let expires_at = now + self.policy.grant_lifetime;
                self.store
                    .create_step_up_grant(CreateStepUpGrant {
                        tenant_id,
                        account_id,
                        family_id,
                        action: StepUpAction::ChangeAccountRole,
                        target_digest: &target_digest,
                        token_digest: &issued.digest,
                        expires_at,
                        correlation_id,
                    })
                    .await?;
                Ok(StepUpIssueOutcome::Granted(IssuedStepUpGrant {
                    token: issued.raw,
                    expires_at,
                }))
            }
        }
    }

    /// Consumes a role-change grant for exactly the authenticated actor/family/target.
    ///
    /// # Errors
    ///
    /// Returns [`StepUpError::Store`] only for durable-state failure. Every
    /// unavailable grant state returns `Ok(false)` for one public step-up denial.
    pub async fn consume_role_change(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        family_id: Uuid,
        target: RoleChangeTarget,
        raw_token: &SecretString,
        correlation_id: &str,
    ) -> Result<bool, StepUpError> {
        let token_digest = derive_opaque_token_digest(&self.digest_key, raw_token);
        let target_digest = role_change_target_digest(target);
        self.store
            .consume_step_up_grant(ConsumeStepUpGrant {
                tenant_id,
                account_id,
                family_id,
                action: StepUpAction::ChangeAccountRole,
                target_digest: &target_digest,
                token_digest: &token_digest,
                correlation_id,
            })
            .await
            .map_err(StepUpError::Store)
    }
}

/// Input for one role-change-target-bound fresh TOTP proof.
#[derive(Clone, Copy, Debug)]
pub struct IssueRoleChangeStepUp<'a> {
    /// Verified access-session tenant scope.
    pub tenant_id: TenantId,
    /// Verified access-session actor.
    pub account_id: AccountId,
    /// Verified access-session family.
    pub family_id: Uuid,
    /// Exact account/role/grant-or-revoke mutation bound by the step-up proof.
    pub target: RoleChangeTarget,
    /// Current authenticator-app TOTP proof.
    pub code: &'a str,
    /// Bounded redacted operation correlation identifier.
    pub correlation_id: &'a str,
    /// Request verification clock.
    pub now: OffsetDateTime,
}

/// Exact role-assignment mutation bound to a one-use step-up grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleChangeTarget {
    /// Account whose role is being changed.
    pub account_id: AccountId,
    /// Role being granted or revoked.
    pub role: Role,
    /// `true` to grant the role, `false` to revoke it.
    pub grant: bool,
}

/// One-time result of fresh TOTP step-up proof.
#[derive(Clone)]
pub enum StepUpIssueOutcome {
    /// Generic denial for unavailable/replayed/invalid authenticator proof.
    Denied,
    /// Sensitive one-use action-bound grant delivery.
    Granted(IssuedStepUpGrant),
}

/// Sensitive one-use step-up grant delivery.
#[derive(Clone)]
pub struct IssuedStepUpGrant {
    /// Raw opaque grant token; transmit in an `HttpOnly` cookie once.
    pub token: SecretString,
    /// Absolute grant expiry.
    pub expires_at: OffsetDateTime,
}

/// Step-up service failure distinct from generic proof/grant denial.
#[derive(Debug, Error)]
pub enum StepUpError {
    /// The configured grant lifetime violates the supported security bound.
    #[error("step-up policy is invalid")]
    InvalidPolicy,
    /// Fresh TOTP verification failed due to KMS/HSM or durable state failure.
    #[error("step-up TOTP verification failed: {0}")]
    Totp(#[from] TotpLoginError),
    /// Durable grant issuance or consumption failed.
    #[error("step-up grant storage failed: {0}")]
    Store(#[from] StoreError),
}

fn role_change_target_digest(target: RoleChangeTarget) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"fcp-fabric-step-up-target-v1\0change-account-role\0");
    hasher.update(target.account_id.as_uuid().as_bytes());
    hasher.update([u8::from(target.grant)]);
    hasher.update(match target.role {
        Role::Owner => b"owner".as_slice(),
        Role::Admin => b"admin".as_slice(),
        Role::Operator => b"operator".as_slice(),
        Role::Auditor => b"auditor".as_slice(),
        Role::Member => b"member".as_slice(),
    });
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{role_change_target_digest, RoleChangeTarget, StepUpPolicy};
    use fcp_fabric_domain::{AccountId, Role};
    use time::Duration;

    #[test]
    fn step_up_policy_and_target_binding_are_bounded_and_deterministic() {
        assert_eq!(
            StepUpPolicy::standard(),
            StepUpPolicy::new(Duration::minutes(5)).expect("valid")
        );
        assert!(StepUpPolicy::new(Duration::ZERO).is_err());
        assert!(StepUpPolicy::new(Duration::minutes(6)).is_err());
        let target = RoleChangeTarget {
            account_id: AccountId::new(),
            role: Role::Operator,
            grant: true,
        };
        assert_eq!(
            role_change_target_digest(target),
            role_change_target_digest(target)
        );
        assert_ne!(
            role_change_target_digest(target),
            role_change_target_digest(RoleChangeTarget {
                grant: false,
                ..target
            })
        );
    }
}
