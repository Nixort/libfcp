// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Typed administration commands and their policy validation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AccountId, AccountState, DomainName, Localpart, Permission, PolicyVersion, Role, TenantId,
};

/// Request to create the first authority tenant and owner account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapTenant {
    /// Organization domain that will own local user addresses and federation identity.
    pub domain: DomainName,
    /// First owner localpart.
    pub owner_localpart: Localpart,
    /// Bounded external correlation identifier for audit correlation.
    pub correlation_id: String,
}

impl BootstrapTenant {
    /// Validates a bootstrap command before persistence.
    ///
    /// # Errors
    ///
    /// Returns [`AdministrationError::InvalidCorrelationId`] when audit
    /// correlation metadata violates the bounded safe-text policy.
    pub fn validate(&self) -> Result<(), AdministrationError> {
        validate_correlation_id(&self.correlation_id)
    }
}

/// Durable result of a successful tenant bootstrap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootstrapResult {
    /// New tenant identity.
    pub tenant_id: TenantId,
    /// New owner account identity.
    pub owner_id: AccountId,
    /// Initial tenant policy revision.
    pub policy_version: PolicyVersion,
    /// Owner is deliberately limited until its first MFA factor is verified.
    pub owner_state: AccountState,
}

/// Request to create an invite-only tenant account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteAccount {
    /// Tenant in which the new account is created.
    pub tenant_id: TenantId,
    /// Invited tenant-local login name.
    pub localpart: Localpart,
    /// Initial least-privilege role.
    pub initial_role: Role,
    /// Authenticated actor's confirmed tenant-local authorization context.
    pub actor: AdministrationActor,
    /// Bounded external correlation identifier for audit correlation.
    pub correlation_id: String,
}

impl InviteAccount {
    /// Validates tenant boundary and role policy for account invitation.
    ///
    /// # Errors
    ///
    /// Returns [`AdministrationError`] when the actor is cross-tenant,
    /// unavailable, unauthorized, attempts a privileged initial role, or
    /// provides invalid audit correlation metadata.
    pub fn validate(&self) -> Result<(), AdministrationError> {
        self.actor.require_same_tenant(self.tenant_id)?;
        self.actor.require(Permission::ManageAccounts)?;
        if matches!(self.initial_role, Role::Owner | Role::Admin) {
            return Err(AdministrationError::PrivilegedRoleRequiresDedicatedWorkflow);
        }
        validate_correlation_id(&self.correlation_id)
    }
}

/// A request-local actor proven by an authenticated service boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrationActor {
    /// Actor's tenant boundary.
    pub tenant_id: TenantId,
    /// Actor account.
    pub account_id: AccountId,
    /// Active roles in the tenant.
    pub roles: Vec<Role>,
    /// Whether the actor has completed an action-bound step-up flow.
    pub step_up_verified: bool,
    /// Whether the account has an ordinary usable state.
    pub account_state: AccountState,
}

impl AdministrationActor {
    /// Requires an action inside the actor's own tenant.
    ///
    /// # Errors
    ///
    /// Returns [`AdministrationError::CrossTenantMutation`] when the target
    /// tenant differs from this authenticated actor's tenant.
    pub fn require_same_tenant(&self, target_tenant: TenantId) -> Result<(), AdministrationError> {
        if self.tenant_id == target_tenant {
            Ok(())
        } else {
            Err(AdministrationError::CrossTenantMutation)
        }
    }

    /// Requires a permission granted by at least one current actor role.
    ///
    /// # Errors
    ///
    /// Returns [`AdministrationError::ActorUnavailable`] for non-active actors
    /// and [`AdministrationError::PermissionDenied`] otherwise when no role
    /// grants `permission`.
    pub fn require(&self, permission: Permission) -> Result<(), AdministrationError> {
        if !self.account_state.permits_session() {
            return Err(AdministrationError::ActorUnavailable);
        }
        if self
            .roles
            .iter()
            .copied()
            .any(|role| role.grants(permission))
        {
            Ok(())
        } else {
            Err(AdministrationError::PermissionDenied)
        }
    }

    /// Requires step-up verification for an irreversible or privileged action.
    ///
    /// # Errors
    ///
    /// Returns [`AdministrationError::StepUpRequired`] if the request did not
    /// carry a current action-bound step-up result.
    pub fn require_step_up(&self) -> Result<(), AdministrationError> {
        if self.step_up_verified {
            Ok(())
        } else {
            Err(AdministrationError::StepUpRequired)
        }
    }
}

/// Request to alter a tenant-local role assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeRole {
    /// Target tenant.
    pub tenant_id: TenantId,
    /// Account whose role will change.
    pub target_account_id: AccountId,
    /// Role to grant or revoke.
    pub role: Role,
    /// Whether to grant (`true`) or revoke (`false`) the role.
    pub grant: bool,
    /// Authenticated, tenant-local administrator.
    pub actor: AdministrationActor,
    /// Bounded external correlation identifier for audit correlation.
    pub correlation_id: String,
}

impl ChangeRole {
    /// Validates the generic role-change boundary.
    ///
    /// Owner-role changes use a dedicated dual-control workflow and cannot pass
    /// through this general administrator command.
    ///
    /// # Errors
    ///
    /// Returns [`AdministrationError`] for cross-tenant/unauthorized actions,
    /// absence of step-up verification, owner-role changes, or invalid audit
    /// correlation metadata.
    pub fn validate(&self) -> Result<(), AdministrationError> {
        self.actor.require_same_tenant(self.tenant_id)?;
        self.actor.require(Permission::ManageRoles)?;
        self.actor.require_step_up()?;
        if self.role == Role::Owner {
            return Err(AdministrationError::OwnerRoleRequiresDedicatedWorkflow);
        }
        validate_correlation_id(&self.correlation_id)
    }
}

fn validate_correlation_id(value: &str) -> Result<(), AdministrationError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(AdministrationError::InvalidCorrelationId)
    } else {
        Ok(())
    }
}

/// Domain validation failure for an administration command.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdministrationError {
    /// A tenant-local actor attempted to mutate another tenant.
    #[error("cross-tenant mutation is forbidden")]
    CrossTenantMutation,
    /// Account is not available for normal authorization decisions.
    #[error("actor account is not available")]
    ActorUnavailable,
    /// Actor does not own the typed permission.
    #[error("actor lacks required tenant-local permission")]
    PermissionDenied,
    /// Action needs a recent action-bound MFA result.
    #[error("step-up authentication is required")]
    StepUpRequired,
    /// Correlation ID is empty, too long or contains a control character.
    #[error("correlation ID is invalid")]
    InvalidCorrelationId,
    /// Generic invitation flow cannot create a privileged account.
    #[error("privileged role requires a dedicated audited workflow")]
    PrivilegedRoleRequiresDedicatedWorkflow,
    /// Owner changes have stronger availability and dual-control invariants.
    #[error("owner role requires a dedicated audited workflow")]
    OwnerRoleRequiresDedicatedWorkflow,
}

#[cfg(test)]
mod tests {
    use super::{AdministrationActor, ChangeRole, InviteAccount};
    use crate::{AccountId, AccountState, Localpart, Role, TenantId};

    fn admin(tenant_id: TenantId, step_up_verified: bool) -> AdministrationActor {
        AdministrationActor {
            tenant_id,
            account_id: AccountId::new(),
            roles: vec![Role::Admin],
            step_up_verified,
            account_state: AccountState::Active,
        }
    }

    #[test]
    fn administrator_can_invite_member_but_not_privileged_role() {
        let tenant_id = TenantId::new();
        let member = InviteAccount {
            tenant_id,
            localpart: Localpart::parse("alice").expect("localpart"),
            initial_role: Role::Member,
            actor: admin(tenant_id, false),
            correlation_id: "invite-1".to_owned(),
        };
        assert!(member.validate().is_ok());
        let privileged = InviteAccount {
            initial_role: Role::Admin,
            ..member
        };
        assert!(privileged.validate().is_err());
    }

    #[test]
    fn administrator_needs_step_up_for_role_change() {
        let tenant_id = TenantId::new();
        let command = ChangeRole {
            tenant_id,
            target_account_id: AccountId::new(),
            role: Role::Operator,
            grant: true,
            actor: admin(tenant_id, false),
            correlation_id: "role-1".to_owned(),
        };
        assert!(command.validate().is_err());
    }
}
