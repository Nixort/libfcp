// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Tenant-local account, role and authorization policy types.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AccountId, TenantId};

/// An account lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    /// Account is usable after required authentication policy is met.
    Active,
    /// Account may only complete mandatory bootstrap MFA enrollment.
    MfaEnrollmentRequired,
    /// Account is temporarily disabled and all sessions must be revoked.
    Suspended,
    /// Account is permanently disabled; audit history remains retained.
    Deactivated,
}

impl AccountState {
    /// Returns whether this state permits a normal authenticated session.
    #[must_use]
    pub const fn permits_session(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A tenant-local authority role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Owns tenant-level trust and administrator policy.
    Owner,
    /// Manages ordinary members and tenant operation.
    Admin,
    /// Publishes operational FCP configuration without identity administration.
    Operator,
    /// Reads audit records without mutation permissions.
    Auditor,
    /// A normal tenant member.
    Member,
}

/// A typed operation subject to authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Changes tenant domains or trust settings.
    ManageTenant,
    /// Grants or removes tenant-local roles.
    ManageRoles,
    /// Invites and manages ordinary accounts.
    ManageAccounts,
    /// Publishes/revokes FCP endpoint bindings.
    PublishConfiguration,
    /// Modifies trusted federation peers.
    ManageFederation,
    /// Reads redacted audit records.
    ReadAudit,
    /// Changes the caller's own security factors.
    ManageOwnSecurity,
    /// Uses permitted application functions.
    UseApplication,
}

impl Role {
    /// Determines whether this role grants a permission inside its own tenant.
    #[must_use]
    pub const fn grants(self, permission: Permission) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => matches!(
                permission,
                Permission::ManageAccounts
                    | Permission::PublishConfiguration
                    | Permission::ReadAudit
                    | Permission::ManageOwnSecurity
                    | Permission::UseApplication
            ),
            Self::Operator => matches!(
                permission,
                Permission::PublishConfiguration
                    | Permission::ReadAudit
                    | Permission::ManageOwnSecurity
                    | Permission::UseApplication
            ),
            Self::Auditor => matches!(
                permission,
                Permission::ReadAudit | Permission::ManageOwnSecurity | Permission::UseApplication
            ),
            Self::Member => matches!(
                permission,
                Permission::ManageOwnSecurity | Permission::UseApplication
            ),
        }
    }
}

/// A federation peer's locally governed trust state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationTrustState {
    /// A fingerprint exists but owner approval is incomplete.
    Pending,
    /// Signed federation requests may be considered under policy.
    Active,
    /// New federation requests are denied while evidence is retained.
    Suspended,
    /// The peer is permanently denied under current policy.
    Revoked,
}

impl FederationTrustState {
    /// Returns whether a peer may submit new federation requests.
    #[must_use]
    pub const fn accepts_requests(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Authenticated actor attributes needed for a single policy decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    tenant_id: TenantId,
    account_id: AccountId,
    state: AccountState,
    roles: Vec<Role>,
    step_up_verified: bool,
}

impl AuthorizationContext {
    /// Constructs request-local authorization attributes from a verified session.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        account_id: AccountId,
        state: AccountState,
        roles: Vec<Role>,
        step_up_verified: bool,
    ) -> Self {
        Self {
            tenant_id,
            account_id,
            state,
            roles,
            step_up_verified,
        }
    }

    /// Returns the tenant to which all authorization applies.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the local account that authenticated the request.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Returns the account's current tenant-local role set.
    #[must_use]
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    /// Returns the account's current lifecycle state.
    #[must_use]
    pub const fn account_state(&self) -> AccountState {
        self.state
    }

    /// Requires a normal active account and the named tenant-local permission.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError::AccountUnavailable`] for a non-active
    /// account or [`AuthorizationError::PermissionDenied`] when no current role
    /// grants `permission` within this tenant.
    pub fn require(&self, permission: Permission) -> Result<(), AuthorizationError> {
        if !self.state.permits_session() {
            return Err(AuthorizationError::AccountUnavailable);
        }
        if self
            .roles
            .iter()
            .copied()
            .any(|role| role.grants(permission))
        {
            Ok(())
        } else {
            Err(AuthorizationError::PermissionDenied)
        }
    }

    /// Requires a successful step-up authentication for the bound operation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError::StepUpRequired`] when the service did not
    /// bind a current step-up result to this request.
    pub fn require_step_up(&self) -> Result<(), AuthorizationError> {
        if self.step_up_verified {
            Ok(())
        } else {
            Err(AuthorizationError::StepUpRequired)
        }
    }
}

/// Tenant-local authorization failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthorizationError {
    /// Account is not in a state that permits ordinary session activity.
    #[error("account is not available for this action")]
    AccountUnavailable,
    /// Authenticated actor does not hold tenant-local permission.
    #[error("tenant-local permission denied")]
    PermissionDenied,
    /// The operation requires a recent MFA step-up result.
    #[error("step-up authentication is required")]
    StepUpRequired,
}
