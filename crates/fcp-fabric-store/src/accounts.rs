// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Tenant, account, password and current-authorization persistence operations.

use super::{
    insert_audit, json, parse_account_state, parse_role, role_text, sqlx, validate_correlation_id,
    AccountId, AccountState, AuditAction, AuditEventId, AuditWrite, AuthorizationContext,
    BootstrapResult, BootstrapTenant, ChangeRole, InviteAccount, LoginAccount, OffsetDateTime,
    PasswordVerifierString, PolicyVersion, PostgresAuthorityStore, Role, StoreError, TenantId,
    UserAddress, Uuid,
};

impl PostgresAuthorityStore {
    /// Creates the first tenant owner in a MFA-enrollment-required state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when domain command validation, uniqueness or any
    /// transaction/audit write fails; no partial tenant is committed.
    pub async fn bootstrap_tenant(
        &self,
        command: &BootstrapTenant,
    ) -> Result<BootstrapResult, StoreError> {
        command.validate().map_err(StoreError::Administration)?;
        let tenant_id = TenantId::new();
        let owner_id = AccountId::new();
        let policy_version = PolicyVersion::new(1);
        let audit_id = AuditEventId::new();
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO tenants (id, canonical_domain, policy_version, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $4)",
        )
        .bind(tenant_id.as_uuid())
        .bind(command.domain.as_str())
        .bind(i64::try_from(policy_version.get()).map_err(|_| StoreError::PolicyVersionOverflow)?)
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, normalized_localpart, state, created_at, updated_at) \
             VALUES ($1, $2, $3, 'mfa_enrollment_required', $4, $4)",
        )
        .bind(owner_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(command.owner_localpart.as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO account_roles (tenant_id, account_id, role, granted_by_account_id, granted_at) \
             VALUES ($1, $2, 'owner', NULL, $3)",
        )
        .bind(tenant_id.as_uuid())
        .bind(owner_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id,
                actor_id: Some(owner_id),
                action: AuditAction::TenantBootstrapped,
                correlation_id: &command.correlation_id,
                metadata: json!({"domain": command.domain.as_str()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;

        Ok(BootstrapResult {
            tenant_id,
            owner_id,
            policy_version,
            owner_state: AccountState::MfaEnrollmentRequired,
        })
    }

    /// Creates an invite-only account inside the actor's tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when tenant-role validation, account uniqueness
    /// or the combined account/audit transaction fails.
    pub async fn invite_account(&self, command: &InviteAccount) -> Result<AccountId, StoreError> {
        command.validate().map_err(StoreError::Administration)?;
        let account_id = AccountId::new();
        let audit_id = AuditEventId::new();
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO accounts (id, tenant_id, normalized_localpart, state, created_at, updated_at) \
             VALUES ($1, $2, $3, 'mfa_enrollment_required', $4, $4)",
        )
        .bind(account_id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .bind(command.localpart.as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO account_roles (tenant_id, account_id, role, granted_by_account_id, granted_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(command.tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(role_text(command.initial_role))
        .bind(command.actor.account_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id: command.tenant_id,
                actor_id: Some(command.actor.account_id),
                action: AuditAction::AccountCreated,
                correlation_id: &command.correlation_id,
                metadata: json!({"account_id": account_id.as_uuid(), "initial_role": role_text(command.initial_role)}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(account_id)
    }

    /// Applies a validated non-owner role grant or revocation in the actor's tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when validation fails, the target is outside the
    /// tenant/no-op, or the role and audit transaction cannot commit.
    pub async fn change_role(&self, command: &ChangeRole) -> Result<(), StoreError> {
        command.validate().map_err(StoreError::Administration)?;
        let audit_id = AuditEventId::new();
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let affected = if command.grant {
            sqlx::query(
                "INSERT INTO account_roles (tenant_id, account_id, role, granted_by_account_id, granted_at) \
                 SELECT $1, $2, $3, $4, $5 \
                 WHERE EXISTS (SELECT 1 FROM accounts WHERE tenant_id = $1 AND id = $2) \
                 ON CONFLICT (tenant_id, account_id, role) DO NOTHING",
            )
            .bind(command.tenant_id.as_uuid())
            .bind(command.target_account_id.as_uuid())
            .bind(role_text(command.role))
            .bind(command.actor.account_id.as_uuid())
            .bind(now)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "DELETE FROM account_roles \
                 WHERE tenant_id = $1 AND account_id = $2 AND role = $3",
            )
            .bind(command.tenant_id.as_uuid())
            .bind(command.target_account_id.as_uuid())
            .bind(role_text(command.role))
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        };
        if affected != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }

        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id: command.tenant_id,
                actor_id: Some(command.actor.account_id),
                action: AuditAction::RoleChanged,
                correlation_id: &command.correlation_id,
                metadata: json!({
                    "target_account_id": command.target_account_id.as_uuid(),
                    "role": role_text(command.role),
                    "grant": command.grant,
                }),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Stores a validated Argon2id PHC verifier for an account in its own tenant.
    ///
    /// The caller must have already authenticated the password-set or recovery
    /// workflow. This low-level store method does not accept raw passwords.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the account is outside `tenant_id` or the
    /// credential/audit transaction cannot commit.
    pub async fn store_password_verifier(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        verifier: &PasswordVerifierString,
        pepper_key_version: Option<&str>,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        validate_correlation_id(correlation_id)?;
        let audit_id = AuditEventId::new();
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let affected = sqlx::query(
            "INSERT INTO password_credentials (account_id, tenant_id, phc_verifier, pepper_key_version, changed_at) \
             SELECT $1, $2, $3, $4, $5 \
             WHERE EXISTS (SELECT 1 FROM accounts WHERE id = $1 AND tenant_id = $2) \
             ON CONFLICT (account_id) DO UPDATE SET \
               phc_verifier = EXCLUDED.phc_verifier, \
               pepper_key_version = EXCLUDED.pepper_key_version, \
               changed_at = EXCLUDED.changed_at",
        )
        .bind(account_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(verifier.as_str())
        .bind(pepper_key_version)
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if affected != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::PasswordChanged,
                correlation_id,
                metadata: json!({"pepper_key_version": pepper_key_version}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Finds one local login account and its current verifier state by canonical address.
    ///
    /// This operation intentionally returns `None` for unknown accounts; transport
    /// handlers must map that result to the same generic public login response as
    /// an incorrect password.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the lookup cannot complete.
    pub async fn login_account(
        &self,
        address: &UserAddress,
    ) -> Result<Option<LoginAccount>, StoreError> {
        let row = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>)>(
            "SELECT accounts.id, tenants.id, accounts.state, password_credentials.phc_verifier \
             FROM tenants \
             JOIN accounts ON accounts.tenant_id = tenants.id \
             LEFT JOIN password_credentials ON password_credentials.account_id = accounts.id \
             WHERE tenants.canonical_domain = $1 \
               AND accounts.normalized_localpart = $2",
        )
        .bind(address.domain().as_str())
        .bind(address.localpart().as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(account_id, tenant_id, state, verifier)| {
            Ok(LoginAccount {
                account_id: AccountId::from_uuid(account_id),
                tenant_id: TenantId::from_uuid(tenant_id),
                state: parse_account_state(&state)?,
                verifier: verifier
                    .map(PasswordVerifierString::from_persisted)
                    .transpose()
                    .map_err(StoreError::Credential)?,
            })
        })
        .transpose()
    }

    /// Reconstructs the canonical local address for an account in its tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidStoredAddress`] if normalized persistent
    /// address data cannot form one canonical Fabric address.
    pub async fn user_address_for_account(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
    ) -> Result<Option<UserAddress>, StoreError> {
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT accounts.normalized_localpart, tenants.canonical_domain \
             FROM accounts JOIN tenants ON tenants.id = accounts.tenant_id \
             WHERE accounts.tenant_id = $1 AND accounts.id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(localpart, domain)| {
            UserAddress::parse(&format!("{localpart}@{domain}"))
                .map_err(|_| StoreError::InvalidStoredAddress)
        })
        .transpose()
    }

    /// Loads current tenant-local roles for one account after session verification.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::CorruptRole`] if persistent role data is outside the closed
    /// tenant-role set.
    pub async fn roles_for_account(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
    ) -> Result<Vec<Role>, StoreError> {
        let roles = sqlx::query_scalar::<_, String>(
            "SELECT role FROM account_roles WHERE tenant_id = $1 AND account_id = $2 ORDER BY role",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;
        roles.into_iter().map(|role| parse_role(&role)).collect()
    }

    /// Reconstructs current tenant-local authorization for session issuance.
    ///
    /// The caller must already hold a valid, consumed authentication transaction.
    /// This query rechecks account state and reads roles in the same tenant; it
    /// never allows a caller to apply roles from another tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] for a persistence failure and
    /// [`StoreError::CorruptRole`] when a persisted role is outside the closed
    /// Fabric role set.
    pub async fn session_authorization_context(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
    ) -> Result<Option<AuthorizationContext>, StoreError> {
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM accounts WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        let Some(state) = state else {
            return Ok(None);
        };
        let state = parse_account_state(&state)?;
        if !state.permits_session() {
            return Ok(None);
        }
        let roles = self.roles_for_account(tenant_id, account_id).await?;
        Ok(Some(AuthorizationContext::new(
            tenant_id, account_id, state, roles, false,
        )))
    }
}
