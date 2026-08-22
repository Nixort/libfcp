// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Opaque access/refresh session persistence and family-revocation operations.

use super::{
    insert_audit, json, parse_account_state, revoke_session_family,
    rotate_locked_refresh_credential, sqlx, validate_correlation_id, AccessSessionAuthorization,
    AccountId, AuditAction, AuditEventId, AuditWrite, AuthorizationContext, CreateRefreshSession,
    OffsetDateTime, OpaqueTokenDigest, PostgresAuthorityStore, RefreshRotation,
    RefreshRotationWrite, RefreshSessionRecord, StoreError, TenantId, Uuid,
};

impl PostgresAuthorityStore {
    /// Authenticates one short-lived opaque access session against current state.
    ///
    /// The lookup rejects expired/revoked access records, a revoked refresh family,
    /// and unavailable account state before constructing a request-local context.
    /// Roles are reloaded from the session owner's tenant on every successful
    /// authentication; no browser-supplied role or tenant data is trusted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for persistence/corrupt-role state. All ordinary
    /// unavailable credential outcomes return `Ok(None)`.
    pub async fn access_session_authorization_context(
        &self,
        token_digest: &OpaqueTokenDigest,
    ) -> Result<Option<AccessSessionAuthorization>, StoreError> {
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query_as::<_, (Uuid, Uuid, Uuid, String)>(
            "SELECT access.tenant_id, access.account_id, access.family_id, account.state \
             FROM access_sessions AS access \
             JOIN session_families AS family ON family.id = access.family_id \
             JOIN accounts AS account ON account.id = access.account_id AND account.tenant_id = access.tenant_id \
             WHERE access.token_digest = $1 \
               AND access.revoked_at IS NULL AND access.expires_at > $2 \
               AND family.revoked_at IS NULL",
        )
        .bind(token_digest.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some((tenant_id, account_id, family_id, account_state)) = row else {
            return Ok(None);
        };
        let tenant_id = TenantId::from_uuid(tenant_id);
        let account_id = AccountId::from_uuid(account_id);
        let account_state = parse_account_state(&account_state)?;
        if !account_state.permits_session() {
            return Ok(None);
        }
        let roles = self.roles_for_account(tenant_id, account_id).await?;
        Ok(Some(AccessSessionAuthorization {
            context: AuthorizationContext::new(tenant_id, account_id, account_state, roles, false),
            family_id,
        }))
    }

    /// Creates a refresh-token family and stores only its keyed opaque-token digest.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if expiry is invalid, account scope is absent, or
    /// the family/credential/audit transaction cannot commit.
    pub async fn create_refresh_session(
        &self,
        request: CreateRefreshSession<'_>,
    ) -> Result<RefreshSessionRecord, StoreError> {
        let CreateRefreshSession {
            tenant_id,
            account_id,
            refresh_digest,
            access_digest,
            refresh_expires_at,
            access_expires_at,
            correlation_id,
        } = request;
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        if refresh_expires_at <= now || access_expires_at <= now {
            return Err(StoreError::InvalidSessionExpiry);
        }
        let family_id = Uuid::now_v7();
        let credential_id = Uuid::now_v7();
        let access_session_id = Uuid::now_v7();
        let audit_id = AuditEventId::new();
        let mut transaction = self.pool.begin().await?;
        let family = sqlx::query(
            "INSERT INTO session_families (id, tenant_id, account_id, created_at) \
             SELECT $1, $2, $3, $4 \
             WHERE EXISTS ( \
                 SELECT 1 FROM accounts WHERE id = $3 AND tenant_id = $2 AND state = 'active' \
             )",
        )
        .bind(family_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if family != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        sqlx::query(
            "INSERT INTO refresh_credentials ( \
               id, tenant_id, account_id, family_id, token_digest, issued_at, expires_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(credential_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(family_id)
        .bind(refresh_digest.as_bytes().as_slice())
        .bind(now)
        .bind(refresh_expires_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO access_sessions ( \
               id, tenant_id, account_id, family_id, token_digest, issued_at, expires_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(access_session_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(family_id)
        .bind(access_digest.as_bytes().as_slice())
        .bind(now)
        .bind(access_expires_at)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::SessionIssued,
                correlation_id,
                metadata: json!({
                    "family_id": family_id,
                    "credential_id": credential_id,
                    "access_session_id": access_session_id,
                }),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(RefreshSessionRecord {
            family_id,
            credential_id,
            expires_at: refresh_expires_at,
            access_session_id,
            access_expires_at,
        })
    }

    /// Rotates one valid refresh credential and revokes its family on reuse.
    ///
    /// The presented and successor values are keyed digests only. This operation
    /// row-locks the matched credential, consumes it, stores a successor in the
    /// same family and audits the outcome in one transaction. A later concurrent
    /// presentation of that consumed credential revokes the entire family.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for a database or audit failure. Invalid, expired,
    /// revoked, inactive-account and unknown credentials return a typed generic
    /// [`RefreshRotation::Denied`] result instead.
    pub async fn rotate_refresh_credential(
        &self,
        presented_digest: &OpaqueTokenDigest,
        successor_digest: &OpaqueTokenDigest,
        successor_access_digest: &OpaqueTokenDigest,
        successor_expires_at: OffsetDateTime,
        successor_access_expires_at: OffsetDateTime,
        correlation_id: &str,
    ) -> Result<RefreshRotation, StoreError> {
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        if successor_expires_at <= now || successor_access_expires_at <= now {
            return Err(StoreError::InvalidSessionExpiry);
        }
        let mut transaction = self.pool.begin().await?;
        let credential = sqlx::query_as::<_, (Uuid, Uuid, Uuid, Uuid, OffsetDateTime, Option<OffsetDateTime>, Option<OffsetDateTime>, String)>(
            "SELECT credential.id, credential.tenant_id, credential.account_id, credential.family_id, \
                    credential.expires_at, credential.consumed_at, family.revoked_at, account.state \
             FROM refresh_credentials AS credential \
             JOIN session_families AS family ON family.id = credential.family_id \
             JOIN accounts AS account ON account.id = credential.account_id AND account.tenant_id = credential.tenant_id \
             WHERE credential.token_digest = $1 \
             FOR UPDATE OF credential, family, account",
        )
        .bind(presented_digest.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((
            credential_id,
            tenant_id,
            account_id,
            family_id,
            credential_expires_at,
            consumed_at,
            revoked_at,
            account_state,
        )) = credential
        else {
            transaction.commit().await?;
            return Ok(RefreshRotation::Denied);
        };
        let tenant_id = TenantId::from_uuid(tenant_id);
        let account_id = AccountId::from_uuid(account_id);
        let account_state = parse_account_state(&account_state)?;
        if consumed_at.is_some() {
            if revoked_at.is_none() {
                revoke_session_family(
                    &mut transaction,
                    tenant_id,
                    account_id,
                    family_id,
                    "refresh_token_reuse",
                    correlation_id,
                    now,
                )
                .await?;
                transaction.commit().await?;
                return Ok(RefreshRotation::ReuseDetected);
            }
            transaction.commit().await?;
            return Ok(RefreshRotation::Denied);
        }
        if revoked_at.is_some() || credential_expires_at <= now || !account_state.permits_session()
        {
            transaction.commit().await?;
            return Ok(RefreshRotation::Denied);
        }
        let outcome = rotate_locked_refresh_credential(
            &mut transaction,
            RefreshRotationWrite {
                credential_id,
                tenant_id,
                account_id,
                family_id,
                successor_digest,
                successor_access_digest,
                successor_expires_at,
                successor_access_expires_at,
                correlation_id,
                now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Revokes one tenant-local session family explicitly.
    ///
    /// This is intended for authenticated administration, account-security
    /// response and later device/session management. It is idempotent: an absent,
    /// cross-tenant or already revoked family returns `false` without revealing
    /// more detail to a transport caller.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] only if the revocation and redacted audit write
    /// cannot commit atomically.
    pub async fn revoke_refresh_session_family(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        family_id: Uuid,
        correlation_id: &str,
    ) -> Result<bool, StoreError> {
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let revoked = revoke_session_family(
            &mut transaction,
            tenant_id,
            account_id,
            family_id,
            "explicit_revocation",
            correlation_id,
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(revoked)
    }
}
