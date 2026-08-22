// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! One-use, action-bound step-up MFA grant persistence operations.

use super::{
    insert_audit, json, sqlx, validate_correlation_id, AuditAction, AuditEventId, AuditWrite,
    ConsumeStepUpGrant, CreateStepUpGrant, OffsetDateTime, PostgresAuthorityStore,
    StepUpGrantRecord, StoreError, Uuid,
};

impl PostgresAuthorityStore {
    /// Creates one action-bound, short-lived MFA step-up grant.
    ///
    /// The caller supplies opaque token and target digests only. The grant is
    /// accepted only while the same tenant-local session family remains active.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for invalid expiry/correlation, inactive account or
    /// family scope, or failure of the combined durable grant/audit write.
    pub async fn create_step_up_grant(
        &self,
        request: CreateStepUpGrant<'_>,
    ) -> Result<StepUpGrantRecord, StoreError> {
        let CreateStepUpGrant {
            tenant_id,
            account_id,
            family_id,
            action,
            target_digest,
            token_digest,
            expires_at,
            correlation_id,
        } = request;
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(StoreError::InvalidStepUpGrantExpiry);
        }
        let grant_id = Uuid::now_v7();
        let mut transaction = self.pool.begin().await?;
        let created = sqlx::query(
            "INSERT INTO step_up_grants ( \
               id, tenant_id, account_id, family_id, action, target_digest, token_digest, issued_at, expires_at \
             ) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 \
             WHERE EXISTS ( \
                 SELECT 1 FROM session_families AS family \
                 JOIN accounts AS account ON account.id = family.account_id AND account.tenant_id = family.tenant_id \
                 WHERE family.id = $4 AND family.tenant_id = $2 AND family.account_id = $3 \
                   AND family.revoked_at IS NULL AND account.state = 'active'
             )",
        )
        .bind(grant_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(family_id)
        .bind(action.database_value())
        .bind(target_digest.as_slice())
        .bind(token_digest.as_bytes().as_slice())
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if created != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::StepUpGranted,
                correlation_id,
                metadata: json!({"grant_id": grant_id, "action": action.database_value()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(StepUpGrantRecord {
            grant_id,
            expires_at,
        })
    }

    /// Atomically consumes one action-bound step-up grant.
    ///
    /// All unavailable states intentionally return `false`: wrong token, target,
    /// action, actor/family, expiry, replay, or a revoked family are not
    /// distinguishable at the transport boundary.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] only for persistence or audit failure.
    pub async fn consume_step_up_grant(
        &self,
        request: ConsumeStepUpGrant<'_>,
    ) -> Result<bool, StoreError> {
        let ConsumeStepUpGrant {
            tenant_id,
            account_id,
            family_id,
            action,
            target_digest,
            token_digest,
            correlation_id,
        } = request;
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let consumed = sqlx::query_scalar::<_, Uuid>(
            "UPDATE step_up_grants AS grant SET consumed_at = $7 \
             WHERE grant.token_digest = $1 AND grant.tenant_id = $2 AND grant.account_id = $3 \
               AND grant.family_id = $4 AND grant.action = $5 AND grant.target_digest = $6 \
               AND grant.consumed_at IS NULL AND grant.expires_at > $7 \
               AND EXISTS (SELECT 1 FROM session_families AS family WHERE family.id = $4 AND family.revoked_at IS NULL) \
             RETURNING grant.id",
        )
        .bind(token_digest.as_bytes().as_slice())
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(family_id)
        .bind(action.database_value())
        .bind(target_digest.as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(grant_id) = consumed else {
            transaction.commit().await?;
            return Ok(false);
        };
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::StepUpConsumed,
                correlation_id,
                metadata: json!({"grant_id": grant_id, "action": action.database_value()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }
}
