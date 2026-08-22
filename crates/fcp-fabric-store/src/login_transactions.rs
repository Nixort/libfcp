// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Durable password-to-MFA/session login transaction persistence operations.

use super::{
    insert_audit, json, sqlx, validate_correlation_id, AccountId, AuditAction, AuditEventId,
    AuditWrite, CreateLoginTransaction, LoginTransactionRecord, LoginTransactionStage,
    OffsetDateTime, OpaqueTokenDigest, PostgresAuthorityStore, StoreError, TenantId, Uuid,
};

impl PostgresAuthorityStore {
    /// Creates a short-lived opaque login transaction after a valid password stage.
    ///
    /// The caller supplies only a keyed digest of the raw transaction credential;
    /// account and tenant identities remain entirely server-side.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the account scope is absent, expiration is
    /// invalid or the transaction/audit write cannot commit atomically.
    pub async fn create_login_transaction(
        &self,
        request: CreateLoginTransaction<'_>,
    ) -> Result<LoginTransactionRecord, StoreError> {
        validate_correlation_id(request.correlation_id)?;
        let now = OffsetDateTime::now_utc();
        if request.expires_at <= now {
            return Err(StoreError::InvalidLoginTransactionExpiry);
        }
        let transaction_id = Uuid::now_v7();
        let audit_id = AuditEventId::new();
        let mut transaction = self.pool.begin().await?;
        let created = sqlx::query(
            "INSERT INTO login_transactions ( \
               id, tenant_id, account_id, token_digest, stage, binding_digest, factor_id, issued_at, expires_at \
             ) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 \
             WHERE EXISTS (SELECT 1 FROM accounts WHERE id = $3 AND tenant_id = $2)",
        )
        .bind(transaction_id)
        .bind(request.tenant_id.as_uuid())
        .bind(request.account_id.as_uuid())
        .bind(request.token_digest.as_bytes().as_slice())
        .bind(request.stage.database_value())
        .bind(request.binding_digest.as_slice())
        .bind(request.factor_id)
        .bind(now)
        .bind(request.expires_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if created != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id: request.tenant_id,
                actor_id: Some(request.account_id),
                action: AuditAction::LoginTransactionIssued,
                correlation_id: request.correlation_id,
                metadata: json!({"transaction_id": transaction_id, "stage": request.stage.database_value()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(LoginTransactionRecord {
            transaction_id,
            tenant_id: request.tenant_id,
            account_id: request.account_id,
            stage: request.stage,
            expires_at: request.expires_at,
            factor_id: request.factor_id,
        })
    }

    /// Atomically consumes an opaque login transaction for exactly its expected step.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidOrExpiredLoginTransaction`] for a wrong,
    /// expired, replayed or binding-mismatched credential. Database failures are
    /// returned separately and must not be mapped to credential denial.
    pub async fn consume_login_transaction(
        &self,
        token_digest: &OpaqueTokenDigest,
        expected_stage: LoginTransactionStage,
        binding_digest: &[u8; 32],
        correlation_id: &str,
    ) -> Result<LoginTransactionRecord, StoreError> {
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let consumed = sqlx::query_as::<_, (Uuid, Uuid, Uuid, Option<Uuid>, OffsetDateTime)>(
            "UPDATE login_transactions SET stage = 'consumed', consumed_at = $4 \
             WHERE token_digest = $1 AND binding_digest = $2 AND stage = $3 \
               AND consumed_at IS NULL AND expires_at > $4 \
             RETURNING id, tenant_id, account_id, factor_id, expires_at",
        )
        .bind(token_digest.as_bytes().as_slice())
        .bind(binding_digest.as_slice())
        .bind(expected_stage.database_value())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((transaction_id, tenant_id, account_id, factor_id, expires_at)) = consumed else {
            return Err(StoreError::InvalidOrExpiredLoginTransaction);
        };
        let tenant_id = TenantId::from_uuid(tenant_id);
        let account_id = AccountId::from_uuid(account_id);
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::LoginTransactionConsumed,
                correlation_id,
                metadata: json!({
                    "transaction_id": transaction_id,
                    "stage": expected_stage.database_value(),
                }),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(LoginTransactionRecord {
            transaction_id,
            tenant_id,
            account_id,
            stage: expected_stage,
            expires_at,
            factor_id,
        })
    }
}
