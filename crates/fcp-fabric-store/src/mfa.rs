// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! TOTP and recovery-code persistence operations.

use super::{
    insert_audit, json, sqlx, validate_correlation_id, AccountId, AuditAction, AuditEventId,
    AuditWrite, CreateTotpDataKeyEnvelope, EncryptedTotpSeed, OffsetDateTime, PersistedTotpFactor,
    PostgresAuthorityStore, RecoveryCodeSetRecord, StoreError, StoredTotpDataKeyEnvelope, TenantId,
    TotpKeyReference, Uuid,
};

impl PostgresAuthorityStore {
    /// Returns whether an account owns an active TOTP factor in the same tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when the authorization-state query
    /// cannot complete.
    pub async fn has_active_totp_factor(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
    ) -> Result<bool, StoreError> {
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
               SELECT 1 FROM mfa_totp_factors \
               WHERE tenant_id = $1 AND account_id = $2 AND status = 'active' \
             )",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_one(&self.pool)
        .await?;
        Ok(active)
    }

    /// Persists one KMS/HSM ciphertext envelope for a future TOTP data-encryption key.
    ///
    /// The envelope is non-secret metadata: its ciphertext cannot decrypt an MFA
    /// seed without the external configured KMS/HSM. Existing references are
    /// immutable so active factors remain decryptable throughout key rotation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidTotpDataKeyEnvelope`] for malformed provider
    /// metadata and [`StoreError::TargetNotFoundOrUnchanged`] for a duplicate
    /// opaque reference.
    pub async fn create_totp_data_key_envelope(
        &self,
        request: CreateTotpDataKeyEnvelope<'_>,
    ) -> Result<(), StoreError> {
        if request.provider != "aws_kms"
            || request.wrapping_key_reference.is_empty()
            || request.wrapping_key_reference.len() > 2048
            || request.wrapping_key_reference.chars().any(char::is_control)
            || request.encrypted_data_key.is_empty()
            || request.encrypted_data_key.len() > 6144
        {
            return Err(StoreError::InvalidTotpDataKeyEnvelope);
        }
        let inserted = sqlx::query(
            "INSERT INTO totp_data_key_envelopes ( \
               key_reference, provider, wrapping_key_reference, encrypted_data_key, created_at \
             ) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (key_reference) DO NOTHING",
        )
        .bind(request.key_reference.as_str())
        .bind(request.provider)
        .bind(request.wrapping_key_reference)
        .bind(request.encrypted_data_key)
        .bind(request.created_at)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted == 1 {
            Ok(())
        } else {
            Err(StoreError::TargetNotFoundOrUnchanged)
        }
    }

    /// Resolves non-secret KMS/HSM envelope metadata for one factor key reference.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidTotpDataKeyEnvelope`] if durable envelope
    /// metadata violates the closed AWS KMS production contract.
    pub async fn totp_data_key_envelope(
        &self,
        reference: &TotpKeyReference,
    ) -> Result<Option<StoredTotpDataKeyEnvelope>, StoreError> {
        let row = sqlx::query_as::<_, (String, String, Vec<u8>)>(
            "SELECT provider, wrapping_key_reference, encrypted_data_key \
             FROM totp_data_key_envelopes WHERE key_reference = $1",
        )
        .bind(reference.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(provider, wrapping_key_reference, encrypted_data_key)| {
            if provider != "aws_kms"
                || wrapping_key_reference.is_empty()
                || wrapping_key_reference.len() > 2048
                || wrapping_key_reference.chars().any(char::is_control)
                || encrypted_data_key.is_empty()
                || encrypted_data_key.len() > 6144
            {
                return Err(StoreError::InvalidTotpDataKeyEnvelope);
            }
            Ok(StoredTotpDataKeyEnvelope {
                key_reference: reference.clone(),
                provider,
                wrapping_key_reference,
                encrypted_data_key,
            })
        })
        .transpose()
    }

    /// Persists one pending encrypted TOTP factor after authenticated enrollment starts.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the factor cannot be bound to the tenant/account
    /// or the factor/audit transaction cannot commit.
    pub async fn create_pending_totp_factor(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        factor_id: Uuid,
        encrypted: &EncryptedTotpSeed,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        validate_correlation_id(correlation_id)?;
        let audit_id = AuditEventId::new();
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let affected = sqlx::query(
            "INSERT INTO mfa_totp_factors ( \
               id, tenant_id, account_id, status, seed_ciphertext, seed_nonce, key_reference, \
               algorithm, digits, period_seconds, created_at \
             ) \
             SELECT $1, $2, $3, 'pending', $4, $5, $6, 'sha256', $7, $8, $9 \
             WHERE EXISTS (SELECT 1 FROM accounts WHERE id = $3 AND tenant_id = $2)",
        )
        .bind(factor_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(&encrypted.ciphertext)
        .bind(encrypted.nonce.as_slice())
        .bind(encrypted.key_reference.as_str())
        .bind(i16::try_from(encrypted.digits).map_err(|_| StoreError::InvalidStoredTotp)?)
        .bind(i16::try_from(encrypted.period_seconds).map_err(|_| StoreError::InvalidStoredTotp)?)
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
                action: AuditAction::MfaChanged,
                correlation_id,
                metadata: json!({"factor_id": factor_id, "operation": "pending_created"}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Loads one active encrypted TOTP factor for an account in its tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for database failure or malformed persisted factor
    /// metadata. `Ok(None)` represents no active factor.
    pub async fn active_totp_factor(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
    ) -> Result<Option<PersistedTotpFactor>, StoreError> {
        let row = sqlx::query_as::<_, (Uuid, Vec<u8>, Vec<u8>, String, i16, i16, Option<i64>)>(
            "SELECT id, seed_ciphertext, seed_nonce, key_reference, digits, period_seconds, last_accepted_time_step \
             FROM mfa_totp_factors \
             WHERE tenant_id = $1 AND account_id = $2 AND status = 'active'",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        row.map(PersistedTotpFactor::try_from_row).transpose()
    }

    /// Loads one specific pending encrypted TOTP factor for enrollment confirmation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for database failure or malformed persisted factor
    /// metadata. `Ok(None)` represents an absent, non-pending or cross-tenant factor.
    pub async fn pending_totp_factor(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        factor_id: Uuid,
    ) -> Result<Option<PersistedTotpFactor>, StoreError> {
        let row = sqlx::query_as::<_, (Uuid, Vec<u8>, Vec<u8>, String, i16, i16, Option<i64>)>(
            "SELECT id, seed_ciphertext, seed_nonce, key_reference, digits, period_seconds, last_accepted_time_step \
             FROM mfa_totp_factors \
             WHERE id = $1 AND tenant_id = $2 AND account_id = $3 AND status = 'pending'",
        )
        .bind(factor_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        row.map(PersistedTotpFactor::try_from_row).transpose()
    }

    /// Activates a confirmed pending TOTP factor and releases bootstrap account state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if factor state is not pending in the tenant/account
    /// or the activation/account/audit transaction cannot commit.
    pub async fn activate_totp_factor(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        factor_id: Uuid,
        accepted_step: i64,
        correlation_id: &str,
    ) -> Result<(), StoreError> {
        validate_correlation_id(correlation_id)?;
        let audit_id = AuditEventId::new();
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let activated = sqlx::query(
            "UPDATE mfa_totp_factors \
             SET status = 'active', activated_at = $4, last_accepted_time_step = $5 \
             WHERE id = $1 AND tenant_id = $2 AND account_id = $3 AND status = 'pending' \
               AND EXISTS ( \
                   SELECT 1 FROM accounts \
                   WHERE id = $3 AND tenant_id = $2 AND state = 'mfa_enrollment_required' \
               )",
        )
        .bind(factor_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(now)
        .bind(accepted_step)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if activated != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        let account_activated = sqlx::query(
            "UPDATE accounts SET state = 'active', updated_at = $3 \
             WHERE id = $1 AND tenant_id = $2 AND state = 'mfa_enrollment_required'",
        )
        .bind(account_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if account_activated != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: audit_id.as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::MfaChanged,
                correlation_id,
                metadata: json!({"factor_id": factor_id, "operation": "activated"}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically consumes one verified active-factor time step.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TargetNotFoundOrUnchanged`] when the factor is not
    /// active, outside tenant scope or the time step was already consumed.
    pub async fn consume_totp_step(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        factor_id: Uuid,
        accepted_step: i64,
    ) -> Result<(), StoreError> {
        let affected = sqlx::query(
            "UPDATE mfa_totp_factors SET last_accepted_time_step = $4 \
             WHERE id = $1 AND tenant_id = $2 AND account_id = $3 AND status = 'active' \
               AND (last_accepted_time_step IS NULL OR last_accepted_time_step < $4) \
               AND EXISTS ( \
                   SELECT 1 FROM accounts WHERE id = $3 AND tenant_id = $2 AND state = 'active' \
               )",
        )
        .bind(factor_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(accepted_step)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(StoreError::TargetNotFoundOrUnchanged)
        }
    }

    /// Replaces every usable recovery code for a tenant-local account.
    ///
    /// The caller must pass derived verifier text only. Raw recovery values must
    /// never enter this persistence API, audit metadata, or database record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRecoveryCodeSet`] for an unsafe verifier set
    /// and [`StoreError`] if invalidation, creation, verifier insertion or audit
    /// recording cannot commit atomically.
    pub async fn replace_recovery_code_set(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        verifiers: &[String],
        correlation_id: &str,
    ) -> Result<RecoveryCodeSetRecord, StoreError> {
        validate_correlation_id(correlation_id)?;
        if !(8..=16).contains(&verifiers.len())
            || verifiers
                .iter()
                .any(|verifier| verifier.is_empty() || verifier.len() > 128)
        {
            return Err(StoreError::InvalidRecoveryCodeSet);
        }
        let now = OffsetDateTime::now_utc();
        let set_id = Uuid::now_v7();
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "UPDATE recovery_code_sets SET invalidated_at = $3 \
             WHERE tenant_id = $1 AND account_id = $2 AND invalidated_at IS NULL",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let created = sqlx::query(
            "INSERT INTO recovery_code_sets (id, tenant_id, account_id, created_at) \
             SELECT $1, $2, $3, $4 \
             WHERE EXISTS (SELECT 1 FROM accounts WHERE id = $3 AND tenant_id = $2)",
        )
        .bind(set_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if created != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        for verifier in verifiers {
            sqlx::query(
                "INSERT INTO recovery_code_verifiers (id, set_id, verifier) VALUES ($1, $2, $3)",
            )
            .bind(Uuid::now_v7())
            .bind(set_id)
            .bind(verifier)
            .execute(&mut *transaction)
            .await?;
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::MfaChanged,
                correlation_id,
                metadata: json!({"operation": "recovery_set_replaced", "count": verifiers.len()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(RecoveryCodeSetRecord {
            set_id,
            code_count: verifiers.len(),
            created_at: now,
        })
    }

    /// Atomically consumes one current recovery-code verifier in its tenant scope.
    ///
    /// The caller supplies a service-derived verifier and receives only whether it
    /// was usable. Missing, consumed, invalidated or cross-tenant verifiers all
    /// return `false` without disclosing which condition applied.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] only when the durable consume/audit transaction fails.
    pub async fn consume_recovery_code(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        verifier: &str,
        correlation_id: &str,
    ) -> Result<bool, StoreError> {
        validate_correlation_id(correlation_id)?;
        if verifier.is_empty() || verifier.len() > 128 {
            return Ok(false);
        }
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let consumed = sqlx::query_scalar::<_, Uuid>(
            "UPDATE recovery_code_verifiers AS verifier \
             SET consumed_at = $4 \
             FROM recovery_code_sets AS code_set \
             WHERE verifier.set_id = code_set.id \
               AND code_set.tenant_id = $1 AND code_set.account_id = $2 \
               AND code_set.invalidated_at IS NULL \
               AND verifier.verifier = $3 AND verifier.consumed_at IS NULL \
             RETURNING verifier.id",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(verifier)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        if consumed.is_none() {
            transaction.commit().await?;
            return Ok(false);
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::MfaChanged,
                correlation_id,
                metadata: json!({"operation": "recovery_code_consumed"}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }
}
