// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Server-side `WebAuthn` ceremony and passkey persistence operations.

use super::{
    insert_audit, json, parse_webauthn_ceremony_kind, sqlx, validate_correlation_id, AccountId,
    AuditAction, AuditEventId, AuditWrite, CreateWebauthnCeremony, OffsetDateTime,
    OpaqueTokenDigest, PostgresAuthorityStore, RegisterWebauthnPasskey, StoreError,
    StoredWebauthnPasskey, TenantId, Uuid, WebauthnCeremonyRecord,
};

impl PostgresAuthorityStore {
    /// Creates one short-lived `WebAuthn` ceremony retained only on the server.
    ///
    /// `state` contains the library-provided cryptographic challenge state. Its
    /// raw contents never enter a cookie, URL, audit event or client response.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for invalid expiry/correlation, unavailable local
    /// account, or a failed ceremony/audit transaction.
    pub async fn create_webauthn_ceremony(
        &self,
        request: CreateWebauthnCeremony<'_>,
    ) -> Result<(), StoreError> {
        let CreateWebauthnCeremony {
            tenant_id,
            account_id,
            kind,
            state,
            token_digest,
            binding_digest,
            expires_at,
            correlation_id,
        } = request;
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(StoreError::InvalidWebauthnCeremonyExpiry);
        }
        let ceremony_id = Uuid::now_v7();
        let mut transaction = self.pool.begin().await?;
        let created = sqlx::query(
            "INSERT INTO webauthn_ceremonies ( \
               id, tenant_id, account_id, kind, state, token_digest, binding_digest, created_at, expires_at \
             ) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 \
             WHERE EXISTS ( \
                SELECT 1 FROM accounts WHERE tenant_id = $2 AND id = $3 \
                  AND state IN ('active', 'mfa_enrollment_required')
             )",
        )
        .bind(ceremony_id)
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(kind.database_value())
        .bind(state)
        .bind(token_digest.as_bytes().as_slice())
        .bind(binding_digest.as_bytes().as_slice())
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
                action: AuditAction::WebauthnCeremonyIssued,
                correlation_id,
                metadata: json!({"ceremony_id": ceremony_id, "kind": kind.database_value()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Consumes one exact browser-bound `WebAuthn` ceremony and returns server state.
    ///
    /// # Errors
    ///
    /// Wrong, expired, replayed or binding-mismatched handles return
    /// [`StoreError::InvalidOrExpiredWebauthnCeremony`] without disclosing which
    /// condition applied. Persistence failure remains distinct.
    pub async fn consume_webauthn_ceremony(
        &self,
        token_digest: &OpaqueTokenDigest,
        binding_digest: &OpaqueTokenDigest,
        correlation_id: &str,
    ) -> Result<WebauthnCeremonyRecord, StoreError> {
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let record = sqlx::query_as::<_, (Uuid, Uuid, String, serde_json::Value)>(
            "UPDATE webauthn_ceremonies SET consumed_at = $3 \
             WHERE token_digest = $1 AND binding_digest = $2 AND consumed_at IS NULL AND expires_at > $3 \
             RETURNING tenant_id, account_id, kind, state",
        )
        .bind(token_digest.as_bytes().as_slice())
        .bind(binding_digest.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((tenant_id, account_id, kind, state)) = record else {
            transaction.commit().await?;
            return Err(StoreError::InvalidOrExpiredWebauthnCeremony);
        };
        let tenant_id = TenantId::from_uuid(tenant_id);
        let account_id = AccountId::from_uuid(account_id);
        let kind = parse_webauthn_ceremony_kind(&kind)?;
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::WebauthnCeremonyConsumed,
                correlation_id,
                metadata: json!({"kind": kind.database_value()}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(WebauthnCeremonyRecord {
            tenant_id,
            account_id,
            kind,
            state,
        })
    }

    /// Returns all active serialized passkeys belonging to one tenant-local account.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] only for persistence failure.
    pub async fn active_webauthn_passkeys(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
    ) -> Result<Vec<StoredWebauthnPasskey>, StoreError> {
        let records = sqlx::query_as::<_, (String, serde_json::Value)>(
            "SELECT credential_id, passkey FROM webauthn_credentials \
             WHERE tenant_id = $1 AND account_id = $2 AND disabled_at IS NULL \
             ORDER BY created_at ASC",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;
        Ok(records
            .into_iter()
            .map(|(credential_id, passkey)| StoredWebauthnPasskey {
                credential_id,
                passkey,
            })
            .collect())
    }

    /// Persists one newly verified passkey with a globally unique credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for invalid metadata or a failed credential/audit transaction.
    pub async fn register_webauthn_passkey(
        &self,
        request: RegisterWebauthnPasskey<'_>,
    ) -> Result<(), StoreError> {
        let RegisterWebauthnPasskey {
            tenant_id,
            account_id,
            credential_id,
            passkey,
            label,
            correlation_id,
        } = request;
        validate_correlation_id(correlation_id)?;
        if credential_id.is_empty() || credential_id.len() > 2048 {
            return Err(StoreError::InvalidWebauthnCredentialId);
        }
        if label.is_some_and(|value| {
            value.is_empty() || value.len() > 96 || value.chars().any(char::is_control)
        }) {
            return Err(StoreError::InvalidWebauthnPasskeyLabel);
        }
        let now = OffsetDateTime::now_utc();
        let mut transaction = self.pool.begin().await?;
        let created = sqlx::query(
            "INSERT INTO webauthn_credentials (id, tenant_id, account_id, credential_id, passkey, label, created_at)
             SELECT $1, $2, $3, $4, $5, $6, $7
             WHERE EXISTS (
                SELECT 1 FROM accounts WHERE tenant_id = $2 AND id = $3 AND state = 'active'
             )",
        )
        .bind(Uuid::now_v7())
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(credential_id)
        .bind(passkey)
        .bind(label)
        .bind(now)
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
                action: AuditAction::PasskeyChanged,
                correlation_id,
                metadata: json!({"outcome": "registered"}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Stores only verified updated passkey state and the last-use timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TargetNotFoundOrUnchanged`] when the credential is no
    /// longer active under this tenant-local account.
    pub async fn update_webauthn_passkey(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        credential_id: &str,
        passkey: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let changed = sqlx::query(
            "UPDATE webauthn_credentials SET passkey = $4, last_used_at = $5
             WHERE tenant_id = $1 AND account_id = $2 AND credential_id = $3 AND disabled_at IS NULL
               AND EXISTS (
                   SELECT 1 FROM accounts WHERE tenant_id = $1 AND id = $2 AND state = 'active'
               )",
        )
        .bind(tenant_id.as_uuid())
        .bind(account_id.as_uuid())
        .bind(credential_id)
        .bind(passkey)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::TargetNotFoundOrUnchanged);
        }
        Ok(())
    }
}
