// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Explicit federation peer-policy and replay-evidence persistence operations.

use super::{
    insert_audit, json, parse_federation_trust_state, sqlx, validate_correlation_id, AuditAction,
    AuditEventId, AuditWrite, DomainName, OffsetDateTime, PostgresAuthorityStore,
    RecordFederationReplay, StoreError, StoredFederationKeyMaterial, StoredFederationPeerMaterial,
    TenantId, Uuid,
};

impl PostgresAuthorityStore {
    /// Resolves persisted explicit federation trust and currently valid key documents.
    ///
    /// The caller supplies canonical local and remote domains. This store method
    /// performs no key parsing and never falls back to automatic discovery; an
    /// absent peer returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for database or corrupt trust-state data.
    pub async fn federation_peer_material(
        &self,
        local_domain: &DomainName,
        remote_domain: &DomainName,
    ) -> Result<Option<StoredFederationPeerMaterial>, StoreError> {
        let peer = sqlx::query_as::<_, (Uuid, Uuid, String, Vec<u8>)>(
            "SELECT peer.id, peer.tenant_id, peer.trust_state, peer.expected_key_fingerprint \
             FROM federation_peers AS peer \
             JOIN tenants AS tenant ON tenant.id = peer.tenant_id \
             WHERE tenant.canonical_domain = $1 AND peer.remote_domain = $2",
        )
        .bind(local_domain.as_str())
        .bind(remote_domain.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some((peer_id, tenant_id, trust_state, expected_key_fingerprint)) = peer else {
            return Ok(None);
        };
        let now = OffsetDateTime::now_utc();
        let keys = sqlx::query_as::<_, (String, serde_json::Value, OffsetDateTime)>(
            "SELECT key_id, public_key_document, valid_until \
             FROM federation_keys \
             WHERE peer_id = $1 AND retired_at IS NULL AND valid_until > $2 \
             ORDER BY first_seen_at ASC",
        )
        .bind(peer_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(
            |(key_id, public_key_document, valid_until)| StoredFederationKeyMaterial {
                key_id,
                public_key_document,
                valid_until,
            },
        )
        .collect();
        Ok(Some(StoredFederationPeerMaterial {
            tenant_id: TenantId::from_uuid(tenant_id),
            peer_id,
            trust_state: parse_federation_trust_state(&trust_state)?,
            expected_key_fingerprint,
            keys,
        }))
    }

    /// Atomically records one admitted inbound federation request ID.
    ///
    /// The supplied digest must cover the exact canonical verified delivery. A
    /// duplicate request ID for the same tenant/peer returns `false` and creates
    /// no second audit event or application delivery opportunity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for invalid expiry/correlation, unknown foreign-key
    /// scope, or a failed replay/audit transaction.
    pub async fn record_federation_replay(
        &self,
        request: RecordFederationReplay<'_>,
    ) -> Result<bool, StoreError> {
        let RecordFederationReplay {
            tenant_id,
            peer_id,
            request_id,
            body_digest,
            expires_at,
            correlation_id,
        } = request;
        validate_correlation_id(correlation_id)?;
        let now = OffsetDateTime::now_utc();
        if expires_at <= now {
            return Err(StoreError::InvalidFederationReplayExpiry);
        }
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO federation_replays (tenant_id, peer_id, request_id, body_digest, accepted_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (tenant_id, peer_id, request_id) DO NOTHING",
        )
        .bind(tenant_id.as_uuid())
        .bind(peer_id)
        .bind(request_id)
        .bind(body_digest.as_slice())
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if inserted != 1 {
            transaction.commit().await?;
            return Ok(false);
        }
        insert_audit(
            &mut transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: None,
                action: AuditAction::FederationRequestEvaluated,
                correlation_id,
                metadata: json!({"peer_id": peer_id, "request_id": request_id, "outcome": "accepted"}),
                occurred_at: now,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }
}
