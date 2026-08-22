// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Shared transactional write and strict persisted-value helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) struct AuditWrite<'a> {
    pub(super) id: Uuid,
    pub(super) tenant_id: TenantId,
    pub(super) actor_id: Option<AccountId>,
    pub(super) action: AuditAction,
    pub(super) correlation_id: &'a str,
    pub(super) metadata: serde_json::Value,
    pub(super) occurred_at: OffsetDateTime,
}

pub(super) struct RefreshRotationWrite<'a> {
    pub(super) credential_id: Uuid,
    pub(super) tenant_id: TenantId,
    pub(super) account_id: AccountId,
    pub(super) family_id: Uuid,
    pub(super) successor_digest: &'a OpaqueTokenDigest,
    pub(super) successor_access_digest: &'a OpaqueTokenDigest,
    pub(super) successor_expires_at: OffsetDateTime,
    pub(super) successor_access_expires_at: OffsetDateTime,
    pub(super) correlation_id: &'a str,
    pub(super) now: OffsetDateTime,
}

pub(super) async fn rotate_locked_refresh_credential(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: RefreshRotationWrite<'_>,
) -> Result<RefreshRotation, StoreError> {
    let RefreshRotationWrite {
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
    } = request;
    let successor_id = Uuid::now_v7();
    let successor_access_session_id = Uuid::now_v7();
    let consumed = sqlx::query(
        "UPDATE refresh_credentials SET consumed_at = $2, replaced_by = $3 \
         WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(credential_id)
    .bind(now)
    .bind(successor_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if consumed != 1 {
        return Ok(RefreshRotation::Denied);
    }
    sqlx::query(
        "INSERT INTO refresh_credentials ( \
           id, tenant_id, account_id, family_id, token_digest, issued_at, expires_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(successor_id)
    .bind(tenant_id.as_uuid())
    .bind(account_id.as_uuid())
    .bind(family_id)
    .bind(successor_digest.as_bytes().as_slice())
    .bind(now)
    .bind(successor_expires_at)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE access_sessions SET revoked_at = $2 \
         WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO access_sessions ( \
           id, tenant_id, account_id, family_id, token_digest, issued_at, expires_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(successor_access_session_id)
    .bind(tenant_id.as_uuid())
    .bind(account_id.as_uuid())
    .bind(family_id)
    .bind(successor_access_digest.as_bytes().as_slice())
    .bind(now)
    .bind(successor_access_expires_at)
    .execute(&mut **transaction)
    .await?;
    insert_audit(
        transaction,
        AuditWrite {
            id: AuditEventId::new().as_uuid(),
            tenant_id,
            actor_id: Some(account_id),
            action: AuditAction::SessionIssued,
            correlation_id,
            metadata: json!({
                "operation": "refresh_rotated",
                "family_id": family_id,
                "credential_id": successor_id,
                "access_session_id": successor_access_session_id,
            }),
            occurred_at: now,
        },
    )
    .await?;
    Ok(RefreshRotation::Rotated(RefreshRotationRecord {
        tenant_id,
        account_id,
        family_id,
        credential_id: successor_id,
        expires_at: successor_expires_at,
        access_session_id: successor_access_session_id,
        access_expires_at: successor_access_expires_at,
    }))
}

pub(super) async fn revoke_session_family(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: TenantId,
    account_id: AccountId,
    family_id: Uuid,
    reason: &str,
    correlation_id: &str,
    now: OffsetDateTime,
) -> Result<bool, StoreError> {
    let revoked = sqlx::query(
        "UPDATE session_families SET revoked_at = $4, revoke_reason = $5 \
         WHERE id = $1 AND tenant_id = $2 AND account_id = $3 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(tenant_id.as_uuid())
    .bind(account_id.as_uuid())
    .bind(now)
    .bind(reason)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if revoked == 1 {
        sqlx::query(
            "UPDATE access_sessions SET revoked_at = $2 \
             WHERE family_id = $1 AND revoked_at IS NULL",
        )
        .bind(family_id)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
        insert_audit(
            transaction,
            AuditWrite {
                id: AuditEventId::new().as_uuid(),
                tenant_id,
                actor_id: Some(account_id),
                action: AuditAction::SessionRevoked,
                correlation_id,
                metadata: json!({"family_id": family_id, "reason": reason}),
                occurred_at: now,
            },
        )
        .await?;
    }
    Ok(revoked == 1)
}

pub(super) async fn insert_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: AuditWrite<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (id, tenant_id, actor_id, action, correlation_id, metadata, occurred_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(event.id)
    .bind(event.tenant_id.as_uuid())
    .bind(event.actor_id.map(AccountId::as_uuid))
    .bind(audit_action_text(event.action))
    .bind(event.correlation_id)
    .bind(event.metadata)
    .bind(event.occurred_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) fn parse_webauthn_ceremony_kind(
    value: &str,
) -> Result<WebauthnCeremonyKind, StoreError> {
    match value {
        "registration" => Ok(WebauthnCeremonyKind::Registration),
        "authentication" => Ok(WebauthnCeremonyKind::Authentication),
        _ => Err(StoreError::CorruptWebauthnCeremonyKind),
    }
}

pub(super) fn parse_federation_trust_state(
    value: &str,
) -> Result<FederationTrustState, StoreError> {
    match value {
        "pending" => Ok(FederationTrustState::Pending),
        "active" => Ok(FederationTrustState::Active),
        "suspended" => Ok(FederationTrustState::Suspended),
        "revoked" => Ok(FederationTrustState::Revoked),
        _ => Err(StoreError::CorruptFederationTrustState),
    }
}

pub(super) fn parse_account_state(value: &str) -> Result<AccountState, StoreError> {
    match value {
        "active" => Ok(AccountState::Active),
        "mfa_enrollment_required" => Ok(AccountState::MfaEnrollmentRequired),
        "suspended" => Ok(AccountState::Suspended),
        "deactivated" => Ok(AccountState::Deactivated),
        _ => Err(StoreError::CorruptAccountState),
    }
}

pub(super) fn parse_role(value: &str) -> Result<Role, StoreError> {
    match value {
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        "operator" => Ok(Role::Operator),
        "auditor" => Ok(Role::Auditor),
        "member" => Ok(Role::Member),
        _ => Err(StoreError::CorruptRole),
    }
}

pub(super) fn validate_correlation_id(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(StoreError::InvalidCorrelationId)
    } else {
        Ok(())
    }
}

pub(super) const fn role_text(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Operator => "operator",
        Role::Auditor => "auditor",
        Role::Member => "member",
    }
}

pub(super) const fn audit_action_text(action: AuditAction) -> &'static str {
    match action {
        AuditAction::TenantBootstrapped => "tenant_bootstrapped",
        AuditAction::AccountCreated => "account_created",
        AuditAction::RoleChanged => "role_changed",
        AuditAction::PasswordChanged => "password_changed",
        AuditAction::MfaChanged => "mfa_changed",
        AuditAction::LoginTransactionIssued => "login_transaction_issued",
        AuditAction::LoginTransactionConsumed => "login_transaction_consumed",
        AuditAction::SessionIssued => "session_issued",
        AuditAction::SessionRevoked => "session_revoked",
        AuditAction::StepUpGranted => "step_up_granted",
        AuditAction::StepUpConsumed => "step_up_consumed",
        AuditAction::WebauthnCeremonyIssued => "webauthn_ceremony_issued",
        AuditAction::WebauthnCeremonyConsumed => "webauthn_ceremony_consumed",
        AuditAction::PasskeyChanged => "passkey_changed",
        AuditAction::FederationTrustChanged => "federation_trust_changed",
        AuditAction::FederationRequestEvaluated => "federation_request_evaluated",
    }
}
