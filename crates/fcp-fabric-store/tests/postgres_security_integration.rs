// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Opt-in real PostgreSQL security-invariant coverage.
//!
//! Set `FCP_FABRIC_TEST_DATABASE_URL` to a disposable database. The test drops
//! and recreates its `public` schema before running embedded migrations; it must
//! never point to an operator or production database.

use fcp_fabric_auth::{issue_opaque_token, EncryptedTotpSeed, TokenDigestKey, TotpKeyReference};
use fcp_fabric_domain::{BootstrapResult, BootstrapTenant, DomainName, Localpart};
use fcp_fabric_store::{
    CreateRefreshSession, CreateTotpDataKeyEnvelope, CreateWebauthnCeremony,
    PostgresAuthorityStore, RefreshRotation, RegisterWebauthnPasskey, StoreError,
    WebauthnCeremonyKind,
};
use serde_json::json;
use sqlx_core::{query::query, query_scalar::query_scalar};
use sqlx_postgres::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn real_postgres_enforces_security_lifecycle_invariants() {
    let Some(database_url) = test_database_url() else {
        return;
    };
    let pool = PgPool::connect(&database_url)
        .await
        .expect("connect disposable PostgreSQL database");
    reset_public_schema(&pool).await;
    let store = PostgresAuthorityStore::from_pool(pool.clone());
    store.migrate().await.expect("apply Fabric migrations");
    let bootstrap = bootstrap_active_test_account(&store, &pool).await;

    assert_refresh_reuse_revokes_family(&store, &pool, &bootstrap).await;
    assert_webauthn_ceremony_consumes_once(&store, &bootstrap).await;
    assert_kms_data_key_envelope_is_ciphertext_only(&store).await;
    assert_inactive_account_cannot_register_passkey(&store, &pool, &bootstrap).await;
    assert_inactive_account_cannot_issue_session(&store, &pool, &bootstrap).await;
    assert_deactivated_bootstrap_account_cannot_activate_totp(&store, &pool).await;
}

fn test_database_url() -> Option<String> {
    let Ok(database_url) = std::env::var("FCP_FABRIC_TEST_DATABASE_URL") else {
        eprintln!("skipping PostgreSQL integration test: FCP_FABRIC_TEST_DATABASE_URL is unset");
        return None;
    };
    assert!(
        database_url.contains("localhost") || database_url.contains("127.0.0.1"),
        "integration test database must be a local disposable PostgreSQL instance"
    );
    Some(database_url)
}

async fn bootstrap_active_test_account(
    store: &PostgresAuthorityStore,
    pool: &PgPool,
) -> BootstrapResult {
    let bootstrap = store
        .bootstrap_tenant(&BootstrapTenant {
            domain: DomainName::parse("postgres-test.local").expect("canonical local domain"),
            owner_localpart: Localpart::parse("benjamin").expect("canonical localpart"),
            correlation_id: "postgres-test-bootstrap".to_owned(),
        })
        .await
        .expect("bootstrap test tenant");
    query("UPDATE accounts SET state = 'active' WHERE tenant_id = $1 AND id = $2")
        .bind(bootstrap.tenant_id.as_uuid())
        .bind(bootstrap.owner_id.as_uuid())
        .execute(pool)
        .await
        .expect("activate test account");
    bootstrap
}

async fn assert_refresh_reuse_revokes_family(
    store: &PostgresAuthorityStore,
    pool: &PgPool,
    bootstrap: &BootstrapResult,
) {
    let digest_key = TokenDigestKey::from_bytes([0xA5; 32]);
    let refresh = issue_opaque_token(&digest_key);
    let access = issue_opaque_token(&digest_key);
    let now = OffsetDateTime::now_utc();
    let initial = store
        .create_refresh_session(CreateRefreshSession {
            tenant_id: bootstrap.tenant_id,
            account_id: bootstrap.owner_id,
            refresh_digest: &refresh.digest,
            access_digest: &access.digest,
            refresh_expires_at: now + Duration::hours(1),
            access_expires_at: now + Duration::minutes(15),
            correlation_id: "postgres-test-session-create",
        })
        .await
        .expect("create paired session");
    let successor = issue_opaque_token(&digest_key);
    let successor_access = issue_opaque_token(&digest_key);
    let rotation = store
        .rotate_refresh_credential(
            &refresh.digest,
            &successor.digest,
            &successor_access.digest,
            now + Duration::hours(2),
            now + Duration::minutes(20),
            "postgres-test-session-rotate",
        )
        .await
        .expect("rotate refresh credential");
    assert!(matches!(rotation, RefreshRotation::Rotated(_)));
    let reuse = rotate_replayed_refresh(store, &digest_key, &refresh).await;
    assert_eq!(reuse, RefreshRotation::ReuseDetected);
    let revoked_at = query_scalar::<_, Option<OffsetDateTime>>(
        "SELECT revoked_at FROM session_families WHERE id = $1",
    )
    .bind(initial.family_id)
    .fetch_one(pool)
    .await
    .expect("query revoked family");
    assert!(
        revoked_at.is_some(),
        "reuse must revoke the full session family"
    );
}

async fn rotate_replayed_refresh(
    store: &PostgresAuthorityStore,
    digest_key: &TokenDigestKey,
    refresh: &fcp_fabric_auth::IssuedOpaqueToken,
) -> RefreshRotation {
    store
        .rotate_refresh_credential(
            &refresh.digest,
            &issue_opaque_token(digest_key).digest,
            &issue_opaque_token(digest_key).digest,
            OffsetDateTime::now_utc() + Duration::hours(2),
            OffsetDateTime::now_utc() + Duration::minutes(20),
            "postgres-test-session-reuse",
        )
        .await
        .expect("detect refresh credential reuse")
}

async fn assert_webauthn_ceremony_consumes_once(
    store: &PostgresAuthorityStore,
    bootstrap: &BootstrapResult,
) {
    let ceremony_key = TokenDigestKey::from_bytes([0x5A; 32]);
    let ceremony = issue_opaque_token(&ceremony_key);
    let binding = issue_opaque_token(&ceremony_key);
    store
        .create_webauthn_ceremony(CreateWebauthnCeremony {
            tenant_id: bootstrap.tenant_id,
            account_id: bootstrap.owner_id,
            kind: WebauthnCeremonyKind::Authentication,
            state: &json!({"server_only": "challenge-state"}),
            token_digest: &ceremony.digest,
            binding_digest: &binding.digest,
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            correlation_id: "postgres-test-webauthn-create",
        })
        .await
        .expect("create server-side WebAuthn ceremony");
    let consumed = store
        .consume_webauthn_ceremony(
            &ceremony.digest,
            &binding.digest,
            "postgres-test-webauthn-consume",
        )
        .await
        .expect("consume ceremony once");
    assert_eq!(consumed.tenant_id, bootstrap.tenant_id);
    assert_eq!(consumed.account_id, bootstrap.owner_id);
    assert_eq!(consumed.kind, WebauthnCeremonyKind::Authentication);
    let replay = store
        .consume_webauthn_ceremony(
            &ceremony.digest,
            &binding.digest,
            "postgres-test-webauthn-replay",
        )
        .await;
    assert!(matches!(
        replay,
        Err(StoreError::InvalidOrExpiredWebauthnCeremony)
    ));
}

async fn assert_kms_data_key_envelope_is_ciphertext_only(store: &PostgresAuthorityStore) {
    let reference = TotpKeyReference::new("aws-kms:totp-dek:postgres-regression".to_owned())
        .expect("bounded opaque KMS reference");
    let now = OffsetDateTime::now_utc();
    store
        .create_totp_data_key_envelope(CreateTotpDataKeyEnvelope {
            key_reference: &reference,
            provider: "aws_kms",
            wrapping_key_reference: "arn:aws:kms:us-east-1:111122223333:key/postgres-regression",
            encrypted_data_key: &[0xA5; 96],
            created_at: now,
        })
        .await
        .expect("persist KMS ciphertext envelope");
    let stored = store
        .totp_data_key_envelope(&reference)
        .await
        .expect("load KMS envelope")
        .expect("stored KMS envelope");
    assert_eq!(stored.key_reference, reference);
    assert_eq!(stored.provider, "aws_kms");
    assert_eq!(stored.encrypted_data_key, vec![0xA5; 96]);
    let duplicate = store
        .create_totp_data_key_envelope(CreateTotpDataKeyEnvelope {
            key_reference: &reference,
            provider: "aws_kms",
            wrapping_key_reference: "arn:aws:kms:us-east-1:111122223333:key/postgres-regression",
            encrypted_data_key: &[0xA5; 96],
            created_at: now,
        })
        .await;
    assert!(matches!(
        duplicate,
        Err(StoreError::TargetNotFoundOrUnchanged)
    ));
    let invalid_reference = TotpKeyReference::new("aws-kms:totp-dek:invalid-provider".to_owned())
        .expect("bounded opaque KMS reference");
    let invalid = store
        .create_totp_data_key_envelope(CreateTotpDataKeyEnvelope {
            key_reference: &invalid_reference,
            provider: "unexpected_provider",
            wrapping_key_reference: "arn:aws:kms:us-east-1:111122223333:key/postgres-regression",
            encrypted_data_key: &[0xA5; 96],
            created_at: now,
        })
        .await;
    assert!(matches!(
        invalid,
        Err(StoreError::InvalidTotpDataKeyEnvelope)
    ));
}

async fn assert_inactive_account_cannot_register_passkey(
    store: &PostgresAuthorityStore,
    pool: &PgPool,
    bootstrap: &BootstrapResult,
) {
    const EXISTING_CREDENTIAL_ID: &str = "postgres-test-existing-passkey";
    store
        .register_webauthn_passkey(RegisterWebauthnPasskey {
            tenant_id: bootstrap.tenant_id,
            account_id: bootstrap.owner_id,
            credential_id: EXISTING_CREDENTIAL_ID,
            passkey: &json!({"verified": "server-side only in actual service"}),
            label: Some("active-account-regression"),
            correlation_id: "postgres-test-active-passkey",
        })
        .await
        .expect("register active-account passkey");
    query("UPDATE accounts SET state = 'deactivated' WHERE tenant_id = $1 AND id = $2")
        .bind(bootstrap.tenant_id.as_uuid())
        .bind(bootstrap.owner_id.as_uuid())
        .execute(pool)
        .await
        .expect("deactivate test account");
    let registration = store
        .register_webauthn_passkey(RegisterWebauthnPasskey {
            tenant_id: bootstrap.tenant_id,
            account_id: bootstrap.owner_id,
            credential_id: "postgres-test-inactive-passkey",
            passkey: &json!({"verified": "server-side only in actual service"}),
            label: Some("inactive-account-regression"),
            correlation_id: "postgres-test-inactive-passkey",
        })
        .await;
    assert!(
        matches!(registration, Err(StoreError::TargetNotFoundOrUnchanged)),
        "inactive passkey registration must fail closed, got {registration:?}"
    );
    let update = store
        .update_webauthn_passkey(
            bootstrap.tenant_id,
            bootstrap.owner_id,
            EXISTING_CREDENTIAL_ID,
            &json!({"must_not": "replace stored passkey"}),
        )
        .await;
    assert!(
        matches!(update, Err(StoreError::TargetNotFoundOrUnchanged)),
        "inactive passkey update must fail closed, got {update:?}"
    );
    let credential_count = query_scalar::<_, i64>(
        "SELECT count(*) FROM webauthn_credentials WHERE tenant_id = $1 AND account_id = $2",
    )
    .bind(bootstrap.tenant_id.as_uuid())
    .bind(bootstrap.owner_id.as_uuid())
    .fetch_one(pool)
    .await
    .expect("count inactive-account credentials");
    assert_eq!(credential_count, 1);
    let last_used_at = query_scalar::<_, Option<OffsetDateTime>>(
        "SELECT last_used_at FROM webauthn_credentials WHERE credential_id = $1",
    )
    .bind(EXISTING_CREDENTIAL_ID)
    .fetch_one(pool)
    .await
    .expect("query inactive-account credential state");
    assert!(last_used_at.is_none());
    let audit_count = query_scalar::<_, i64>(
        "SELECT count(*) FROM audit_events \
         WHERE tenant_id = $1 AND actor_id = $2 AND action = 'passkey_changed'",
    )
    .bind(bootstrap.tenant_id.as_uuid())
    .bind(bootstrap.owner_id.as_uuid())
    .fetch_one(pool)
    .await
    .expect("count inactive-account passkey audit events");
    assert_eq!(audit_count, 1);
}

async fn assert_inactive_account_cannot_issue_session(
    store: &PostgresAuthorityStore,
    pool: &PgPool,
    bootstrap: &BootstrapResult,
) {
    let digest_key = TokenDigestKey::from_bytes([0x3C; 32]);
    let now = OffsetDateTime::now_utc();
    let result = store
        .create_refresh_session(CreateRefreshSession {
            tenant_id: bootstrap.tenant_id,
            account_id: bootstrap.owner_id,
            refresh_digest: &issue_opaque_token(&digest_key).digest,
            access_digest: &issue_opaque_token(&digest_key).digest,
            refresh_expires_at: now + Duration::hours(1),
            access_expires_at: now + Duration::minutes(15),
            correlation_id: "postgres-test-inactive-session",
        })
        .await;
    assert!(
        matches!(result, Err(StoreError::TargetNotFoundOrUnchanged)),
        "inactive session issuance must fail closed, got {result:?}"
    );
    let family_count = query_scalar::<_, i64>(
        "SELECT count(*) FROM session_families WHERE tenant_id = $1 AND account_id = $2",
    )
    .bind(bootstrap.tenant_id.as_uuid())
    .bind(bootstrap.owner_id.as_uuid())
    .fetch_one(pool)
    .await
    .expect("count inactive-account session families");
    assert_eq!(family_count, 1);
}

async fn assert_deactivated_bootstrap_account_cannot_activate_totp(
    store: &PostgresAuthorityStore,
    pool: &PgPool,
) {
    let bootstrap = store
        .bootstrap_tenant(&BootstrapTenant {
            domain: DomainName::parse("totp-regression.local").expect("canonical local domain"),
            owner_localpart: Localpart::parse("totpowner").expect("canonical localpart"),
            correlation_id: "postgres-test-totp-bootstrap".to_owned(),
        })
        .await
        .expect("bootstrap TOTP regression tenant");
    let factor_id = Uuid::now_v7();
    let encrypted = EncryptedTotpSeed {
        ciphertext: vec![0x42; 48],
        nonce: [0x24; 12],
        key_reference: TotpKeyReference::new("postgres-test-kms-key".to_owned())
            .expect("bounded key reference"),
        digits: 6,
        period_seconds: 30,
    };
    store
        .create_pending_totp_factor(
            bootstrap.tenant_id,
            bootstrap.owner_id,
            factor_id,
            &encrypted,
            "postgres-test-totp-pending",
        )
        .await
        .expect("create pending TOTP factor");
    query("UPDATE accounts SET state = 'deactivated' WHERE tenant_id = $1 AND id = $2")
        .bind(bootstrap.tenant_id.as_uuid())
        .bind(bootstrap.owner_id.as_uuid())
        .execute(pool)
        .await
        .expect("deactivate bootstrap account");
    let activation = store
        .activate_totp_factor(
            bootstrap.tenant_id,
            bootstrap.owner_id,
            factor_id,
            42,
            "postgres-test-totp-activation",
        )
        .await;
    assert!(
        matches!(activation, Err(StoreError::TargetNotFoundOrUnchanged)),
        "deactivated bootstrap TOTP activation must fail closed, got {activation:?}"
    );
    let status = query_scalar::<_, String>("SELECT status FROM mfa_totp_factors WHERE id = $1")
        .bind(factor_id)
        .fetch_one(pool)
        .await
        .expect("query pending factor status");
    assert_eq!(status, "pending");
    let audit_count = query_scalar::<_, i64>(
        "SELECT count(*) FROM audit_events \
         WHERE tenant_id = $1 AND actor_id = $2 AND action = 'mfa_changed'",
    )
    .bind(bootstrap.tenant_id.as_uuid())
    .bind(bootstrap.owner_id.as_uuid())
    .fetch_one(pool)
    .await
    .expect("count bootstrap MFA audit events");
    assert_eq!(audit_count, 1);
}

async fn reset_public_schema(pool: &PgPool) {
    query("DROP SCHEMA public CASCADE")
        .execute(pool)
        .await
        .expect("drop disposable public schema");
    query("CREATE SCHEMA public")
        .execute(pool)
        .await
        .expect("recreate disposable public schema");
}
