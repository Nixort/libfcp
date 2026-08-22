// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! PostgreSQL persistence boundary for the FCP Fabric service.
//!
//! Every public mutation in this crate is tenant-scoped and emits a redacted
//! audit event in the same transaction. Production code must call
//! [`PostgresAuthorityStore::migrate`] before serving requests.

mod accounts;
mod errors;
mod federation;
mod helpers;
mod login_transactions;
mod mfa;
mod migrations;
mod sessions;
mod sqlx;
mod step_up;
mod types;
mod webauthn;

pub use errors::StoreError;
use helpers::{
    insert_audit, parse_account_state, parse_federation_trust_state, parse_role,
    parse_webauthn_ceremony_kind, revoke_session_family, role_text,
    rotate_locked_refresh_credential, validate_correlation_id, AuditWrite, RefreshRotationWrite,
};
pub use types::*;

use std::{borrow::Cow, sync::LazyLock};

use fcp_fabric_auth::{
    EncryptedTotpSeed, OpaqueTokenDigest, PasswordVerifierString, TotpError, TotpKeyReference,
};
use fcp_fabric_domain::{
    AccountId, AccountState, AdministrationError, AuditAction, AuditEventId, AuthorizationContext,
    BootstrapResult, BootstrapTenant, ChangeRole, DomainName, FederationTrustState, InviteAccount,
    PolicyVersion, Role, TenantId, UserAddress,
};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// PostgreSQL-backed FCP Fabric store.
#[derive(Clone, Debug)]
pub struct PostgresAuthorityStore {
    pool: PgPool,
}

impl PostgresAuthorityStore {
    /// Connects a PostgreSQL pool with bounded connection count.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the PostgreSQL pool cannot connect.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Wraps an already configured PostgreSQL pool.
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the underlying pool for health probes and controlled integration.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies all embedded migrations.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Migration`] if PostgreSQL rejects the embedded
    /// migration plan or a concurrent migration state is invalid.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        migrations::MIGRATOR
            .run(&self.pool)
            .await
            .map_err(StoreError::Migration)
    }
}
