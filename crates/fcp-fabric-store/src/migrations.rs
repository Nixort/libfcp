// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Statically embedded PostgreSQL migration plan.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Embedded migration plan for the Fabric PostgreSQL schema.
///
/// The SQL is compiled into the crate, preserving production migration behavior
/// without `SQLx`'s compile-time macro feature and its unnecessary non-PostgreSQL
/// database dependency graph.
pub(super) static MIGRATOR: LazyLock<sqlx::migrate::Migrator> =
    LazyLock::new(|| sqlx::migrate::Migrator {
        migrations: Cow::Owned(vec![
            embedded_migration(
                1,
                "authority schema",
                include_str!("../migrations/001_authority_schema.sql"),
            ),
            embedded_migration(
                2,
                "login transactions",
                include_str!("../migrations/002_login_transactions.sql"),
            ),
            embedded_migration(
                3,
                "login transaction factor binding",
                include_str!("../migrations/003_login_transaction_factor_binding.sql"),
            ),
            embedded_migration(
                4,
                "recovery code active set",
                include_str!("../migrations/004_recovery_code_active_set.sql"),
            ),
            embedded_migration(
                5,
                "access sessions",
                include_str!("../migrations/005_access_sessions.sql"),
            ),
            embedded_migration(
                6,
                "step up grants",
                include_str!("../migrations/006_step_up_grants.sql"),
            ),
            embedded_migration(
                7,
                "webauthn passkeys",
                include_str!("../migrations/007_webauthn_passkeys.sql"),
            ),
            embedded_migration(
                8,
                "totp kms data keys",
                include_str!("../migrations/008_totp_kms_data_keys.sql"),
            ),
        ]),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    });

fn embedded_migration(
    version: i64,
    description: &'static str,
    sql: &'static str,
) -> sqlx::migrate::Migration {
    sqlx::migrate::Migration::new(
        version,
        Cow::Borrowed(description),
        sqlx::migrate::MigrationType::Simple,
        Cow::Borrowed(sql),
        false,
    )
}
