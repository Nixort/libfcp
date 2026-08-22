// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! PostgreSQL-only `SQLx` compatibility surface used by the Fabric store.
//!
//! The public `sqlx` umbrella crate wires optional macro, MySQL and SQLite
//! packages into its migration feature. Fabric uses only PostgreSQL and dynamic
//! query APIs, so this module re-exports the required stable implementation
//! crates directly. Keeping the surface local makes that driver boundary explicit
//! and avoids compiling or shipping unneeded database protocol code.

pub use sqlx_core::{
    error::Error, migrate, query::query, query_as::query_as, query_scalar::query_scalar,
    transaction::Transaction,
};
pub use sqlx_postgres::{PgPool, Postgres};

/// PostgreSQL-specific connection and pool configuration types.
pub mod postgres {
    pub use sqlx_postgres::PgPoolOptions;
}
