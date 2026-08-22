// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Offline migration and initial-tenant bootstrap client for FCP Fabric.
//!
//! Direct PostgreSQL access is intentionally restricted to schema migration and
//! one-time tenant bootstrap. After bootstrap, role, account and federation
//! changes belong to authenticated FCP Fabric service flows rather than operator SQL.

use clap::{Args, Parser, Subcommand};
use fcp_fabric_domain::{BootstrapTenant, DomainName, Localpart};
use fcp_fabric_store::PostgresAuthorityStore;
use thiserror::Error;

/// FCP Fabric offline administration command-line interface.
#[derive(Debug, Parser)]
#[command(name = "fcp-fabric", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Supported offline FCP Fabric setup commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Apply embedded PostgreSQL FCP Fabric schema migrations.
    Migrate(ConnectionOptions),
    /// One-time tenant bootstrap operations.
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
}

/// Tenant bootstrap subcommands.
#[derive(Debug, Subcommand)]
enum TenantCommand {
    /// Create an organization domain and its first MFA-enrollment-required owner.
    Bootstrap {
        #[command(flatten)]
        connection: ConnectionOptions,
        /// Canonical organization domain, for example `parley.io`.
        #[arg(long)]
        domain: String,
        /// Lower-case tenant-local owner localpart, for example `benjamin`.
        #[arg(long)]
        owner: String,
        /// Redacted audit correlation identifier for this bootstrap event.
        #[arg(long, default_value = "fcp-fabric-bootstrap")]
        correlation_id: String,
    },
}

/// Non-secret database connection configuration.
///
/// The connection URL itself is read only from `FCP_DATABASE_URL`; it is never a
/// command-line flag and therefore does not enter shell history or process args.
#[derive(Debug, Args)]
struct ConnectionOptions {
    /// Bounded connection pool limit used only by this short-lived CLI command.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=10))]
    max_connections: u32,
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Migrate(connection) => {
            let store = connect(&connection).await?;
            store.migrate().await?;
            println!("FCP Fabric schema migrations applied");
        }
        Command::Tenant {
            command:
                TenantCommand::Bootstrap {
                    connection,
                    domain,
                    owner,
                    correlation_id,
                },
        } => {
            let store = connect(&connection).await?;
            store.migrate().await?;
            let result = store
                .bootstrap_tenant(&BootstrapTenant {
                    domain: DomainName::parse(&domain)?,
                    owner_localpart: Localpart::parse(&owner)?,
                    correlation_id,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }
    Ok(())
}

async fn connect(options: &ConnectionOptions) -> Result<PostgresAuthorityStore, CliError> {
    let database_url =
        std::env::var("FCP_DATABASE_URL").map_err(|_| CliError::MissingDatabaseUrl)?;
    Ok(PostgresAuthorityStore::connect(&database_url, options.max_connections).await?)
}

/// CLI parsing, canonicalization, storage or output error.
#[derive(Debug, Error)]
enum CliError {
    /// Domain argument was outside the canonical FCP Fabric grammar.
    #[error("invalid tenant domain: {0}")]
    Domain(#[from] fcp_fabric_domain::DomainError),
    /// Owner login argument was outside the stable first-release grammar.
    #[error("invalid owner localpart: {0}")]
    Localpart(#[from] fcp_fabric_domain::LocalpartError),
    /// Required database URL environment variable was not configured.
    #[error("FCP_DATABASE_URL environment variable is required")]
    MissingDatabaseUrl,
    /// FCP Fabric storage operation failed.
    #[error("FCP Fabric storage failed: {0}")]
    Store(#[from] fcp_fabric_store::StoreError),
    /// Successful FCP Fabric result could not be rendered as JSON.
    #[error("FCP Fabric result serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}
