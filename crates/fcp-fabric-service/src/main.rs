// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Loopback-only FCP Fabric service process for deployment behind a verified TLS edge.

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[cfg(feature = "aws-kms")]
use fcp_fabric_auth::TotpKeyReference;
use fcp_fabric_auth::{PasswordVerifierString, TokenDigestKey};
use fcp_fabric_domain::DomainName;
use fcp_fabric_service::{
    router, router_with_login, FabricLoginFlow, FabricTransportConfig, LoginTransactionPolicy,
    LoginTransactionService, PasswordLoginService,
};
#[cfg(feature = "aws-kms")]
use fcp_fabric_service::{
    router_with_mfa_session, AccessSessionAuthenticator, AwsKmsTotpKeyProvider,
    FabricMfaSessionDependencies, FabricMfaSessionServices, SessionIssuer, SessionPolicy,
    SessionRotator, StepUpPolicy, StepUpService, TotpEnrollmentService, TotpLoginService,
    WebauthnPolicy, WebauthnService,
};
use fcp_fabric_store::PostgresAuthorityStore;
use thiserror::Error;
use tokio::net::TcpListener;
#[cfg(feature = "aws-kms")]
use url::Url;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "FCP Fabric service stopped");
            eprintln!("fcp-fabric-service: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ServiceLaunchError> {
    let config = LaunchConfig::from_environment()?;
    let login_routes_enabled = config.login.is_some();
    let mfa_routes_enabled = config
        .login
        .as_ref()
        .is_some_and(|login| login.mfa.is_some());
    let app = match config.login {
        Some(login) => {
            let store = PostgresAuthorityStore::connect(&login.database_url, login.max_connections)
                .await
                .map_err(ServiceLaunchError::Store)?;
            let dummy_verifier = PasswordVerifierString::from_persisted(login.dummy_verifier)
                .map_err(ServiceLaunchError::DummyVerifier)?;
            let password_service = PasswordLoginService::new(store.clone(), dummy_verifier, 1024);
            let transaction_service = LoginTransactionService::new(
                store.clone(),
                TokenDigestKey::from_bytes(login.transaction_digest_key),
                LoginTransactionPolicy::standard(),
            );
            let flow = Arc::new(FabricLoginFlow::new(
                password_service,
                transaction_service,
                TokenDigestKey::from_bytes(login.binding_digest_key),
            ));
            match login.mfa {
                Some(mfa) => full_mfa_router(config.transport.clone(), store, flow, mfa).await?,
                None => router_with_login(config.transport.clone(), flow),
            }
        }
        None => router(config.transport.clone()),
    };
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(
        bind = %config.bind,
        domain = %config.transport.public_domain(),
        login_routes = login_routes_enabled,
        mfa_session_routes = mfa_routes_enabled,
        "FCP Fabric loopback transport listening behind TLS edge"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(ServiceLaunchError::Serve)
}

#[cfg(feature = "aws-kms")]
async fn full_mfa_router(
    transport: FabricTransportConfig,
    store: PostgresAuthorityStore,
    login_flow: Arc<FabricLoginFlow>,
    mfa: MfaRuntimeConfig,
) -> Result<axum::Router, ServiceLaunchError> {
    let active_reference = TotpKeyReference::new(mfa.active_totp_key_reference)
        .map_err(ServiceLaunchError::ActiveTotpKeyReference)?;
    let provider = Arc::new(
        AwsKmsTotpKeyProvider::from_default_environment(store.clone(), active_reference).await,
    );
    let totp_login = Arc::new(TotpLoginService::new(store.clone(), provider.clone()));
    let totp_enrollment = Arc::new(TotpEnrollmentService::new(
        store.clone(),
        provider,
        mfa.totp_issuer,
    ));
    let session_policy =
        SessionPolicy::new(time::Duration::days(30)).map_err(ServiceLaunchError::SessionPolicy)?;
    let session_digest_key = TokenDigestKey::from_bytes(mfa.session_digest_key);
    let webauthn_origin = Url::parse(&format!("https://{}/", transport.public_domain()))
        .map_err(ServiceLaunchError::WebauthnOrigin)?;
    let webauthn_policy = WebauthnPolicy::new(transport.public_domain().clone(), webauthn_origin)
        .map_err(ServiceLaunchError::WebauthnPolicy)?;
    let webauthn = Arc::new(
        WebauthnService::new(
            store.clone(),
            webauthn_policy,
            TokenDigestKey::from_bytes(mfa.webauthn_ceremony_digest_key),
            TokenDigestKey::from_bytes(mfa.webauthn_binding_digest_key),
        )
        .map_err(ServiceLaunchError::Webauthn)?,
    );
    let dependencies = FabricMfaSessionDependencies {
        totp_login: totp_login.clone(),
        totp_enrollment,
        session_issuer: Arc::new(SessionIssuer::new(
            store.clone(),
            session_digest_key.clone(),
            session_policy,
        )),
        session_rotator: Arc::new(SessionRotator::new(
            store.clone(),
            session_digest_key.clone(),
            session_policy,
        )),
        access_authenticator: Arc::new(AccessSessionAuthenticator::new(
            store.clone(),
            session_digest_key,
        )),
        step_up: Arc::new(StepUpService::new(
            store.clone(),
            totp_login,
            TokenDigestKey::from_bytes(mfa.step_up_digest_key),
            StepUpPolicy::standard(),
        )),
        webauthn,
    };
    Ok(router_with_mfa_session(
        transport,
        login_flow,
        FabricMfaSessionServices::new(store, dependencies),
    ))
}

#[cfg(not(feature = "aws-kms"))]
async fn full_mfa_router(
    _transport: FabricTransportConfig,
    _store: PostgresAuthorityStore,
    _login_flow: Arc<FabricLoginFlow>,
    _mfa: MfaRuntimeConfig,
) -> Result<axum::Router, ServiceLaunchError> {
    std::future::ready(()).await;
    Err(ServiceLaunchError::AwsKmsFeatureRequired)
}

#[derive(Clone, Eq, PartialEq)]
struct LaunchConfig {
    bind: SocketAddr,
    transport: FabricTransportConfig,
    login: Option<LoginRuntimeConfig>,
}

#[derive(Clone, Eq, PartialEq)]
struct LoginRuntimeConfig {
    database_url: String,
    dummy_verifier: String,
    transaction_digest_key: [u8; 32],
    binding_digest_key: [u8; 32],
    max_connections: u32,
    mfa: Option<MfaRuntimeConfig>,
}

/// All keys in this group are raw deployment secrets and intentionally neither
/// derive `Debug` nor appear in process logs, CLI arguments or public responses.
#[derive(Clone, Eq, PartialEq)]
struct MfaRuntimeConfig {
    active_totp_key_reference: String,
    totp_issuer: String,
    session_digest_key: [u8; 32],
    step_up_digest_key: [u8; 32],
    webauthn_ceremony_digest_key: [u8; 32],
    webauthn_binding_digest_key: [u8; 32],
}

impl LaunchConfig {
    fn from_environment() -> Result<Self, ServiceLaunchError> {
        let domain = std::env::var("FABRIC_PUBLIC_DOMAIN")
            .map_err(|_| ServiceLaunchError::MissingPublicDomain)
            .and_then(|value| DomainName::parse(&value).map_err(ServiceLaunchError::Domain))?;
        let bind = std::env::var("FABRIC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
        let bind = SocketAddr::from_str(&bind).map_err(ServiceLaunchError::BindAddress)?;
        if !bind.ip().is_loopback() {
            return Err(ServiceLaunchError::PublicBindForbidden);
        }
        let transport = if matches!(std::env::var("FABRIC_ENABLE_HSTS").as_deref(), Ok("true")) {
            FabricTransportConfig::new(domain).with_hsts()
        } else {
            FabricTransportConfig::new(domain)
        };
        Ok(Self {
            bind,
            transport,
            login: LoginRuntimeConfig::from_environment()?,
        })
    }
}

impl LoginRuntimeConfig {
    fn from_environment() -> Result<Option<Self>, ServiceLaunchError> {
        let database_url = std::env::var("FCP_DATABASE_URL").ok();
        let dummy_verifier = std::env::var("FABRIC_PASSWORD_DUMMY_VERIFIER").ok();
        let transaction_digest_key = std::env::var("FABRIC_LOGIN_TRANSACTION_DIGEST_KEY").ok();
        let binding_digest_key = std::env::var("FABRIC_LOGIN_BINDING_DIGEST_KEY").ok();
        let configured = [
            database_url.is_some(),
            dummy_verifier.is_some(),
            transaction_digest_key.is_some(),
            binding_digest_key.is_some(),
        ];
        if configured.iter().all(|configured| !configured) {
            if MfaRuntimeConfig::any_environment_variable_is_set() {
                return Err(ServiceLaunchError::MfaRequiresLoginConfiguration);
            }
            return Ok(None);
        }
        if configured.iter().any(|configured| !configured) {
            return Err(ServiceLaunchError::PartialLoginConfiguration);
        }
        let max_connections = std::env::var("FABRIC_DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_owned())
            .parse::<u32>()
            .map_err(ServiceLaunchError::DatabasePoolSize)?;
        if max_connections == 0 || max_connections > 64 {
            return Err(ServiceLaunchError::InvalidDatabasePoolSize);
        }
        Ok(Some(Self {
            database_url: database_url.expect("checked complete configuration"),
            dummy_verifier: dummy_verifier.expect("checked complete configuration"),
            transaction_digest_key: decode_key(
                &transaction_digest_key.expect("checked complete configuration"),
            )?,
            binding_digest_key: decode_key(
                &binding_digest_key.expect("checked complete configuration"),
            )?,
            max_connections,
            mfa: MfaRuntimeConfig::from_environment()?,
        }))
    }
}

impl MfaRuntimeConfig {
    const VARIABLES: [&'static str; 6] = [
        "FABRIC_TOTP_ACTIVE_KEY_REFERENCE",
        "FABRIC_TOTP_ISSUER",
        "FABRIC_SESSION_DIGEST_KEY",
        "FABRIC_STEP_UP_DIGEST_KEY",
        "FABRIC_WEBAUTHN_CEREMONY_DIGEST_KEY",
        "FABRIC_WEBAUTHN_BINDING_DIGEST_KEY",
    ];

    fn any_environment_variable_is_set() -> bool {
        Self::VARIABLES
            .iter()
            .any(|name| std::env::var(name).is_ok())
    }

    fn from_environment() -> Result<Option<Self>, ServiceLaunchError> {
        let active_totp_key_reference = std::env::var("FABRIC_TOTP_ACTIVE_KEY_REFERENCE").ok();
        let totp_issuer = std::env::var("FABRIC_TOTP_ISSUER").ok();
        let session_digest_key = std::env::var("FABRIC_SESSION_DIGEST_KEY").ok();
        let step_up_digest_key = std::env::var("FABRIC_STEP_UP_DIGEST_KEY").ok();
        let webauthn_ceremony_digest_key =
            std::env::var("FABRIC_WEBAUTHN_CEREMONY_DIGEST_KEY").ok();
        let webauthn_binding_digest_key = std::env::var("FABRIC_WEBAUTHN_BINDING_DIGEST_KEY").ok();
        let configured = [
            active_totp_key_reference.is_some(),
            totp_issuer.is_some(),
            session_digest_key.is_some(),
            step_up_digest_key.is_some(),
            webauthn_ceremony_digest_key.is_some(),
            webauthn_binding_digest_key.is_some(),
        ];
        if configured.iter().all(|configured| !configured) {
            return Ok(None);
        }
        if configured.iter().any(|configured| !configured) {
            return Err(ServiceLaunchError::PartialMfaConfiguration);
        }
        Ok(Some(Self {
            active_totp_key_reference: active_totp_key_reference
                .expect("checked complete configuration"),
            totp_issuer: totp_issuer.expect("checked complete configuration"),
            session_digest_key: decode_key(
                &session_digest_key.expect("checked complete configuration"),
            )?,
            step_up_digest_key: decode_key(
                &step_up_digest_key.expect("checked complete configuration"),
            )?,
            webauthn_ceremony_digest_key: decode_key(
                &webauthn_ceremony_digest_key.expect("checked complete configuration"),
            )?,
            webauthn_binding_digest_key: decode_key(
                &webauthn_binding_digest_key.expect("checked complete configuration"),
            )?,
        }))
    }
}

fn decode_key(value: &str) -> Result<[u8; 32], ServiceLaunchError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ServiceLaunchError::MalformedDigestKey)?
        .try_into()
        .map_err(|_| ServiceLaunchError::MalformedDigestKey)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("FCP Fabric received shutdown signal");
}

#[derive(Debug, Error)]
enum ServiceLaunchError {
    #[error("FABRIC_PUBLIC_DOMAIN environment variable is required")]
    MissingPublicDomain,
    #[error("FABRIC_PUBLIC_DOMAIN is invalid: {0}")]
    Domain(#[source] fcp_fabric_domain::DomainError),
    #[error("FABRIC_BIND must be a valid socket address: {0}")]
    BindAddress(#[source] std::net::AddrParseError),
    #[error("direct public HTTP bind is forbidden; terminate TLS at a local verified edge")]
    PublicBindForbidden,
    #[error("either configure every Fabric login runtime secret or configure none")]
    PartialLoginConfiguration,
    #[error("MFA configuration requires the complete Fabric login runtime configuration")]
    MfaRequiresLoginConfiguration,
    #[error("either configure every AWS KMS MFA runtime value or configure none")]
    PartialMfaConfiguration,
    #[cfg(not(feature = "aws-kms"))]
    #[error("AWS KMS MFA mode was configured but this binary lacks the aws-kms feature")]
    AwsKmsFeatureRequired,
    #[error("Fabric database pool size is invalid: {0}")]
    DatabasePoolSize(#[source] std::num::ParseIntError),
    #[error("Fabric database pool size must be between one and 64")]
    InvalidDatabasePoolSize,
    #[error("Fabric opaque-token digest key must be unpadded URL-safe base64 encoding of exactly 32 bytes")]
    MalformedDigestKey,
    #[error("Fabric password dummy verifier is invalid: {0}")]
    DummyVerifier(#[source] fcp_fabric_auth::PasswordError),
    #[cfg(feature = "aws-kms")]
    #[error("FABRIC_TOTP_ACTIVE_KEY_REFERENCE is invalid: {0}")]
    ActiveTotpKeyReference(#[source] fcp_fabric_auth::TotpError),
    #[cfg(feature = "aws-kms")]
    #[error("generated exact WebAuthn HTTPS origin is invalid: {0}")]
    WebauthnOrigin(#[source] url::ParseError),
    #[cfg(feature = "aws-kms")]
    #[error("WebAuthn origin policy is invalid: {0}")]
    WebauthnPolicy(#[source] fcp_fabric_service::WebauthnServiceError),
    #[cfg(feature = "aws-kms")]
    #[error("WebAuthn service initialization failed: {0}")]
    Webauthn(#[source] fcp_fabric_service::WebauthnServiceError),
    #[cfg(feature = "aws-kms")]
    #[error("Fabric session policy is invalid: {0}")]
    SessionPolicy(#[source] fcp_fabric_service::SessionIssueError),
    #[error("failed to initialize Fabric persistent store: {0}")]
    Store(#[source] fcp_fabric_store::StoreError),
    #[error("failed to bind Fabric loopback listener: {0}")]
    Bind(#[from] std::io::Error),
    #[error("Fabric HTTP server failed: {0}")]
    Serve(#[source] std::io::Error),
}
