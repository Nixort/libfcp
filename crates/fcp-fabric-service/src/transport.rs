// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! HTTP transport boundary for the FCP Fabric service.
//!
//! This module deliberately supplies only a loopback/proxy-friendly router.
//! TLS termination, client-certificate policy and Internet exposure belong to a
//! verified deployment edge; the service rejects unexpected `Host` values and
//! does not enable cross-origin access by default.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self as axum_middleware, Next},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fcp_fabric_domain::{
    AccountId, AdministrationActor, ChangeRole, DomainName, InviteAccount, Localpart, Permission,
    Role,
};
use fcp_fabric_store::{LoginTransactionStage, PostgresAuthorityStore, StoreError};
use libfcp_core::{
    EndpointIdentity, EndpointKey, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tower_http::{catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use uuid::Uuid;

use crate::{
    AccessSessionAuthenticator, AuthenticatedAccessSession, FabricLoginFlow, FabricLoginFlowError,
    FabricLoginStart, FederationDelivery, FederationIngressError, FederationIngressOutcome,
    FederationIngressService, IssueRoleChangeStepUp, IssuedRefreshSession,
    LoginTransactionServiceError, RoleChangeTarget, SessionIssuer, SessionRotationOutcome,
    SessionRotator, SignedFederationDelivery, StepUpIssueOutcome, StepUpService,
    TotpEnrollmentOutcome, TotpEnrollmentService, TotpLoginOutcome, TotpLoginService,
    WebauthnBeginOutcome, WebauthnFinishOutcome, WebauthnService, WebauthnServiceError,
};

/// Largest transport request body accepted before route processing.
pub const MAX_REQUEST_BODY_BYTES: usize = 131_072;
mod admin;
mod auth;
mod browser;
mod federation;
mod middleware;
mod passkeys;
mod session;
#[cfg(test)]
mod tests;

use browser::{
    access_cookie, browser_cookie, clear_login_cookies, clear_step_up_cookie,
    clear_webauthn_cookies, csrf_cookie, csrf_proof_is_valid, generic_login_denial,
    issue_browser_csrf_token, login_cookie, login_flow_denial, passkey_denial, refresh_cookie,
    session_csrf_cookie, session_refresh_denial, step_up_cookie, step_up_required, webauthn_cookie,
};
use middleware::{host_guard, request_correlation, response_security_headers};
use session::{
    administration_actor, authenticate_access, authenticate_admin, issue_browser_session,
    refresh_session,
};

const LOGIN_COOKIE_MAX_AGE_SECONDS: u32 = 300;
const LOGIN_TRANSACTION_COOKIE: &str = "__Host-fabric-login";
const LOGIN_BINDING_COOKIE: &str = "__Host-fabric-binding";
const LOGIN_CSRF_COOKIE: &str = "__Host-fabric-csrf";
const REFRESH_COOKIE: &str = "__Host-fabric-refresh";
const ACCESS_COOKIE: &str = "__Host-fabric-access";
const STEP_UP_COOKIE: &str = "__Secure-fabric-step-up";
const SESSION_CSRF_COOKIE: &str = "__Host-fabric-session-csrf";
const WEBAUTHN_CEREMONY_COOKIE: &str = "__Host-fabric-webauthn";
const WEBAUTHN_BINDING_COOKIE: &str = "__Host-fabric-webauthn-binding";
const WEBAUTHN_CSRF_COOKIE: &str = "__Host-fabric-webauthn-csrf";
const CSRF_HEADER: &str = "x-fabric-csrf";

/// Immutable deployment-owned transport policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FabricTransportConfig {
    public_domain: DomainName,
    enable_hsts: bool,
}

impl FabricTransportConfig {
    /// Creates a single-domain Fabric transport policy with HSTS disabled.
    ///
    /// HSTS is deployment-specific because enabling it for a domain that is not
    /// uniformly HTTPS-capable can make clients unavailable. Production TLS-edge
    /// configurations may opt in explicitly with [`Self::with_hsts`].
    #[must_use]
    pub const fn new(public_domain: DomainName) -> Self {
        Self {
            public_domain,
            enable_hsts: false,
        }
    }

    /// Enables a one-year include-subdomains HSTS response policy.
    #[must_use]
    pub const fn with_hsts(mut self) -> Self {
        self.enable_hsts = true;
        self
    }

    /// Returns the canonical public domain that inbound Host headers must match.
    #[must_use]
    pub const fn public_domain(&self) -> &DomainName {
        &self.public_domain
    }
}

#[derive(Clone)]
struct FabricHttpState {
    transport: FabricTransportConfig,
    login_flow: Option<Arc<FabricLoginFlow>>,
    mfa_session: Option<FabricMfaSessionServices>,
    federation_ingress: Option<FederationIngressService>,
}

/// Explicit dependency set for the authenticated Fabric browser routes.
///
/// All account and tenant identity is derived from opaque server-side state;
/// this bundle contains no client-provided identity fields.
#[derive(Clone)]
pub struct FabricMfaSessionDependencies {
    /// TOTP login proof verifier backed by a KMS/HSM key resolver.
    pub totp_login: Arc<TotpLoginService>,
    /// TOTP enrollment policy backed by a KMS/HSM key resolver.
    pub totp_enrollment: Arc<TotpEnrollmentService>,
    /// Opaque refresh/access session issuer.
    pub session_issuer: Arc<SessionIssuer>,
    /// Atomic opaque refresh credential rotator.
    pub session_rotator: Arc<SessionRotator>,
    /// Server-side opaque access-cookie authenticator.
    pub access_authenticator: Arc<AccessSessionAuthenticator>,
    /// Action-bound privileged mutation step-up service.
    pub step_up: Arc<StepUpService>,
    /// Strict RP-bound `WebAuthn` passkey ceremony service.
    pub webauthn: Arc<WebauthnService>,
}

/// Server-side dependencies for the authenticated TOTP-to-session transition.
///
/// All account and tenant identity comes from a consumed opaque login
/// transaction. The service bundle intentionally contains no client-derived
/// identity fields.
#[derive(Clone)]
pub struct FabricMfaSessionServices {
    store: PostgresAuthorityStore,
    totp_login: Arc<TotpLoginService>,
    totp_enrollment: Arc<TotpEnrollmentService>,
    session_issuer: Arc<SessionIssuer>,
    session_rotator: Arc<SessionRotator>,
    access_authenticator: Arc<AccessSessionAuthenticator>,
    step_up: Arc<StepUpService>,
    webauthn: Arc<WebauthnService>,
}

impl FabricMfaSessionServices {
    /// Creates the authenticated browser route dependencies from explicit parts.
    #[must_use]
    pub fn new(store: PostgresAuthorityStore, dependencies: FabricMfaSessionDependencies) -> Self {
        let FabricMfaSessionDependencies {
            totp_login,
            totp_enrollment,
            session_issuer,
            session_rotator,
            access_authenticator,
            step_up,
            webauthn,
        } = dependencies;
        Self {
            store,
            totp_login,
            totp_enrollment,
            session_issuer,
            session_rotator,
            access_authenticator,
            step_up,
            webauthn,
        }
    }
}

/// Builds the hardened Fabric router without identity routes.
///
/// This is useful for infrastructure probes and deployments which intentionally
/// install identity routes later through [`router_with_login`].
pub fn router(config: FabricTransportConfig) -> Router {
    router_inner(config, None, None, None)
}

/// Builds the hardened Fabric router with the local browser password-login route.
///
/// The route creates an opaque server-bound transaction and two short-lived
/// secure cookies after successful password verification; it never returns
/// account, tenant, role or next-stage data to the caller.
pub fn router_with_login(
    config: FabricTransportConfig,
    login_flow: Arc<FabricLoginFlow>,
) -> Router {
    router_inner(config, Some(login_flow), None, None)
}

/// Builds the hardened router with the complete browser TOTP-to-session flow.
///
/// The caller must have already configured a KMS/HSM-backed [`TotpLoginService`]
/// and a server-side [`SessionIssuer`].
pub fn router_with_mfa_session(
    config: FabricTransportConfig,
    login_flow: Arc<FabricLoginFlow>,
    services: FabricMfaSessionServices,
) -> Router {
    router_inner(config, Some(login_flow), Some(services), None)
}

/// Builds a router for explicitly pinned federation ingress without local identity routes.
pub fn router_with_federation(
    config: FabricTransportConfig,
    federation_ingress: FederationIngressService,
) -> Router {
    router_inner(config, None, None, Some(federation_ingress))
}

/// Builds the full router with local browser identity and explicit federation ingress.
pub fn router_with_mfa_session_and_federation(
    config: FabricTransportConfig,
    login_flow: Arc<FabricLoginFlow>,
    services: FabricMfaSessionServices,
    federation_ingress: FederationIngressService,
) -> Router {
    router_inner(
        config,
        Some(login_flow),
        Some(services),
        Some(federation_ingress),
    )
}

fn router_inner(
    config: FabricTransportConfig,
    login_flow: Option<Arc<FabricLoginFlow>>,
    mfa_session: Option<FabricMfaSessionServices>,
    federation_ingress: Option<FederationIngressService>,
) -> Router {
    let state = Arc::new(FabricHttpState {
        transport: config,
        login_flow,
        mfa_session,
        federation_ingress,
    });
    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/v1/login", post(auth::start_password_login))
        .route("/v1/login/totp", post(auth::complete_totp_login))
        .route(
            "/v1/login/session",
            post(auth::complete_password_only_login),
        )
        .route(
            "/v1/login/passkey/begin",
            post(passkeys::begin_passkey_login),
        )
        .route(
            "/v1/login/passkey/finish",
            post(passkeys::finish_passkey_login),
        )
        .route(
            "/v1/login/enroll/totp/begin",
            post(auth::begin_totp_enrollment),
        )
        .route(
            "/v1/login/enroll/totp/confirm",
            post(auth::confirm_totp_enrollment),
        )
        .route("/v1/session/refresh", post(refresh_session))
        .route("/v1/admin/accounts/invite", post(admin::invite_account))
        .route(
            "/v1/admin/passkeys/begin",
            post(passkeys::begin_passkey_registration),
        )
        .route(
            "/v1/admin/passkeys/finish",
            post(passkeys::finish_passkey_registration),
        )
        .route(
            "/v1/federation/deliver/{request_id}",
            put(federation::deliver_federation),
        )
        .route(
            "/v1/admin/accounts/{account_id}/roles",
            post(admin::change_account_role),
        )
        .route(
            "/v1/admin/accounts/{account_id}/roles/step-up",
            post(admin::begin_role_change_step_up),
        )
        .with_state(state.clone())
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            response_security_headers,
        ))
        .layer(axum_middleware::from_fn(request_correlation))
        .layer(axum_middleware::from_fn_with_state(state, host_guard))
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readiness() -> Json<Readiness> {
    Json(Readiness {
        service: "fcp-fabric",
        status: "transport-ready",
    })
}

#[derive(Serialize)]
struct Readiness {
    service: &'static str,
    status: &'static str,
}
