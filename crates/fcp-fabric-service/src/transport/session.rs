// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Server-side access authentication and browser-session issuance helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) async fn authenticate_access(
    services: &FabricMfaSessionServices,
    headers: &HeaderMap,
) -> Result<AuthenticatedAccessSession, Box<axum::response::Response>> {
    if !csrf_proof_is_valid(headers, SESSION_CSRF_COOKIE) {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    let Some(access_token) = browser_cookie(headers, ACCESS_COOKIE) else {
        return Err(Box::new(session_refresh_denial()));
    };
    match services
        .access_authenticator
        .authenticate(&access_token)
        .await
    {
        Ok(Some(authenticated)) => Ok(authenticated),
        Ok(None) => Err(Box::new(session_refresh_denial())),
        Err(error) => {
            tracing::error!(error = %error, "Fabric access-session authentication failed");
            Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))
        }
    }
}

pub(super) async fn authenticate_admin(
    services: &FabricMfaSessionServices,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<AuthenticatedAccessSession, Box<axum::response::Response>> {
    let authenticated = authenticate_access(services, headers).await?;
    if authenticated.context.require(permission).is_err() {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    Ok(authenticated)
}

pub(super) fn administration_actor(
    authenticated: &AuthenticatedAccessSession,
    step_up_verified: bool,
) -> AdministrationActor {
    AdministrationActor {
        tenant_id: authenticated.context.tenant_id(),
        account_id: authenticated.context.account_id(),
        roles: authenticated.context.roles().to_vec(),
        step_up_verified,
        account_state: authenticated.context.account_state(),
    }
}

pub(super) async fn refresh_session(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(refresh_token) = browser_cookie(&headers, REFRESH_COOKIE) else {
        return session_refresh_denial();
    };
    if !csrf_proof_is_valid(&headers, SESSION_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let correlation_id = format!("http-refresh-{}", Uuid::now_v7());
    match services
        .session_rotator
        .rotate(
            &refresh_token,
            &correlation_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(SessionRotationOutcome::Rotated(session)) => browser_session_response(&session),
        Ok(SessionRotationOutcome::ReuseDetected) => {
            tracing::warn!("Fabric refresh credential reuse detected; session family revoked");
            session_refresh_denial()
        }
        Ok(SessionRotationOutcome::Denied) => session_refresh_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric refresh rotation failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(super) async fn issue_browser_session(
    session_issuer: &SessionIssuer,
    context: &fcp_fabric_domain::AuthorizationContext,
    correlation_id: &str,
) -> axum::response::Response {
    let now = time::OffsetDateTime::now_utc();
    let session = match session_issuer.issue(context, correlation_id, now).await {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(error = %error, "Fabric refresh-session issuance failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut response = browser_session_response(&session);
    clear_login_cookies(response.headers_mut());
    response
}

pub(super) fn browser_session_response(session: &IssuedRefreshSession) -> axum::response::Response {
    let session_expires_at = match session
        .expires_at
        .format(&time::format_description::well_known::Rfc3339)
    {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "Fabric session expiry formatting failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let refresh_cookie = refresh_cookie(session.refresh_token.expose_secret());
    let access_cookie = access_cookie(session.access_token.expose_secret());
    let session_csrf_cookie = session_csrf_cookie(&issue_browser_csrf_token());
    let (Ok(refresh_cookie), Ok(access_cookie), Ok(session_csrf_cookie)) = (
        HeaderValue::from_str(&refresh_cookie),
        HeaderValue::from_str(&access_cookie),
        HeaderValue::from_str(&session_csrf_cookie),
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = (
        StatusCode::OK,
        Json(auth::AuthenticatedLoginResponse {
            status: "authenticated",
            session_expires_at,
        }),
    )
        .into_response();
    let response_headers = response.headers_mut();
    response_headers.append(header::SET_COOKIE, refresh_cookie);
    response_headers.append(header::SET_COOKIE, access_cookie);
    response_headers.append(header::SET_COOKIE, session_csrf_cookie);
    response
}
