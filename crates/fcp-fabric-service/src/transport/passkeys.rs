// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Strict RP-bound passkey login and self-enrollment routes.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyLoginBeginRequest {
    address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyRegistrationBeginRequest {
    label: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyFinishRequest<T> {
    response: T,
}

pub(super) async fn begin_passkey_login(
    State(state): State<Arc<FabricHttpState>>,
    Json(request): Json<PasskeyLoginBeginRequest>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(address) = fcp_fabric_domain::UserAddress::parse(&request.address) else {
        return passkey_denial();
    };
    let correlation_id = format!("http-passkey-login-begin-{}", Uuid::now_v7());
    match services
        .webauthn
        .begin_authentication(&address, &correlation_id, time::OffsetDateTime::now_utc())
        .await
    {
        Ok(WebauthnBeginOutcome::Denied) => passkey_denial(),
        Ok(WebauthnBeginOutcome::Challenge {
            ceremony,
            challenge,
            ..
        }) => passkey_challenge_response(&ceremony, challenge),
        Err(error) => {
            tracing::error!(error = %error, "Fabric passkey login challenge failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(super) async fn finish_passkey_login(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Json(request): Json<PasskeyFinishRequest<webauthn_rs::prelude::PublicKeyCredential>>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !csrf_proof_is_valid(&headers, WEBAUTHN_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (Some(token), Some(binding)) = (
        browser_cookie(&headers, WEBAUTHN_CEREMONY_COOKIE),
        browser_cookie(&headers, WEBAUTHN_BINDING_COOKIE),
    ) else {
        return passkey_denial();
    };
    let correlation_id = format!("http-passkey-login-finish-{}", Uuid::now_v7());
    match services
        .webauthn
        .finish_authentication(&token, &binding, &request.response, &correlation_id)
        .await
    {
        Ok(WebauthnFinishOutcome::Authenticated(context)) => {
            let mut response =
                issue_browser_session(&services.session_issuer, &context, &correlation_id).await;
            clear_webauthn_cookies(response.headers_mut());
            response
        }
        Ok(WebauthnFinishOutcome::Denied | WebauthnFinishOutcome::Registered)
        | Err(
            WebauthnServiceError::Webauthn(_)
            | WebauthnServiceError::Store(StoreError::InvalidOrExpiredWebauthnCeremony),
        ) => passkey_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric passkey login completion failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(super) async fn begin_passkey_registration(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Json(request): Json<PasskeyRegistrationBeginRequest>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authenticated = match authenticate_access(services, &headers).await {
        Ok(authenticated) => authenticated,
        Err(response) => return *response,
    };
    let correlation_id = format!("http-passkey-registration-begin-{}", Uuid::now_v7());
    match services
        .webauthn
        .begin_registration(
            authenticated.context.tenant_id(),
            authenticated.context.account_id(),
            request.label.as_deref(),
            &correlation_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(WebauthnBeginOutcome::Denied) => StatusCode::FORBIDDEN.into_response(),
        Ok(WebauthnBeginOutcome::Challenge {
            ceremony,
            challenge,
            ..
        }) => passkey_challenge_response(&ceremony, challenge),
        Err(error) => {
            tracing::error!(error = %error, "Fabric passkey registration challenge failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(super) async fn finish_passkey_registration(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Json(request): Json<PasskeyFinishRequest<webauthn_rs::prelude::RegisterPublicKeyCredential>>,
) -> axum::response::Response {
    let Some(services) = &state.mfa_session else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authenticated = match authenticate_access(services, &headers).await {
        Ok(authenticated) => authenticated,
        Err(response) => return *response,
    };
    if !csrf_proof_is_valid(&headers, WEBAUTHN_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (Some(token), Some(binding)) = (
        browser_cookie(&headers, WEBAUTHN_CEREMONY_COOKIE),
        browser_cookie(&headers, WEBAUTHN_BINDING_COOKIE),
    ) else {
        return passkey_denial();
    };
    let correlation_id = format!("http-passkey-registration-finish-{}", Uuid::now_v7());
    match services
        .webauthn
        .finish_registration(
            authenticated.context.tenant_id(),
            authenticated.context.account_id(),
            &token,
            &binding,
            &request.response,
            &correlation_id,
        )
        .await
    {
        Ok(WebauthnFinishOutcome::Registered) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            clear_webauthn_cookies(response.headers_mut());
            response
        }
        Ok(WebauthnFinishOutcome::Denied | WebauthnFinishOutcome::Authenticated(_))
        | Err(
            WebauthnServiceError::Webauthn(_)
            | WebauthnServiceError::Store(StoreError::InvalidOrExpiredWebauthnCeremony),
        ) => passkey_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric passkey registration completion failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

fn passkey_challenge_response<T: Serialize>(
    ceremony: &crate::IssuedWebauthnCeremony,
    challenge: T,
) -> axum::response::Response {
    let csrf = issue_browser_csrf_token();
    let cookies = [
        webauthn_cookie(
            WEBAUTHN_CEREMONY_COOKIE,
            ceremony.token.expose_secret(),
            true,
        ),
        webauthn_cookie(
            WEBAUTHN_BINDING_COOKIE,
            ceremony.binding.expose_secret(),
            true,
        ),
        webauthn_cookie(WEBAUTHN_CSRF_COOKIE, &csrf, false),
    ];
    let Ok(cookies) = cookies
        .iter()
        .map(|cookie| HeaderValue::from_str(cookie))
        .collect::<Result<Vec<_>, _>>()
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = Json(challenge).into_response();
    for cookie in cookies {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}
