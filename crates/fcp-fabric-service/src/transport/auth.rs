// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Password, TOTP enrollment and local login-completion routes.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Password-stage request body. It intentionally does not implement `Debug`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasswordLoginRequest {
    address: String,
    password: String,
}

#[derive(Serialize)]
pub(super) struct AcceptedLoginResponse {
    pub(super) status: &'static str,
}

/// TOTP-stage request body. It intentionally does not implement `Debug`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TotpLoginRequest {
    code: String,
}

#[derive(Serialize)]
pub(super) struct AuthenticatedLoginResponse {
    pub(super) status: &'static str,
    pub(super) session_expires_at: String,
}

pub(super) async fn start_password_login(
    State(state): State<Arc<FabricHttpState>>,
    Json(request): Json<PasswordLoginRequest>,
) -> axum::response::Response {
    let Some(login_flow) = &state.login_flow else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(address) = fcp_fabric_domain::UserAddress::parse(&request.address) else {
        return generic_login_denial();
    };
    let password = SecretString::from(request.password);
    let correlation_id = format!("http-login-{}", Uuid::now_v7());
    let result = login_flow
        .start_password_login(
            &address,
            &password,
            &correlation_id,
            time::OffsetDateTime::now_utc(),
        )
        .await;
    match result {
        Ok(FabricLoginStart::Denied) => generic_login_denial(),
        Ok(FabricLoginStart::Pending(challenge)) => {
            let transaction = challenge.transaction.token.expose_secret();
            let binding = challenge.binding_token.expose_secret();
            let mut response = (
                StatusCode::ACCEPTED,
                Json(AcceptedLoginResponse { status: "accepted" }),
            )
                .into_response();
            let headers = response.headers_mut();
            let transaction_cookie = login_cookie(LOGIN_TRANSACTION_COOKIE, transaction);
            let binding_cookie = login_cookie(LOGIN_BINDING_COOKIE, binding);
            let csrf_cookie = csrf_cookie(&issue_browser_csrf_token());
            if let (Ok(transaction_cookie), Ok(binding_cookie), Ok(csrf_cookie)) = (
                HeaderValue::from_str(&transaction_cookie),
                HeaderValue::from_str(&binding_cookie),
                HeaderValue::from_str(&csrf_cookie),
            ) {
                headers.append(header::SET_COOKIE, transaction_cookie);
                headers.append(header::SET_COOKIE, binding_cookie);
                headers.append(header::SET_COOKIE, csrf_cookie);
                response
            } else {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "Fabric password login flow failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[derive(Serialize)]
struct TotpProvisioningResponse {
    status: &'static str,
    otpauth_uri: String,
}

pub(super) async fn begin_totp_enrollment(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let (Some(login_flow), Some(services)) = (&state.login_flow, &state.mfa_session) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(transaction_token) = browser_cookie(&headers, LOGIN_TRANSACTION_COOKIE) else {
        return login_flow_denial();
    };
    let Some(binding_token) = browser_cookie(&headers, LOGIN_BINDING_COOKIE) else {
        return login_flow_denial();
    };
    if !csrf_proof_is_valid(&headers, LOGIN_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let correlation_id = format!("http-totp-enroll-begin-{}", Uuid::now_v7());
    let transaction = match login_flow
        .consume_next_step(
            &transaction_token,
            &binding_token,
            LoginTransactionStage::MfaEnrollment,
            &correlation_id,
        )
        .await
    {
        Ok(transaction) => transaction,
        Err(FabricLoginFlowError::Transaction(LoginTransactionServiceError::Store(
            StoreError::InvalidOrExpiredLoginTransaction,
        ))) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP enrollment transaction consumption failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let enrollment = match services
        .totp_enrollment
        .begin(
            transaction.tenant_id,
            transaction.account_id,
            &correlation_id,
        )
        .await
    {
        Ok(enrollment) => enrollment,
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP enrollment creation failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let confirmation = match login_flow
        .begin_totp_enrollment_confirmation(
            transaction.tenant_id,
            transaction.account_id,
            enrollment.factor_id,
            &binding_token,
            &correlation_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(confirmation) => confirmation,
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP enrollment confirmation creation failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let transaction_cookie =
        login_cookie(LOGIN_TRANSACTION_COOKIE, confirmation.token.expose_secret());
    let binding_cookie = login_cookie(LOGIN_BINDING_COOKIE, binding_token.expose_secret());
    let csrf_cookie = csrf_cookie(&issue_browser_csrf_token());
    let (Ok(transaction_cookie), Ok(binding_cookie), Ok(csrf_cookie)) = (
        HeaderValue::from_str(&transaction_cookie),
        HeaderValue::from_str(&binding_cookie),
        HeaderValue::from_str(&csrf_cookie),
    ) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = (
        StatusCode::CREATED,
        Json(TotpProvisioningResponse {
            status: "provisioning",
            otpauth_uri: enrollment.provisioning_uri.expose_secret().to_owned(),
        }),
    )
        .into_response();
    let response_headers = response.headers_mut();
    response_headers.append(header::SET_COOKIE, transaction_cookie);
    response_headers.append(header::SET_COOKIE, binding_cookie);
    response_headers.append(header::SET_COOKIE, csrf_cookie);
    response
}

pub(super) async fn confirm_totp_enrollment(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Json(request): Json<TotpLoginRequest>,
) -> axum::response::Response {
    let (Some(login_flow), Some(services)) = (&state.login_flow, &state.mfa_session) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(transaction_token) = browser_cookie(&headers, LOGIN_TRANSACTION_COOKIE) else {
        return login_flow_denial();
    };
    let Some(binding_token) = browser_cookie(&headers, LOGIN_BINDING_COOKIE) else {
        return login_flow_denial();
    };
    if !csrf_proof_is_valid(&headers, LOGIN_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let correlation_id = format!("http-totp-enroll-confirm-{}", Uuid::now_v7());
    let transaction = match login_flow
        .consume_next_step(
            &transaction_token,
            &binding_token,
            LoginTransactionStage::MfaEnrollment,
            &correlation_id,
        )
        .await
    {
        Ok(transaction) => transaction,
        Err(FabricLoginFlowError::Transaction(LoginTransactionServiceError::Store(
            StoreError::InvalidOrExpiredLoginTransaction,
        ))) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP enrollment confirmation consumption failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let Some(factor_id) = transaction.factor_id else {
        return login_flow_denial();
    };
    let context = match services
        .totp_enrollment
        .confirm(
            transaction.tenant_id,
            transaction.account_id,
            factor_id,
            &request.code,
            &correlation_id,
            time::OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(TotpEnrollmentOutcome::Authenticated(context)) => context,
        Ok(TotpEnrollmentOutcome::Denied) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP enrollment confirmation failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    issue_browser_session(&services.session_issuer, &context, &correlation_id).await
}

pub(super) async fn complete_totp_login(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
    Json(request): Json<TotpLoginRequest>,
) -> axum::response::Response {
    let (Some(login_flow), Some(services)) = (&state.login_flow, &state.mfa_session) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(transaction_token) = browser_cookie(&headers, LOGIN_TRANSACTION_COOKIE) else {
        return login_flow_denial();
    };
    let Some(binding_token) = browser_cookie(&headers, LOGIN_BINDING_COOKIE) else {
        return login_flow_denial();
    };
    if !csrf_proof_is_valid(&headers, LOGIN_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let correlation_id = format!("http-totp-{}", Uuid::now_v7());
    let transaction = match login_flow
        .consume_next_step(
            &transaction_token,
            &binding_token,
            LoginTransactionStage::MfaChallenge,
            &correlation_id,
        )
        .await
    {
        Ok(transaction) => transaction,
        Err(FabricLoginFlowError::Transaction(LoginTransactionServiceError::Store(
            StoreError::InvalidOrExpiredLoginTransaction,
        ))) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP login transaction consumption failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let context = match services
        .totp_login
        .complete(
            transaction.tenant_id,
            transaction.account_id,
            &request.code,
            time::OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(TotpLoginOutcome::Authenticated(context)) => context,
        Ok(TotpLoginOutcome::Denied) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric TOTP verification service failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    issue_browser_session(&services.session_issuer, &context, &correlation_id).await
}

pub(super) async fn complete_password_only_login(
    State(state): State<Arc<FabricHttpState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let (Some(login_flow), Some(services)) = (&state.login_flow, &state.mfa_session) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(transaction_token) = browser_cookie(&headers, LOGIN_TRANSACTION_COOKIE) else {
        return login_flow_denial();
    };
    let Some(binding_token) = browser_cookie(&headers, LOGIN_BINDING_COOKIE) else {
        return login_flow_denial();
    };
    if !csrf_proof_is_valid(&headers, LOGIN_CSRF_COOKIE) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let correlation_id = format!("http-session-{}", Uuid::now_v7());
    let transaction = match login_flow
        .consume_next_step(
            &transaction_token,
            &binding_token,
            LoginTransactionStage::SessionIssuance,
            &correlation_id,
        )
        .await
    {
        Ok(transaction) => transaction,
        Err(FabricLoginFlowError::Transaction(LoginTransactionServiceError::Store(
            StoreError::InvalidOrExpiredLoginTransaction,
        ))) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric session login transaction consumption failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let context = match services
        .store
        .session_authorization_context(transaction.tenant_id, transaction.account_id)
        .await
    {
        Ok(Some(context)) => context,
        Ok(None) => return login_flow_denial(),
        Err(error) => {
            tracing::error!(error = %error, "Fabric session authorization lookup failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    issue_browser_session(&services.session_issuer, &context, &correlation_id).await
}
