// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Browser denial responses, cookie construction and CSRF/cookie parsing helpers.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn passkey_denial() -> axum::response::Response {
    let mut response = generic_login_denial();
    clear_webauthn_cookies(response.headers_mut());
    response
}

pub(super) fn generic_login_denial() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(auth::AcceptedLoginResponse { status: "denied" }),
    )
        .into_response()
}

pub(super) fn login_flow_denial() -> axum::response::Response {
    let mut response = generic_login_denial();
    clear_login_cookies(response.headers_mut());
    response
}

pub(super) fn session_refresh_denial() -> axum::response::Response {
    let mut response = generic_login_denial();
    clear_session_cookies(response.headers_mut());
    response
}

pub(super) fn webauthn_cookie(name: &str, value: &str, http_only: bool) -> String {
    let mut cookie = format!(
        "{name}={value}; Path=/; Max-Age={LOGIN_COOKIE_MAX_AGE_SECONDS}; Secure; SameSite=Strict"
    );
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    cookie
}

pub(super) fn login_cookie(name: &str, value: &str) -> String {
    format!(
        "{name}={value}; Path=/; Max-Age={LOGIN_COOKIE_MAX_AGE_SECONDS}; Secure; HttpOnly; SameSite=Strict"
    )
}

pub(super) fn csrf_cookie(value: &str) -> String {
    format!(
        "{LOGIN_CSRF_COOKIE}={value}; Path=/; Max-Age={LOGIN_COOKIE_MAX_AGE_SECONDS}; Secure; SameSite=Strict"
    )
}

pub(super) fn step_up_required() -> axum::response::Response {
    let mut response = StatusCode::PRECONDITION_REQUIRED.into_response();
    clear_step_up_cookie(response.headers_mut());
    response
}

pub(super) fn refresh_cookie(value: &str) -> String {
    format!("{REFRESH_COOKIE}={value}; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict")
}

pub(super) fn step_up_cookie(value: &str) -> String {
    format!("{STEP_UP_COOKIE}={value}; Path=/v1/admin/accounts; Max-Age=300; Secure; HttpOnly; SameSite=Strict")
}

pub(super) fn access_cookie(value: &str) -> String {
    format!("{ACCESS_COOKIE}={value}; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Strict")
}

pub(super) fn session_csrf_cookie(value: &str) -> String {
    format!("{SESSION_CSRF_COOKIE}={value}; Path=/; Max-Age=2592000; Secure; SameSite=Strict")
}

pub(super) fn clear_webauthn_cookies(headers: &mut HeaderMap) {
    for (name, http_only) in [
        (WEBAUTHN_CEREMONY_COOKIE, true),
        (WEBAUTHN_BINDING_COOKIE, true),
        (WEBAUTHN_CSRF_COOKIE, false),
    ] {
        let mut value = format!("{name}=; Path=/; Max-Age=0; Secure; SameSite=Strict");
        if http_only {
            value.push_str("; HttpOnly");
        }
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.append(header::SET_COOKIE, value);
        }
    }
}

pub(super) fn clear_login_cookies(headers: &mut HeaderMap) {
    for (name, http_only) in [
        (LOGIN_TRANSACTION_COOKIE, true),
        (LOGIN_BINDING_COOKIE, true),
        (LOGIN_CSRF_COOKIE, false),
    ] {
        let mut value = format!("{name}=; Path=/; Max-Age=0; Secure; SameSite=Strict");
        if http_only {
            value.push_str("; HttpOnly");
        }
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.append(header::SET_COOKIE, value);
        }
    }
}

pub(super) fn clear_step_up_cookie(headers: &mut HeaderMap) {
    let value = format!(
        "{STEP_UP_COOKIE}=; Path=/v1/admin/accounts; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub(super) fn clear_session_cookies(headers: &mut HeaderMap) {
    for (name, http_only) in [
        (REFRESH_COOKIE, true),
        (ACCESS_COOKIE, true),
        (SESSION_CSRF_COOKIE, false),
    ] {
        let mut value = format!("{name}=; Path=/; Max-Age=0; Secure; SameSite=Strict");
        if http_only {
            value.push_str("; HttpOnly");
        }
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.append(header::SET_COOKIE, value);
        }
    }
}

pub(super) fn issue_browser_csrf_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn browser_cookie(headers: &HeaderMap, name: &str) -> Option<SecretString> {
    let mut matches = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter_map(|pair| pair.split_once('='))
        .filter(|(candidate_name, value)| *candidate_name == name && is_opaque_browser_token(value))
        .map(|(_, value)| value);
    let value = matches.next()?;
    matches
        .next()
        .is_none()
        .then(|| SecretString::from(value.to_owned()))
}

pub(super) fn csrf_proof_is_valid(headers: &HeaderMap, cookie_name: &str) -> bool {
    let Some(cookie) = browser_cookie(headers, cookie_name) else {
        return false;
    };
    headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_opaque_browser_token(value))
        .is_some_and(|value| value == cookie.expose_secret())
}

pub(super) fn is_opaque_browser_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
