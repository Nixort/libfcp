// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Host allowlist, correlation and response-header middleware.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) async fn host_guard(
    State(state): State<Arc<FabricHttpState>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let accepted = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(canonical_host)
        .is_some_and(|value| value == state.transport.public_domain().as_str());
    if accepted {
        next.run(request).await
    } else {
        StatusCode::MISDIRECTED_REQUEST.into_response()
    }
}

pub(super) fn canonical_host(value: &str) -> Option<String> {
    let host = match value.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        Some(_) => return None,
        None => value,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || !host.is_ascii() || host.contains(':') {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

pub(super) async fn request_correlation(
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_safe_request_id(value))
        .map_or_else(|| Uuid::now_v7().to_string(), ToOwned::to_owned);
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn is_safe_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) async fn response_security_headers(
    State(state): State<Arc<FabricHttpState>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if state.transport.enable_hsts {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}
