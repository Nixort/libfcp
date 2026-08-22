// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Transport regression tests.

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use fcp_fabric_domain::{DomainName, UserAddress};
use libfcp_core::SigningIdentity;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

use super::middleware::canonical_host;
use super::{
    browser_cookie, federation, login_cookie, router, step_up_cookie, FabricTransportConfig,
    LOGIN_CSRF_COOKIE,
};
use crate::{FederationDelivery, SignedFederationDelivery};

#[test]
fn browser_mutation_requests_reject_unknown_fields() {
    assert!(serde_json::from_str::<super::auth::PasswordLoginRequest>(
            r#"{"address":"benjamin@parley.io","password":"correct horse battery staple","extra":true}"#,
        )
        .is_err());
    assert!(serde_json::from_str::<super::auth::TotpLoginRequest>(
        r#"{"code":"123456","extra":true}"#,
    )
    .is_err());
    assert!(serde_json::from_str::<super::admin::InviteAccountRequest>(
        r#"{"localpart":"alice","initial_role":"member","extra":true}"#,
    )
    .is_err());
    assert!(serde_json::from_str::<super::admin::ChangeRoleRequest>(
        r#"{"role":"member","grant":true,"extra":true}"#,
    )
    .is_err());
    assert!(serde_json::from_str::<super::admin::StepUpRequest>(
        r#"{"code":"123456","role":"member","grant":true,"extra":true}"#,
    )
    .is_err());
}

#[test]
fn canonical_host_rejects_malformed_port_and_normalizes_valid_host() {
    assert_eq!(
        canonical_host("PARLEY.IO.:443"),
        Some("parley.io".to_owned())
    );
    assert_eq!(canonical_host("parley.io:not-a-port"), None);
    assert_eq!(canonical_host("parley.io:"), None);
    assert_eq!(canonical_host("parley.io:443:extra"), None);
}

#[tokio::test]
async fn transport_rejects_wrong_host_and_hardens_accepted_response() {
    let app = router(
        FabricTransportConfig::new(DomainName::parse("parley.io").expect("domain")).with_hsts(),
    );
    let wrong_host = Request::builder()
        .uri("/healthz")
        .header("host", "nextfcp.io")
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(wrong_host).await.expect("response");
    assert_eq!(
        response.status(),
        axum::http::StatusCode::MISDIRECTED_REQUEST
    );

    let valid = Request::builder()
        .uri("/healthz")
        .header("host", "PARLEY.IO")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(valid).await.expect("response");
    assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(response.headers().contains_key("x-request-id"));
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("strict-transport-security")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
}

#[test]
fn federation_wire_decoder_preserves_real_hybrid_signed_delivery() {
    let signing_identity = SigningIdentity::new(
        SigningKey::from_bytes(&[9; 32]),
        MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from([9; 32])),
    );
    let now = OffsetDateTime::now_utc();
    let delivery_record = SignedFederationDelivery::sign(
        &signing_identity,
        FederationDelivery {
            source_domain: DomainName::parse("nextfcp.io").expect("source"),
            destination_domain: DomainName::parse("parley.io").expect("destination"),
            sender: UserAddress::parse("alice@nextfcp.io").expect("sender"),
            recipient: UserAddress::parse("benjamin@parley.io").expect("recipient"),
            request_id: Uuid::now_v7(),
            issued_at: now,
            expires_at: now + Duration::minutes(2),
            payload: b"verified FCP application signal".to_vec(),
        },
    )
    .expect("sign");
    let request = federation::FederationDeliveryRequest {
        source_domain: delivery_record.delivery.source_domain.to_string(),
        destination_domain: delivery_record.delivery.destination_domain.to_string(),
        sender: delivery_record.delivery.sender.to_string(),
        recipient: delivery_record.delivery.recipient.to_string(),
        request_id: delivery_record.delivery.request_id.to_string(),
        issued_at: delivery_record
            .delivery
            .issued_at
            .format(&time::format_description::well_known::Rfc3339)
            .expect("timestamp"),
        expires_at: delivery_record
            .delivery
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .expect("timestamp"),
        payload: URL_SAFE_NO_PAD.encode(&delivery_record.delivery.payload),
        classical_public_key: URL_SAFE_NO_PAD
            .encode(delivery_record.authority_identity.classical.as_bytes()),
        post_quantum_public_key: URL_SAFE_NO_PAD
            .encode(delivery_record.authority_identity.post_quantum),
        classical_signature: URL_SAFE_NO_PAD.encode(delivery_record.classical_signature),
        post_quantum_signature: URL_SAFE_NO_PAD.encode(delivery_record.post_quantum_signature),
    };
    let decoded = request.into_signed().expect("decode");
    decoded
        .verify(signing_identity.endpoint())
        .expect("both FCP signatures remain valid");
    assert_eq!(decoded.delivery, delivery_record.delivery);
}

#[test]
fn federation_wire_decoder_rejects_wrong_fixed_identity_width() {
    let request = federation::FederationDeliveryRequest {
        source_domain: "nextfcp.io".to_owned(),
        destination_domain: "parley.io".to_owned(),
        sender: "alice@nextfcp.io".to_owned(),
        recipient: "benjamin@parley.io".to_owned(),
        request_id: Uuid::now_v7().to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_owned(),
        expires_at: "2026-01-01T00:01:00Z".to_owned(),
        payload: URL_SAFE_NO_PAD.encode(b"payload"),
        classical_public_key: URL_SAFE_NO_PAD.encode([0_u8; 31]),
        post_quantum_public_key: URL_SAFE_NO_PAD.encode([0_u8; 1_952]),
        classical_signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
        post_quantum_signature: URL_SAFE_NO_PAD.encode([0_u8; 3_309]),
    };
    assert!(request.into_signed().is_err());
}

#[test]
fn login_cookie_is_host_only_secure_and_short_lived() {
    let cookie = login_cookie("__Host-fabric-login", "opaque-value");
    assert!(cookie.starts_with("__Host-fabric-login=opaque-value; Path=/"));
    assert!(cookie.contains("Max-Age=300"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(!cookie.contains("Domain="));
}

#[test]
fn step_up_cookie_is_secure_and_admin_path_scoped() {
    let cookie = step_up_cookie("opaque-value");
    assert!(cookie.starts_with("__Secure-fabric-step-up=opaque-value; Path=/v1/admin/accounts"));
    assert!(cookie.contains("Max-Age=300"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(!cookie.contains("Domain="));
}

#[test]
fn browser_cookie_rejects_duplicate_sensitive_name() {
    let token = "a".repeat(43);
    let mut headers = HeaderMap::new();
    let cookie = format!("{LOGIN_CSRF_COOKIE}={token}; {LOGIN_CSRF_COOKIE}={token}");
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie).expect("valid cookie header"),
    );
    assert!(browser_cookie(&headers, LOGIN_CSRF_COOKIE).is_none());
}
