// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Signed federation ingress wire contract and delivery route.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FederationDeliveryRequest {
    pub(super) source_domain: String,
    pub(super) destination_domain: String,
    pub(super) sender: String,
    pub(super) recipient: String,
    pub(super) request_id: String,
    pub(super) issued_at: String,
    pub(super) expires_at: String,
    pub(super) payload: String,
    pub(super) classical_public_key: String,
    pub(super) post_quantum_public_key: String,
    pub(super) classical_signature: String,
    pub(super) post_quantum_signature: String,
}

impl FederationDeliveryRequest {
    pub(super) fn into_signed(self) -> Result<SignedFederationDelivery, ()> {
        let source_domain = DomainName::parse(&self.source_domain).map_err(|_| ())?;
        let destination_domain = DomainName::parse(&self.destination_domain).map_err(|_| ())?;
        let sender = fcp_fabric_domain::UserAddress::parse(&self.sender).map_err(|_| ())?;
        let recipient = fcp_fabric_domain::UserAddress::parse(&self.recipient).map_err(|_| ())?;
        let request_id = Uuid::parse_str(&self.request_id).map_err(|_| ())?;
        let issued_at = time::OffsetDateTime::parse(
            &self.issued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ())?;
        let expires_at = time::OffsetDateTime::parse(
            &self.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| ())?;
        let payload = URL_SAFE_NO_PAD.decode(self.payload).map_err(|_| ())?;
        let classical = EndpointKey::from_bytes(decode_fixed(&self.classical_public_key)?);
        let post_quantum =
            decode_fixed::<ML_DSA_65_PUBLIC_KEY_BYTES>(&self.post_quantum_public_key)?;
        let classical_signature = decode_fixed(&self.classical_signature)?;
        let post_quantum_signature =
            decode_fixed::<ML_DSA_65_SIGNATURE_BYTES>(&self.post_quantum_signature)?;
        Ok(SignedFederationDelivery {
            delivery: FederationDelivery {
                source_domain,
                destination_domain,
                sender,
                recipient,
                request_id,
                issued_at,
                expires_at,
                payload,
            },
            authority_identity: EndpointIdentity::new(classical, post_quantum),
            classical_signature,
            post_quantum_signature,
        })
    }
}

pub(super) async fn deliver_federation(
    State(state): State<Arc<FabricHttpState>>,
    Path(request_id): Path<String>,
    Json(request): Json<FederationDeliveryRequest>,
) -> axum::response::Response {
    let Some(ingress) = &state.federation_ingress else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(request_id) = Uuid::parse_str(&request_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let signed = match request.into_signed() {
        Ok(signed) if signed.delivery.request_id == request_id => signed,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let correlation_id = format!("http-federation-{}", Uuid::now_v7());
    match ingress
        .admit(&signed, &correlation_id, time::OffsetDateTime::now_utc())
        .await
    {
        Ok(FederationIngressOutcome::Accepted) => StatusCode::ACCEPTED.into_response(),
        Ok(FederationIngressOutcome::Replay) => StatusCode::CONFLICT.into_response(),
        Err(FederationIngressError::Rejected | FederationIngressError::Policy(_)) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        Err(FederationIngressError::Resolver | FederationIngressError::Store(_)) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], ()> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    decoded.try_into().map_err(|_| ())
}
