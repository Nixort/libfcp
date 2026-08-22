// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Durable admission boundary for signed inbound federation deliveries.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fcp_fabric_domain::{DomainName, TenantId};
use fcp_fabric_store::{
    PostgresAuthorityStore, RecordFederationReplay, StoreError, StoredFederationKeyMaterial,
};
use libfcp_core::{EndpointIdentity, EndpointKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{FederationError, RemotePeerPolicy, SignedFederationDelivery};

/// Independently resolved remote peer policy and durable local peer identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedFederationPeer {
    /// Local tenant owning the destination Fabric domain.
    pub tenant_id: TenantId,
    /// Durable explicitly pinned remote peer record.
    pub peer_id: Uuid,
    /// Active remote-domain trust and hybrid identity policy.
    pub policy: RemotePeerPolicy,
}

/// Resolves local destination and remote source domains to explicit pinned policy.
#[async_trait]
pub trait FederationPeerPolicyResolver: Send + Sync {
    /// Returns the locally approved policy for exactly this destination/source pair.
    ///
    /// `None` means the peer is not approved. Implementations must not perform
    /// automatic unauthenticated discovery or silently accept a new key here.
    async fn resolve(
        &self,
        local_domain: &DomainName,
        remote_domain: &DomainName,
    ) -> Result<Option<ResolvedFederationPeer>, FederationIngressError>;
}

/// PostgreSQL adapter for explicit local federation peer policy.
///
/// It accepts only current non-retired key documents whose complete identity
/// matches the tenant-owner-pinned fingerprint. It never queries remote DNS,
/// fetches a remote key document, or auto-activates a presented identity.
#[derive(Clone)]
pub struct PostgresFederationPeerPolicyResolver {
    store: PostgresAuthorityStore,
}

impl PostgresFederationPeerPolicyResolver {
    /// Creates a resolver over the Fabric PostgreSQL persistence boundary.
    #[must_use]
    pub const fn new(store: PostgresAuthorityStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl FederationPeerPolicyResolver for PostgresFederationPeerPolicyResolver {
    async fn resolve(
        &self,
        local_domain: &DomainName,
        remote_domain: &DomainName,
    ) -> Result<Option<ResolvedFederationPeer>, FederationIngressError> {
        let Some(material) = self
            .store
            .federation_peer_material(local_domain, remote_domain)
            .await
            .map_err(FederationIngressError::Store)?
        else {
            return Ok(None);
        };
        let expected_fingerprint: [u8; 32] = material
            .expected_key_fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| FederationIngressError::Resolver)?;
        let Some(identity) = material
            .keys
            .iter()
            .find_map(parse_pinned_identity)
            .filter(|identity| identity_fingerprint(identity) == expected_fingerprint)
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedFederationPeer {
            tenant_id: material.tenant_id,
            peer_id: material.peer_id,
            policy: RemotePeerPolicy {
                local_domain: local_domain.clone(),
                remote_domain: remote_domain.clone(),
                trust_state: material.trust_state,
                active_authority_identity: identity,
            },
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEndpointIdentityDocument {
    classical_public_key: String,
    post_quantum_public_key: String,
}

fn parse_pinned_identity(key: &StoredFederationKeyMaterial) -> Option<EndpointIdentity> {
    let document: StoredEndpointIdentityDocument =
        serde_json::from_value(key.public_key_document.clone()).ok()?;
    let classical = decode_fixed(&document.classical_public_key)?;
    let post_quantum = decode_fixed(&document.post_quantum_public_key)?;
    Some(EndpointIdentity::new(
        EndpointKey::from_bytes(classical),
        post_quantum,
    ))
}

fn identity_fingerprint(identity: &EndpointIdentity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"fcp-fabric/federation/identity-fingerprint/v1\0");
    hasher.update(identity.classical.as_bytes());
    hasher.update(identity.post_quantum);
    hasher.finalize().into()
}

fn decode_fixed<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

/// Admits dual-signed remote federation deliveries before application dispatch.
#[derive(Clone)]
pub struct FederationIngressService {
    store: PostgresAuthorityStore,
    policy_resolver: Arc<dyn FederationPeerPolicyResolver>,
}

impl FederationIngressService {
    /// Creates ingress admission with explicit trust-policy resolution.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        policy_resolver: Arc<dyn FederationPeerPolicyResolver>,
    ) -> Self {
        Self {
            store,
            policy_resolver,
        }
    }

    /// Verifies, admits, and atomically replay-records one inbound delivery.
    ///
    /// A successful result is durable security admission only. Application payload
    /// dispatch belongs to a later transactional inbox/outbox phase; callers must
    /// not infer that the opaque payload has been executed or delivered locally.
    ///
    /// # Errors
    ///
    /// Returns [`FederationIngressError::Rejected`] for unknown/untrusted peers,
    /// domain/identity/freshness/signature failures, and [`FederationIngressError`]
    /// for resolver or persistence infrastructure failures.
    pub async fn admit(
        &self,
        signed: &SignedFederationDelivery,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<FederationIngressOutcome, FederationIngressError> {
        let delivery = &signed.delivery;
        let Some(peer) = self
            .policy_resolver
            .resolve(&delivery.destination_domain, &delivery.source_domain)
            .await?
        else {
            return Err(FederationIngressError::Rejected);
        };
        peer.policy
            .admit(now, signed)
            .map_err(|error| FederationIngressError::Policy(Box::new(error)))?;
        let body_digest = signed
            .canonical_body_digest()
            .map_err(|error| FederationIngressError::Policy(Box::new(error)))?;
        let inserted = self
            .store
            .record_federation_replay(RecordFederationReplay {
                tenant_id: peer.tenant_id,
                peer_id: peer.peer_id,
                request_id: delivery.request_id,
                body_digest: &body_digest,
                expires_at: delivery.expires_at,
                correlation_id,
            })
            .await?;
        Ok(if inserted {
            FederationIngressOutcome::Accepted
        } else {
            FederationIngressOutcome::Replay
        })
    }
}

/// Non-secret durable admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationIngressOutcome {
    /// The verified request ID was newly recorded for this tenant/peer.
    Accepted,
    /// A request ID for this tenant/peer was already recorded and was not re-admitted.
    Replay,
}

/// Federation ingress failure distinct from a normal duplicate replay result.
#[derive(Debug, Error)]
pub enum FederationIngressError {
    /// Resolver infrastructure failed without exposing trust/key detail.
    #[error("federation peer policy resolution failed")]
    Resolver,
    /// Signed delivery failed local explicit trust, binding, freshness or signature policy.
    #[error("federation delivery was rejected")]
    Rejected,
    /// Signed delivery policy parsing or hybrid signature verification failed.
    #[error("federation delivery policy evaluation failed: {0}")]
    Policy(#[source] Box<FederationError>),
    /// Replay evidence or audit persistence failed.
    #[error("federation replay persistence failed: {0}")]
    Store(#[from] StoreError),
}
