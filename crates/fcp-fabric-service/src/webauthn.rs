// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Phishing-resistant `WebAuthn` passkey ceremonies with server-side state.

use fcp_fabric_auth::{derive_opaque_token_digest, issue_opaque_token, TokenDigestKey};
use fcp_fabric_domain::{AccountId, AuthorizationContext, DomainName, TenantId, UserAddress};
use fcp_fabric_store::{
    CreateWebauthnCeremony, PostgresAuthorityStore, RegisterWebauthnPasskey, StoreError,
    WebauthnCeremonyKind,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use url::Url;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder, WebauthnError,
};

const CEREMONY_LIFETIME: Duration = Duration::minutes(5);

mod authentication;
mod policy;
mod registration;
mod types;

pub use policy::WebauthnPolicy;
use types::{canonical_credential_id, json_string, RegistrationCeremonyState};
pub use types::{
    IssuedWebauthnCeremony, WebauthnBeginOutcome, WebauthnFinishOutcome, WebauthnServiceError,
};

/// Safe passkey ceremony service for one Fabric relying-party deployment.
#[derive(Clone)]
pub struct WebauthnService {
    store: PostgresAuthorityStore,
    webauthn: Webauthn,
    policy: WebauthnPolicy,
    ceremony_digest_key: TokenDigestKey,
    binding_digest_key: TokenDigestKey,
}

impl WebauthnService {
    /// Creates the passkey ceremony service.
    ///
    /// `ceremony_digest_key` and `binding_digest_key` must be independent 32-byte
    /// deployment secrets and must not be reused for login, refresh, recovery or
    /// other opaque token classes.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnServiceError::Webauthn`] when the selected exact RP ID
    /// and origin cannot initialize the upstream secure passkey implementation.
    pub fn new(
        store: PostgresAuthorityStore,
        policy: WebauthnPolicy,
        ceremony_digest_key: TokenDigestKey,
        binding_digest_key: TokenDigestKey,
    ) -> Result<Self, WebauthnServiceError> {
        let webauthn = WebauthnBuilder::new(policy.rp_domain().as_str(), policy.origin())
            .map_err(WebauthnServiceError::Webauthn)?
            .rp_name("FCP Fabric")
            .build()
            .map_err(WebauthnServiceError::Webauthn)?;
        Ok(Self {
            store,
            webauthn,
            policy,
            ceremony_digest_key,
            binding_digest_key,
        })
    }

    async fn persist_ceremony(
        &self,
        tenant_id: fcp_fabric_domain::TenantId,
        account_id: AccountId,
        kind: WebauthnCeremonyKind,
        state: &Value,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<IssuedWebauthnCeremony, WebauthnServiceError> {
        let token = issue_opaque_token(&self.ceremony_digest_key);
        let binding = issue_opaque_token(&self.binding_digest_key);
        let expires_at = now + CEREMONY_LIFETIME;
        self.store
            .create_webauthn_ceremony(CreateWebauthnCeremony {
                tenant_id,
                account_id,
                kind,
                state,
                token_digest: &token.digest,
                binding_digest: &binding.digest,
                expires_at,
                correlation_id,
            })
            .await?;
        Ok(IssuedWebauthnCeremony {
            token: token.raw,
            binding: binding.raw,
            expires_at,
        })
    }

    async fn consume_ceremony(
        &self,
        token: &SecretString,
        binding: &SecretString,
        correlation_id: &str,
    ) -> Result<fcp_fabric_store::WebauthnCeremonyRecord, WebauthnServiceError> {
        let token_digest = derive_opaque_token_digest(&self.ceremony_digest_key, token);
        let binding_digest = derive_opaque_token_digest(&self.binding_digest_key, binding);
        self.store
            .consume_webauthn_ceremony(&token_digest, &binding_digest, correlation_id)
            .await
            .map_err(WebauthnServiceError::Store)
    }

    async fn deserialize_active_passkeys(
        &self,
        tenant_id: fcp_fabric_domain::TenantId,
        account_id: AccountId,
    ) -> Result<Vec<Passkey>, WebauthnServiceError> {
        self.store
            .active_webauthn_passkeys(tenant_id, account_id)
            .await?
            .into_iter()
            .map(|record| {
                serde_json::from_value(record.passkey).map_err(WebauthnServiceError::Serialization)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{WebauthnPolicy, WebauthnServiceError};
    use fcp_fabric_domain::DomainName;
    use url::Url;

    #[test]
    fn policy_requires_exact_https_origin_without_relaxations() {
        let domain = DomainName::parse("parley.io").expect("canonical domain");
        let policy = WebauthnPolicy::new(
            domain.clone(),
            Url::parse("https://parley.io/").expect("valid URL"),
        )
        .expect("exact HTTPS origin is allowed");
        assert_eq!(policy.rp_domain(), &domain);

        for origin in [
            "http://parley.io/",
            "https://login.parley.io/",
            "https://parley.io:8443/",
            "https://parley.io/path",
            "https://parley.io/?query=value",
            "https://parley.io/#fragment",
            "https://user@parley.io/",
        ] {
            let error = WebauthnPolicy::new(
                domain.clone(),
                Url::parse(origin).expect("syntactically valid URL"),
            )
            .expect_err("relaxed origin must fail");
            assert!(matches!(error, WebauthnServiceError::InvalidPolicy));
        }
    }
}
