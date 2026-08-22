// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Server-side passkey registration ceremony flow.

#[allow(clippy::wildcard_imports)]
use super::*;

impl WebauthnService {
    /// Starts a new passkey-registration ceremony for a verified local account.
    ///
    /// The account address, existing credential exclusions and tenant scope are
    /// always loaded from server state. The returned opaque handle and binding are
    /// references to server-side state only; neither contains a challenge.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnServiceError`] for persisted-state, serialization or
    /// challenge-construction failure. Unavailable/wrong-domain accounts return
    /// [`WebauthnBeginOutcome::Denied`].
    pub async fn begin_registration(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        label: Option<&str>,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<WebauthnBeginOutcome<CreationChallengeResponse>, WebauthnServiceError> {
        let Some(address) = self
            .store
            .user_address_for_account(tenant_id, account_id)
            .await?
        else {
            return Ok(WebauthnBeginOutcome::Denied);
        };
        if address.domain() != self.policy.rp_domain() {
            return Ok(WebauthnBeginOutcome::Denied);
        }
        let existing = self
            .deserialize_active_passkeys(tenant_id, account_id)
            .await?;
        let exclusions = existing
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(
                account_id.as_uuid(),
                &address.to_string(),
                &address.to_string(),
                Some(exclusions),
            )
            .map_err(WebauthnServiceError::Webauthn)?;
        let state = serde_json::to_value(RegistrationCeremonyState {
            state,
            label: label.map(str::to_owned),
        })
        .map_err(WebauthnServiceError::Serialization)?;
        let ceremony = self
            .persist_ceremony(
                tenant_id,
                account_id,
                WebauthnCeremonyKind::Registration,
                &state,
                correlation_id,
                now,
            )
            .await?;
        Ok(WebauthnBeginOutcome::Challenge {
            ceremony,
            challenge,
            label: None,
        })
    }

    /// Completes a previously issued passkey-registration ceremony once.
    ///
    /// The state is atomically consumed before credential processing. The caller
    /// supplies the current authenticated tenant/account, which must match the
    /// persisted ceremony before a credential can be registered. The verified
    /// credential is persisted with a global credential-ID uniqueness constraint.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnServiceError`] for server-state, cryptographic, duplicate
    /// credential or persistence failure. Wrong/replayed/stage-mismatched ceremony
    /// handles return [`WebauthnFinishOutcome::Denied`] where available.
    pub async fn finish_registration(
        &self,
        expected_tenant_id: TenantId,
        expected_account_id: AccountId,
        token: &SecretString,
        binding: &SecretString,
        response: &RegisterPublicKeyCredential,
        correlation_id: &str,
    ) -> Result<WebauthnFinishOutcome, WebauthnServiceError> {
        let ceremony = self
            .consume_ceremony(token, binding, correlation_id)
            .await?;
        if ceremony.kind != WebauthnCeremonyKind::Registration
            || ceremony.tenant_id != expected_tenant_id
            || ceremony.account_id != expected_account_id
        {
            return Ok(WebauthnFinishOutcome::Denied);
        }
        let state: RegistrationCeremonyState =
            serde_json::from_value(ceremony.state).map_err(WebauthnServiceError::Serialization)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state.state)
            .map_err(WebauthnServiceError::Webauthn)?;
        let credential_id = canonical_credential_id(&passkey)?;
        let passkey = serde_json::to_value(passkey).map_err(WebauthnServiceError::Serialization)?;
        self.store
            .register_webauthn_passkey(RegisterWebauthnPasskey {
                tenant_id: ceremony.tenant_id,
                account_id: ceremony.account_id,
                credential_id: &credential_id,
                passkey: &passkey,
                label: state.label.as_deref(),
                correlation_id,
            })
            .await?;
        Ok(WebauthnFinishOutcome::Registered)
    }
}
