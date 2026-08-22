// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Server-side passkey authentication ceremony flow.

#[allow(clippy::wildcard_imports)]
use super::*;

impl WebauthnService {
    /// Starts a passkey authentication ceremony for a known local address.
    ///
    /// The supplied address is canonicalized before lookup. Public callers receive
    /// only [`WebauthnBeginOutcome::Denied`] for unknown/unavailable/no-passkey
    /// accounts; no account/tenant/credential identifiers leave this service.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnServiceError`] for persistence, serialization or challenge
    /// construction failure. Non-enrolled/unavailable accounts return generic denial.
    pub async fn begin_authentication(
        &self,
        address: &UserAddress,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<WebauthnBeginOutcome<RequestChallengeResponse>, WebauthnServiceError> {
        if address.domain() != self.policy.rp_domain() {
            return Ok(WebauthnBeginOutcome::Denied);
        }
        let Some(account) = self.store.login_account(address).await? else {
            return Ok(WebauthnBeginOutcome::Denied);
        };
        if !account.state.permits_session() {
            return Ok(WebauthnBeginOutcome::Denied);
        }
        let passkeys = self
            .deserialize_active_passkeys(account.tenant_id, account.account_id)
            .await?;
        if passkeys.is_empty() {
            return Ok(WebauthnBeginOutcome::Denied);
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(WebauthnServiceError::Webauthn)?;
        let state = serde_json::to_value(state).map_err(WebauthnServiceError::Serialization)?;
        let ceremony = self
            .persist_ceremony(
                account.tenant_id,
                account.account_id,
                WebauthnCeremonyKind::Authentication,
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

    /// Completes a passkey authentication ceremony and returns fresh authorization.
    ///
    /// Credential counter and backup-state changes returned by verified library
    /// processing are persisted before a session is issued by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`WebauthnServiceError`] for server-state, cryptographic or
    /// credential-update failure. Wrong/replayed/stage-mismatched ceremony handles
    /// return [`WebauthnFinishOutcome::Denied`] where available.
    pub async fn finish_authentication(
        &self,
        token: &SecretString,
        binding: &SecretString,
        response: &PublicKeyCredential,
        correlation_id: &str,
    ) -> Result<WebauthnFinishOutcome, WebauthnServiceError> {
        let ceremony = self
            .consume_ceremony(token, binding, correlation_id)
            .await?;
        if ceremony.kind != WebauthnCeremonyKind::Authentication {
            return Ok(WebauthnFinishOutcome::Denied);
        }
        let state: PasskeyAuthentication =
            serde_json::from_value(ceremony.state).map_err(WebauthnServiceError::Serialization)?;
        let verification = self
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(WebauthnServiceError::Webauthn)?;
        let credential_id = serde_json::to_value(verification.cred_id())
            .map_err(WebauthnServiceError::Serialization)
            .and_then(json_string)?;
        let mut passkeys = self
            .deserialize_active_passkeys(ceremony.tenant_id, ceremony.account_id)
            .await?;
        let Some(passkey) = passkeys
            .iter_mut()
            .find(|passkey| canonical_credential_id(passkey).is_ok_and(|id| id == credential_id))
        else {
            return Ok(WebauthnFinishOutcome::Denied);
        };
        let _updated = passkey.update_credential(&verification);
        let passkey = serde_json::to_value(passkey).map_err(WebauthnServiceError::Serialization)?;
        match self
            .store
            .update_webauthn_passkey(
                ceremony.tenant_id,
                ceremony.account_id,
                &credential_id,
                &passkey,
            )
            .await
        {
            Ok(()) => {}
            Err(StoreError::TargetNotFoundOrUnchanged) => {
                return Ok(WebauthnFinishOutcome::Denied);
            }
            Err(error) => return Err(WebauthnServiceError::Store(error)),
        }
        let context = self
            .store
            .session_authorization_context(ceremony.tenant_id, ceremony.account_id)
            .await?
            .ok_or(WebauthnServiceError::SessionUnavailable)?;
        Ok(WebauthnFinishOutcome::Authenticated(context))
    }
}
