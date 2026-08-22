// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Password-stage Fabric login flow that creates server-bound opaque challenges.

use fcp_fabric_auth::{derive_opaque_token_digest, issue_opaque_token, TokenDigestKey};
use fcp_fabric_domain::UserAddress;
use secrecy::SecretString;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    IssuedLoginTransaction, LoginTransactionService, LoginTransactionServiceError,
    LoginTransactionStart, PasswordLoginError, PasswordLoginOutcome, PasswordLoginService,
};

/// Runs the password stage and produces an opaque next-step Fabric challenge.
#[derive(Clone)]
pub struct FabricLoginFlow {
    password_service: PasswordLoginService,
    transaction_service: LoginTransactionService,
    binding_digest_key: TokenDigestKey,
}

impl FabricLoginFlow {
    /// Combines password verification and durable login-transaction issuance.
    #[must_use]
    pub fn new(
        password_service: PasswordLoginService,
        transaction_service: LoginTransactionService,
        binding_digest_key: TokenDigestKey,
    ) -> Self {
        Self {
            password_service,
            transaction_service,
            binding_digest_key,
        }
    }

    /// Authenticates a password and starts the only permitted next local step.
    ///
    /// The caller must set both returned opaque values as Secure/HttpOnly,
    /// `SameSite=Strict` short-lived cookies for browser flows, or place them in
    /// OS-protected native storage. The account address, role set and next stage
    /// are never serialized into the response.
    ///
    /// # Errors
    ///
    /// Returns [`FabricLoginFlowError`] only for a service/store failure.
    /// Invalid credentials return [`FabricLoginStart::Denied`] and do not issue
    /// a client-visible credential.
    pub async fn start_password_login(
        &self,
        address: &UserAddress,
        password: &SecretString,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<FabricLoginStart, FabricLoginFlowError> {
        let outcome = self
            .password_service
            .authenticate(address, password)
            .await?;
        if matches!(outcome, PasswordLoginOutcome::Denied) {
            return Ok(FabricLoginStart::Denied);
        }
        let binding = issue_opaque_token(&self.binding_digest_key);
        let binding_digest = derive_opaque_token_digest(&self.binding_digest_key, &binding.raw);
        let started = self
            .transaction_service
            .begin(outcome, binding_digest.as_bytes(), correlation_id, now)
            .await?;
        match started {
            LoginTransactionStart::Denied => Ok(FabricLoginStart::Denied),
            LoginTransactionStart::Pending(transaction) => {
                Ok(FabricLoginStart::Pending(FabricLoginChallenge {
                    transaction,
                    binding_token: binding.raw,
                }))
            }
        }
    }

    /// Starts one factor-bound TOTP enrollment confirmation transaction.
    ///
    /// The caller must have consumed an `mfa_enrollment` transaction before
    /// calling this method. It presents the same browser binding secret but does
    /// not expose the pending factor identity to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`FabricLoginFlowError`] for persistence failures.
    pub async fn begin_totp_enrollment_confirmation(
        &self,
        tenant_id: fcp_fabric_domain::TenantId,
        account_id: fcp_fabric_domain::AccountId,
        factor_id: uuid::Uuid,
        binding_token: &SecretString,
        correlation_id: &str,
        now: OffsetDateTime,
    ) -> Result<IssuedLoginTransaction, FabricLoginFlowError> {
        let binding_digest = derive_opaque_token_digest(&self.binding_digest_key, binding_token);
        self.transaction_service
            .begin_totp_enrollment_confirmation(
                tenant_id,
                account_id,
                factor_id,
                binding_digest.as_bytes(),
                correlation_id,
                now,
            )
            .await
            .map_err(FabricLoginFlowError::Transaction)
    }

    /// Consumes a one-use transaction after the transport presents both secrets.
    ///
    /// # Errors
    ///
    /// Returns [`FabricLoginFlowError`] for persistence failures. Invalid or
    /// replayed transaction material is returned as the store's generic login
    /// transaction error and must be mapped to one public denial response.
    pub async fn consume_next_step(
        &self,
        transaction_token: &SecretString,
        binding_token: &SecretString,
        expected_stage: fcp_fabric_store::LoginTransactionStage,
        correlation_id: &str,
    ) -> Result<fcp_fabric_store::LoginTransactionRecord, FabricLoginFlowError> {
        let binding_digest = derive_opaque_token_digest(&self.binding_digest_key, binding_token);
        self.transaction_service
            .consume(
                transaction_token,
                expected_stage,
                binding_digest.as_bytes(),
                correlation_id,
            )
            .await
            .map_err(FabricLoginFlowError::Transaction)
    }
}

/// Generic public result of the Fabric password-login endpoint.
#[derive(Clone)]
pub enum FabricLoginStart {
    /// Generic denial; HTTP must use the same response shape for unknown users.
    Denied,
    /// One-time transaction and independent client binding secret.
    Pending(FabricLoginChallenge),
}

/// Sensitive short-lived challenge delivery after successful local password verification.
#[derive(Clone)]
pub struct FabricLoginChallenge {
    /// Opaque next-step credential selected solely by the server-side transaction record.
    pub transaction: IssuedLoginTransaction,
    /// Independent secret bound to the same browser/native flow.
    pub binding_token: SecretString,
}

/// Fabric password-login flow failure distinct from generic public denial.
#[derive(Debug, Error)]
pub enum FabricLoginFlowError {
    /// Password-stage account lookup failed.
    #[error("Fabric password login failed: {0}")]
    Password(#[from] PasswordLoginError),
    /// Durable next-step transaction creation failed.
    #[error("Fabric login transaction creation failed: {0}")]
    Transaction(#[from] LoginTransactionServiceError),
}
