// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! One-display recovery-code issuance and one-use verification policy.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fcp_fabric_auth::{derive_opaque_token_digest, issue_opaque_token, TokenDigestKey};
use fcp_fabric_domain::{AccountId, TenantId};
use fcp_fabric_store::{PostgresAuthorityStore, StoreError};
use secrecy::SecretString;
use thiserror::Error;

/// Bounded recovery-code inventory policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCodePolicy {
    code_count: usize,
}

impl RecoveryCodePolicy {
    /// Creates a bounded recovery-code policy.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryCodeError::InvalidPolicy`] unless the count lies in the
    /// supported eight-to-sixteen range.
    pub const fn new(code_count: usize) -> Result<Self, RecoveryCodeError> {
        if code_count < 8 || code_count > 16 {
            return Err(RecoveryCodeError::InvalidPolicy);
        }
        Ok(Self { code_count })
    }

    /// Returns the standard ten-code recovery inventory.
    #[must_use]
    pub const fn standard() -> Self {
        Self { code_count: 10 }
    }
}

/// Issues and consumes tenant-local recovery credentials.
#[derive(Clone)]
pub struct RecoveryCodeService {
    store: PostgresAuthorityStore,
    digest_key: TokenDigestKey,
    policy: RecoveryCodePolicy,
}

impl RecoveryCodeService {
    /// Creates the service with a dedicated KMS/HSM-provided HMAC digest key.
    ///
    /// The key must be independent of refresh-token and login-transaction keys.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        digest_key: TokenDigestKey,
        policy: RecoveryCodePolicy,
    ) -> Self {
        Self {
            store,
            digest_key,
            policy,
        }
    }

    /// Replaces the account's recovery inventory and returns raw codes exactly once.
    ///
    /// The caller must show the `codes` only to the already authenticated owner
    /// through a secure display/download flow. They must not be logged, retained
    /// by an application server, delivered by ordinary email, or included in audit
    /// records. The store receives only keyed fixed-width digests.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryCodeError::Store`] when the complete replacement cannot
    /// commit atomically. No raw code is returned on failure.
    pub async fn replace(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        correlation_id: &str,
    ) -> Result<IssuedRecoveryCodes, RecoveryCodeError> {
        let mut codes = Vec::with_capacity(self.policy.code_count);
        let mut verifiers = Vec::with_capacity(self.policy.code_count);
        for _ in 0..self.policy.code_count {
            let issued = issue_opaque_token(&self.digest_key);
            let verifier = URL_SAFE_NO_PAD.encode(issued.digest.as_bytes());
            codes.push(issued.raw);
            verifiers.push(verifier);
        }
        let set = self
            .store
            .replace_recovery_code_set(tenant_id, account_id, &verifiers, correlation_id)
            .await?;
        Ok(IssuedRecoveryCodes {
            codes,
            code_count: set.code_count,
        })
    }

    /// Consumes one recovery code exactly once in its tenant/account scope.
    ///
    /// Callers must map `false` to the same public denial for unknown, expired,
    /// invalidated, already consumed and malformed recovery credentials.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryCodeError::Store`] only for a durable-state failure.
    pub async fn consume(
        &self,
        tenant_id: TenantId,
        account_id: AccountId,
        raw_code: &SecretString,
        correlation_id: &str,
    ) -> Result<bool, RecoveryCodeError> {
        let digest = derive_opaque_token_digest(&self.digest_key, raw_code);
        let verifier = URL_SAFE_NO_PAD.encode(digest.as_bytes());
        self.store
            .consume_recovery_code(tenant_id, account_id, &verifier, correlation_id)
            .await
            .map_err(RecoveryCodeError::Store)
    }
}

/// Sensitive replacement inventory returned one display only.
#[derive(Clone)]
pub struct IssuedRecoveryCodes {
    /// Raw opaque recovery credentials. Never log or persist these values.
    pub codes: Vec<SecretString>,
    /// Number of codes returned in this inventory.
    pub code_count: usize,
}

/// Recovery-code service failure distinct from generic code denial.
#[derive(Debug, Error)]
pub enum RecoveryCodeError {
    /// Supported recovery code count policy was violated.
    #[error("recovery code policy is invalid")]
    InvalidPolicy,
    /// Recovery inventory persistence or consumption failed.
    #[error("recovery code storage failed: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::RecoveryCodePolicy;

    #[test]
    fn standard_policy_has_ten_codes_and_bounds_are_enforced() {
        assert_eq!(
            RecoveryCodePolicy::standard(),
            RecoveryCodePolicy::new(10).expect("valid")
        );
        assert!(RecoveryCodePolicy::new(7).is_err());
        assert!(RecoveryCodePolicy::new(17).is_err());
    }
}
