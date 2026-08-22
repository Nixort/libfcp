// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! AWS KMS envelope-key provider for encrypted TOTP seeds.
//!
//! Each newly enrolled factor uses a fresh AES-256 data-encryption key from
//! `GenerateDataKey`. Fabric persists only the KMS ciphertext blob and an opaque
//! key reference. Resolution uses `Decrypt` with the exact authenticated
//! encryption context. The KMS client uses the standard AWS credential provider
//! chain, so production deployments should prefer workload identity instead of
//! long-lived static credentials.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::{primitives::Blob, types::DataKeySpec, Client};
use fcp_fabric_auth::{TotpDataEncryptionKey, TotpKeyReference};
use fcp_fabric_store::{CreateTotpDataKeyEnvelope, PostgresAuthorityStore, StoreError};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    ActiveTotpEncryptionKey, TotpEnrollmentKeyProvider, TotpKeyResolutionError, TotpKeyResolver,
};

const PROVIDER: &str = "aws_kms";
const CONTEXT_PURPOSE_KEY: &str = "fcp-fabric-purpose";
const CONTEXT_PURPOSE_VALUE: &str = "totp-data-key/v1";
const CONTEXT_REFERENCE_KEY: &str = "fcp-fabric-key-reference";

/// AWS KMS-backed resolver and active-key provider for TOTP AES-256 data keys.
///
/// The active opaque reference must already identify an envelope row produced by
/// [`Self::provision_data_key`]. Updating the active reference and rolling the
/// service creates a forward-only data-key rotation: existing factor references
/// continue to decrypt with their original envelope.
#[derive(Clone)]
pub struct AwsKmsTotpKeyProvider {
    store: PostgresAuthorityStore,
    client: Client,
    active_reference: TotpKeyReference,
}

impl AwsKmsTotpKeyProvider {
    /// Creates a provider from an explicitly configured AWS KMS client.
    #[must_use]
    pub fn new(
        store: PostgresAuthorityStore,
        client: Client,
        active_reference: TotpKeyReference,
    ) -> Self {
        Self {
            store,
            client,
            active_reference,
        }
    }

    /// Creates a provider using the standard AWS credential and Region chain.
    ///
    /// Workload identity is preferred. This constructor intentionally accepts no
    /// access-key arguments and never reads or logs credential values itself.
    pub async fn from_default_environment(
        store: PostgresAuthorityStore,
        active_reference: TotpKeyReference,
    ) -> Self {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        Self::new(store, Client::new(&config), active_reference)
    }

    /// Generates and stores a fresh AES-256 KMS-wrapped data key envelope.
    ///
    /// The returned opaque reference is suitable for a future provider instance
    /// after the deployment configuration has been updated and rolled. It is not
    /// a plaintext key and does not expose KMS credentials or key material.
    ///
    /// # Errors
    ///
    /// Returns [`TotpKeyResolutionError`] when the KMS request, stored envelope
    /// contract or the supplied wrapping key reference is unavailable or invalid.
    pub async fn provision_data_key(
        store: &PostgresAuthorityStore,
        client: &Client,
        wrapping_key_reference: &str,
        now: OffsetDateTime,
    ) -> Result<TotpKeyReference, TotpKeyResolutionError> {
        validate_wrapping_key_reference(wrapping_key_reference)?;
        let reference = TotpKeyReference::new(format!("aws-kms:totp-dek:{}", Uuid::now_v7()))
            .map_err(|_| TotpKeyResolutionError::ProviderFailure)?;
        let output = client
            .generate_data_key()
            .key_id(wrapping_key_reference)
            .key_spec(DataKeySpec::Aes256)
            .set_encryption_context(Some(encryption_context(&reference)))
            .send()
            .await
            .map_err(|_| TotpKeyResolutionError::Unavailable)?;
        let key = data_key_from_plaintext(
            output
                .plaintext()
                .ok_or(TotpKeyResolutionError::ProviderFailure)?
                .as_ref(),
        )?;
        let ciphertext = output
            .ciphertext_blob()
            .ok_or(TotpKeyResolutionError::ProviderFailure)?
            .as_ref()
            .to_vec();
        if ciphertext.is_empty() || ciphertext.len() > 6144 {
            return Err(TotpKeyResolutionError::ProviderFailure);
        }
        store
            .create_totp_data_key_envelope(CreateTotpDataKeyEnvelope {
                key_reference: &reference,
                provider: PROVIDER,
                wrapping_key_reference,
                encrypted_data_key: &ciphertext,
                created_at: now,
            })
            .await
            .map_err(|error| map_store_error(&error))?;
        // The service copies the AES-256 plaintext into `TotpDataEncryptionKey`,
        // whose inner representation is zeroizing. The SDK-owned response is not
        // persisted; this layer makes no stronger zeroization claim for it.
        drop(key);
        Ok(reference)
    }

    async fn resolve_envelope_key(
        &self,
        reference: &TotpKeyReference,
    ) -> Result<TotpDataEncryptionKey, TotpKeyResolutionError> {
        let envelope = self
            .store
            .totp_data_key_envelope(reference)
            .await
            .map_err(|error| map_store_error(&error))?
            .ok_or(TotpKeyResolutionError::Unavailable)?;
        if envelope.provider != PROVIDER {
            return Err(TotpKeyResolutionError::Unavailable);
        }
        let output = self
            .client
            .decrypt()
            .key_id(envelope.wrapping_key_reference)
            .ciphertext_blob(Blob::new(envelope.encrypted_data_key))
            .set_encryption_context(Some(encryption_context(reference)))
            .send()
            .await
            .map_err(|_| TotpKeyResolutionError::Unavailable)?;
        data_key_from_plaintext(
            output
                .plaintext()
                .ok_or(TotpKeyResolutionError::ProviderFailure)?
                .as_ref(),
        )
    }
}

#[async_trait]
impl TotpKeyResolver for AwsKmsTotpKeyProvider {
    async fn resolve(
        &self,
        reference: &TotpKeyReference,
    ) -> Result<TotpDataEncryptionKey, TotpKeyResolutionError> {
        self.resolve_envelope_key(reference).await
    }
}

#[async_trait]
impl TotpEnrollmentKeyProvider for AwsKmsTotpKeyProvider {
    async fn active_key(&self) -> Result<ActiveTotpEncryptionKey, TotpKeyResolutionError> {
        let key = self.resolve_envelope_key(&self.active_reference).await?;
        Ok(ActiveTotpEncryptionKey {
            reference: self.active_reference.clone(),
            key,
        })
    }
}

fn encryption_context(reference: &TotpKeyReference) -> HashMap<String, String> {
    HashMap::from([
        (
            CONTEXT_PURPOSE_KEY.to_owned(),
            CONTEXT_PURPOSE_VALUE.to_owned(),
        ),
        (
            CONTEXT_REFERENCE_KEY.to_owned(),
            reference.as_str().to_owned(),
        ),
    ])
}

fn validate_wrapping_key_reference(value: &str) -> Result<(), TotpKeyResolutionError> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        Err(TotpKeyResolutionError::ProviderFailure)
    } else {
        Ok(())
    }
}

fn data_key_from_plaintext(
    plaintext: &[u8],
) -> Result<TotpDataEncryptionKey, TotpKeyResolutionError> {
    let mut material = plaintext.to_vec();
    let key_bytes: [u8; 32] = material
        .as_slice()
        .try_into()
        .map_err(|_| TotpKeyResolutionError::ProviderFailure)?;
    material.zeroize();
    Ok(TotpDataEncryptionKey::from_bytes(key_bytes))
}

fn map_store_error(error: &StoreError) -> TotpKeyResolutionError {
    match error {
        StoreError::InvalidTotpDataKeyEnvelope => TotpKeyResolutionError::ProviderFailure,
        _ => TotpKeyResolutionError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kms_encryption_context_is_reference_bound_and_non_secret() {
        let reference = TotpKeyReference::new("aws-kms:totp-dek:example".to_owned())
            .expect("bounded opaque reference");
        let context = encryption_context(&reference);
        assert_eq!(
            context.get(CONTEXT_PURPOSE_KEY),
            Some(&CONTEXT_PURPOSE_VALUE.to_owned())
        );
        assert_eq!(
            context.get(CONTEXT_REFERENCE_KEY),
            Some(&"aws-kms:totp-dek:example".to_owned())
        );
        assert_eq!(context.len(), 2);
    }

    #[test]
    fn plaintext_data_key_requires_exact_aes_256_width() {
        assert!(data_key_from_plaintext(&[7_u8; 32]).is_ok());
        assert!(data_key_from_plaintext(&[7_u8; 31]).is_err());
        assert!(data_key_from_plaintext(&[7_u8; 33]).is_err());
    }

    #[test]
    fn wrapping_key_reference_is_bounded_safe_text() {
        assert!(validate_wrapping_key_reference("arn:aws:kms:us-east-1:123:key/example").is_ok());
        assert!(validate_wrapping_key_reference("").is_err());
        assert!(validate_wrapping_key_reference("invalid\nreference").is_err());
    }
}
