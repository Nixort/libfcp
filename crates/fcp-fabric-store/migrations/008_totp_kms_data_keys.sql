-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

-- Non-secret envelope metadata for TOTP AES-256 data-encryption keys. The
-- encrypted data key is unusable without the configured external KMS/HSM.
CREATE TABLE totp_data_key_envelopes (
    key_reference VARCHAR(256) PRIMARY KEY,
    provider VARCHAR(32) NOT NULL CHECK (provider IN ('aws_kms')),
    wrapping_key_reference VARCHAR(2048) NOT NULL,
    encrypted_data_key BYTEA NOT NULL CHECK (
        octet_length(encrypted_data_key) BETWEEN 1 AND 6144
    ),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX totp_data_key_envelopes_provider_created_idx
    ON totp_data_key_envelopes (provider, created_at DESC);

COMMENT ON TABLE totp_data_key_envelopes IS
    'KMS/HSM-wrapped TOTP AES-256 data-encryption keys; no plaintext key material.';
COMMENT ON COLUMN totp_data_key_envelopes.key_reference IS
    'Opaque reference persisted with an encrypted TOTP factor.';
COMMENT ON COLUMN totp_data_key_envelopes.wrapping_key_reference IS
    'Explicit KMS key ARN or provider-specific wrapping-key reference.';
COMMENT ON COLUMN totp_data_key_envelopes.encrypted_data_key IS
    'Provider ciphertext blob; plaintext is never persisted.';
