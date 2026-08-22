-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    credential_id TEXT NOT NULL UNIQUE CHECK (char_length(credential_id) BETWEEN 1 AND 2048),
    passkey JSONB NOT NULL,
    label TEXT CHECK (label IS NULL OR char_length(label) BETWEEN 1 AND 96),
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX webauthn_credentials_account_active_idx
    ON webauthn_credentials (tenant_id, account_id)
    WHERE disabled_at IS NULL;

CREATE TABLE webauthn_ceremonies (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
    state JSONB NOT NULL,
    token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    binding_digest BYTEA NOT NULL CHECK (octet_length(binding_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at)
);
CREATE INDEX webauthn_ceremonies_active_token_idx
    ON webauthn_ceremonies (token_digest, expires_at)
    WHERE consumed_at IS NULL;
