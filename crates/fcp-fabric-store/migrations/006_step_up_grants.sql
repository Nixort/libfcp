-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

CREATE TABLE step_up_grants (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    family_id UUID NOT NULL REFERENCES session_families(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 64),
    target_digest BYTEA NOT NULL CHECK (octet_length(target_digest) = 32),
    token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX step_up_grants_active_lookup_idx
    ON step_up_grants (token_digest, expires_at)
    WHERE consumed_at IS NULL;
