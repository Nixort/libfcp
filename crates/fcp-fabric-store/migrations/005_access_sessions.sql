-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

CREATE TABLE access_sessions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    family_id UUID NOT NULL REFERENCES session_families(id) ON DELETE RESTRICT,
    token_digest BYTEA NOT NULL CHECK (octet_length(token_digest) = 32),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    UNIQUE (token_digest),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX access_sessions_active_lookup_idx
    ON access_sessions (token_digest, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX access_sessions_family_idx
    ON access_sessions (family_id)
    WHERE revoked_at IS NULL;
