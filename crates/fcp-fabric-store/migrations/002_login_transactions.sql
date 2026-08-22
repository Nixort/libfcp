-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

CREATE TABLE login_transactions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    stage TEXT NOT NULL CHECK (stage IN (
        'mfa_enrollment', 'mfa_challenge', 'session_issuance', 'consumed', 'revoked'
    )),
    binding_digest BYTEA NOT NULL CHECK (octet_length(binding_digest) = 32),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > issued_at)
);
CREATE INDEX login_transactions_active_expiry
    ON login_transactions(expires_at)
    WHERE consumed_at IS NULL;
CREATE INDEX login_transactions_account_active
    ON login_transactions(tenant_id, account_id, expires_at)
    WHERE consumed_at IS NULL;
