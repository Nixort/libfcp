-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    canonical_domain TEXT NOT NULL UNIQUE,
    policy_version BIGINT NOT NULL CHECK (policy_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (canonical_domain = lower(canonical_domain))
);

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    normalized_localpart TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'active', 'mfa_enrollment_required', 'suspended', 'deactivated'
    )),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deactivated_at TIMESTAMPTZ,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, normalized_localpart)
);

CREATE TABLE account_roles (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'auditor', 'member')),
    granted_by_account_id UUID REFERENCES accounts(id) ON DELETE RESTRICT,
    granted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, account_id, role),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE password_credentials (
    account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE RESTRICT,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    phc_verifier TEXT NOT NULL,
    pepper_key_version TEXT,
    changed_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE mfa_totp_factors (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
    seed_ciphertext BYTEA NOT NULL,
    seed_nonce BYTEA NOT NULL CHECK (octet_length(seed_nonce) = 12),
    key_reference TEXT NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('sha256', 'sha512')),
    digits SMALLINT NOT NULL CHECK (digits IN (6, 8)),
    period_seconds SMALLINT NOT NULL CHECK (period_seconds = 30),
    last_accepted_time_step BIGINT,
    created_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX active_mfa_totp_factor_per_account
    ON mfa_totp_factors(tenant_id, account_id) WHERE status = 'active';

CREATE TABLE recovery_code_sets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL,
    invalidated_at TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE recovery_code_verifiers (
    id UUID PRIMARY KEY,
    set_id UUID NOT NULL REFERENCES recovery_code_sets(id) ON DELETE RESTRICT,
    verifier TEXT NOT NULL,
    consumed_at TIMESTAMPTZ,
    UNIQUE (set_id, verifier)
);

CREATE TABLE session_families (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE refresh_credentials (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    family_id UUID NOT NULL REFERENCES session_families(id) ON DELETE RESTRICT,
    token_digest BYTEA NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    replaced_by UUID UNIQUE,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > issued_at)
);

CREATE TABLE federation_peers (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    remote_domain TEXT NOT NULL,
    trust_state TEXT NOT NULL CHECK (trust_state IN ('pending', 'active', 'suspended', 'revoked')),
    expected_key_fingerprint BYTEA NOT NULL,
    policy_version BIGINT NOT NULL CHECK (policy_version >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, remote_domain)
);

CREATE TABLE federation_keys (
    peer_id UUID NOT NULL REFERENCES federation_peers(id) ON DELETE RESTRICT,
    key_id TEXT NOT NULL,
    public_key_document JSONB NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (peer_id, key_id)
);

CREATE TABLE federation_replays (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    peer_id UUID NOT NULL REFERENCES federation_peers(id) ON DELETE RESTRICT,
    request_id UUID NOT NULL,
    body_digest BYTEA NOT NULL CHECK (octet_length(body_digest) = 32),
    accepted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, peer_id, request_id),
    CHECK (expires_at > accepted_at)
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    actor_id UUID REFERENCES accounts(id) ON DELETE RESTRICT,
    action TEXT NOT NULL,
    correlation_id TEXT NOT NULL CHECK (char_length(correlation_id) BETWEEN 1 AND 128),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX audit_events_tenant_time ON audit_events(tenant_id, occurred_at DESC);

CREATE TABLE federation_outbox (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    peer_id UUID NOT NULL REFERENCES federation_peers(id) ON DELETE RESTRICT,
    request_id UUID NOT NULL,
    canonical_request BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, peer_id, request_id)
);
