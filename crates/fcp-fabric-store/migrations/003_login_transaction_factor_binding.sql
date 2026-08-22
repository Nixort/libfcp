-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

-- A TOTP enrollment confirmation transaction is bound to exactly the pending
-- factor created during the one-display provisioning step. Browser input never
-- identifies a factor, tenant or account.
ALTER TABLE login_transactions
    ADD COLUMN factor_id UUID NULL;

CREATE INDEX login_transactions_pending_factor_idx
    ON login_transactions (tenant_id, account_id, factor_id)
    WHERE consumed_at IS NULL AND factor_id IS NOT NULL;
