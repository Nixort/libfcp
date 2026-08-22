-- Copyright Nixort <https://github.com/Nixort> 2026.
--
-- License: GNU General Public License v3.0 only.
-- You can find the license file in the project root.
--
-- Federated CFR Connect Protocol (FCP).

-- A newly issued recovery set invalidates its predecessor. This partial unique
-- index makes that invariant durable even if a service implementation regresses.
CREATE UNIQUE INDEX active_recovery_code_set_per_account
    ON recovery_code_sets(tenant_id, account_id)
    WHERE invalidated_at IS NULL;
