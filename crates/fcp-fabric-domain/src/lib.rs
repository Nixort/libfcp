// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Typed FCP Fabric domain invariants for organizations and federation.
//!
//! Local human accounts, tenant authorization and remote federation identities
//! are intentionally distinct. No public type in this crate carries a
//! password, session token, TOTP secret, SQL connection or HTTP request.

mod administration;
mod audit;
mod identity;
mod ids;
mod policy;

pub use administration::{
    AdministrationActor, AdministrationError, BootstrapResult, BootstrapTenant, ChangeRole,
    InviteAccount,
};
pub use audit::{AuditAction, AuditEvent};
pub use identity::{
    DomainError, DomainName, Localpart, LocalpartError, UserAddress, UserAddressError,
};
pub use ids::{AccountId, AuditEventId, PolicyVersion, PolicyVersionError, TenantId};
pub use policy::{
    AccountState, AuthorizationContext, AuthorizationError, FederationTrustState, Permission, Role,
};

#[cfg(test)]
mod tests {
    use super::{
        AccountId, AccountState, AuthorizationContext, DomainName, Localpart, Permission, Role,
        TenantId, UserAddress,
    };

    #[test]
    fn canonicalizes_internationalized_domain() {
        let domain = DomainName::parse("BÜCHER.example").expect("domain");
        assert_eq!(domain.as_str(), "xn--bcher-kva.example");
    }

    #[test]
    fn user_address_is_tenant_scoped_and_canonical() {
        let address = UserAddress::parse("benjamin@parley.io").expect("address");
        assert_eq!(address.to_string(), "benjamin@parley.io");
        assert!(UserAddress::parse("Benjamin@parley.io").is_err());
        assert!(UserAddress::parse("benjamin@parley.io@nextfcp.io").is_err());
    }

    #[test]
    fn administrator_cannot_change_tenant_trust() {
        let context = AuthorizationContext::new(
            TenantId::new(),
            AccountId::new(),
            AccountState::Active,
            vec![Role::Admin],
            false,
        );
        assert!(context.require(Permission::ManageFederation).is_err());
        assert!(context.require(Permission::ManageAccounts).is_ok());
    }

    #[test]
    fn localpart_rejects_noncanonical_forms() {
        assert!(Localpart::parse("benjamin").is_ok());
        assert!(Localpart::parse("benjamin..lee").is_err());
        assert!(Localpart::parse("béjamin").is_err());
    }
}
