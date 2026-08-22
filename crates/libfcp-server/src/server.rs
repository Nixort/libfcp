// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Signed federation configuration publisher.

use alloc::vec::Vec;

use libfcp_core::{
    EndpointIdentity, FederationConfiguration, FederationId, FederationMember,
    SignedFederationConfiguration, SigningIdentity,
};

use crate::Error;

/// Server-side authority that publishes one federation's signed settings.
///
/// The server owns policy publication only. Applications still decide how a
/// client authenticates this authority key and how the signed bytes are carried
/// to clients. The server is not a signaling relay and does not participate in
/// a peer's WebRTC or CFR state machine.
pub struct FederationServer {
    signer: SigningIdentity,
    configuration: FederationConfiguration,
}

impl FederationServer {
    /// Creates an empty epoch-zero configuration with the supplied authority identity.
    pub fn new(federation: FederationId, signer: SigningIdentity) -> Result<Self, Error> {
        let authority = signer.endpoint();
        let configuration = FederationConfiguration::new(federation, authority, 0, Vec::new())?;
        Ok(Self {
            signer,
            configuration,
        })
    }

    /// Returns the pinned authority identity clients must authenticate out of band.
    pub fn authority(&self) -> EndpointIdentity {
        self.configuration.authority
    }

    /// Returns the currently configured federation namespace.
    pub fn federation(&self) -> FederationId {
        self.configuration.federation
    }

    /// Returns the current monotonic policy version.
    pub fn epoch(&self) -> u64 {
        self.configuration.epoch
    }

    /// Replaces all explicit member bindings at a strictly newer epoch.
    ///
    /// An application must apply its admission and identity policy before calling
    /// this method. In particular, an FCP endpoint identity and CFR identity key are
    /// not considered equivalent simply because this server publishes them in one
    /// record.
    pub fn replace_members(
        &mut self,
        epoch: u64,
        members: Vec<FederationMember>,
    ) -> Result<(), Error> {
        if epoch <= self.configuration.epoch {
            return Err(Error::NonIncreasingEpoch);
        }
        self.configuration = FederationConfiguration::new(
            self.configuration.federation,
            self.configuration.authority,
            epoch,
            members,
        )?;
        Ok(())
    }

    /// Produces the canonical signed configuration artifact for application-selected delivery.
    pub fn publish(&self) -> Result<SignedFederationConfiguration, Error> {
        Ok(SignedFederationConfiguration::sign(
            self.configuration.clone(),
            &self.signer,
        )?)
    }
}
