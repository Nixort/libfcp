// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! HTTPS Fabric service for tenant administration and FCP federation.
//!
//! The public federation boundary accepts a remote authority only after local
//! trust policy, destination binding, bounded freshness and both mandatory FCP
//! signatures verify. It never accepts a remote password or user session.

mod authentication;
#[cfg(feature = "aws-kms")]
mod aws_kms;
mod federation;
mod federation_ingress;
mod login_flow;
mod login_transaction;
mod mfa;
mod recovery;
mod session;
mod step_up;
mod transport;
mod webauthn;

pub use authentication::{PasswordLoginError, PasswordLoginOutcome, PasswordLoginService};
#[cfg(feature = "aws-kms")]
pub use aws_kms::AwsKmsTotpKeyProvider;
pub use federation::{
    FederationDelivery, FederationError, RemotePeerPolicy, SignedFederationDelivery,
};
pub use federation_ingress::{
    FederationIngressError, FederationIngressOutcome, FederationIngressService,
    FederationPeerPolicyResolver, PostgresFederationPeerPolicyResolver, ResolvedFederationPeer,
};
pub use login_flow::{
    FabricLoginChallenge, FabricLoginFlow, FabricLoginFlowError, FabricLoginStart,
};
pub use login_transaction::{
    IssuedLoginTransaction, LoginTransactionPolicy, LoginTransactionService,
    LoginTransactionServiceError, LoginTransactionStart,
};
pub use mfa::{
    ActiveTotpEncryptionKey, PendingTotpEnrollment, TotpEnrollmentError, TotpEnrollmentKeyProvider,
    TotpEnrollmentOutcome, TotpEnrollmentService, TotpKeyResolutionError, TotpKeyResolver,
    TotpLoginError, TotpLoginOutcome, TotpLoginService,
};
pub use recovery::{
    IssuedRecoveryCodes, RecoveryCodeError, RecoveryCodePolicy, RecoveryCodeService,
};
pub use session::{
    AccessSessionAuthenticationError, AccessSessionAuthenticator, AuthenticatedAccessSession,
    IssuedRefreshSession, SessionIssueError, SessionIssuer, SessionPolicy, SessionRevocationError,
    SessionRevoker, SessionRotationError, SessionRotationOutcome, SessionRotator,
};
pub use step_up::{
    IssueRoleChangeStepUp, IssuedStepUpGrant, RoleChangeTarget, StepUpError, StepUpIssueOutcome,
    StepUpPolicy, StepUpService,
};
pub use transport::{
    router, router_with_federation, router_with_login, router_with_mfa_session,
    router_with_mfa_session_and_federation, FabricMfaSessionDependencies, FabricMfaSessionServices,
    FabricTransportConfig, MAX_REQUEST_BODY_BYTES,
};
pub use webauthn::{
    IssuedWebauthnCeremony, WebauthnBeginOutcome, WebauthnFinishOutcome, WebauthnPolicy,
    WebauthnService, WebauthnServiceError,
};
