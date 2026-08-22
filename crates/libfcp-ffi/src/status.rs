// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Stable integer result returned by every fallible FCP ABI function.
pub type FcpStatus = u32;

/// Successful FFI operation status.
pub const FCP_STATUS_OK: FcpStatus = 0;
/// A null output pointer, malformed record or incorrect fixed-width byte input was supplied.
pub const FCP_STATUS_INVALID_ARGUMENT: FcpStatus = 1;
/// The caller requested an unsupported ABI version.
pub const FCP_STATUS_ABI_MISMATCH: FcpStatus = 2;
/// The input exceeded the fixed public allocation bound for its operation.
pub const FCP_STATUS_TOO_LARGE: FcpStatus = 3;
/// FCP rejected canonical bytes, signatures, bindings or a state transition.
pub const FCP_STATUS_PROTOCOL: FcpStatus = 4;
/// A configuration was valid FCP wire data but violated the pinned client policy.
pub const FCP_STATUS_CONFIGURATION: FcpStatus = 5;
/// The requested connection has no queued action.
pub const FCP_STATUS_NO_ACTION: FcpStatus = 6;
/// The native handle is unavailable or its state lock was poisoned.
pub const FCP_STATUS_CLOSED: FcpStatus = 7;
/// A Rust panic was contained before it could escape the ABI.
pub const FCP_STATUS_PANIC: FcpStatus = 8;
/// The operation failed without exposing internal diagnostic data.
pub const FCP_STATUS_INTERNAL: FcpStatus = 9;

pub(crate) fn ffi_status(operation: impl FnOnce() -> Result<(), FcpStatus>) -> FcpStatus {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => FCP_STATUS_OK,
        Ok(Err(status)) => status,
        Err(_) => FCP_STATUS_PANIC,
    }
}

pub(crate) fn status_from_core(_error: libfcp_core::Error) -> FcpStatus {
    FCP_STATUS_PROTOCOL
}

pub(crate) fn status_from_client(error: libfcp::Error) -> FcpStatus {
    match error {
        libfcp::Error::Fcp(error) => status_from_core(error),
        libfcp::Error::WrongFederation
        | libfcp::Error::WrongAuthority
        | libfcp::Error::StaleConfiguration
        | libfcp::Error::MissingLocalMember
        | libfcp::Error::WrongLocalEndpoint => FCP_STATUS_CONFIGURATION,
        libfcp::Error::MissingBinding
        | libfcp::Error::MissingConnection
        | libfcp::Error::MismatchedConnection => FCP_STATUS_INTERNAL,
    }
}
