// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use std::{
    collections::VecDeque,
    ptr,
    sync::{Arc, Mutex},
};

use libfcp::FederationClient;
use libfcp_core::{Connection, SigningIdentity};

use crate::action::QueuedAction;

/// An immutable foreign byte range borrowed only for the duration of one call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FcpByteSlice {
    /// Pointer to readable bytes, or null only when `len` is zero.
    pub data: *const u8,
    /// Number of readable bytes.
    pub len: usize,
}

/// A byte buffer allocated by FCP and released by `fcp_buffer_free`.
#[repr(C)]
#[derive(Debug)]
pub struct FcpOwnedBuffer {
    /// Pointer to FCP-owned bytes, or null when `len` is zero.
    pub data: *mut u8,
    /// Number of FCP-owned bytes.
    pub len: usize,
}

impl Default for FcpOwnedBuffer {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

/// A generated opaque endpoint signer; its private keys never leave Rust memory.
pub struct FcpSigner {
    pub(crate) inner: Arc<SigningIdentity>,
}

/// Input used to construct a configuration-validation client.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FcpClientOptions {
    /// Exact 32-byte federation identifier.
    pub federation: FcpByteSlice,
    /// Exact 1,984-byte authority endpoint identity.
    pub authority: FcpByteSlice,
    /// Exact 32-byte local CFR participant identity.
    pub local_cfr_identity: FcpByteSlice,
    /// Exact 1,984-byte local FCP endpoint identity.
    pub local_endpoint: FcpByteSlice,
}

/// Opaque FCP federation-configuration client state.
pub struct FcpClient {
    pub(crate) inner: Mutex<FederationClient>,
}

/// Input used to construct a signer-backed per-peer FCP connection.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FcpConnectionOptions {
    /// Exact 32-byte federation identifier.
    pub federation: FcpByteSlice,
    /// Exact 16-byte application-selected attempt identifier.
    pub attempt: FcpByteSlice,
    /// Exact 1,984-byte remote FCP endpoint identity.
    pub remote_endpoint: FcpByteSlice,
}

/// Opaque FCP per-peer connection state and its ordered action queue.
pub struct FcpConnection {
    pub(crate) inner: Mutex<ConnectionState>,
}

pub(crate) struct ConnectionState {
    pub(crate) connection: Connection,
    pub(crate) signer: Arc<SigningIdentity>,
    pub(crate) actions: VecDeque<QueuedAction>,
}
