// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use crate::{
    memory::{endpoint_buffer, free_handle, required_handle, required_out},
    status::{ffi_status, FcpStatus},
    types::{FcpOwnedBuffer, FcpSigner},
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use libfcp_core::SigningIdentity;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroizing;
/// Creates an opaque process-local dual-signature endpoint signer using OS entropy.
///
/// The signer exposes only its public identity. It intentionally has no private-key
/// import/export API and must not be used as a persistent production key store.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_signer_generate(out: *mut *mut FcpSigner) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: Output validation and write occur only for the caller-provided slot.
        let out = unsafe { required_out(out)? };
        let mut classical_seed = Zeroizing::new([0_u8; 32]);
        let mut post_quantum_seed = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut *classical_seed);
        OsRng.fill_bytes(&mut *post_quantum_seed);
        let signer = SigningIdentity::new(
            Ed25519SigningKey::from_bytes(&classical_seed),
            MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(*post_quantum_seed)),
        );
        *out = Box::into_raw(Box::new(FcpSigner {
            inner: Arc::new(signer),
        }));
        Ok(())
    })
}

/// Returns the exact 1,984-byte public endpoint identity of an opaque signer.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_signer_public_identity(
    signer: *const FcpSigner,
    out: *mut FcpOwnedBuffer,
) -> FcpStatus {
    ffi_status(|| {
        // SAFETY: The input handle and output record are validated at the ABI boundary.
        let signer = unsafe { required_handle(signer)? };
        // SAFETY: The output pointer is caller-owned writable storage.
        let out = unsafe { required_out(out)? };
        let endpoint = signer.inner.endpoint();
        *out = endpoint_buffer(&endpoint);
        Ok(())
    })
}

/// Releases a signer handle and sets its caller-owned handle slot to null.
///
/// # Safety
/// The caller must provide live, correctly aligned opaque handles and writable output
/// records, plus readable input ranges, for the duration of the call. It must not
/// release a handle concurrently with an operation that uses it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcp_signer_free(signer: *mut *mut FcpSigner) {
    // SAFETY: The caller owns the pointer slot and may pass null for a no-op release.
    unsafe { free_handle(signer) };
}
