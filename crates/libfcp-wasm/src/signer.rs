// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use std::rc::Rc;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use libfcp_core::SigningIdentity;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, B32};
use rand_core::{OsRng, RngCore};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::error::endpoint_bytes;

/// Opaque browser-session FCP dual signer; private keys never leave WASM memory.
#[wasm_bindgen]
pub struct Signer {
    pub(crate) inner: Rc<SigningIdentity>,
}

#[wasm_bindgen]
impl Signer {
    /// Generates a new process-local signer from browser-compatible OS entropy.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript error when browser-backed entropy is unavailable.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Signer, JsError> {
        let mut classical_seed = Zeroizing::new([0_u8; 32]);
        let mut post_quantum_seed = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(&mut *classical_seed);
        OsRng.fill_bytes(&mut *post_quantum_seed);
        Ok(Self {
            inner: Rc::new(SigningIdentity::new(
                Ed25519SigningKey::from_bytes(&classical_seed),
                MlDsaSigningKey::<MlDsa65>::from_seed(&B32::from(*post_quantum_seed)),
            )),
        })
    }

    /// Returns the exact 1,984-byte public endpoint identity.
    #[must_use]
    pub fn public_identity(&self) -> Vec<u8> {
        let endpoint = self.inner.endpoint();
        endpoint_bytes(&endpoint)
    }
}
