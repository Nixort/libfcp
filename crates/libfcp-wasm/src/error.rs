// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

use libfcp_core::{EndpointIdentity, EndpointKey, ML_DSA_65_PUBLIC_KEY_BYTES};
use wasm_bindgen::prelude::JsError;

use crate::ENDPOINT_IDENTITY_BYTES;

pub(crate) fn bounded(value: &[u8], maximum: usize) -> Result<(), JsError> {
    if value.len() > maximum {
        return Err(JsError::new("FCP input exceeds its fixed public bound"));
    }
    Ok(())
}

pub(crate) fn core_error(_error: libfcp_core::Error) -> JsError {
    JsError::new("FCP canonical validation or state transition failed")
}

pub(crate) fn endpoint_bytes(endpoint: &EndpointIdentity) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ENDPOINT_IDENTITY_BYTES);
    bytes.extend_from_slice(endpoint.classical.as_bytes());
    bytes.extend_from_slice(&endpoint.post_quantum);
    bytes
}

pub(crate) fn endpoint_identity(bytes: &[u8]) -> Result<EndpointIdentity, JsError> {
    if bytes.len() != ENDPOINT_IDENTITY_BYTES {
        return Err(JsError::new(
            "FCP endpoint identity has an invalid fixed width",
        ));
    }
    let classical = fixed(&bytes[..32])?;
    let mut post_quantum = [0_u8; ML_DSA_65_PUBLIC_KEY_BYTES];
    post_quantum.copy_from_slice(&bytes[32..]);
    Ok(EndpointIdentity::new(
        EndpointKey::from_bytes(classical),
        post_quantum,
    ))
}

pub(crate) fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new("FCP fixed-width value has an invalid byte length"))
}
