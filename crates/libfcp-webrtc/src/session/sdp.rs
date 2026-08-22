// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).
//! Minimal SDP validation helpers for FCP binding derivation.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn dtls_fingerprint(description: &[u8]) -> Result<Vec<u8>, Error> {
    let text = core::str::from_utf8(description).map_err(|_| Error::DescriptionEncoding)?;
    text.lines()
        .find_map(|line| {
            line.strip_prefix("a=fingerprint:")
                .map(|value| value.as_bytes().to_vec())
        })
        .ok_or(Error::InvalidAction("SDP contains no DTLS fingerprint"))
}
