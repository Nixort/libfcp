// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Stable FCP identifiers, constants and typed policy values.

/// Stable FCP wire marker.
pub const FCP_WIRE_MARKER: [u8; 3] = *b"FCP";
/// Stable FCP data-channel subprotocol identifier.
pub const PROTOCOL_ID: &str = "org.nixort.cfr.fcp";
/// Current FCP wire version.
pub const FCP_WIRE_VERSION: u8 = 1;
/// Maximum opaque offer or answer description length.
pub const MAX_DESCRIPTION_BYTES: usize = 96 * 1024;
/// Maximum opaque ICE-candidate length.
pub const MAX_CANDIDATE_BYTES: usize = 4 * 1024;
/// Maximum carried CFR control payload length.
pub const MAX_CFR_CONTROL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum complete FCP envelope length, including two endpoint identities and signatures.
pub const MAX_ENVELOPE_BYTES: usize = MAX_CFR_CONTROL_BYTES + 8 * 1024;
/// Maximum deduplicated accepted envelopes retained per connection attempt.
pub const MAX_SEEN_ENVELOPES: usize = 1024;

/// A federation routing namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FederationId([u8; 32]);

impl FederationId {
    /// Creates an ID from its fixed-width canonical bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A fresh application-provided connection-attempt ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId([u8; 16]);

impl AttemptId {
    /// Creates an ID from fixed-width canonical bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// An Ed25519 endpoint key used to authenticate FCP envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointKey([u8; 32]);

impl EndpointKey {
    /// Creates an endpoint key from canonical public-key bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical public-key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A digest binding an exact engine description and its DTLS fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WebRtcBinding([u8; 32]);

impl WebRtcBinding {
    /// Creates a binding from canonical digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hashes exact description bytes together with engine-produced fingerprint bytes.
    pub fn derive(description: &[u8], dtls_fingerprint: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"org.nixort.cfr.fcp/webrtc-binding");
        hasher.update(&(description.len() as u64).to_be_bytes());
        hasher.update(description);
        hasher.update(&(dtls_fingerprint.len() as u64).to_be_bytes());
        hasher.update(dtls_fingerprint);
        Self(*hasher.finalize().as_bytes())
    }

    /// Returns canonical digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An envelope id derived from the complete canonical signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvelopeId([u8; 32]);

impl EnvelopeId {
    /// Creates an envelope id from canonical digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns canonical digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A forward-compatible application close code carried in a signed FCP close envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CloseCode(u16);

impl CloseCode {
    /// Normal application-directed shutdown.
    pub const NORMAL: Self = Self(0);
    /// The local endpoint is replacing this attempt with a fresh one.
    pub const RESTART: Self = Self(1);
    /// The peer violated an FCP state or adapter policy.
    pub const PROTOCOL_ERROR: Self = Self(2);

    /// Creates a close code from its stable wire value.
    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    /// Returns the stable wire value.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}
