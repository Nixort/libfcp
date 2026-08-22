// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

//! Canonical FCP envelopes, mandatory dual signatures and bounded wire parsing.

use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{
    AttemptId, CloseCode, EndpointIdentity, EndpointSigner, EnvelopeId, Error, FederationId,
    WebRtcBinding, FCP_WIRE_MARKER, FCP_WIRE_VERSION, MAX_CANDIDATE_BYTES, MAX_CFR_CONTROL_BYTES,
    MAX_DESCRIPTION_BYTES, MAX_ENVELOPE_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};

/// FCP envelope kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Initial signed WebRTC offer.
    Offer = 1,
    /// Signed answer bound to one offer ID.
    Answer = 2,
    /// Signed opaque ICE candidate bound to one negotiation parent.
    Candidate = 3,
    /// Signed close signal.
    Close = 4,
    /// Opaque CFR control bytes over an established reliable data channel.
    CfrControl = 5,
}

impl TryFrom<u8> for Kind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Offer),
            2 => Ok(Self::Answer),
            3 => Ok(Self::Candidate),
            4 => Ok(Self::Close),
            5 => Ok(Self::CfrControl),
            _ => Err(Error::UnknownKind),
        }
    }
}

/// The kind-specific canonical FCP body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Opaque engine offer description and a binding digest.
    Offer {
        /// Digest of exact description and DTLS fingerprint bytes.
        binding: WebRtcBinding,
        /// Bounded opaque engine description.
        description: Vec<u8>,
    },
    /// Opaque engine answer bound to one offer.
    Answer {
        /// Complete-envelope digest of the corresponding offer.
        offer_id: EnvelopeId,
        /// Digest of exact description and DTLS fingerprint bytes.
        binding: WebRtcBinding,
        /// Bounded opaque engine description.
        description: Vec<u8>,
    },
    /// An opaque engine ICE candidate.
    Candidate {
        /// Complete-envelope digest of the offer or answer it belongs to.
        parent_id: EnvelopeId,
        /// Sender-local diagnostic sequence number.
        sequence: u32,
        /// Bounded opaque candidate bytes.
        candidate: Vec<u8>,
    },
    /// A caller-defined close reason.
    Close {
        /// Stable application close code.
        reason: CloseCode,
    },
    /// Opaque raw CFR payload bytes.
    CfrControl {
        /// Exact bytes passed to `cfr_protocol::Conference::handle`.
        payload: Vec<u8>,
    },
}

impl Body {
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::Offer { .. } => Kind::Offer,
            Self::Answer { .. } => Kind::Answer,
            Self::Candidate { .. } => Kind::Candidate,
            Self::Close { .. } => Kind::Close,
            Self::CfrControl { .. } => Kind::CfrControl,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Offer { description, .. } | Self::Answer { description, .. } => {
                validate_len(description.len(), MAX_DESCRIPTION_BYTES)
            }
            Self::Candidate { candidate, .. } => validate_len(candidate.len(), MAX_CANDIDATE_BYTES),
            Self::Close { .. } => Ok(()),
            Self::CfrControl { payload } => validate_len(payload.len(), MAX_CFR_CONTROL_BYTES),
        }
    }
}

/// A verified or to-be-signed FCP envelope.
///
/// Both signatures authenticate the exact same canonical bytes, including the
/// complete sender and recipient identities. No single-signature record is a
/// valid FCP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Federation routing namespace.
    pub federation: FederationId,
    /// Connection attempt identifier.
    pub attempt: AttemptId,
    /// Complete identity of the envelope author.
    pub sender: EndpointIdentity,
    /// Complete identity of the intended endpoint.
    pub recipient: EndpointIdentity,
    /// Kind-specific body.
    pub body: Body,
    classical_signature: [u8; 64],
    post_quantum_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl Envelope {
    /// Creates and signs a canonical FCP envelope with both required algorithms.
    pub fn sign<S: EndpointSigner>(
        signer: &S,
        federation: FederationId,
        attempt: AttemptId,
        recipient: EndpointIdentity,
        body: Body,
    ) -> Result<Self, Error> {
        body.validate()?;
        let mut envelope = Self {
            federation,
            attempt,
            sender: signer.endpoint(),
            recipient,
            body,
            classical_signature: [0; 64],
            post_quantum_signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let transcript = envelope.signed_bytes()?;
        envelope.classical_signature = signer.sign_classical(&transcript);
        envelope.post_quantum_signature = signer.sign_post_quantum(&transcript);
        Ok(envelope)
    }

    /// Parses one complete canonical envelope without trusting its sender.
    pub fn decode(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut reader = Reader::new(wire);
        if reader.fixed::<3>()? != FCP_WIRE_MARKER {
            return Err(Error::BadMarker);
        }
        if reader.u8()? != FCP_WIRE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let kind = Kind::try_from(reader.u8()?)?;
        let federation = FederationId::from_bytes(reader.fixed()?);
        let attempt = AttemptId::from_bytes(reader.fixed()?);
        let sender = read_identity(&mut reader)?;
        let recipient = read_identity(&mut reader)?;
        let body = match kind {
            Kind::Offer => Body::Offer {
                binding: WebRtcBinding::from_bytes(reader.fixed()?),
                description: reader.bytes(MAX_DESCRIPTION_BYTES)?,
            },
            Kind::Answer => Body::Answer {
                offer_id: EnvelopeId::from_bytes(reader.fixed()?),
                binding: WebRtcBinding::from_bytes(reader.fixed()?),
                description: reader.bytes(MAX_DESCRIPTION_BYTES)?,
            },
            Kind::Candidate => Body::Candidate {
                parent_id: EnvelopeId::from_bytes(reader.fixed()?),
                sequence: reader.u32()?,
                candidate: reader.bytes(MAX_CANDIDATE_BYTES)?,
            },
            Kind::Close => Body::Close {
                reason: CloseCode::from_u16(reader.u16()?),
            },
            Kind::CfrControl => Body::CfrControl {
                payload: reader.bytes(MAX_CFR_CONTROL_BYTES)?,
            },
        };
        body.validate()?;
        let classical_signature = reader.fixed()?;
        let post_quantum_signature = reader.fixed()?;
        reader.finish()?;
        let result = Self {
            federation,
            attempt,
            sender,
            recipient,
            body,
            classical_signature,
            post_quantum_signature,
        };
        if result.encode()? != wire {
            return Err(Error::NonCanonical);
        }
        Ok(result)
    }

    /// Parses and verifies one canonical envelope before returning it.
    pub fn decode_verified(wire: &[u8]) -> Result<Self, Error> {
        verify_wire(wire)?;
        Self::decode(wire)
    }

    /// Verifies both mandatory signatures under the embedded sender identity.
    pub fn verify(&self) -> Result<(), Error> {
        let transcript = self.signed_bytes()?;
        self.sender
            .verify_classical(&transcript, &self.classical_signature)?;
        self.sender
            .verify_post_quantum(&transcript, &self.post_quantum_signature)
    }

    /// Returns the kind carried by this envelope.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.body.kind()
    }

    /// Returns the stable envelope id.
    pub fn id(&self) -> Result<EnvelopeId, Error> {
        Ok(EnvelopeId::from_bytes(
            *blake3::hash(&self.encode()?).as_bytes(),
        ))
    }

    /// Returns the full canonical signed envelope wire encoding.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.signed_bytes()?;
        bytes.extend_from_slice(&self.classical_signature);
        bytes.extend_from_slice(&self.post_quantum_signature);
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        self.body.validate()?;
        let mut writer = Writer::default();
        writer.fixed(&FCP_WIRE_MARKER);
        writer.u8(FCP_WIRE_VERSION);
        writer.u8(self.kind() as u8);
        writer.fixed(self.federation.as_bytes());
        writer.fixed(self.attempt.as_bytes());
        write_identity(&mut writer, &self.sender);
        write_identity(&mut writer, &self.recipient);
        match &self.body {
            Body::Offer {
                binding,
                description,
            } => {
                writer.fixed(binding.as_bytes());
                writer.bytes(description)?;
            }
            Body::Answer {
                offer_id,
                binding,
                description,
            } => {
                writer.fixed(offer_id.as_bytes());
                writer.fixed(binding.as_bytes());
                writer.bytes(description)?;
            }
            Body::Candidate {
                parent_id,
                sequence,
                candidate,
            } => {
                writer.fixed(parent_id.as_bytes());
                writer.u32(*sequence);
                writer.bytes(candidate)?;
            }
            Body::Close { reason } => writer.u16(reason.as_u16()),
            Body::CfrControl { payload } => writer.bytes(payload)?,
        }
        Ok(writer.finish())
    }
}

fn verify_wire(wire: &[u8]) -> Result<(), Error> {
    if wire.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut reader = Reader::new(wire);
    if reader.fixed::<3>()? != FCP_WIRE_MARKER {
        return Err(Error::BadMarker);
    }
    if reader.u8()? != FCP_WIRE_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let kind = Kind::try_from(reader.u8()?)?;
    let _federation = reader.fixed::<32>()?;
    let _attempt = reader.fixed::<16>()?;
    let sender = read_identity(&mut reader)?;
    let _recipient = read_identity(&mut reader)?;
    match kind {
        Kind::Offer => {
            let _binding = reader.fixed::<32>()?;
            let _description = reader.bytes_ref(MAX_DESCRIPTION_BYTES)?;
        }
        Kind::Answer => {
            let _offer = reader.fixed::<32>()?;
            let _binding = reader.fixed::<32>()?;
            let _description = reader.bytes_ref(MAX_DESCRIPTION_BYTES)?;
        }
        Kind::Candidate => {
            let _parent = reader.fixed::<32>()?;
            let _sequence = reader.u32()?;
            let _candidate = reader.bytes_ref(MAX_CANDIDATE_BYTES)?;
        }
        Kind::Close => {
            let _reason = reader.u16()?;
        }
        Kind::CfrControl => {
            let _payload = reader.bytes_ref(MAX_CFR_CONTROL_BYTES)?;
        }
    }
    let signed_end = reader.offset;
    let classical_signature = reader.fixed()?;
    let post_quantum_signature = reader.fixed()?;
    reader.finish()?;
    sender.verify_classical(&wire[..signed_end], &classical_signature)?;
    sender.verify_post_quantum(&wire[..signed_end], &post_quantum_signature)
}

fn write_identity(writer: &mut Writer, identity: &EndpointIdentity) {
    writer.fixed(identity.classical.as_bytes());
    writer.fixed(&identity.post_quantum);
}

fn read_identity(reader: &mut Reader<'_>) -> Result<EndpointIdentity, Error> {
    Ok(EndpointIdentity::new(
        crate::EndpointKey::from_bytes(reader.fixed()?),
        reader.fixed()?,
    ))
}

fn validate_len(length: usize, maximum: usize) -> Result<(), Error> {
    if length > maximum || length > u32::MAX as usize {
        return Err(Error::FieldTooLarge);
    }
    Ok(())
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn fixed(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.fixed(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        validate_len(value.len(), MAX_CFR_CONTROL_BYTES)?;
        let length = u32::try_from(value.len()).map_err(|_| Error::FieldTooLarge)?;
        self.u32(length);
        self.fixed(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct Reader<'a> {
    wire: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(wire: &'a [u8]) -> Self {
        Self { wire, offset: 0 }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self.offset.checked_add(N).ok_or(Error::Truncated)?;
        let bytes = self.wire.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        bytes.try_into().map_err(|_| Error::Truncated)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        Ok(self.bytes_ref(maximum)?.to_vec())
    }

    fn bytes_ref(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.u32()?).map_err(|_| Error::FieldTooLarge)?;
        validate_len(length, maximum)?;
        let end = self.offset.checked_add(length).ok_or(Error::Truncated)?;
        let bytes = self.wire.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), Error> {
        if self.offset == self.wire.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}
