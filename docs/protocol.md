# Federated CFR Connect Protocol (FCP)

> **Status:** release-candidate implementation specification. FCP provides signed federation configuration publication, connection control, and CFR routing. It is **not** a replacement for CFR, ICE, DTLS, SCTP, SRTP, a user-identity system, a signaling service, federation governance, or application admission policy.

## 1. Purpose and scope

FCP connects two federation endpoints through a WebRTC-capable transport. It binds offer, answer, candidate, and close traffic to a fixed federation, connection attempt, and complete endpoint identity. It carries opaque CFR control payloads over a reliable ordered WebRTC data channel because CFR intentionally owns no socket and expects applications to deliver control bytes according to `Recipient`.[1]

| Plane | FCP responsibility | Explicit non-responsibility |
|---|---|---|
| Federation configuration | Canonical signed `FCFG` snapshot with a federation ID, authority identity, monotonic epoch, and explicit CFR-to-endpoint bindings | Account authentication, admission workflow, person identity proof, trusted snapshot delivery, or WebRTC relaying |
| Federation signaling | Canonical offer, answer, candidate, and close envelopes with mandatory dual signatures, replay controls, and strict state transitions | Discovery, signaling infrastructure, account authentication, or TURN credential issuance |
| WebRTC transport | Conveys opaque negotiation data to a platform adapter and mandates one reliable ordered control channel | ICE, DTLS, SCTP, SRTP, and media implementation |
| CFR delivery | Routes raw `Message.payload` bytes under CFR recipient instructions | Membership, conference keys, repair semantics, or media encryption |

`libfcp-server` publishes bounded explicit configuration snapshots after the integrating application applies its admission policy. A client pins the complete authority identity out of band, accepts only a strictly newer verified epoch, and verifies that its own CFR identity maps to its exact local endpoint identity. The carrier can be HTTPS, a relay, an invite, or a file; carrying the bytes does not make the carrier trusted. The server neither terminates peer WebRTC nor participates in CFR.

## 2. Names and trust boundary

| Name | Width | Meaning |
|---|---:|---|
| `FederationId` | 32 bytes | Application-chosen immutable routing namespace that must match at both endpoints |
| `AttemptId` | 16 bytes | Fresh application-supplied connection-attempt identifier |
| `EndpointIdentity` | 1,984 bytes | Atomic binding of an Ed25519 public key (32 bytes) and an ML-DSA-65 public key (1,952 bytes) |
| `WebRtcBinding` | 32 bytes | BLAKE3 digest of exact engine-provided DTLS-fingerprint bytes and the exact offer or answer body |
| `EnvelopeId` | 32 bytes | BLAKE3 digest of complete canonical envelope bytes; an idempotency key, not an authority |

An `EndpointIdentity` proves only control of the corresponding Ed25519 and ML-DSA-65 private keys. It does **not** prove a person, device, domain, federation operator, or WebRTC peer identity. The application establishes that relationship through an explicit trust policy such as verified fingerprints, enterprise identity, invite policy, or QR comparison.[2]

FCP validates both signatures before it makes a remote state transition, then checks the federation ID, attempt ID, exact sender identity, and exact recipient identity. It never infers identity from a DTLS fingerprint, source address, endpoint identity, or CFR participant key. The portable grammar bounds variable fields before allocation; the adapter calls `decode_verified` before it supplies untrusted signaling to its engine.

## 3. Canonical envelope

Every FCP envelope has one canonical binary encoding. Integers are fixed-width big endian. Length-prefixed fields are bounded before allocation. Any unknown kind, truncated field, trailing byte, unsupported wire version, or non-canonical encoding fails parsing.

```text
identity := ed25519_key[32] || mldsa65_key[1952]

header := marker[3] || wire_version:u8 || kind:u8
       || federation_id[32] || attempt_id[16]
       || sender_identity[1984] || recipient_identity[1984]
body   := kind-specific fixed or length-prefixed fields
signed := header || body
wire   := signed || ed25519_signature[64] || mldsa65_signature[3309]
```

`marker` is ASCII `FCP`; the current `wire_version` is `1`. Both signatures authenticate exactly `signed`, including both endpoint identities and the routing bindings. A record that lacks either signature is not FCP. FCP does not reuse a CFR control marker and does not modify CFR payloads.

| Kind | Body | State precondition | Effect |
|---|---|---|---|
| `Offer` | `webrtc_binding[32]`, bounded opaque SDP/engine description | Initiator: `Idle`; responder: `Idle` | Responder enters `OfferReceived`; an accepted duplicate is idempotent |
| `Answer` | `offer_envelope_id[32]`, `webrtc_binding[32]`, bounded opaque description | Responder: `OfferReceived`; initiator: `OfferSent` | Binds the answer to one exact offer; initiator enters `AnswerReceived` |
| `Candidate` | `parent_envelope_id[32]`, `sequence:u32`, bounded opaque candidate | Live negotiation or established state | Delivers to the WebRTC adapter after parent binding validation |
| `Close` | `reason:CloseCode(u16)` | Any live state | Transitions the matched attempt to `Closed`; unknown codes remain wire-valid |
| `CfrControl` | Bounded opaque CFR payload | `Established` only | Delivers bytes unchanged to `Conference::handle` |

`Offer` and `Answer` descriptions are opaque because SDP is engine-specific. The platform adapter validates them. `WebRtcBinding` is calculated from the exact bytes that the adapter will provide to its engine and the corresponding engine-provided DTLS fingerprint. FCP authenticates the resulting digest; it does not claim that SDP is canonical.

## 4. Signed federation configuration

A configuration snapshot uses a separate canonical encoding.

```text
identity := ed25519_key[32] || mldsa65_key[1952]
member   := cfr_identity[32] || endpoint_identity[1984]

signed_config := "FCFG" || config_version:u8 || federation_id[32]
              || authority_identity[1984] || epoch:u64 || member_count:u16
              || members[member_count]
config_wire   := signed_config || ed25519_signature[64] || mldsa65_signature[3309]
```

The current `config_version` is `1`. Both signatures cover `signed_config`. A client verifies the authority identity against its out-of-band pin, validates both authority signatures, rejects duplicate CFR identities or endpoint identities, requires the local member binding, and accepts only a strictly newer epoch. No legacy or single-signature configuration fallback exists.

## 5. State machine and bounds

```text
Idle --local Offer--> OfferSent --valid Answer--> AnswerReceived --adapter connected--> Established --Close/local close--> Closed
Idle --valid Offer--> OfferReceived --local Answer--> AnswerSent --adapter connected--> Established
OfferSent/OfferReceived/AnswerSent/AnswerReceived/Established --valid Candidate--> same state
any live state --valid Close--> Closed
```

A duplicate accepted envelope produces no second adapter action. The fixed parser and replay bounds are `MAX_ENVELOPE_BYTES = 4,202,496`, `MAX_DESCRIPTION_BYTES = 98,304`, `MAX_CANDIDATE_BYTES = 4,096`, `MAX_CFR_CONTROL_BYTES = 4,194,304`, and `MAX_SEEN_ENVELOPES = 1,024` per attempt. The replay window is a fixed-capacity FIFO; a limit breach fails before unbounded remote-controlled state allocation.

Candidate messages carry a parent offer or answer ID, so candidates cannot be silently moved between concurrent attempts. Candidate sequence numbers are diagnostic; they do not replace WebRTC engine validation or ICE restart behavior. FCP transports opaque ICE candidates and does not attempt to replace ICE’s NAT traversal algorithm.[3]

## 6. WebRTC adapter contract

The portable core exposes actions instead of an engine dependency. A platform adapter receives `ApplyOffer`, `ApplyAnswer`, `AddCandidate`, `OpenControlChannel`, and `CloseTransport` actions, then emits `Connected`, `ControlBinary`, `Failed`, or `Closed` events. For `ControlBinary`, the adapter must use the core verified decode path before applying a state transition.

```text
label    = "org.nixort.cfr.fcp.control/1"
protocol = "org.nixort.cfr.fcp"
ordered  = true
reliable = true
binary   = true
```

The label and protocol are interoperation metadata, not security controls. An adapter must not declare `Established` solely because it received an answer; it waits for a successful connected event from its WebRTC engine. It must not deliver `CfrControl` before that state. The WebRTC Data Channel Establishment Protocol defines symmetric data-channel properties and relies on reliable ordered control for its own setup messages.[4]

## 7. CFR bridge and security scope

| CFR recipient | FCP bridge action |
|---|---|
| `Recipient::Peer(key)` | Look up the application-approved `CfrEndpointBindings` entry, then send one `CfrControl` through the matching established `PeerConnections` entry |
| `Recipient::Everyone` | Send the same unchanged payload through every explicitly bound remote endpoint identity |

`PeerConnections` is pinned to one `FederationId` and local endpoint identity. It rejects a connection with another federation or local identity. On `CfrControl`, the application calls `Conference::handle(payload)` and routes returned CFR messages through the same bridge. FCP must not acknowledge CFR agreement, suppress repair, alter payload bytes, aggregate messages, or use its endpoint directory as a CFR roster.[1]

FCP provides dual-algorithm endpoint and authority authentication, exact attempt/recipient/federation binding, bounded replay idempotency, strict state transitions, and bounded parser allocation. It does **not** add confidentiality to a signaling relay; WebRTC data confidentiality begins when DTLS connects. It does not hide metadata, stop a relay from dropping messages, authenticate a person to an endpoint identity, automatically resolve simultaneous-offer glare, or replace TURN where NAT topology requires a relay.[2] [3]

The authenticated signaling and configuration boundaries use Ed25519 plus ML-DSA-65. The WebRTC DTLS handshake, SCTP, and SRTP media path remain conventionally authenticated by the selected WebRTC engine; FCP does not make DTLS post-quantum.

## References

[1] [CFR integration guide](https://github.com/Nixort/cfr_protocol/blob/main/docs/integration.md).

[2] [CFR security boundary](https://github.com/Nixort/cfr_protocol/blob/main/docs/security.md).

[3] [RFC 8445 — Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445.html).

[4] [RFC 8832 — WebRTC Data Channel Establishment Protocol](https://datatracker.ietf.org/doc/html/rfc8832).

[5] [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final).
