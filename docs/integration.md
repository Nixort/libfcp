# Integrating FCP

FCP sits between an application’s CFR instance and a selected peer transport. A
member application owns identity policy, authority-identity bootstrap and signaling
delivery. FCP owns signed federation configuration acceptance, connection control
and exact CFR payload routing.

## 1. Bootstrap one member

An application creates or receives its local CFR identity and separately owns an
FCP signing identity: an Ed25519 signing key paired with an ML-DSA-65 signing
key. It constructs `FederationClient` with its federation ID, local CFR identity,
local FCP endpoint identity and a pinned authority identity.

The authority identity is an application trust decision. It may be distributed in an
enterprise enrollment record, an authenticated invite, a QR comparison or
another explicit mechanism. Do not accept it from an unauthenticated signaling
message.

## 2. Apply signed federation configuration

The operator publishes a `SignedFederationConfiguration`. The application may
retrieve its bytes from HTTPS, a relay, an invite or local storage. Parse with
`SignedFederationConfiguration::decode_verified`, then pass the result to
`FederationClient::apply_configuration`.

The client rejects a wrong authority, federation mismatch, non-increasing epoch
or missing/mismatched local binding. Once accepted, the explicit remote CFR to
FCP endpoint-identity map becomes the only routing policy used by the bridge.

## 3. Create and connect a peer attempt

For the Rust/Tokio adapter, create `WebRtcRsSession` with one `SessionConfig`,
federation ID, fresh application-provided `AttemptId`, local `SigningIdentity` and
remote FCP endpoint identity. `SessionConfig::loopback()` is only for tests. A real
deployment supplies its own UDP policy and approved STUN/TURN entries.

The initiating member calls `begin_offer()`. The responder calls
`accept_signal()` followed by `answer()`. Each side regularly drains
`try_take_signal()` and transfers exact `SignalEvent::encode()` bytes through
its own signaling carrier. The carrier is not trusted: every inbound signal is
verified under both required signatures before opaque SDP or ICE data reaches the engine.

The adapter emits `SessionEvent::Connected` only after the ordered reliable FCP
control channel opens over WebRTC. Do not route CFR messages before this event.

## 4. Route CFR bytes

When CFR yields an outbound `Message`, call `route_outbound` using the client’s
explicit bindings and established `PeerConnections`. FCP creates one
`CfrControl` envelope for each requested remote endpoint and preserves
`Message.payload` byte-for-byte.

On `SessionEvent::DeliverCfr { envelope_id, remote_endpoint, payload }`, pass
`payload` unchanged to `Conference::handle`. `remote_endpoint` is the complete
verified FCP identity that signed the carrying envelope, and `envelope_id` is
its stable signed identifier. Persist or apply application policy to that
transport context before handling CFR; do not infer a sender from an unauthenticated
WebRTC callback. Route any returned CFR messages through the same bridge. FCP is
not a CFR roster and must not suppress CFR repair or invent delivery acknowledgements. See [`bindings.md`](bindings.md) for the language-binding façade, native-artifact publication and cross-language conformance requirements.

## 5. Handle lifecycle events

Drain `try_take_event()` regularly. Treat `SessionEvent::Failed` as a selected
engine/control-channel failure requiring application retry or cleanup policy.
Treat `SessionEvent::Closed { reason }` as a verified peer-directed FCP close.
For local graceful shutdown, call `begin_close(CloseCode)` and deliver the
returned signal before calling `close()` when the application may tear down the
engine.

## Adapter contract

Every adapter, including future JNI, Swift or browser implementations, must
apply the `libfcp::transport` action/event contract. It must open exactly one
binary, ordered and reliable channel:

```text
label    = "org.nixort.cfr.fcp.control/1"
protocol = "org.nixort.cfr.fcp"
ordered  = true
reliable = true
binary   = true
```

The adapter may not mark FCP established merely because it received an Answer;
it waits for a concrete transport connected event. It may not deliver
`CfrControl` beforehand. See [`protocol.md`](protocol.md) and
[`security.md`](security.md) for the full invariants.
