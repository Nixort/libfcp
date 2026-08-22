// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

/** Minimal executable JNI smoke test; it uses no Java protocol implementation. */
public final class SmokeTest {
    private SmokeTest() {}

    /** Executes the native action-order and verification path. */
    public static void main(String[] args) {
        try (Signer local = new Signer(); Signer remote = new Signer()) {
            final byte[] federation = new byte[Connection.FEDERATION_ID_BYTES];
            final byte[] attempt = new byte[Connection.ATTEMPT_ID_BYTES];
            final byte[] binding = new byte[Connection.WEBRTC_BINDING_BYTES];
            federation[0] = 3;
            attempt[0] = 7;
            binding[0] = 9;
            try (Connection connection = new Connection(local, federation, attempt, remote.publicIdentity())) {
                connection.beginOffer(binding, "opaque-offer".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                final Action channel = connection.takeAction();
                if (channel == null || channel.kind() != Action.OPEN_CONTROL_CHANNEL) {
                    throw new AssertionError("expected control-channel action first");
                }
                final Action envelope = connection.takeAction();
                if (envelope == null || envelope.kind() != Action.SEND_ENVELOPE) {
                    throw new AssertionError("expected signed envelope action second");
                }
                NativeLibrary.verifyEnvelope(envelope.payload());
                if (connection.takeAction() != null) {
                    throw new AssertionError("expected exhausted action queue");
                }
            }
        }
    }
}
