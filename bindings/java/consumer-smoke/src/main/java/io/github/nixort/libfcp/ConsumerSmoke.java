// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

/** Runs an installed-Maven-artifact smoke test through the public Java and Kotlin façades. */
public final class ConsumerSmoke {
    private ConsumerSmoke() {}

    /** Verifies resource-loaded native packaging and ordered FCP actions. */
    public static void main(String[] arguments) {
        try (Signer local = new Signer(); Signer remote = new Signer();
                Connection connection = new Connection(
                        local, new byte[32], new byte[16], remote.publicIdentity())) {
            final byte[] binding = new byte[32];
            binding[0] = 9;
            connection.beginOffer(binding, "maven-consumer-offer".getBytes());
            final Action first = connection.takeAction();
            final Action second = connection.takeAction();
            if (first == null || second == null || first.kind() != Action.OPEN_CONTROL_CHANNEL
                    || second.kind() != Action.SEND_ENVELOPE) {
                throw new AssertionError("Maven-installed libfcp did not preserve offer action order");
            }
            NativeLibrary.verifyEnvelope(second.payload());
        }

        try (io.github.nixort.libfcp.kotlin.Signer local = new io.github.nixort.libfcp.kotlin.Signer();
                io.github.nixort.libfcp.kotlin.Signer remote = new io.github.nixort.libfcp.kotlin.Signer();
                io.github.nixort.libfcp.kotlin.Connection connection =
                        new io.github.nixort.libfcp.kotlin.Connection(
                                local, new byte[32], new byte[16], remote.getPublicIdentity())) {
            final byte[] binding = new byte[32];
            binding[0] = 10;
            connection.beginOffer(binding, "maven-kotlin-consumer-offer".getBytes());
            final io.github.nixort.libfcp.kotlin.Action first = connection.takeAction();
            final io.github.nixort.libfcp.kotlin.Action second = connection.takeAction();
            if (first == null || second == null || first.getKind() != Action.OPEN_CONTROL_CHANNEL
                    || second.getKind() != Action.SEND_ENVELOPE) {
                throw new AssertionError("Maven-installed Kotlin façade did not preserve offer action order");
            }
        }
    }
}
