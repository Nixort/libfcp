// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp.kotlin

/** Minimal executable smoke test for the Kotlin/JVM façade over the direct JNI bridge. */
fun main() {
    Signer().use { local ->
        Signer().use { remote ->
            Connection(local, ByteArray(32) { 3 }, ByteArray(16) { 7 }, remote.publicIdentity).use { connection ->
                connection.beginOffer(ByteArray(32) { 9 }, "opaque-offer".toByteArray(Charsets.US_ASCII))
                check(connection.takeAction()?.kind == 5) { "expected control-channel action first" }
                check(connection.takeAction()?.kind == 1) { "expected signed envelope action second" }
                check(connection.takeAction() == null) { "expected exhausted action queue" }
            }
        }
    }
}
