// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp.kotlin

import io.github.nixort.libfcp.Action as JavaAction
import io.github.nixort.libfcp.Connection as JavaConnection
import io.github.nixort.libfcp.Signer as JavaSigner
import java.io.Closeable

/** An immutable Kotlin copy of an ordered FCP host action. */
data class Action(
    val kind: Int,
    val binding: ByteArray,
    val sequence: Int,
    val closeCode: Int,
    val payload: ByteArray
) {
    companion object {
        internal fun fromJava(action: JavaAction): Action = Action(
            action.kind(), action.binding(), action.sequence(), action.closeCode(), action.payload()
        )
    }
}

/** A Kotlin/JVM owner of the shared native opaque FCP signer. */
class Signer : Closeable {
    private val delegate = JavaSigner()

    /** Returns an independent 1,984-byte FCP public endpoint identity. */
    val publicIdentity: ByteArray
        get() = delegate.publicIdentity()

    internal fun delegate(): JavaSigner = delegate

    /** Releases the shared native signer. */
    override fun close() = delegate.close()
}

/** Kotlin/JVM façade for the shared native signer-backed FCP connection state machine. */
class Connection(
    signer: Signer,
    federation: ByteArray,
    attempt: ByteArray,
    remoteEndpoint: ByteArray
) : Closeable {
    private val delegate = JavaConnection(signer.delegate(), federation, attempt, remoteEndpoint)

    /** Queues FCP offer actions for the host signaling carrier and platform WebRTC engine. */
    fun beginOffer(binding: ByteArray, description: ByteArray) = delegate.beginOffer(binding, description)

    /** Queues a signed answer envelope after an inbound offer was received. */
    fun answer(binding: ByteArray, description: ByteArray) = delegate.answer(binding, description)

    /** Queues a signed candidate envelope for the active negotiation. */
    fun addCandidate(sequence: Int, candidate: ByteArray) = delegate.addCandidate(sequence, candidate)

    /** Verifies inbound FCP bytes and queues ordered host actions. */
    fun receive(envelope: ByteArray) = delegate.receive(envelope)

    /** Reports the real platform control-channel connection transition. */
    fun transportConnected() = delegate.transportConnected()

    /** Reports terminal local platform transport failure. */
    fun transportFailed() = delegate.transportFailed()

    /** Queues a signed local close envelope. */
    fun closeWithCode(closeCode: Int) = delegate.closeWithCode(closeCode)

    /** Returns the next action or null only when the native FIFO is drained. */
    fun takeAction(): Action? = delegate.takeAction()?.let { Action.fromJava(it) }

    /** Returns native phase 0 idle through 6 closed. */
    val phase: Int
        get() = delegate.phase()

    /** Releases the shared native connection. */
    override fun close() = delegate.close()
}
