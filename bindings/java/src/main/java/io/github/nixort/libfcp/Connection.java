// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

import java.util.Objects;

/** One signer-backed federation/attempt/peer-pinned FCP connection state machine. */
public final class Connection implements AutoCloseable {
    public static final int FEDERATION_ID_BYTES = 32;
    public static final int ATTEMPT_ID_BYTES = 16;
    public static final int ENDPOINT_IDENTITY_BYTES = 1_984;
    public static final int WEBRTC_BINDING_BYTES = 32;

    private long handle;

    /** Creates a connection for one remote endpoint; the signer provides the fixed local endpoint. */
    public Connection(Signer signer, byte[] federation, byte[] attempt, byte[] remoteEndpoint) {
        Objects.requireNonNull(signer, "signer");
        requireLength(federation, FEDERATION_ID_BYTES, "federation");
        requireLength(attempt, ATTEMPT_ID_BYTES, "attempt");
        requireLength(remoteEndpoint, ENDPOINT_IDENTITY_BYTES, "remoteEndpoint");
        this.handle = NativeLibrary.connectionCreate(
                signer.nativeHandle(), federation.clone(), attempt.clone(), remoteEndpoint.clone());
    }

    /** Starts a local offer and queues ordered signaling/WebRTC actions. */
    public synchronized void beginOffer(byte[] binding, byte[] description) {
        requireOpen();
        requireLength(binding, WEBRTC_BINDING_BYTES, "binding");
        NativeLibrary.connectionBeginOffer(handle, binding.clone(), requireBytes(description, "description"));
    }

    /** Answers a received offer and queues its signed signaling envelope. */
    public synchronized void answer(byte[] binding, byte[] description) {
        requireOpen();
        requireLength(binding, WEBRTC_BINDING_BYTES, "binding");
        NativeLibrary.connectionAnswer(handle, binding.clone(), requireBytes(description, "description"));
    }

    /** Queues a signed candidate for the active negotiation. */
    public synchronized void addCandidate(int sequence, byte[] candidate) {
        requireOpen();
        NativeLibrary.connectionCandidate(handle, sequence, requireBytes(candidate, "candidate"));
    }

    /** Verifies a received canonical FCP envelope and queues resulting host actions. */
    public synchronized void receive(byte[] envelope) {
        requireOpen();
        NativeLibrary.connectionReceive(handle, requireBytes(envelope, "envelope"));
    }

    /** Reports a real platform control-channel connection; only then may CFR bytes flow. */
    public synchronized void transportConnected() {
        requireOpen();
        NativeLibrary.connectionTransportConnected(handle);
    }

    /** Reports terminal local platform transport failure without manufacturing a remote close. */
    public synchronized void transportFailed() {
        requireOpen();
        NativeLibrary.connectionTransportFailed(handle);
    }

    /** Queues one signed local close envelope with an unsigned-u16 application code. */
    public synchronized void closeWithCode(int closeCode) {
        requireOpen();
        if (closeCode < 0 || closeCode > 0xffff) {
            throw new IllegalArgumentException("closeCode must fit in u16");
        }
        NativeLibrary.connectionClose(handle, closeCode);
    }

    /** Returns and removes the next action, or null after the native queue is drained. */
    public synchronized Action takeAction() {
        requireOpen();
        return NativeLibrary.connectionTakeAction(handle);
    }

    /** Returns phase 0 idle through 6 closed. */
    public synchronized int phase() {
        requireOpen();
        return NativeLibrary.connectionPhase(handle);
    }

    /** Releases the native connection. Repeated close calls are harmless. */
    @Override
    public synchronized void close() {
        if (handle != 0) {
            NativeLibrary.connectionFree(handle);
            handle = 0;
        }
    }

    private void requireOpen() {
        if (handle == 0) {
            throw new IllegalStateException("FCP connection is closed");
        }
    }

    private static byte[] requireBytes(byte[] value, String name) {
        return Objects.requireNonNull(value, name).clone();
    }

    private static void requireLength(byte[] value, int expected, String name) {
        if (Objects.requireNonNull(value, name).length != expected) {
            throw new IllegalArgumentException(name + " must contain exactly " + expected + " bytes");
        }
    }
}
