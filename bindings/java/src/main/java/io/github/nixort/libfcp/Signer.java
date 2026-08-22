// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

/** A process-local opaque dual-signature FCP signer. */
public final class Signer implements AutoCloseable {
    private long handle;

    /** Creates a signer from OS entropy. This initial façade intentionally has no private-key import/export API. */
    public Signer() {
        this.handle = NativeLibrary.signerGenerate();
    }

    /** Returns an independent 1,984-byte public FCP endpoint identity. */
    public synchronized byte[] publicIdentity() {
        ensureOpen();
        return NativeLibrary.signerPublicIdentity(handle);
    }

    synchronized long nativeHandle() {
        ensureOpen();
        return handle;
    }

    /** Releases the native signer. Repeated close calls are harmless. */
    @Override
    public synchronized void close() {
        if (handle != 0) {
            NativeLibrary.signerFree(handle);
            handle = 0;
        }
    }

    private void ensureOpen() {
        if (handle == 0) {
            throw new IllegalStateException("FCP signer is closed");
        }
    }
}
