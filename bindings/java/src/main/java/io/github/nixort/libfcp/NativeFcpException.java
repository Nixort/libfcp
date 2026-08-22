// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

/** A checked native FCP status converted to a Java runtime exception. */
public final class NativeFcpException extends RuntimeException {
    private final int status;

    NativeFcpException(int status) {
        super("libfcp native operation failed with status " + Integer.toUnsignedString(status));
        this.status = status;
    }

    /** Returns the stable unsigned FCP ABI status. */
    public int status() {
        return status;
    }
}
