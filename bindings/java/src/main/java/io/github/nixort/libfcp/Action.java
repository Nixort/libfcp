// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

import java.util.Arrays;

/** One ordered FCP action for an application signaling carrier, WebRTC engine or CFR bridge. */
public final class Action {
    /** Deliver the exact signed envelope through the application-selected signaling carrier. */
    public static final int SEND_ENVELOPE = 1;
    /** Apply an opaque offer to the platform-owned WebRTC engine. */
    public static final int APPLY_OFFER = 2;
    /** Apply an opaque answer to the platform-owned WebRTC engine. */
    public static final int APPLY_ANSWER = 3;
    /** Add an opaque ICE candidate to the platform-owned WebRTC engine. */
    public static final int ADD_CANDIDATE = 4;
    /** Open FCP's reliable ordered binary control channel on the platform WebRTC engine. */
    public static final int OPEN_CONTROL_CHANNEL = 5;
    /** Deliver exact opaque CFR payload bytes to the application bridge. */
    public static final int DELIVER_CFR = 6;
    /** Close the platform WebRTC transport using the signed application close code. */
    public static final int CLOSE_TRANSPORT = 7;

    private final int kind;
    private final byte[] binding;
    private final int sequence;
    private final int closeCode;
    private final byte[] payload;

    Action(int kind, byte[] binding, int sequence, int closeCode, byte[] payload) {
        this.kind = kind;
        this.binding = binding.clone();
        this.sequence = sequence;
        this.closeCode = closeCode;
        this.payload = payload.clone();
    }

    /** Returns one stable action kind constant. */
    public int kind() {
        return kind;
    }

    /** Returns the exact 32-byte offer/answer binding, or all zeroes for other actions. */
    public byte[] binding() {
        return binding.clone();
    }

    /** Returns the diagnostic candidate sequence, or zero for other actions. */
    public int sequence() {
        return sequence;
    }

    /** Returns the u16 application close code, or zero for non-close actions. */
    public int closeCode() {
        return closeCode;
    }

    /** Returns exact signed envelope, opaque engine or CFR payload bytes. */
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Action action)) {
            return false;
        }
        return kind == action.kind
                && sequence == action.sequence
                && closeCode == action.closeCode
                && Arrays.equals(binding, action.binding)
                && Arrays.equals(payload, action.payload);
    }

    @Override
    public int hashCode() {
        int result = Integer.hashCode(kind);
        result = 31 * result + Arrays.hashCode(binding);
        result = 31 * result + Integer.hashCode(sequence);
        result = 31 * result + Integer.hashCode(closeCode);
        result = 31 * result + Arrays.hashCode(payload);
        return result;
    }
}
