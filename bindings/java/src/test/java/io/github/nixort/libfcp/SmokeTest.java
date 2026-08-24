// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Minimal executable JNI smoke test; it uses no Java protocol implementation. */
public final class SmokeTest {
    private SmokeTest() {}

    /** Executes the native action-order, negotiation and CFR-origin verification paths. */
    public static void main(String[] args) {
        try (Signer alice = new Signer(); Signer bob = new Signer()) {
            final byte[] federation = new byte[Connection.FEDERATION_ID_BYTES];
            final byte[] attempt = new byte[Connection.ATTEMPT_ID_BYTES];
            final byte[] offerBinding = new byte[Connection.WEBRTC_BINDING_BYTES];
            final byte[] answerBinding = new byte[Connection.WEBRTC_BINDING_BYTES];
            federation[0] = 3;
            attempt[0] = 7;
            offerBinding[0] = 9;
            answerBinding[0] = 10;
            final byte[] aliceIdentity = alice.publicIdentity();
            final byte[] bobIdentity = bob.publicIdentity();
            try (Connection initiator = new Connection(alice, federation, attempt, bobIdentity);
                    Connection responder = new Connection(bob, federation, attempt, aliceIdentity)) {
                initiator.beginOffer(offerBinding, "opaque-offer".getBytes(StandardCharsets.US_ASCII));
                requireAction(initiator, Action.OPEN_CONTROL_CHANNEL, "control-channel action");
                final Action offer = requireAction(initiator, Action.SEND_ENVELOPE, "offer envelope");
                NativeLibrary.verifyEnvelope(offer.payload());
                responder.receive(offer.payload());
                requireAction(responder, Action.APPLY_OFFER, "apply-offer action");
                responder.answer(answerBinding, "opaque-answer".getBytes(StandardCharsets.US_ASCII));
                final Action answer = requireAction(responder, Action.SEND_ENVELOPE, "answer envelope");
                initiator.receive(answer.payload());
                requireAction(initiator, Action.APPLY_ANSWER, "apply-answer action");
                initiator.transportConnected();
                responder.transportConnected();
                final byte[] payload = "exact-jni-cfr".getBytes(StandardCharsets.US_ASCII);
                initiator.cfrControl(payload);
                final Action signedControl = requireAction(initiator, Action.SEND_ENVELOPE, "CFR envelope");
                responder.receive(signedControl.payload());
                final Action delivery = requireAction(responder, Action.DELIVER_CFR, "CFR delivery");
                if (!Arrays.equals(delivery.payload(), payload)) {
                    throw new AssertionError("CFR delivery payload changed");
                }
                if (!Arrays.equals(delivery.remoteEndpoint(), aliceIdentity)) {
                    throw new AssertionError("CFR delivery lost verified FCP remote endpoint");
                }
                if (Arrays.equals(delivery.envelopeId(), new byte[32])) {
                    throw new AssertionError("CFR delivery lost signed envelope ID");
                }
                if (initiator.takeAction() != null || responder.takeAction() != null) {
                    throw new AssertionError("expected exhausted action queues");
                }
            }
        }
    }

    private static Action requireAction(Connection connection, int kind, String description) {
        final Action action = connection.takeAction();
        if (action == null || action.kind() != kind) {
            throw new AssertionError("expected " + description);
        }
        return action;
    }
}
