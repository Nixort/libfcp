// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package libfcp

import "testing"

func TestNativeOfferActionsAreOrderedAndSigned(t *testing.T) {
    local, err := NewSigner()
    if err != nil {
        t.Fatal(err)
    }
    defer local.Close()
    remote, err := NewSigner()
    if err != nil {
        t.Fatal(err)
    }
    defer remote.Close()
    remoteIdentity, err := remote.PublicIdentity()
    if err != nil {
        t.Fatal(err)
    }
    connection, err := NewConnection(
        local,
        make([]byte, FederationIDBytes),
        make([]byte, AttemptIDBytes),
        remoteIdentity,
    )
    if err != nil {
        t.Fatal(err)
    }
    defer connection.Close()
    binding := make([]byte, WebRTCBindingBytes)
    binding[0] = 9
    if err := connection.BeginOffer(binding, []byte("opaque-offer")); err != nil {
        t.Fatal(err)
    }
    channel, err := connection.TakeAction()
    if err != nil || channel == nil || channel.Kind != 5 {
        t.Fatalf("expected control-channel action first: action=%#v err=%v", channel, err)
    }
    envelope, err := connection.TakeAction()
    if err != nil || envelope == nil || envelope.Kind != 1 {
        t.Fatalf("expected signed envelope action second: action=%#v err=%v", envelope, err)
    }
    if err := VerifyEnvelope(envelope.Payload); err != nil {
        t.Fatal(err)
    }
    exhausted, err := connection.TakeAction()
    if err != nil || exhausted != nil {
        t.Fatalf("expected drained action queue: action=%#v err=%v", exhausted, err)
    }
}
