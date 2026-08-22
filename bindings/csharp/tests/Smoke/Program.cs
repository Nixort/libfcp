// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

using Nixort.LibFcp;

using var local = new Signer();
using var remote = new Signer();
using var connection = new Connection(
    local,
    Enumerable.Repeat((byte)3, Connection.FederationIdBytes).ToArray(),
    Enumerable.Repeat((byte)7, Connection.AttemptIdBytes).ToArray(),
    remote.PublicIdentity());
connection.BeginOffer(
    Enumerable.Repeat((byte)9, Connection.WebRtcBindingBytes).ToArray(),
    "opaque-offer"u8.ToArray());
if (connection.TakeAction()?.Kind != 5)
{
    throw new InvalidOperationException("expected control-channel action first");
}
if (connection.TakeAction()?.Kind != 1)
{
    throw new InvalidOperationException("expected signed envelope action second");
}
if (connection.TakeAction() is not null)
{
    throw new InvalidOperationException("expected an exhausted action queue");
}
