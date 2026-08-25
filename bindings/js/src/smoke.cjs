// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');

const packageDirectory = process.env.LIBFCP_WASM_PACKAGE;
if (!packageDirectory) {
  throw new Error('LIBFCP_WASM_PACKAGE must name the generated wasm-bindgen Node package directory');
}

const fcp = require(path.join(packageDirectory, 'libfcp_wasm.js'));

assert.equal(fcp.abi_version(), 2);
assert.equal(fcp.wire_version(), 1);

const local = new fcp.Signer();
const remote = new fcp.Signer();
try {
  const connection = new fcp.FcpConnection(
    local,
    new Uint8Array(32).fill(3),
    new Uint8Array(16).fill(7),
    remote.public_identity(),
  );
  try {
    connection.begin_offer(new Uint8Array(32).fill(9), Buffer.from('opaque-offer'));
    const channel = connection.take_action();
    assert.equal(channel.kind, 5);
    channel.free();
    const envelope = connection.take_action();
    assert.equal(envelope.kind, 1);
    fcp.verify_envelope(envelope.payload);
    envelope.free();
    assert.equal(connection.take_action(), undefined);
  } finally {
    connection.free();
  }
} finally {
  local.free();
  remote.free();
}
