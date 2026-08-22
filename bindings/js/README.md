# @nixort/libfcp

`@nixort/libfcp` is the Node.js and browser-bundler WebAssembly façade over the canonical Rust FCP core. It exposes canonical configuration/envelope verification, ephemeral signers, one peer connection state machine and ordered host actions. It does **not** implement signaling, browser WebRTC, persistent private keys or FCP Fabric administration.

## Installation

The package is currently produced and tested as a local prerelease artifact. It is not yet published to npm or GitHub Packages.

```sh
npm install @nixort/libfcp@1.0.0-rc.1
```

The command becomes usable after a controlled registry publication. For source validation, run `./scripts/test_js_npm_package.sh` from the repository root; it builds a local tarball, installs it into a clean temporary consumer and executes this API.

## API boundary

```js
const fcp = require('@nixort/libfcp');

const local = new fcp.Signer();
const remote = new fcp.Signer();
try {
  const connection = new fcp.FcpConnection(
    local,
    new Uint8Array(32),
    new Uint8Array(16),
    remote.public_identity(),
  );
  try {
    connection.begin_offer(new Uint8Array(32), Buffer.from('host SDP bytes'));
    const action = connection.take_action();
    // Send the action through application-owned signaling/WebRTC infrastructure.
    action.free();
  } finally {
    connection.free();
  }
} finally {
  local.free();
  remote.free();
}
```

Copy or consume every action payload before `free()`. A host can exchange FCP control/CFR bytes only after reporting a real platform transport-connected event. The package verifies FCP bytes but does not itself create a browser data channel, establish ICE/DTLS/SCTP, or persist keys.

## Platform status

Node 18+ package loading is locally tested. Generated `wasm-bindgen` output is suitable for bundlers that support WebAssembly, but this prerelease has **not** completed live browser WebRTC acceptance testing. It must not be described as a browser transport SDK.

The package is GPL-3.0-only. See the repository root for the full license and the canonical protocol, FFI and release documentation.
