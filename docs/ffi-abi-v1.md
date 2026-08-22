# `libfcp-ffi` ABI v1 contract

**Status:** implementation contract for the `v1.0.0-rc.1` prerelease family. This document defines one native FCP core and thin language façades. It does not define a second Java, Kotlin, C++, JavaScript, Python, C# or Go protocol implementation.

## Boundary and supported operations

`libfcp-ffi` is a `cdylib`/`staticlib` over `libfcp-core` and `libfcp`. It exposes byte-oriented FCP configuration validation, a configuration-client handle, opaque signing handles and per-peer connection handles. The native ABI drives platform-owned WebRTC through an ordered action queue. The host application owns signaling delivery, WebRTC engine invocation, user interface, account credentials and persistent key-management policy.

| ABI area | Stable v1 behavior | Explicitly excluded |
|---|---|---|
| Configuration | Verify canonical dual-signed `FCFG` bytes and atomically apply a strictly newer configuration to an opaque client. | Fabric database, tenants, passwords, TOTP, passkeys, service secrets and configuration-authority private keys. |
| FCP connection | Create one federation/attempt/peer-pinned state machine; create/receive FCP envelopes; report engine connection or failure. | A universal WebRTC engine, TURN provisioning, sockets, signaling transport and a claim that an adapter is connected before its engine reports it. |
| Signing | Generate an opaque, process-local dual-algorithm endpoint signer and export only its public identity. A connection retains its signer by reference count. | Private-key export/import, a key-store abstraction or a promise of persistence across restart. A production host must use a reviewed platform key-management integration before depending on persistent endpoint identity. |
| CFR | Emit and accept exact opaque CFR payload bytes after the established-state gate. | CFR roster mutation, private CFR key material and a language-side reimplementation of FCP routing. |

## ABI and ownership rules

All public native functions use `extern "C"`, fixed-width integer types, `size_t` lengths and `#[repr(C)]` records. No Rust `String`, `Vec`, reference, trait object, enum layout or unwinding crosses the boundary. The shared library exports `fcp_ffi_abi_version()` and reports `1` for this contract. Bindings must reject any other ABI major before calling a stateful function.

A non-empty `FcpByteSlice` must contain a non-null readable pointer for the duration of the call. Input bytes are copied before a function returns and no caller pointer is retained. A zero-length slice may use a null pointer. Every `FcpOwnedBuffer` returned by FCP belongs to the caller and must be released exactly once with `fcp_buffer_free`; buffer release is idempotent after the record is zeroed. An opaque handle must be destroyed with its matching `*_free` function. Releasing a handle is idempotent when the caller has set its own pointer to null; passing an already-freed non-null handle is a foreign-language memory error and is outside the ABI safety guarantee.

> `libfcp-ffi` catches Rust panics at every exported entry point and converts them to `FCP_STATUS_PANIC`. Rust panics, C++ exceptions, JVM exceptions, callbacks and foreign pointers never cross from one runtime into another.

## Result model

Every fallible function returns `FcpStatus` (`uint32_t`). `FCP_STATUS_OK` is zero. Stable categories are: invalid argument, ABI mismatch, object closed, no queued action, bounded input too large, protocol validation/state failure, configuration policy failure, allocation failure and contained panic. The header exports numeric named constants; high-level façades map those codes to typed language errors.

The library does not return diagnostic strings containing untrusted input, secret material or native backtraces. A binding may attach a local, fixed message for a documented status code.

## Byte representations

All identifiers are exact canonical bytes, not strings.

| Value | Required byte width |
|---|---:|
| Federation ID | 32 |
| Attempt ID | 16 |
| Endpoint identity | 1,984 (`32` Ed25519 + `1,952` ML-DSA-65 public key) |
| WebRTC binding digest | 32 |
| FCP configuration (`FCFG`) / envelope (`FCP`) | Variable, bounded and validated by the Rust core |

The FFI API validates fixed widths before allocating or constructing a core object. Opaque offer/answer descriptions, candidates, CFR payloads and whole envelopes are bounded by the public core limits.

## Ordered action queue

Mutating connection calls append zero or more actions to the connection-owned FIFO. The foreign host repeatedly calls `fcp_connection_take_action` until it receives `FCP_STATUS_NO_ACTION`. Each record is one of the following actions and preserves the order produced by the Rust state machine.

| Action | Required host behavior |
|---|---|
| `SEND_ENVELOPE` | Deliver the returned exact signed FCP envelope through the application-selected signaling/data carrier. |
| `APPLY_OFFER` / `APPLY_ANSWER` | Pass the exact opaque description and 32-byte binding to the platform WebRTC engine. |
| `ADD_CANDIDATE` | Pass the exact opaque candidate and FCP sequence to the platform WebRTC engine. |
| `OPEN_CONTROL_CHANNEL` | Create `org.nixort.cfr.fcp.control/1` using the documented FCP subprotocol as reliable, ordered binary data. |
| `DELIVER_CFR` | Give the exact returned CFR payload bytes to the application’s CFR bridge. |
| `CLOSE_TRANSPORT` | Close the platform peer connection with the returned application close code. |

The host must report `fcp_connection_transport_connected` only after the platform engine has connected the required control channel. `cfr_control` and inbound CFR delivery are rejected before that transition. This is a security and ordering invariant, not a UI preference.

## Threading and lifecycle

Each client and connection handle internally serializes its mutable state; simultaneous calls on the same handle are linearized. A `FcpConnection` holds a reference-counted signer, so releasing a separately held signer handle does not invalidate an existing connection. The native layer does not retain foreign object references, start unmanaged threads or invoke foreign callbacks. Therefore Java/JNI local-reference rules, Go cgo pointer rules and managed-runtime GC lifetimes remain entirely at the façade boundary.

## Binding policy

C and C++ consume the generated/reviewed C header directly. Java uses a small JNI façade over this ABI; Kotlin/JVM and Android call the same native ABI through Kotlin/JNI glue, not a copy of protocol logic. Python, C# and Go use `ctypes`/extension, P/Invoke and cgo respectively, with deterministic handle/buffer release. JavaScript is deliberately separate: its browser façade compiles the portable `libfcp-core` behavior to WASM with `wasm-bindgen`; browser runtime and cryptographic compatibility must pass dedicated tests before it is treated as equivalent to native FFI.

No registry upload is implied by this implementation. Every package remains prerelease-only until the canonical-vector, stateful-interoperability, native-lifecycle, platform-transport and publication-integrity gates in [the binding contract](bindings.md) pass.

## References

[1] [The Rustonomicon — Foreign Function Interface](https://doc.rust-lang.org/nomicon/ffi.html)

[2] [Oracle — Java Native Interface Design Overview](https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html)

[3] [The UniFFI User Guide — Generating bindings](https://mozilla.github.io/uniffi-rs/latest/bindings.html)

[4] [Microsoft Learn — Native library loading](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/native-library-loading)

[5] [Go — cgo package documentation](https://pkg.go.dev/cmd/cgo)
