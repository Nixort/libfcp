# Cross-platform bindings and publication contract

**Status:** `v1.0.0-rc.1` contains **source-level, locally tested FFI façades** for C, C++, Python, Java, Kotlin/JVM, JavaScript/WASM, C# and Go. Reproducible local Maven and npm prerelease packages can now be built for the combined Java 17/Kotlin/JVM API and the Node/browser-bundler WASM façade. GitHub workflows also produce attested Linux `x86_64` native binding bundles. The Node/browser-bundler package **`@nixort/libfcp@1.0.0-rc.1` is published to GitHub Packages**. No remote Maven artifact, wheel, npmjs package, NuGet package, Go module release or platform binary is published; Java, Kotlin, Swift, Python, C#, Go and C/C++ package publication therefore remains unavailable. The Rust surface remains `libfcp-core`, `libfcp`, `libfcp-server` and the optional `libfcp-webrtc` adapter.

## One protocol implementation, not language ports

FCP remains cross-platform through **one canonical Rust implementation**. The earlier **Proposed `libfcp-ffi`** design is now implemented as an audited native C ABI. `libfcp-core` owns canonical encoding, dual-signature verification and protocol state transitions. `libfcp-ffi` owns opaque handles, bounded input copies, owned output buffers, status codes, panic containment and ordered host actions. Java, Kotlin, C++, Python, C# and Go only marshal bytes and handles to that ABI; they do not parse FCP, create a second signer implementation or reproduce a state machine.

The browser is deliberately a separate runtime surface. `libfcp-wasm` is a `wasm-bindgen` façade over the same portable `libfcp-core`; JNI or a native shared library must not be presented as a browser package.

> A language binding is not a port of every Rust crate. It is a narrow façade over canonical verification, opaque signer and connection state, explicit platform transport actions/events and exact CFR payload bytes.

| Layer | RC source status | Cross-language rule |
|---|---|---|
| `libfcp-core` | Implemented Rust canonical wire/state core | Remains the only initial reference implementation for byte vectors and state transitions. |
| `libfcp` | Implemented Rust member SDK and queue-backed transport contract | Supplies the semantic model for the language-neutral façade. |
| `libfcp-ffi` | Implemented native `cdylib`/`staticlib`, public C header and C smoke test | Exposes opaque signer/client/connection handles, bounded bytes, status codes and ordered actions. |
| `libfcp-wasm` | Implemented `wasm-bindgen` browser façade and Node smoke test | Uses the portable core directly; JavaScript owns browser WebRTC and signaling. |
| `libfcp-webrtc` | Optional Rust/Tokio adapter | Is not exported as a universal mobile/browser transport. Each platform owns its WebRTC engine. |
| `fcp-fabric-*` | Server-side identity/federation platform | Is never bundled into a client language binding. |

## Implemented façade matrix

| Target | Source façade | Local evidence | Publication status |
|---|---|---|---|
| C | `crates/libfcp-ffi/include/libfcp_ffi.h` | Compiled C ABI lifecycle/action smoke test; Linux native artifact bundle | Not published |
| C++20 | `bindings/cpp/include/libfcp.hpp` | Compiled RAII C++ smoke test; Linux native artifact bundle | Not published |
| Python 3.10+ | `bindings/python` with `ctypes` | CPython native smoke test; source façade is included in Linux native artifact bundle | Not published to PyPI |
| Java 17+ | `bindings/java` direct JNI bridge and JAR source | JDK JNI compile/load/action smoke test; isolated Maven consumer loads bundled Linux native libraries | Local Maven artifact only; not published remotely |
| Kotlin/JVM | `bindings/kotlin` thin delegation to Java/JNI façade | Kotlin/JVM action smoke test; compiled into the same local Maven JAR | Local Maven artifact only; not published remotely |
| JavaScript/Node/browser | `crates/libfcp-wasm` and `bindings/js` | `wasm-bindgen` Node smoke test and isolated installed-tarball consumer test | Published as `@nixort/libfcp@1.0.0-rc.1` to GitHub Packages; not published to npmjs |
| C#/.NET 8 | `bindings/csharp` P/Invoke façade | .NET native smoke test; source façade is included in Linux native artifact bundle | Not published to NuGet |
| Go 1.22 | `bindings/go` cgo façade | Go cgo native smoke test; source façade is included in Linux native artifact bundle | Not released as a Go module |
| Swift/iOS/macOS | No source façade in this RC | Requires Apple-host XCFramework and Swift test work | Not published |

The Java and Kotlin APIs are intentionally separate public façades over the same direct JNI/native ABI. Kotlin is **not** presented as the Java API. Android is also not claimed supported yet: it needs Android ABI outputs, Android library packaging and instrumented tests before an AAR is considered releasable.

**UniFFI** remains an evaluated future generator option for Swift/Apple and a potential Python redesign, but this RC does not claim generated UniFFI bindings or publish any UniFFI artifact. Any migration must preserve the same canonical vector, lifecycle and native-artifact gates.[4]

## ABI and lifecycle contract

The canonical native ABI is versioned by `fcp_ffi_abi_version()` and `fcp_ffi_wire_version()`. Foreign wrappers must reject an incompatible ABI or wire major before creating state. The C header defines exact fixed-width values, opaque handle types, `FcpByteSlice`, `FcpOwnedBuffer`, `FcpAction`, stable status codes and idempotent `*_free` functions.

| Contract element | Required rule |
|---|---|
| Caller input | Borrowed only for one FFI call; native FCP copies bounded dynamic bytes before state mutation. |
| Native output | Copied into managed/application memory, then released exactly once with `fcp_buffer_free` or `fcp_action_free`. |
| Handles | Opaque, idempotently releasable and invalid after close. A wrapper must not close a handle concurrently with a native call using it. |
| Errors | Stable ABI status values for native/C consumers; wrappers map them to typed errors/exceptions without allowing panics or unmanaged exceptions to cross the boundary. |
| Keys | The current `Signer` generator creates process-local ephemeral key material only. It neither imports nor exports a long-lived private key. |
| Transport | A platform WebRTC engine and application signaling carrier execute emitted actions. FCP control/CFR delivery remains forbidden until an actual `transport_connected` event. |

The façade must never accept a password, recovery code, database URL, cloud credential, TOTP seed, `FCP_DATABASE_URL`, Fabric digest key or raw long-lived signing key through a convenience API. It also never exposes Fabric storage, administration or identity operations to a client binding.

## Canonical vectors and conformance

`testdata/fcp-ffi/v1/vectors.json` contains deterministic valid and tampered canonical FCP envelope/configuration fixture bytes. It is generated by `crates/libfcp-ffi/examples/generate_vectors.rs` from the repository reference implementation; it does not contain production credentials or private key material. `scripts/test_foreign_bindings.sh` is the local cross-language gate and runs the compiled native/managed/browser smoke matrix.

| Gate | Current RC evidence | Remaining release requirement |
|---|---|---|
| Canonical vectors | Deterministic vector generator and valid/tampered fixture file | Every package CI job must consume the fixtures and check expected error categories. |
| Stateful interoperability | Rust FFI, C, C++, Python, Java, Kotlin, JS/WASM, C# and Go exercise an ordered offer/action lifecycle | Add independent two-runtime, replay and close-lifecycle scenarios per target. |
| Native lifecycle | Idempotent close APIs and local create/use/close smoke tests | Add sanitizers, memory-leak checks and stress/concurrency tests by target. |
| Platform transport | Correct FCP action contract is exposed | Run real Android, Apple and browser WebRTC engine tests; Node is not a browser transport test. |
| Publication integrity | Source remains secrets-free; JVM local package emits SHA-256 checksums, CI attests trusted `main` artifacts and the JavaScript RC is published to GitHub Packages through an explicitly confirmed workflow | Add an SBOM and any separately approved public npmjs trusted-publisher release. |

## Packaging and release boundaries

A final package release remains a separate controlled operation. Native target artifacts are unavoidable even though the protocol code is single-source Rust: JVM, CPython, .NET, Go/cgo and C/C++ must load a platform binary, while the browser loads a WASM module. This is packaging, not a second FCP implementation.

| Family | Intended prerelease coordinate/artifact | Release host and required gate |
|---|---|---|
| Java/Kotlin JVM | `io.github.nixort:libfcp:1.0.0-rc.1` plus native classifiers; current local output is `linux-x86_64` | Isolated Maven consumer loads Java and Kotlin façades through bundled JNI libraries; add macOS/Windows classifiers before declaring those targets |
| Kotlin/Android | `io.github.nixort:libfcp-kotlin-android` AAR | Android `arm64-v8a`/`x86_64` output and instrumented test |
| Python | `libfcp-python` wheel family | CPython ABI matrix, wheel audit and vector tests |
| JavaScript | Published GitHub Packages RC: `@nixort/libfcp@1.0.0-rc.1`; current artifact is a Node-compatible WASM tarball | Isolated npm install/consumer gate; add browser runtime/size and browser WebRTC interoperability before any public npmjs release |
| C/C++ | header plus platform archive/shared-library bundle | Linux `x86_64` artifact bundle is automated; add target compiler matrix and platform bundles before a release declaration |
| C# | `Nixort.LibFcp` prerelease | .NET source façade is included in Linux artifact bundle; add NuGet RID native assets and packaging/consumer gates |
| Go | module release with declared cgo target support | Go source façade is included in Linux artifact bundle; add Go release builds and declared cgo target matrix |

Run `./scripts/test_jvm_maven_package.sh` to build an isolated local repository, verify JAR/POM checksums, resolve it from a clean Maven cache and execute Java plus Kotlin consumer smoke tests. Run `./scripts/test_js_npm_package.sh` to build an npm tarball, verify its checksum, install it into a clean Node consumer and execute the WASM API smoke test. The GitHub `libfcp JVM prerelease`, `libfcp npm prerelease` and `libfcp native bindings prerelease` workflows repeat those gates, upload short-retention artifacts, and attest only trusted `main` builds.

`@nixort/libfcp` defaults to the repository-linked GitHub Packages registry, preventing an accidental npmjs upload. The `v1.0.0-rc.1` GitHub Packages RC was published through the separate `libfcp npm GitHub Packages release` workflow after an explicit `workflow_dispatch` confirmation from `main`; its package gates, job-scoped `packages: write` token and provenance attestation completed successfully. The same workflow also supports a matching GitHub prerelease event, but the published RC does not require a Git tag or GitHub Release. A public npmjs release is intentionally not configured: it needs an npm package record and a separately approved OIDC trusted-publisher relationship before it may be added.[8] [9]

No registry login, namespace credential, signer secret, cloud credential or endpoint is stored in this repository or supplied through a binding command. A human must approve each upload after the target-specific gates pass.

## References

[1] [Rust Nomicon — Foreign Function Interface](https://doc.rust-lang.org/nomicon/ffi.html)

[2] [Oracle — Java Native Interface specification](https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html)

[3] [wasm-bindgen Guide](https://wasm-bindgen.github.io/wasm-bindgen/)

[4] [Kotlin documentation — multiplatform library publication](https://kotlinlang.org/docs/multiplatform/multiplatform-publish-lib-setup.html)

[5] [Gradle — Maven Publish Plugin](https://docs.gradle.org/current/userguide/publishing_maven.html)

[6] [Maven Central — publishing through the Central Portal](https://central.sonatype.org/publish/publish-portal-gradle/)

[7] [GitHub — artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)

[8] [npm — Trusted publishing for npm packages](https://docs.npmjs.com/trusted-publishers/)

[9] [GitHub — Publishing Node.js packages](https://docs.github.com/actions/publishing-packages/publishing-nodejs-packages)
