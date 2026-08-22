#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Rebuilds and validates local FFI façades only. It never uploads artifacts.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for command in cc c++ python3 javac java kotlinc kotlin node dotnet go; do
    command -v "$command" >/dev/null || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

wasm_bindgen="${WASM_BINDGEN:-$HOME/.cargo/bin/wasm-bindgen}"
[[ -x "$wasm_bindgen" ]] || {
    printf 'wasm-bindgen CLI is unavailable; set WASM_BINDGEN to its executable path\n' >&2
    exit 1
}

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/libfcp-foreign-bindings.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
export CARGO_TARGET_DIR="$work_dir/cargo-target"

cargo fmt --all -- --check
cargo test -p libfcp-ffi -p libfcp-wasm
cargo clippy -p libfcp-ffi -p libfcp-wasm --all-targets -- -D warnings
cargo build -p libfcp-ffi

cargo run -p libfcp-ffi --example generate_vectors > "$work_dir/vectors.json"
cmp "$work_dir/vectors.json" testdata/fcp-ffi/v1/vectors.json

native_dir="$CARGO_TARGET_DIR/debug"
native_library="$native_dir/libfcp_ffi.so"
cc -std=c11 -Wall -Wextra -Werror \
    -I crates/libfcp-ffi/include \
    crates/libfcp-ffi/tests/c_abi_smoke.c \
    -L "$native_dir" -lfcp_ffi -Wl,-rpath,"$native_dir" \
    -o "$work_dir/c-abi-smoke"
"$work_dir/c-abi-smoke"

c++ -std=c++20 -Wall -Wextra -Werror \
    -I crates/libfcp-ffi/include -I bindings/cpp/include \
    bindings/cpp/tests/smoke.cpp \
    -L "$native_dir" -lfcp_ffi -Wl,-rpath,"$native_dir" \
    -o "$work_dir/cpp-abi-smoke"
"$work_dir/cpp-abi-smoke"

LIBFCP_FFI_LIBRARY="$native_library" \
    PYTHONPATH=bindings/python/src \
    python3 -m unittest discover -s bindings/python/tests -v

java_home="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
java_classes="$work_dir/java-classes"
java_jni="$work_dir/java-jni"
mkdir -p "$java_classes" "$java_jni"
cc -std=c11 -Wall -Wextra -Werror -fPIC -shared \
    -I "$java_home/include" -I "$java_home/include/linux" \
    -I crates/libfcp-ffi/include \
    bindings/java/src/main/c/fcp_jni.c \
    -L "$native_dir" -lfcp_ffi -Wl,-rpath,"$native_dir" \
    -o "$java_jni/libfcp_jni.so"
javac --release 17 -d "$java_classes" \
    $(find bindings/java/src/main/java bindings/java/src/test/java -name '*.java' -print)
java \
    -Dio.github.nixort.libfcp.ffiPath="$native_library" \
    -Dio.github.nixort.libfcp.nativePath="$java_jni/libfcp_jni.so" \
    -cp "$java_classes" io.github.nixort.libfcp.SmokeTest

kotlin_classes="$work_dir/kotlin-classes"
kotlinc -jvm-target 1.8 -classpath "$java_classes" -d "$kotlin_classes" \
    $(find bindings/kotlin/src/main/kotlin bindings/kotlin/src/test/kotlin -name '*.kt' -print)
kotlin \
    -Dio.github.nixort.libfcp.ffiPath="$native_library" \
    -Dio.github.nixort.libfcp.nativePath="$java_jni/libfcp_jni.so" \
    -classpath "$java_classes:$kotlin_classes" io.github.nixort.libfcp.kotlin.SmokeTestKt

cargo build -p libfcp-wasm --target wasm32-unknown-unknown --release
wasm_package="$work_dir/js-package"
"$wasm_bindgen" --target nodejs --out-dir "$wasm_package" \
    "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/libfcp_wasm.wasm"
LIBFCP_WASM_PACKAGE="$wasm_package" node bindings/js/src/smoke.cjs

LIBFCP_FFI_LIBRARY="$native_library" \
    dotnet run --project bindings/csharp/tests/Smoke/Smoke.csproj --configuration Release

(
    cd bindings/go
    CGO_ENABLED=1 \
        CGO_LDFLAGS="-L$native_dir -Wl,-rpath,$native_dir" \
        go test ./...
)

printf '%s\n' 'foreign binding matrix passed'
