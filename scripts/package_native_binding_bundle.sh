#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${LIBFCP_NATIVE_BINDING_PACKAGE_DIR:-$repo_root/build/native-bindings}"
cargo_target="${LIBFCP_NATIVE_BINDING_CARGO_TARGET:-$output_root/cargo-target}"
bundle_root="$output_root/libfcp-native-bindings-linux-x86_64"
tarball="$output_root/libfcp-native-bindings-linux-x86_64-1.0.0-rc.1.tar.gz"

for command in cargo cp tar sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

rm -rf "$output_root"
mkdir -p "$bundle_root/include" "$bundle_root/lib" "$bundle_root/bindings"

cd "$repo_root"
CARGO_TARGET_DIR="$cargo_target" cargo build -p libfcp-ffi --release --locked
cp crates/libfcp-ffi/include/libfcp_ffi.h "$bundle_root/include/"
cp "$cargo_target/release/libfcp_ffi.so" "$bundle_root/lib/"
cp bindings/cpp/include/libfcp.hpp "$bundle_root/bindings/"
cp -R bindings/python "$bundle_root/bindings/python"
find "$bundle_root/bindings/python" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$bundle_root/bindings/python" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
cp -R bindings/csharp/src "$bundle_root/bindings/csharp"
cp -R bindings/go "$bundle_root/bindings/go"
cp LICENSE "$bundle_root/"

cat > "$bundle_root/README.md" <<'MARKDOWN'
# libfcp native binding bundle — Linux x86_64

This bundle contains the one Rust `libfcp_ffi.so` native core, the reviewed C header, the C++20 façade and source façades for Python, C#/.NET and Go/cgo. It is not a registry package and does not reimplement FCP in those languages.

Set `LIBFCP_FFI_LIBRARY` to the absolute path of `lib/libfcp_ffi.so` before loading the Python or C# façade. C++ and Go consumers must add `include/` and `lib/` to their build/link search paths. The bundle is limited to Linux x86_64; no other platform is implied.
MARKDOWN

(
    cd "$output_root"
    tar --sort=name --mtime='UTC 2026-01-01' --owner=0 --group=0 --numeric-owner \
        -czf "$tarball" "$(basename "$bundle_root")"
    sha256sum "$(basename "$tarball")" > SHA256SUMS
)
printf 'native binding bundle: %s\n' "$tarball"
