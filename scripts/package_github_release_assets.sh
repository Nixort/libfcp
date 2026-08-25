#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Builds public GitHub Release assets. Maven Central deployment bundles are
# intentionally excluded: Central publication must use the protected workflow
# that assembles all verified native classifiers and applies GPG signatures.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$($repo_root/scripts/release_metadata.sh version)"
output_root="${LIBFCP_GITHUB_RELEASE_ASSETS_DIR:-$repo_root/build/github-release-assets}"
staging="$output_root/.staging"

for command in cp find sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

rm -rf "$output_root"
mkdir -p "$staging/npm" "$staging/native"

LIBFCP_NPM_PACKAGE_DIR="$staging/npm" "$repo_root/scripts/package_js_npm.sh"
wasm_tarball="$(find "$staging/npm/tarballs" -maxdepth 1 -type f -name '*.tgz' -print -quit)"
test -n "$wasm_tarball"
cp "$wasm_tarball" "$output_root/libfcp-wasm-$version.tgz"

LIBFCP_NATIVE_BINDING_PACKAGE_DIR="$staging/native" \
    "$repo_root/scripts/package_native_binding_bundle.sh"
native_tarball="$staging/native/libfcp-native-bindings-linux-x86_64-$version.tar.gz"
test -f "$native_tarball"
cp "$native_tarball" "$output_root/"

(
    cd "$output_root"
    rm -rf .staging
    sha256sum \
        "libfcp-wasm-$version.tgz" \
        "libfcp-native-bindings-linux-x86_64-$version.tar.gz" > SHA256SUMS
)
printf 'GitHub Release assets: %s\n' "$output_root"
printf '%s\n' 'Maven Central bundles are produced only by the protected signed publication workflow.'
