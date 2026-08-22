#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${LIBFCP_NPM_PACKAGE_DIR:-$repo_root/build/npm-package}"
cargo_target="${LIBFCP_NPM_CARGO_TARGET:-$output_root/cargo-target}"
package_root="$output_root/package"
tarball_root="$output_root/tarballs"

for command in cargo npm sha256sum cp; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

wasm_bindgen="${WASM_BINDGEN:-}"
if [[ -z "$wasm_bindgen" ]]; then
    wasm_bindgen="$(command -v wasm-bindgen || true)"
fi
if [[ -z "$wasm_bindgen" && -x "$HOME/.cargo/bin/wasm-bindgen" ]]; then
    wasm_bindgen="$HOME/.cargo/bin/wasm-bindgen"
fi
[[ -n "$wasm_bindgen" && -x "$wasm_bindgen" ]] || {
    printf '%s\n' 'matching wasm-bindgen CLI is unavailable; set WASM_BINDGEN to its executable path' >&2
    exit 1
}

rm -rf "$output_root"
mkdir -p "$package_root" "$tarball_root"

cd "$repo_root"
CARGO_TARGET_DIR="$cargo_target" cargo build -p libfcp-wasm \
    --target wasm32-unknown-unknown --release --locked
"$wasm_bindgen" --target nodejs --out-dir "$package_root" \
    "$cargo_target/wasm32-unknown-unknown/release/libfcp_wasm.wasm"
cp bindings/js/package.json bindings/js/README.md LICENSE "$package_root"/

(
    cd "$package_root"
    npm pack --ignore-scripts --json --pack-destination "$tarball_root" > "$output_root/npm-pack.json"
)

tarball="$(find "$tarball_root" -maxdepth 1 -type f -name '*.tgz' -print -quit)"
[[ -n "$tarball" ]] || {
    printf '%s\n' 'npm pack did not produce a tarball' >&2
    exit 1
}
sha256sum "$tarball" > "$tarball_root/SHA256SUMS"
printf 'npm package directory: %s\n' "$package_root"
printf 'npm tarball: %s\n' "$tarball"
