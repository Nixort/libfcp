#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$($repo_root/scripts/release_metadata.sh version)"
package_root="${LIBFCP_GITHUB_RELEASE_ASSETS_DIR:-}"
if [[ -z "$package_root" ]]; then
    package_root="$(mktemp -d "${TMPDIR:-/tmp}/libfcp-github-release-assets.XXXXXX")"
    trap 'rm -rf "$package_root"' EXIT
fi

LIBFCP_GITHUB_RELEASE_ASSETS_DIR="$package_root" \
    "$repo_root/scripts/package_github_release_assets.sh"

(
    cd "$package_root"
    sha256sum --check SHA256SUMS
    test -f "libfcp-wasm-$version.tgz"
    test -f "libfcp-native-bindings-linux-x86_64-$version.tar.gz"
    test ! -e "libfcp-$version-maven-central-bundle.zip"
    tar -tzf "libfcp-native-bindings-linux-x86_64-$version.tar.gz" \
        | grep -Fx 'libfcp-native-bindings-linux-x86_64/README.md' >/dev/null
)
printf 'GitHub Release asset gate passed.\n'
