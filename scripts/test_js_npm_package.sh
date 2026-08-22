#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/libfcp-npm-package.XXXXXX")"
trap 'rm -rf "$work_root"' EXIT

LIBFCP_NPM_PACKAGE_DIR="$work_root/package-build" "$repo_root/scripts/package_js_npm.sh"
tarball_root="$work_root/package-build/tarballs"
tarball="$(find "$tarball_root" -maxdepth 1 -type f -name '*.tgz' -print -quit)"
test -n "$tarball"
(
    cd "$tarball_root"
    sha256sum --check SHA256SUMS
)

consumer="$work_root/consumer"
mkdir -p "$consumer"
cat > "$consumer/package.json" <<'JSON'
{
  "name": "libfcp-npm-consumer-smoke",
  "private": true,
  "version": "0.0.0"
}
JSON
cp "$repo_root/bindings/js/consumer-smoke/consumer.cjs" "$consumer/consumer.cjs"
(
    cd "$consumer"
    npm install --ignore-scripts --no-audit --no-fund --no-package-lock "$tarball"
    node consumer.cjs
)
printf '%s\n' 'local npm package and consumer verification passed'
