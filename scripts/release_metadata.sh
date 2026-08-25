#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Prints canonical release metadata derived from the workspace manifest.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -nE 's/^version = "([^"]+)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)"

[[ -n "$version" ]] || {
    printf '%s\n' 'unable to read workspace release version from Cargo.toml' >&2
    exit 1
}

case "${1:-version}" in
    version)
        printf '%s\n' "$version"
        ;;
    tag)
        printf 'v%s\n' "$version"
        ;;
    *)
        printf 'usage: %s [version|tag]\n' "${0##*/}" >&2
        exit 64
        ;;
esac
