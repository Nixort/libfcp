#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly METADATA="$ROOT/scripts/release_metadata.sh"
readonly POM="$ROOT/bindings/java/pom.xml"
readonly NPM_MANIFEST="$ROOT/bindings/js/package.json"

fail() {
    printf 'release metadata contract failed: %s\n' "$1" >&2
    exit 1
}

[[ -x "$METADATA" ]] || fail 'missing executable release metadata helper'
version="$($METADATA version)"
tag="$($METADATA tag)"
[[ "$tag" == "v$version" ]] || fail 'release tag does not match workspace version'

pom_version="$(sed -nE 's@^[[:space:]]*<version>([^<]+)</version>@\1@p' "$POM" | head -n 1)"
[[ "$pom_version" == "$version" ]] || fail 'Maven version differs from workspace version'
require_pom_tag='<tag>v${project.version}</tag>'
grep -Fq -- "$require_pom_tag" "$POM" || fail 'Maven SCM tag is not derived from project version'

npm_version="$(node -p "require('$NPM_MANIFEST').version")"
[[ "$npm_version" == "$version" ]] || fail 'npm version differs from workspace version'

for script in \
    scripts/package_jvm_bindings.sh \
    scripts/package_jvm_native_classifier.sh \
    scripts/package_native_binding_bundle.sh \
    scripts/package_github_release_assets.sh \
    scripts/test_jvm_maven_package.sh; do
    grep -Fq 'release_metadata.sh version' "$ROOT/$script" || {
        fail "$script does not use canonical release metadata"
    }
done

printf 'release metadata contract passed: %s (%s).\n' "$version" "$tag"
