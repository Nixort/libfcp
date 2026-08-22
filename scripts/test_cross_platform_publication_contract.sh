#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

set -euo pipefail

readonly ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly BINDINGS="$ROOT/docs/bindings.md"
readonly PRERELEASE="$ROOT/docs/prereleases/v1.0.0-rc.1.md"
readonly JVM_POM="$ROOT/bindings/java/pom.xml"
readonly JVM_PACKAGE="$ROOT/scripts/package_jvm_bindings.sh"
readonly JVM_GATE="$ROOT/scripts/test_jvm_maven_package.sh"
readonly JVM_WORKFLOW="$ROOT/.github/workflows/jvm-prerelease.yml"
readonly NPM_MANIFEST="$ROOT/bindings/js/package.json"
readonly NPM_PACKAGE="$ROOT/scripts/package_js_npm.sh"
readonly NPM_GATE="$ROOT/scripts/test_js_npm_package.sh"
readonly NPM_WORKFLOW="$ROOT/.github/workflows/npm-prerelease.yml"
readonly NPM_GITHUB_RELEASE="$ROOT/.github/workflows/npm-github-packages-release.yml"
readonly NATIVE_BUNDLE="$ROOT/scripts/package_native_binding_bundle.sh"
readonly NATIVE_WORKFLOW="$ROOT/.github/workflows/native-bindings-prerelease.yml"

fail() {
  printf 'cross-platform publication contract failed: %s\n' "$1" >&2
  exit 1
}

require() {
  local pattern=$1
  local file=$2
  grep -Fq -- "$pattern" "$file" || fail "missing $pattern in ${file#$ROOT/}"
}

[[ -f "$BINDINGS" ]] || fail 'missing canonical binding guide'
[[ -f "$PRERELEASE" ]] || fail 'missing prerelease note'
[[ -f "$JVM_POM" ]] || fail 'missing JVM Maven POM'
[[ -x "$JVM_PACKAGE" ]] || fail 'missing executable JVM package builder'
[[ -x "$JVM_GATE" ]] || fail 'missing executable JVM Maven gate'
[[ -f "$JVM_WORKFLOW" ]] || fail 'missing JVM prerelease workflow'
[[ -f "$NPM_MANIFEST" ]] || fail 'missing npm manifest'
[[ -x "$NPM_PACKAGE" ]] || fail 'missing executable npm package builder'
[[ -x "$NPM_GATE" ]] || fail 'missing executable npm consumer gate'
[[ -f "$NPM_WORKFLOW" ]] || fail 'missing npm prerelease workflow'
[[ -f "$NPM_GITHUB_RELEASE" ]] || fail 'missing npm GitHub Packages release workflow'
[[ -x "$NATIVE_BUNDLE" ]] || fail 'missing executable native bundle builder'
[[ -f "$NATIVE_WORKFLOW" ]] || fail 'missing native binding workflow'
[[ ! -e "$ROOT/docs/releases" ]] || fail 'legacy docs/releases directory remains'

require 'The Node/browser-bundler package **`@nixort/libfcp@1.0.0-rc.1` is published to GitHub Packages**' "$BINDINGS"
require 'No remote Maven artifact, wheel, npmjs package, NuGet package, Go module release or platform binary is published' "$BINDINGS"
require 'Proposed `libfcp-ffi`' "$BINDINGS"
require 'Kotlin/JVM' "$BINDINGS"
require 'Kotlin/Android' "$BINDINGS"
require 'Java' "$BINDINGS"
require 'UniFFI' "$BINDINGS"
require 'JNI' "$BINDINGS"
require 'Canonical vectors' "$BINDINGS"
require 'Publication integrity' "$BINDINGS"
require 'FCP_DATABASE_URL' "$BINDINGS"
require 'io.github.nixort:libfcp:1.0.0-rc.1' "$BINDINGS"
require 'linux-x86_64' "$BINDINGS"
require '<groupId>io.github.nixort</groupId>' "$JVM_POM"
require '<artifactId>libfcp</artifactId>' "$JVM_POM"
require '<version>1.0.0-rc.1</version>' "$JVM_POM"
require 'kotlin-stdlib' "$JVM_POM"
require 'maven-repository' "$JVM_PACKAGE"
require 'linux-x86_64' "$JVM_PACKAGE"
require 'maven-repository' "$JVM_GATE"
require 'local Maven package and consumer verification passed' "$JVM_GATE"
require 'This workflow validates and attaches prerelease artifacts. It never publishes' "$JVM_WORKFLOW"
require 'actions/attest@' "$JVM_WORKFLOW"
require '@nixort/libfcp' "$NPM_MANIFEST"
require '1.0.0-rc.1' "$NPM_MANIFEST"
require 'provenance' "$NPM_MANIFEST"
require 'https://npm.pkg.github.com' "$NPM_MANIFEST"
require 'npm pack' "$NPM_PACKAGE"
require 'local npm package and consumer verification passed' "$NPM_GATE"
require 'This workflow validates and attaches prerelease artifacts. It never publishes' "$NPM_WORKFLOW"
require 'actions/attest@' "$NPM_WORKFLOW"
require 'github-packages-release' "$NPM_GITHUB_RELEASE"
require 'github.event.release.prerelease' "$NPM_GITHUB_RELEASE"
require 'npm publish --registry=https://npm.pkg.github.com' "$NPM_GITHUB_RELEASE"
require 'actions/attest@' "$NPM_GITHUB_RELEASE"
require 'libfcp-native-bindings-linux-x86_64' "$NATIVE_BUNDLE"
require 'This workflow validates and attaches prerelease artifacts. It never publishes' "$NATIVE_WORKFLOW"
require 'actions/attest@' "$NATIVE_WORKFLOW"
require '@nixort/libfcp@1.0.0-rc.1' "$BINDINGS"
require 'libfcp npm prerelease' "$BINDINGS"
require 'libfcp native bindings prerelease' "$BINDINGS"
require 'libfcp npm GitHub Packages release' "$BINDINGS"
require 'docs/prereleases/v1.0.0-rc.1.md' "$ROOT/README.md"
require 'docs/bindings.md' "$ROOT/README.md"
require 'bindings.md' "$ROOT/docs/integration.md"

legacy_matches=$(rg -n 'docs/releases/|/releases/v1\.0\.0-rc\.1' "$ROOT/README.md" "$ROOT/CONTRIBUTING.md" "$ROOT/SECURITY.md" "$ROOT/docs" "$ROOT/deploy" "$ROOT/crates" "$ROOT/scripts" --glob '*.md' --glob '*.rs' --glob '*.toml' --glob '*.sh' | grep -vF 'scripts/test_cross_platform_publication_contract.sh' || true)
if [[ -n "$legacy_matches" ]]; then
  printf '%s\n' "$legacy_matches" >&2
  fail 'legacy release-candidate path remains'
fi

bash -n "$JVM_PACKAGE" "$JVM_GATE" "$NPM_PACKAGE" "$NPM_GATE" "$NATIVE_BUNDLE"
printf 'cross-platform publication contract passed.\n'
