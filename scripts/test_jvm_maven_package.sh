#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package_root="$(mktemp -d "${TMPDIR:-/tmp}/libfcp-jvm-package.XXXXXX")"
trap 'rm -rf "$package_root"' EXIT
java_home="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
version="$($repo_root/scripts/release_metadata.sh version)"
artifact_directory="$package_root/maven-repository/io/github/nixort/libfcp/$version"
central_directory="$package_root/central-staging/io/github/nixort/libfcp/$version"
central_bundle="$package_root/libfcp-$version-central-bundle.zip"

LIBFCP_JVM_PACKAGE_DIR="$package_root" "$repo_root/scripts/package_jvm_bindings.sh"
for artifact in \
    "libfcp-$version.jar" \
    "libfcp-$version-sources.jar" \
    "libfcp-$version-javadoc.jar" \
    "libfcp-$version.pom" \
    SHA256SUMS; do
    test -f "$artifact_directory/$artifact"
done

classifiers=(linux-x86_64)
if [[ -n "${LIBFCP_JVM_PREBUILT_CLASSIFIERS_DIR:-}" ]]; then
    classifiers=(linux-x86_64 macos-x86_64 macos-aarch64)
fi
for classifier in "${classifiers[@]}"; do
    test -f "$artifact_directory/libfcp-$version-$classifier.jar"
done
(
    cd "$artifact_directory"
    sha256sum --check SHA256SUMS
)

for artifact in "$central_directory"/*.jar "$central_directory"/*.pom; do
    test -f "$artifact"
    for algorithm in md5 sha1 sha256 sha512; do
        test -s "$artifact.$algorithm"
    done
    if [[ "${LIBFCP_JVM_SIGN:-0}" == "1" ]]; then
        test -s "$artifact.asc"
    fi
done
unzip -t "$central_bundle" >/dev/null
unzip -Z1 "$central_bundle" | grep -Fx "io/github/nixort/libfcp/$version/libfcp-$version.pom" >/dev/null
for classifier in "${classifiers[@]}"; do
    unzip -Z1 "$central_bundle" | grep -Fx "io/github/nixort/libfcp/$version/libfcp-$version-$classifier.jar" >/dev/null
done

consumer="$repo_root/bindings/java/consumer-smoke"
classpath="$package_root/consumer-classpath.txt"
consumer_m2="$package_root/consumer-m2"
JAVA_HOME="$java_home" PATH="$java_home/bin:$PATH" mvn -q --batch-mode -f "$consumer/pom.xml" \
    -Dmaven.repo.local="$consumer_m2" \
    -Dlibfcp.localRepository="file://$package_root/maven-repository" \
    -DskipTests compile dependency:build-classpath -Dmdep.outputFile="$classpath"
"$java_home/bin/java" -cp "$consumer/target/classes:$(cat "$classpath")" \
    io.github.nixort.libfcp.ConsumerSmoke
printf '%s\n' 'local Maven package, Central bundle and consumer verification passed'
