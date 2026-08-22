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

LIBFCP_JVM_PACKAGE_DIR="$package_root" "$repo_root/scripts/package_jvm_bindings.sh"
artifact_directory="$package_root/maven-repository/io/github/nixort/libfcp/1.0.0-rc.1"
for artifact in \
    libfcp-1.0.0-rc.1.jar \
    libfcp-1.0.0-rc.1-sources.jar \
    libfcp-1.0.0-rc.1-javadoc.jar \
    libfcp-1.0.0-rc.1-linux-x86_64.jar \
    libfcp-1.0.0-rc.1.pom \
    SHA256SUMS; do
    test -f "$artifact_directory/$artifact"
done
(
    cd "$artifact_directory"
    sha256sum --check SHA256SUMS
)

consumer="$repo_root/bindings/java/consumer-smoke"
classpath="$package_root/consumer-classpath.txt"
consumer_m2="$package_root/consumer-m2"
mvn -q --batch-mode -f "$consumer/pom.xml" \
    -Dmaven.repo.local="$consumer_m2" \
    -Dlibfcp.localRepository="file://$package_root/maven-repository" \
    -DskipTests compile dependency:build-classpath -Dmdep.outputFile="$classpath"
java -cp "$consumer/target/classes:$(cat "$classpath")" io.github.nixort.libfcp.ConsumerSmoke
printf '%s\n' 'local Maven package and consumer verification passed'
