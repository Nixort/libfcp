#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="1.0.0-rc.1"
group_path="io/github/nixort"
artifact_id="libfcp"
output_root="${LIBFCP_JVM_PACKAGE_DIR:-$repo_root/build/jvm-package}"
repository="$output_root/maven-repository"
staging="$output_root/staging"
native_target="${LIBFCP_JVM_NATIVE_TARGET:-$output_root/cargo-target}"

for command in cargo cc javac jar javadoc kotlinc mvn sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

rm -rf "$output_root"
mkdir -p "$staging/classes" "$staging/kotlin-classes" "$staging/javadoc" \
    "$staging/native/linux-x86_64/META-INF/native/linux-x86_64"

cd "$repo_root"
CARGO_TARGET_DIR="$native_target" cargo build -p libfcp-ffi --release --locked
ffi_library="$native_target/release/libfcp_ffi.so"
test -f "$ffi_library"

java_home="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
cc -shared -fPIC -std=c17 -O2 -Wall -Wextra -Werror \
    -I"$java_home/include" -I"$java_home/include/linux" \
    -I"$repo_root/crates/libfcp-ffi/include" \
    "$repo_root/bindings/java/src/main/c/fcp_jni.c" \
    -L"$native_target/release" -lfcp_ffi \
    -Wl,-rpath,'$ORIGIN' \
    -o "$staging/native/linux-x86_64/META-INF/native/linux-x86_64/libfcp_jni.so"
cp "$ffi_library" "$staging/native/linux-x86_64/META-INF/native/linux-x86_64/libfcp_ffi.so"

find "$repo_root/bindings/java/src/main/java" -name '*.java' -print0 \
    | xargs -0 javac --release 17 -d "$staging/classes"
find "$repo_root/bindings/kotlin/src/main/kotlin" -name '*.kt' -print0 \
    | xargs -0 kotlinc -jvm-target 1.8 -classpath "$staging/classes" -d "$staging/kotlin-classes"
cp -R "$staging/kotlin-classes"/. "$staging/classes"/

jar --create --file "$staging/$artifact_id-$version.jar" -C "$staging/classes" .
jar --create --file "$staging/$artifact_id-$version-sources.jar" \
    -C "$repo_root/bindings/java/src/main/java" . \
    -C "$repo_root/bindings/kotlin/src/main/kotlin" .
javadoc --release 17 -Xdoclint:all,-missing -quiet -d "$staging/javadoc" \
    $(find "$repo_root/bindings/java/src/main/java" -name '*.java' -print)
jar --create --file "$staging/$artifact_id-$version-javadoc.jar" -C "$staging/javadoc" .
jar --create --file "$staging/$artifact_id-$version-linux-x86_64.jar" \
    -C "$staging/native/linux-x86_64" .

mvn -q --batch-mode org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile="$staging/$artifact_id-$version.jar" \
    -DpomFile="$repo_root/bindings/java/pom.xml" \
    -Dsources="$staging/$artifact_id-$version-sources.jar" \
    -Djavadoc="$staging/$artifact_id-$version-javadoc.jar" \
    -DlocalRepositoryPath="$repository"
mvn -q --batch-mode org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile="$staging/$artifact_id-$version-linux-x86_64.jar" \
    -DpomFile="$repo_root/bindings/java/pom.xml" \
    -Dclassifier=linux-x86_64 \
    -DlocalRepositoryPath="$repository"

artifact_directory="$repository/$group_path/$artifact_id/$version"
(
    cd "$artifact_directory"
    sha256sum *.jar *.pom > SHA256SUMS
)
printf 'JVM Maven repository: %s\n' "$repository"
printf 'Coordinates: io.github.nixort:%s:%s\n' "$artifact_id" "$version"
printf 'Native classifier built: linux-x86_64\n'
