#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Builds a local Maven repository and a Central Portal-compatible deployment bundle.
# External publication is intentionally not performed by this script.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$($repo_root/scripts/release_metadata.sh version)"
group_path="io/github/nixort"
artifact_id="libfcp"
output_root="${LIBFCP_JVM_PACKAGE_DIR:-$repo_root/build/jvm-package}"
repository="$output_root/maven-repository"
staging="$output_root/staging"
central_staging="$output_root/central-staging"
central_bundle="$output_root/libfcp-$version-central-bundle.zip"
prebuilt_classifiers="${LIBFCP_JVM_PREBUILT_CLASSIFIERS_DIR:-}"

for command in javac jar javadoc kotlinc mvn sha256sum sha512sum sha1sum md5sum zip; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

rm -rf "$output_root"
mkdir -p "$staging/classes" "$staging/kotlin-classes" "$staging/javadoc" "$staging/native-jars"

cd "$repo_root"
if [[ -n "$prebuilt_classifiers" ]]; then
    [[ -d "$prebuilt_classifiers" ]] || {
        printf 'LIBFCP_JVM_PREBUILT_CLASSIFIERS_DIR is not a directory: %s\n' "$prebuilt_classifiers" >&2
        exit 1
    }
    shopt -s nullglob
    native_jars=("$prebuilt_classifiers/$artifact_id-$version-"*.jar)
    shopt -u nullglob
    [[ ${#native_jars[@]} -gt 0 ]] || {
        printf 'no native classifier JARs found in: %s\n' "$prebuilt_classifiers" >&2
        exit 1
    }
    for native_jar in "${native_jars[@]}"; do
        cp "$native_jar" "$staging/native-jars/"
    done
else
    local_classifier="${LIBFCP_JVM_NATIVE_CLASSIFIER:-linux-x86_64}"
    local_native_root="$staging/local-native"
    LIBFCP_JVM_NATIVE_CLASSIFIER="$local_classifier" \
        LIBFCP_JVM_NATIVE_CLASSIFIER_DIR="$local_native_root" \
        LIBFCP_JVM_NATIVE_CARGO_TARGET="${LIBFCP_JVM_NATIVE_TARGET:-$output_root/cargo-target}" \
        "$repo_root/scripts/package_jvm_native_classifier.sh"
    cp "$local_native_root/$artifact_id-$version-$local_classifier.jar" "$staging/native-jars/"
fi

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

mvn -q --batch-mode org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
    -Dfile="$staging/$artifact_id-$version.jar" \
    -DpomFile="$repo_root/bindings/java/pom.xml" \
    -Dsources="$staging/$artifact_id-$version-sources.jar" \
    -Djavadoc="$staging/$artifact_id-$version-javadoc.jar" \
    -DlocalRepositoryPath="$repository"
for native_jar in "$staging/native-jars/$artifact_id-$version-"*.jar; do
    name="$(basename "$native_jar")"
    classifier="${name#"$artifact_id-$version-"}"
    classifier="${classifier%.jar}"
    [[ -n "$classifier" && "$classifier" != "$name" ]] || {
        printf 'invalid native classifier JAR name: %s\n' "$name" >&2
        exit 1
    }
    mvn -q --batch-mode org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
        -Dfile="$native_jar" \
        -DpomFile="$repo_root/bindings/java/pom.xml" \
        -Dclassifier="$classifier" \
        -DlocalRepositoryPath="$repository"
done

artifact_directory="$repository/$group_path/$artifact_id/$version"
central_directory="$central_staging/$group_path/$artifact_id/$version"
mkdir -p "$central_directory"
cp "$artifact_directory"/*.jar "$artifact_directory"/*.pom "$central_directory"/

write_checksums() {
    local artifact="$1"
    md5sum "$artifact" | awk '{print $1}' > "$artifact.md5"
    sha1sum "$artifact" | awk '{print $1}' > "$artifact.sha1"
    sha256sum "$artifact" | awk '{print $1}' > "$artifact.sha256"
    sha512sum "$artifact" | awk '{print $1}' > "$artifact.sha512"
}

for artifact in "$central_directory"/*.jar "$central_directory"/*.pom; do
    write_checksums "$artifact"
done

if [[ "${LIBFCP_JVM_SIGN:-0}" == "1" ]]; then
    command -v gpg >/dev/null 2>&1 || {
        printf 'LIBFCP_JVM_SIGN=1 requires gpg\n' >&2
        exit 1
    }
    gpg_args=(--batch --yes --armor --detach-sign)
    if [[ -n "${LIBFCP_JVM_GPG_PASSPHRASE:-}" ]]; then
        gpg_args+=(--pinentry-mode loopback --passphrase "$LIBFCP_JVM_GPG_PASSPHRASE")
    fi
    for artifact in "$central_directory"/*.jar "$central_directory"/*.pom; do
        gpg "${gpg_args[@]}" --output "$artifact.asc" "$artifact"
    done
fi

(
    cd "$central_staging"
    zip -q -r "$central_bundle" .
)
(
    cd "$artifact_directory"
    sha256sum *.jar *.pom > SHA256SUMS
)
printf 'JVM Maven repository: %s\n' "$repository"
printf 'Central deployment bundle: %s\n' "$central_bundle"
printf 'Coordinates: io.github.nixort:%s:%s\n' "$artifact_id" "$version"
printf 'Native classifiers: %s\n' "$(find "$staging/native-jars" -maxdepth 1 -name '*.jar' -printf '%f ' | sed 's/\.jar//g')"
printf 'PGP signatures: %s\n' "${LIBFCP_JVM_SIGN:-0}"
