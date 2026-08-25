#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Builds exactly one host-native JNI classifier JAR. It is intentionally separate
# from Maven publication and may run only on the matching operating-system runner.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$($repo_root/scripts/release_metadata.sh version)"
artifact_id="libfcp"
classifier="${LIBFCP_JVM_NATIVE_CLASSIFIER:?LIBFCP_JVM_NATIVE_CLASSIFIER is required}"
output_root="${LIBFCP_JVM_NATIVE_CLASSIFIER_DIR:-$repo_root/build/jvm-native-classifier}"
cargo_target="${LIBFCP_JVM_NATIVE_CARGO_TARGET:-$output_root/cargo-target}"
staging="$output_root/staging"

for command in cargo cc jar; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

case "$classifier" in
    linux-x86_64)
        expected_os="linux"
        native_extension="so"
        linker_args=(-shared -fPIC -Wl,-rpath,'$ORIGIN')
        ;;
    macos-x86_64 | macos-aarch64)
        expected_os="darwin"
        native_extension="dylib"
        linker_args=(-dynamiclib -Wl,-rpath,@loader_path)
        ;;
    *)
        printf 'unsupported host-built JVM native classifier: %s\n' "$classifier" >&2
        exit 1
        ;;
esac

host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "$expected_os" == "darwin" ]]; then
    [[ "$host_os" == darwin* ]] || {
        printf '%s must be built on macOS, not %s\n' "$classifier" "$host_os" >&2
        exit 1
    }
else
    [[ "$host_os" == "$expected_os" ]] || {
        printf '%s must be built on %s, not %s\n' "$classifier" "$expected_os" "$host_os" >&2
        exit 1
    }
fi

rm -rf "$output_root"
mkdir -p "$staging/META-INF/native/$classifier"
cd "$repo_root"
CARGO_TARGET_DIR="$cargo_target" cargo build -p libfcp-ffi --release --locked

java_home="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
ffi_library="$cargo_target/release/libfcp_ffi.$native_extension"
test -f "$ffi_library"
cc -std=c17 -O2 -Wall -Wextra -Werror "${linker_args[@]}" \
    -I"$java_home/include" -I"$java_home/include/$expected_os" \
    -I"$repo_root/crates/libfcp-ffi/include" \
    "$repo_root/bindings/java/src/main/c/fcp_jni.c" \
    -L"$cargo_target/release" -lfcp_ffi \
    -o "$staging/META-INF/native/$classifier/libfcp_jni.$native_extension"
cp "$ffi_library" "$staging/META-INF/native/$classifier/libfcp_ffi.$native_extension"
jar --create --file "$output_root/$artifact_id-$version-$classifier.jar" -C "$staging" .
printf 'JVM native classifier JAR: %s\n' "$output_root/$artifact_id-$version-$classifier.jar"
