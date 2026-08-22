#!/usr/bin/env bash
# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).
#
# Validates a restricted systemd EnvironmentFile without sourcing or printing it.

set -euo pipefail

ENV_FILE=${1:-/etc/fcp-fabric/fcp-fabric.env}
readonly ENV_FILE

fail() {
    printf 'fcp-fabric secret validation failed: %s\n' "$1" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "run this validator as root so it can read the protected environment file"
[[ -f "$ENV_FILE" ]] || fail "environment file does not exist"
[[ ! -L "$ENV_FILE" ]] || fail "environment file must not be a symlink"

owner=$(stat -c '%U' "$ENV_FILE")
mode=$(stat -c '%a' "$ENV_FILE")
[[ "$owner" == root ]] || fail "environment file must be owned by root"
(( (8#$mode & 8#077) == 0 )) || fail "environment file must not be group- or world-readable"

value_for() {
    local name=$1
    local matches
    matches=$(awk -v name="$name" '
        $0 ~ "^[[:space:]]*" name "=" {
            value = $0
            sub("^[[:space:]]*" name "=", "", value)
            if (value == "" || value ~ /^[[:space:]]/) {
                exit 2
            }
            print value
        }
    ' "$ENV_FILE") || fail "invalid assignment for $name"
    local count
    count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)
    (( count <= 1 )) || fail "duplicate assignment for $name"
    printf '%s' "$matches"
}

validate_digest_key() {
    local name=$1
    local value
    value=$(value_for "$name")
    [[ -n "$value" ]] || fail "missing $name"
    [[ "$value" =~ ^[A-Za-z0-9_-]{43}$ ]] || fail "$name must be 32 bytes as unpadded URL-safe Base64"
    local decoded_length
    decoded_length=$(printf '%s=' "$value" | tr '_-' '/+' | base64 --decode 2>/dev/null | wc -c) \
        || fail "$name has invalid Base64 encoding"
    [[ "$decoded_length" == 32 ]] || fail "$name must decode to exactly 32 bytes"
    printf '%s' "$value"
}

require_all_or_none() {
    local present=0
    local missing=0
    local name
    for name in "$@"; do
        if [[ -n $(value_for "$name") ]]; then
            ((present += 1))
        else
            ((missing += 1))
        fi
    done
    (( present == 0 || missing == 0 )) || fail "runtime group must be complete or absent"
}

readonly -a LOGIN_KEYS=(
    FABRIC_LOGIN_TRANSACTION_DIGEST_KEY
    FABRIC_LOGIN_BINDING_DIGEST_KEY
)
readonly -a MFA_KEYS=(
    FABRIC_SESSION_DIGEST_KEY
    FABRIC_STEP_UP_DIGEST_KEY
    FABRIC_WEBAUTHN_CEREMONY_DIGEST_KEY
    FABRIC_WEBAUTHN_BINDING_DIGEST_KEY
)
readonly -a MFA_METADATA=(
    FABRIC_TOTP_ACTIVE_KEY_REFERENCE
    FABRIC_TOTP_ISSUER
)

require_all_or_none FCP_DATABASE_URL FABRIC_PASSWORD_DUMMY_VERIFIER "${LOGIN_KEYS[@]}"
require_all_or_none "${MFA_METADATA[@]}" "${MFA_KEYS[@]}"

all_digests=()
for name in "${LOGIN_KEYS[@]}" "${MFA_KEYS[@]}"; do
    if [[ -n $(value_for "$name") ]]; then
        all_digests+=("$(validate_digest_key "$name")")
    fi
done

if (( ${#all_digests[@]} > 0 )); then
    unique_count=$(printf '%s\n' "${all_digests[@]}" | sort -u | wc -l)
    (( unique_count == ${#all_digests[@]} )) || fail "digest-key values must be pairwise distinct across configured domains"
fi

if [[ -n $(value_for FABRIC_TOTP_ACTIVE_KEY_REFERENCE) ]]; then
    reference=$(value_for FABRIC_TOTP_ACTIVE_KEY_REFERENCE)
    [[ ${#reference} -le 256 && "$reference" != *$'\n'* && "$reference" != *$'\r'* ]] \
        || fail "FABRIC_TOTP_ACTIVE_KEY_REFERENCE is malformed"
fi

printf 'fcp-fabric secret validation passed: file permissions and configured key domains are valid.\n'
