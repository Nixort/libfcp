/* Copyright Nixort <https://github.com/Nixort> 2026.
 *
 * License: GNU General Public License v3.0 only.
 * You can find the license file in the project root.
 *
 * Federated CFR Connect Protocol (FCP).
 */

#include "libfcp_ffi.h"

#include <assert.h>
#include <string.h>

static FcpByteSlice bytes(const uint8_t *data, size_t len) {
    FcpByteSlice result = {data, len};
    return result;
}

int main(void) {
    assert(fcp_ffi_abi_version() == FCP_FFI_ABI_VERSION);
    assert(fcp_ffi_wire_version() == FCP_FFI_WIRE_VERSION);

    FcpSigner *local = NULL;
    FcpSigner *remote = NULL;
    assert(fcp_signer_generate(&local) == FCP_STATUS_OK);
    assert(fcp_signer_generate(&remote) == FCP_STATUS_OK);

    FcpOwnedBuffer remote_identity = {0};
    assert(fcp_signer_public_identity(remote, &remote_identity) == FCP_STATUS_OK);
    assert(remote_identity.len == FCP_ENDPOINT_IDENTITY_BYTES);

    uint8_t federation[FCP_FEDERATION_ID_BYTES] = {3};
    uint8_t attempt[FCP_ATTEMPT_ID_BYTES] = {7};
    FcpConnectionOptions options = {
        bytes(federation, sizeof(federation)),
        bytes(attempt, sizeof(attempt)),
        bytes(remote_identity.data, remote_identity.len),
    };
    FcpConnection *connection = NULL;
    assert(fcp_connection_create(local, options, &connection) == FCP_STATUS_OK);

    uint8_t binding[FCP_WEBRTC_BINDING_BYTES] = {9};
    static const uint8_t description[] = "opaque-offer";
    assert(fcp_connection_begin_offer(
               connection,
               bytes(binding, sizeof(binding)),
               bytes(description, sizeof(description) - 1)) == FCP_STATUS_OK);

    FcpAction action = {0};
    assert(fcp_connection_take_action(connection, &action) == FCP_STATUS_OK);
    assert(action.kind == FCP_ACTION_OPEN_CONTROL_CHANNEL);
    fcp_action_free(&action);

    assert(fcp_connection_take_action(connection, &action) == FCP_STATUS_OK);
    assert(action.kind == FCP_ACTION_SEND_ENVELOPE);
    assert(fcp_envelope_verify(bytes(action.payload.data, action.payload.len)) == FCP_STATUS_OK);
    fcp_action_free(&action);
    assert(fcp_connection_take_action(connection, &action) == FCP_STATUS_NO_ACTION);

    fcp_connection_free(&connection);
    fcp_buffer_free(&remote_identity);
    fcp_signer_free(&local);
    fcp_signer_free(&remote);
    assert(connection == NULL);
    assert(local == NULL);
    assert(remote == NULL);
    return 0;
}
