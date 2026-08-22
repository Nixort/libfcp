/* Copyright Nixort <https://github.com/Nixort> 2026.
 *
 * License: GNU General Public License v3.0 only.
 * You can find the license file in the project root.
 *
 * Federated CFR Connect Protocol (FCP).
 */

#ifndef LIBFCP_FFI_H
#define LIBFCP_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FCP_FFI_ABI_VERSION 1u
#define FCP_FFI_WIRE_VERSION 1u
#define FCP_FEDERATION_ID_BYTES 32u
#define FCP_ATTEMPT_ID_BYTES 16u
#define FCP_CFR_IDENTITY_BYTES 32u
#define FCP_WEBRTC_BINDING_BYTES 32u
#define FCP_ENDPOINT_IDENTITY_BYTES 1984u

/** Stable status code returned by each fallible FCP function. */
typedef uint32_t FcpStatus;

#define FCP_STATUS_OK 0u
#define FCP_STATUS_INVALID_ARGUMENT 1u
#define FCP_STATUS_ABI_MISMATCH 2u
#define FCP_STATUS_TOO_LARGE 3u
#define FCP_STATUS_PROTOCOL 4u
#define FCP_STATUS_CONFIGURATION 5u
#define FCP_STATUS_NO_ACTION 6u
#define FCP_STATUS_CLOSED 7u
#define FCP_STATUS_PANIC 8u
#define FCP_STATUS_INTERNAL 9u

/** Immutable caller memory borrowed only for the duration of a native call. */
typedef struct FcpByteSlice {
    const uint8_t *data;
    size_t len;
} FcpByteSlice;

/** FCP-owned bytes released exactly once with fcp_buffer_free. */
typedef struct FcpOwnedBuffer {
    uint8_t *data;
    size_t len;
} FcpOwnedBuffer;

/** Opaque native endpoint signer; private keys are never exported. */
typedef struct FcpSigner FcpSigner;
/** Opaque native configuration-client state. */
typedef struct FcpClient FcpClient;
/** Opaque native per-peer connection state. */
typedef struct FcpConnection FcpConnection;

/** Public policy used to construct a configuration-validation client. */
typedef struct FcpClientOptions {
    FcpByteSlice federation;
    FcpByteSlice authority;
    FcpByteSlice local_cfr_identity;
    FcpByteSlice local_endpoint;
} FcpClientOptions;

/** Public values used to construct a signer-backed peer connection. */
typedef struct FcpConnectionOptions {
    FcpByteSlice federation;
    FcpByteSlice attempt;
    FcpByteSlice remote_endpoint;
} FcpConnectionOptions;

#define FCP_ACTION_SEND_ENVELOPE 1u
#define FCP_ACTION_APPLY_OFFER 2u
#define FCP_ACTION_APPLY_ANSWER 3u
#define FCP_ACTION_ADD_CANDIDATE 4u
#define FCP_ACTION_OPEN_CONTROL_CHANNEL 5u
#define FCP_ACTION_DELIVER_CFR 6u
#define FCP_ACTION_CLOSE_TRANSPORT 7u

/** One ordered action transferred from FCP to the foreign signaling/WebRTC host. */
typedef struct FcpAction {
    uint32_t kind;
    uint8_t binding[FCP_WEBRTC_BINDING_BYTES];
    uint32_t sequence;
    uint16_t close_code;
    FcpOwnedBuffer payload;
} FcpAction;

/** Returns the ABI major required by every stateful call. */
uint32_t fcp_ffi_abi_version(void);
/** Returns the FCP wire version embedded in the native library. */
uint32_t fcp_ffi_wire_version(void);

/** Releases a returned FCP buffer and resets it to an empty record. */
void fcp_buffer_free(FcpOwnedBuffer *buffer);
/** Releases a returned FCP action's payload and resets the action record. */
void fcp_action_free(FcpAction *action);

/** Generates a process-local opaque signer using OS entropy. */
FcpStatus fcp_signer_generate(FcpSigner **out);
/** Copies the signer's public 1,984-byte endpoint identity to an FCP-owned buffer. */
FcpStatus fcp_signer_public_identity(const FcpSigner *signer, FcpOwnedBuffer *out);
/** Releases a signer and writes null to the caller's handle slot. */
void fcp_signer_free(FcpSigner **signer);

/** Creates a configuration client pinned to the supplied public policy. */
FcpStatus fcp_client_create(FcpClientOptions options, FcpClient **out);
/** Verifies and applies a strictly newer canonical signed configuration. */
FcpStatus fcp_client_apply_configuration(const FcpClient *client, FcpByteSlice configuration);
/** Writes whether an epoch was accepted and its value when present. */
FcpStatus fcp_client_accepted_epoch(const FcpClient *client, uint64_t *out_epoch, uint8_t *out_present);
/** Releases a configuration client and writes null to the caller's handle slot. */
void fcp_client_free(FcpClient **client);

/** Creates a federation/attempt/peer-pinned connection owned by the supplied signer. */
FcpStatus fcp_connection_create(const FcpSigner *signer, FcpConnectionOptions options, FcpConnection **out);
/** Starts an offer and queues host actions. */
FcpStatus fcp_connection_begin_offer(const FcpConnection *connection, FcpByteSlice binding, FcpByteSlice description);
/** Answers an accepted offer and queues the signed answer envelope. */
FcpStatus fcp_connection_answer(const FcpConnection *connection, FcpByteSlice binding, FcpByteSlice description);
/** Queues a signed candidate envelope for the active connection. */
FcpStatus fcp_connection_candidate(const FcpConnection *connection, uint32_t sequence, FcpByteSlice candidate);
/** Queues a signed CFR control envelope only after engine-connected state. */
FcpStatus fcp_connection_cfr_control(const FcpConnection *connection, FcpByteSlice payload);
/** Queues a signed local close envelope. */
FcpStatus fcp_connection_close(const FcpConnection *connection, uint16_t close_code);
/** Verifies an inbound envelope and queues its ordered host actions. */
FcpStatus fcp_connection_receive(const FcpConnection *connection, FcpByteSlice envelope);
/** Records a real platform control-channel connection. */
FcpStatus fcp_connection_transport_connected(const FcpConnection *connection);
/** Records terminal local platform transport failure. */
FcpStatus fcp_connection_transport_failed(const FcpConnection *connection);
/** Moves one queued action to caller storage or returns FCP_STATUS_NO_ACTION. */
FcpStatus fcp_connection_take_action(const FcpConnection *connection, FcpAction *out);
/** Returns phase 0=idle, 1=offer-sent, 2=offer-received, 3=answer-sent, 4=answer-received, 5=established, 6=closed. */
FcpStatus fcp_connection_phase(const FcpConnection *connection, uint32_t *out);
/** Releases a connection and writes null to the caller's handle slot. */
void fcp_connection_free(FcpConnection **connection);

/** Verifies one complete canonical FCP envelope without mutating connection state. */
FcpStatus fcp_envelope_verify(FcpByteSlice envelope);
/** Verifies one complete canonical signed FCP configuration without mutating client state. */
FcpStatus fcp_configuration_verify(FcpByteSlice configuration);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBFCP_FFI_H */
