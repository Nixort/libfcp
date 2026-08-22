/* Copyright Nixort <https://github.com/Nixort> 2026.
 *
 * License: GNU General Public License v3.0 only.
 * You can find the license file in the project root.
 *
 * Federated CFR Connect Protocol (FCP).
 */

#include "libfcp_ffi.h"

#include <jni.h>
#include <stdint.h>

static void throw_status(JNIEnv *env, FcpStatus status) {
    jclass error_class = (*env)->FindClass(env, "io/github/nixort/libfcp/NativeFcpException");
    if (error_class == NULL) {
        return;
    }
    jmethodID constructor = (*env)->GetMethodID(env, error_class, "<init>", "(I)V");
    if (constructor == NULL) {
        return;
    }
    jobject error = (*env)->NewObject(env, error_class, constructor, (jint)status);
    if (error != NULL) {
        (*env)->Throw(env, (jthrowable)error);
    }
}

static void throw_invalid_argument(JNIEnv *env, const char *message) {
    jclass error_class = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (error_class != NULL) {
        (*env)->ThrowNew(env, error_class, message);
    }
}

static int borrow(JNIEnv *env, jbyteArray input, FcpByteSlice *output, jbyte **elements) {
    if (input == NULL) {
        throw_invalid_argument(env, "FCP byte input must not be null");
        return 0;
    }
    const jsize length = (*env)->GetArrayLength(env, input);
    if (length == 0) {
        output->data = NULL;
        output->len = 0;
        *elements = NULL;
        return 1;
    }
    *elements = (*env)->GetByteArrayElements(env, input, NULL);
    if (*elements == NULL) {
        return 0;
    }
    output->data = (const uint8_t *)*elements;
    output->len = (size_t)length;
    return 1;
}

static void release(JNIEnv *env, jbyteArray input, jbyte *elements) {
    if (elements != NULL) {
        (*env)->ReleaseByteArrayElements(env, input, elements, JNI_ABORT);
    }
}

static jlong to_jlong(const void *pointer) {
    return (jlong)(intptr_t)pointer;
}

static void *from_jlong(jlong value) {
    return (void *)(intptr_t)value;
}

JNIEXPORT jint JNICALL Java_io_github_nixort_libfcp_NativeLibrary_abiVersion(
    JNIEnv *env, jclass clazz
) {
    (void)env;
    (void)clazz;
    return (jint)fcp_ffi_abi_version();
}

JNIEXPORT jint JNICALL Java_io_github_nixort_libfcp_NativeLibrary_wireVersion(
    JNIEnv *env, jclass clazz
) {
    (void)env;
    (void)clazz;
    return (jint)fcp_ffi_wire_version();
}

JNIEXPORT jlong JNICALL Java_io_github_nixort_libfcp_NativeLibrary_signerGenerate(
    JNIEnv *env, jclass clazz
) {
    (void)clazz;
    FcpSigner *signer = NULL;
    FcpStatus status = fcp_signer_generate(&signer);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
        return 0;
    }
    return to_jlong(signer);
}

JNIEXPORT jbyteArray JNICALL Java_io_github_nixort_libfcp_NativeLibrary_signerPublicIdentity(
    JNIEnv *env, jclass clazz, jlong signer_value
) {
    (void)clazz;
    FcpOwnedBuffer output = {0};
    FcpStatus status = fcp_signer_public_identity((const FcpSigner *)from_jlong(signer_value), &output);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)output.len);
    if (result != NULL && output.len != 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)output.len, (const jbyte *)output.data);
    }
    fcp_buffer_free(&output);
    return result;
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_signerFree(
    JNIEnv *env, jclass clazz, jlong signer_value
) {
    (void)env;
    (void)clazz;
    FcpSigner *signer = (FcpSigner *)from_jlong(signer_value);
    fcp_signer_free(&signer);
}

JNIEXPORT jlong JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionCreate(
    JNIEnv *env,
    jclass clazz,
    jlong signer_value,
    jbyteArray federation,
    jbyteArray attempt,
    jbyteArray remote_endpoint
) {
    (void)clazz;
    FcpByteSlice federation_slice;
    FcpByteSlice attempt_slice;
    FcpByteSlice remote_slice;
    jbyte *federation_elements = NULL;
    jbyte *attempt_elements = NULL;
    jbyte *remote_elements = NULL;
    if (!borrow(env, federation, &federation_slice, &federation_elements)
        || !borrow(env, attempt, &attempt_slice, &attempt_elements)
        || !borrow(env, remote_endpoint, &remote_slice, &remote_elements)) {
        release(env, federation, federation_elements);
        release(env, attempt, attempt_elements);
        release(env, remote_endpoint, remote_elements);
        return 0;
    }
    const FcpConnectionOptions options = {federation_slice, attempt_slice, remote_slice};
    FcpConnection *connection = NULL;
    const FcpStatus status = fcp_connection_create(
        (const FcpSigner *)from_jlong(signer_value), options, &connection
    );
    release(env, federation, federation_elements);
    release(env, attempt, attempt_elements);
    release(env, remote_endpoint, remote_elements);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
        return 0;
    }
    return to_jlong(connection);
}

static void connection_two_bytes(
    JNIEnv *env,
    jlong connection_value,
    jbyteArray first,
    jbyteArray second,
    FcpStatus (*operation)(const FcpConnection *, FcpByteSlice, FcpByteSlice)
) {
    FcpByteSlice first_slice;
    FcpByteSlice second_slice;
    jbyte *first_elements = NULL;
    jbyte *second_elements = NULL;
    if (!borrow(env, first, &first_slice, &first_elements)
        || !borrow(env, second, &second_slice, &second_elements)) {
        release(env, first, first_elements);
        release(env, second, second_elements);
        return;
    }
    const FcpStatus status = operation(
        (const FcpConnection *)from_jlong(connection_value), first_slice, second_slice
    );
    release(env, first, first_elements);
    release(env, second, second_elements);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionBeginOffer(
    JNIEnv *env, jclass clazz, jlong connection, jbyteArray binding, jbyteArray description
) {
    (void)clazz;
    connection_two_bytes(env, connection, binding, description, fcp_connection_begin_offer);
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionAnswer(
    JNIEnv *env, jclass clazz, jlong connection, jbyteArray binding, jbyteArray description
) {
    (void)clazz;
    connection_two_bytes(env, connection, binding, description, fcp_connection_answer);
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionCandidate(
    JNIEnv *env, jclass clazz, jlong connection, jint sequence, jbyteArray candidate
) {
    (void)clazz;
    FcpByteSlice candidate_slice;
    jbyte *candidate_elements = NULL;
    if (!borrow(env, candidate, &candidate_slice, &candidate_elements)) {
        return;
    }
    const FcpStatus status = fcp_connection_candidate(
        (const FcpConnection *)from_jlong(connection), (uint32_t)sequence, candidate_slice
    );
    release(env, candidate, candidate_elements);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionReceive(
    JNIEnv *env, jclass clazz, jlong connection, jbyteArray envelope
) {
    (void)clazz;
    FcpByteSlice envelope_slice;
    jbyte *envelope_elements = NULL;
    if (!borrow(env, envelope, &envelope_slice, &envelope_elements)) {
        return;
    }
    const FcpStatus status = fcp_connection_receive(
        (const FcpConnection *)from_jlong(connection), envelope_slice
    );
    release(env, envelope, envelope_elements);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionTransportConnected(
    JNIEnv *env, jclass clazz, jlong connection
) {
    (void)clazz;
    const FcpStatus status = fcp_connection_transport_connected(
        (const FcpConnection *)from_jlong(connection)
    );
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionTransportFailed(
    JNIEnv *env, jclass clazz, jlong connection
) {
    (void)clazz;
    const FcpStatus status = fcp_connection_transport_failed(
        (const FcpConnection *)from_jlong(connection)
    );
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionClose(
    JNIEnv *env, jclass clazz, jlong connection, jint close_code
) {
    (void)clazz;
    const FcpStatus status = fcp_connection_close(
        (const FcpConnection *)from_jlong(connection), (uint16_t)close_code
    );
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}

JNIEXPORT jobject JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionTakeAction(
    JNIEnv *env, jclass clazz, jlong connection
) {
    (void)clazz;
    FcpAction action = {0};
    const FcpStatus status = fcp_connection_take_action(
        (const FcpConnection *)from_jlong(connection), &action
    );
    if (status == FCP_STATUS_NO_ACTION) {
        return NULL;
    }
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
        return NULL;
    }
    jbyteArray binding = (*env)->NewByteArray(env, FCP_WEBRTC_BINDING_BYTES);
    jbyteArray payload = (*env)->NewByteArray(env, (jsize)action.payload.len);
    jobject result = NULL;
    if (binding != NULL && payload != NULL) {
        (*env)->SetByteArrayRegion(
            env, binding, 0, FCP_WEBRTC_BINDING_BYTES, (const jbyte *)action.binding
        );
        if (action.payload.len != 0) {
            (*env)->SetByteArrayRegion(
                env, payload, 0, (jsize)action.payload.len, (const jbyte *)action.payload.data
            );
        }
        jclass action_class = (*env)->FindClass(env, "io/github/nixort/libfcp/Action");
        if (action_class != NULL) {
            jmethodID constructor = (*env)->GetMethodID(env, action_class, "<init>", "(I[BII[B)V");
            if (constructor != NULL) {
                result = (*env)->NewObject(
                    env,
                    action_class,
                    constructor,
                    (jint)action.kind,
                    binding,
                    (jint)action.sequence,
                    (jint)action.close_code,
                    payload
                );
            }
        }
    }
    fcp_action_free(&action);
    return result;
}

JNIEXPORT jint JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionPhase(
    JNIEnv *env, jclass clazz, jlong connection
) {
    (void)clazz;
    uint32_t phase = 0;
    const FcpStatus status = fcp_connection_phase((const FcpConnection *)from_jlong(connection), &phase);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
        return 0;
    }
    return (jint)phase;
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_connectionFree(
    JNIEnv *env, jclass clazz, jlong connection_value
) {
    (void)env;
    (void)clazz;
    FcpConnection *connection = (FcpConnection *)from_jlong(connection_value);
    fcp_connection_free(&connection);
}

JNIEXPORT void JNICALL Java_io_github_nixort_libfcp_NativeLibrary_verifyEnvelope(
    JNIEnv *env, jclass clazz, jbyteArray envelope
) {
    (void)clazz;
    FcpByteSlice envelope_slice;
    jbyte *envelope_elements = NULL;
    if (!borrow(env, envelope, &envelope_slice, &envelope_elements)) {
        return;
    }
    const FcpStatus status = fcp_envelope_verify(envelope_slice);
    release(env, envelope, envelope_elements);
    if (status != FCP_STATUS_OK) {
        throw_status(env, status);
    }
}
