// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

// Package libfcp is a thin cgo façade over the single native FCP ABI.
//
// It does not implement FCP parsing, signatures or state transitions in Go. Every
// caller byte slice is borrowed for one native call only, and no Go pointer is
// retained by the native library after that call returns.
package libfcp

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates/libfcp-ffi/include
#cgo LDFLAGS: -lfcp_ffi
#include "libfcp_ffi.h"
*/
import "C"

import (
    "fmt"
    "unsafe"
)

const (
    // FederationIDBytes is the exact canonical federation ID width.
    FederationIDBytes = 32
    // AttemptIDBytes is the exact canonical connection attempt width.
    AttemptIDBytes = 16
    // EndpointIdentityBytes is the exact public endpoint identity width.
    EndpointIdentityBytes = 1984
    // WebRTCBindingBytes is the exact WebRTC binding digest width.
    WebRTCBindingBytes = 32
    statusOK = 0
    statusNoAction = 6
)

// NativeError is a stable non-success FCP ABI status.
type NativeError struct {
    Status uint32
}

func (error NativeError) Error() string {
    return fmt.Sprintf("libfcp native operation failed with status %d", error.Status)
}

// Action is one copied ordered host operation emitted by native FCP.
type Action struct {
    Kind      uint32
    Binding   []byte
    Sequence  uint32
    CloseCode uint16
    Payload   []byte
}

// Signer owns a process-local native dual-signature signer.
type Signer struct {
    handle *C.FcpSigner
}

// NewSigner generates a native signer from OS entropy. It intentionally has no private-key import/export API.
func NewSigner() (*Signer, error) {
    var handle *C.FcpSigner
    if err := check(C.fcp_signer_generate(&handle)); err != nil {
        return nil, err
    }
    return &Signer{handle: handle}, nil
}

// PublicIdentity returns an independent 1,984-byte public FCP endpoint identity.
func (signer *Signer) PublicIdentity() ([]byte, error) {
    if signer == nil || signer.handle == nil {
        return nil, NativeError{Status: 7}
    }
    var output C.FcpOwnedBuffer
    if err := check(C.fcp_signer_public_identity(signer.handle, &output)); err != nil {
        return nil, err
    }
    defer C.fcp_buffer_free(&output)
    return copyBuffer(output)
}

// Close releases the native signer. Repeated calls are harmless.
func (signer *Signer) Close() {
    if signer != nil && signer.handle != nil {
        C.fcp_signer_free(&signer.handle)
    }
}

// Connection owns one signer-backed native FCP state machine.
type Connection struct {
    handle *C.FcpConnection
}

// NewConnection creates one federation/attempt/peer-pinned native connection.
func NewConnection(signer *Signer, federation, attempt, remoteEndpoint []byte) (*Connection, error) {
    if signer == nil || signer.handle == nil {
        return nil, NativeError{Status: 7}
    }
    if err := exact(federation, FederationIDBytes, "federation"); err != nil {
        return nil, err
    }
    if err := exact(attempt, AttemptIDBytes, "attempt"); err != nil {
        return nil, err
    }
    if err := exact(remoteEndpoint, EndpointIdentityBytes, "remote endpoint"); err != nil {
        return nil, err
    }
    options := C.FcpConnectionOptions{
        federation: borrow(federation),
        attempt: borrow(attempt),
        remote_endpoint: borrow(remoteEndpoint),
    }
    var handle *C.FcpConnection
    if err := check(C.fcp_connection_create(signer.handle, options, &handle)); err != nil {
        return nil, err
    }
    return &Connection{handle: handle}, nil
}

// BeginOffer starts a local offer and queues ordered host actions.
func (connection *Connection) BeginOffer(binding, description []byte) error {
    if err := exact(binding, WebRTCBindingBytes, "binding"); err != nil {
        return err
    }
    return check(C.fcp_connection_begin_offer(connection.native(), borrow(binding), borrow(description)))
}

// AddCandidate queues a signed candidate envelope for the active FCP attempt.
func (connection *Connection) AddCandidate(sequence uint32, candidate []byte) error {
    return check(C.fcp_connection_candidate(connection.native(), C.uint32_t(sequence), borrow(candidate)))
}

// Receive verifies one canonical inbound FCP envelope and queues its ordered host actions.
func (connection *Connection) Receive(envelope []byte) error {
    return check(C.fcp_connection_receive(connection.native(), borrow(envelope)))
}

// TransportConnected reports the real platform FCP control-channel connection.
func (connection *Connection) TransportConnected() error {
    return check(C.fcp_connection_transport_connected(connection.native()))
}

// TransportFailed reports terminal local platform transport failure.
func (connection *Connection) TransportFailed() error {
    return check(C.fcp_connection_transport_failed(connection.native()))
}

// TakeAction returns the next copied action or nil only when the native FIFO is drained.
func (connection *Connection) TakeAction() (*Action, error) {
    var raw C.FcpAction
    status := C.fcp_connection_take_action(connection.native(), &raw)
    if uint32(status) == statusNoAction {
        return nil, nil
    }
    if err := check(status); err != nil {
        return nil, err
    }
    defer C.fcp_action_free(&raw)
    binding := C.GoBytes(unsafe.Pointer(&raw.binding[0]), C.int(WebRTCBindingBytes))
    payload, err := copyBuffer(raw.payload)
    if err != nil {
        return nil, err
    }
    return &Action{
        Kind: uint32(raw.kind),
        Binding: binding,
        Sequence: uint32(raw.sequence),
        CloseCode: uint16(raw.close_code),
        Payload: payload,
    }, nil
}

// Phase returns lifecycle phase 0 idle through 6 closed.
func (connection *Connection) Phase() (uint32, error) {
    var phase C.uint32_t
    if err := check(C.fcp_connection_phase(connection.native(), &phase)); err != nil {
        return 0, err
    }
    return uint32(phase), nil
}

// Close releases the native connection. Repeated calls are harmless.
func (connection *Connection) Close() {
    if connection != nil && connection.handle != nil {
        C.fcp_connection_free(&connection.handle)
    }
}

// VerifyEnvelope validates one complete canonical dual-signed FCP envelope without mutating state.
func VerifyEnvelope(envelope []byte) error {
    return check(C.fcp_envelope_verify(borrow(envelope)))
}

func (connection *Connection) native() *C.FcpConnection {
    if connection == nil || connection.handle == nil {
        return nil
    }
    return connection.handle
}

func check(status C.FcpStatus) error {
    if uint32(status) != statusOK {
        return NativeError{Status: uint32(status)}
    }
    return nil
}

func exact(value []byte, expected int, name string) error {
    if len(value) != expected {
        return fmt.Errorf("%s must contain exactly %d bytes", name, expected)
    }
    return nil
}

func borrow(value []byte) C.FcpByteSlice {
    if len(value) == 0 {
        return C.FcpByteSlice{}
    }
    return C.FcpByteSlice{data: (*C.uint8_t)(unsafe.Pointer(&value[0])), len: C.size_t(len(value))}
}

func copyBuffer(buffer C.FcpOwnedBuffer) ([]byte, error) {
    if buffer.len > C.size_t(^uint(0)>>1) {
        return nil, fmt.Errorf("FCP native output exceeds Go slice bounds")
    }
    if buffer.len == 0 {
        return []byte{}, nil
    }
    return C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len)), nil
}
