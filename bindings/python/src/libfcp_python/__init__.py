# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

"""Thin Python façade for the one native libfcp FFI core.

The module contains no FCP parser, signing code or state machine.  It calls the
reviewed C ABI, copies all native byte outputs into Python ``bytes`` and closes
native handles deterministically via context managers or ``close()``.
"""

from __future__ import annotations

import ctypes as _ctypes
import ctypes.util as _ctypes_util
import os as _os
from dataclasses import dataclass
from typing import Final

__all__ = [
    "Action",
    "Connection",
    "NativeStatusError",
    "Signer",
    "WIRE_VERSION",
]

_ABI_VERSION: Final = 2
WIRE_VERSION: Final = 1
_STATUS_OK: Final = 0
_STATUS_NO_ACTION: Final = 6
_ACTION_SEND_ENVELOPE: Final = 1


class NativeStatusError(RuntimeError):
    """A documented non-success native FCP status."""

    def __init__(self, status: int) -> None:
        super().__init__(f"libfcp native operation failed with status {status}")
        self.status = status


class _ByteSlice(_ctypes.Structure):
    _fields_ = [("data", _ctypes.POINTER(_ctypes.c_ubyte)), ("len", _ctypes.c_size_t)]


class _OwnedBuffer(_ctypes.Structure):
    _fields_ = [("data", _ctypes.POINTER(_ctypes.c_ubyte)), ("len", _ctypes.c_size_t)]


class _ConnectionOptions(_ctypes.Structure):
    _fields_ = [
        ("federation", _ByteSlice),
        ("attempt", _ByteSlice),
        ("remote_endpoint", _ByteSlice),
    ]


class _NativeAction(_ctypes.Structure):
    _fields_ = [
        ("kind", _ctypes.c_uint32),
        ("binding", _ctypes.c_ubyte * 32),
        ("sequence", _ctypes.c_uint32),
        ("close_code", _ctypes.c_uint16),
        ("envelope_id", _ctypes.c_ubyte * 32),
        ("remote_endpoint", _OwnedBuffer),
        ("payload", _OwnedBuffer),
    ]


def _load_library() -> _ctypes.CDLL:
    """Load the native library from an explicit path or the system library resolver."""

    explicit = _os.environ.get("LIBFCP_FFI_LIBRARY")
    candidate = explicit or _ctypes_util.find_library("fcp_ffi")
    if candidate is None:
        raise RuntimeError(
            "libfcp native library is not discoverable; set LIBFCP_FFI_LIBRARY "
            "to an absolute platform-specific library path"
        )
    library = _ctypes.CDLL(candidate)
    library.fcp_ffi_abi_version.argtypes = []
    library.fcp_ffi_abi_version.restype = _ctypes.c_uint32
    library.fcp_ffi_wire_version.argtypes = []
    library.fcp_ffi_wire_version.restype = _ctypes.c_uint32
    library.fcp_buffer_free.argtypes = [_ctypes.POINTER(_OwnedBuffer)]
    library.fcp_buffer_free.restype = None
    library.fcp_action_free.argtypes = [_ctypes.POINTER(_NativeAction)]
    library.fcp_action_free.restype = None
    library.fcp_signer_generate.argtypes = [_ctypes.POINTER(_ctypes.c_void_p)]
    library.fcp_signer_generate.restype = _ctypes.c_uint32
    library.fcp_signer_public_identity.argtypes = [_ctypes.c_void_p, _ctypes.POINTER(_OwnedBuffer)]
    library.fcp_signer_public_identity.restype = _ctypes.c_uint32
    library.fcp_signer_free.argtypes = [_ctypes.POINTER(_ctypes.c_void_p)]
    library.fcp_signer_free.restype = None
    library.fcp_connection_create.argtypes = [
        _ctypes.c_void_p,
        _ConnectionOptions,
        _ctypes.POINTER(_ctypes.c_void_p),
    ]
    library.fcp_connection_create.restype = _ctypes.c_uint32
    library.fcp_connection_begin_offer.argtypes = [_ctypes.c_void_p, _ByteSlice, _ByteSlice]
    library.fcp_connection_begin_offer.restype = _ctypes.c_uint32
    library.fcp_connection_answer.argtypes = [_ctypes.c_void_p, _ByteSlice, _ByteSlice]
    library.fcp_connection_answer.restype = _ctypes.c_uint32
    library.fcp_connection_candidate.argtypes = [_ctypes.c_void_p, _ctypes.c_uint32, _ByteSlice]
    library.fcp_connection_candidate.restype = _ctypes.c_uint32
    library.fcp_connection_receive.argtypes = [_ctypes.c_void_p, _ByteSlice]
    library.fcp_connection_receive.restype = _ctypes.c_uint32
    library.fcp_connection_close.argtypes = [_ctypes.c_void_p, _ctypes.c_uint16]
    library.fcp_connection_close.restype = _ctypes.c_uint32
    library.fcp_connection_transport_connected.argtypes = [_ctypes.c_void_p]
    library.fcp_connection_transport_connected.restype = _ctypes.c_uint32
    library.fcp_connection_transport_failed.argtypes = [_ctypes.c_void_p]
    library.fcp_connection_transport_failed.restype = _ctypes.c_uint32
    library.fcp_connection_take_action.argtypes = [_ctypes.c_void_p, _ctypes.POINTER(_NativeAction)]
    library.fcp_connection_take_action.restype = _ctypes.c_uint32
    library.fcp_connection_phase.argtypes = [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_uint32)]
    library.fcp_connection_phase.restype = _ctypes.c_uint32
    library.fcp_connection_free.argtypes = [_ctypes.POINTER(_ctypes.c_void_p)]
    library.fcp_connection_free.restype = None
    library.fcp_envelope_verify.argtypes = [_ByteSlice]
    library.fcp_envelope_verify.restype = _ctypes.c_uint32
    if library.fcp_ffi_abi_version() != _ABI_VERSION:
        raise RuntimeError("libfcp native ABI major does not match this Python façade")
    if library.fcp_ffi_wire_version() != WIRE_VERSION:
        raise RuntimeError("libfcp native wire version does not match this Python façade")
    return library


_LIBRARY = _load_library()


def _require(status: int) -> None:
    if status != _STATUS_OK:
        raise NativeStatusError(status)


def _borrow(value: bytes) -> tuple[_ByteSlice, _ctypes.Array[_ctypes.c_ubyte] | None]:
    if not isinstance(value, bytes):
        raise TypeError("FCP binary inputs must be immutable bytes")
    if not value:
        return _ByteSlice(None, 0), None
    storage = (_ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return _ByteSlice(storage, len(value)), storage


def _copy_and_free(buffer: _OwnedBuffer) -> bytes:
    try:
        return _ctypes.string_at(buffer.data, buffer.len) if buffer.len else b""
    finally:
        _LIBRARY.fcp_buffer_free(_ctypes.byref(buffer))


@dataclass(frozen=True, slots=True)
class Action:
    """One copied ordered native FCP action for signaling, WebRTC or CFR dispatch."""

    kind: int
    binding: bytes
    sequence: int
    close_code: int
    envelope_id: bytes
    remote_endpoint: bytes
    payload: bytes

    @property
    def is_signed_envelope(self) -> bool:
        """Whether payload is a complete signed FCP envelope for host signaling delivery."""

        return self.kind == _ACTION_SEND_ENVELOPE


class Signer:
    """A process-local opaque dual-signature endpoint signer.

    This initial façade intentionally does not import or export private key material.
    Use it for testing and ephemeral sessions; a persistent production key store is a
    separate platform-security integration.
    """

    def __init__(self) -> None:
        self._handle = _ctypes.c_void_p()
        _require(_LIBRARY.fcp_signer_generate(_ctypes.byref(self._handle)))

    def close(self) -> None:
        """Release the native signer once; repeated calls are harmless."""

        _LIBRARY.fcp_signer_free(_ctypes.byref(self._handle))

    def __enter__(self) -> Signer:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    @property
    def public_identity(self) -> bytes:
        """Return the 1,984-byte public FCP endpoint identity."""

        output = _OwnedBuffer()
        _require(_LIBRARY.fcp_signer_public_identity(self._handle, _ctypes.byref(output)))
        return _copy_and_free(output)


class Connection:
    """A move-free Python owner of one signer-backed native FCP connection.

    Do not close this object while another thread is invoking a method on it.
    """

    def __init__(self, signer: Signer, federation: bytes, attempt: bytes, remote_endpoint: bytes) -> None:
        federation_slice, federation_storage = _borrow(federation)
        attempt_slice, attempt_storage = _borrow(attempt)
        remote_slice, remote_storage = _borrow(remote_endpoint)
        _ = (federation_storage, attempt_storage, remote_storage)
        options = _ConnectionOptions(federation_slice, attempt_slice, remote_slice)
        self._handle = _ctypes.c_void_p()
        _require(_LIBRARY.fcp_connection_create(signer._handle, options, _ctypes.byref(self._handle)))

    def close(self) -> None:
        """Release the native connection once; repeated calls are harmless."""

        _LIBRARY.fcp_connection_free(_ctypes.byref(self._handle))

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def begin_offer(self, binding: bytes, description: bytes) -> None:
        binding_slice, binding_storage = _borrow(binding)
        description_slice, description_storage = _borrow(description)
        _ = (binding_storage, description_storage)
        _require(_LIBRARY.fcp_connection_begin_offer(self._handle, binding_slice, description_slice))

    def answer(self, binding: bytes, description: bytes) -> None:
        binding_slice, binding_storage = _borrow(binding)
        description_slice, description_storage = _borrow(description)
        _ = (binding_storage, description_storage)
        _require(_LIBRARY.fcp_connection_answer(self._handle, binding_slice, description_slice))

    def add_candidate(self, sequence: int, candidate: bytes) -> None:
        candidate_slice, candidate_storage = _borrow(candidate)
        _ = candidate_storage
        _require(_LIBRARY.fcp_connection_candidate(self._handle, sequence, candidate_slice))

    def receive(self, envelope: bytes) -> None:
        envelope_slice, envelope_storage = _borrow(envelope)
        _ = envelope_storage
        _require(_LIBRARY.fcp_connection_receive(self._handle, envelope_slice))

    def transport_connected(self) -> None:
        """Report the real platform control-channel connection transition."""

        _require(_LIBRARY.fcp_connection_transport_connected(self._handle))

    def transport_failed(self) -> None:
        """Report terminal local platform transport failure."""

        _require(_LIBRARY.fcp_connection_transport_failed(self._handle))

    def close_with_code(self, close_code: int) -> None:
        """Queue a signed local close envelope using one u16 application close code."""

        _require(_LIBRARY.fcp_connection_close(self._handle, close_code))

    def take_action(self) -> Action | None:
        """Copy and release the next action, or return ``None`` when the queue is drained."""

        action = _NativeAction()
        status = _LIBRARY.fcp_connection_take_action(self._handle, _ctypes.byref(action))
        if status == _STATUS_NO_ACTION:
            return None
        _require(status)
        try:
            return Action(
                action.kind,
                bytes(action.binding),
                action.sequence,
                action.close_code,
                bytes(action.envelope_id),
                _ctypes.string_at(action.remote_endpoint.data, action.remote_endpoint.len)
                if action.remote_endpoint.len
                else b"",
                _ctypes.string_at(action.payload.data, action.payload.len)
                if action.payload.len
                else b"",
            )
        finally:
            _LIBRARY.fcp_action_free(_ctypes.byref(action))

    @property
    def phase(self) -> int:
        """Return lifecycle phase: 0 idle through 6 closed."""

        output = _ctypes.c_uint32()
        _require(_LIBRARY.fcp_connection_phase(self._handle, _ctypes.byref(output)))
        return output.value


def verify_envelope(envelope: bytes) -> None:
    """Raise NativeStatusError unless bytes are a canonical dual-signed FCP envelope."""

    envelope_slice, envelope_storage = _borrow(envelope)
    _ = envelope_storage
    _require(_LIBRARY.fcp_envelope_verify(envelope_slice))
