// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Nixort.LibFcp;

/// A stable FCP native status converted to an idiomatic managed exception.
public sealed class NativeFcpException(uint status) : Exception($"libfcp native operation failed with status {status}")
{
    /// Stable status code from the native ABI.
    public uint Status { get; } = status;
}

/// One copied ordered FCP host action.
public sealed record Action(uint Kind, byte[] Binding, uint Sequence, ushort CloseCode, byte[] Payload);

/// A process-local opaque dual-signature signer. Private key material never enters managed memory.
public sealed class Signer : IDisposable
{
    private IntPtr handle;

    /// Generates a native signer from OS entropy.
    public Signer()
    {
        Native.EnsureVersions();
        Native.Require(Native.SignerGenerate(out handle));
    }

    /// Returns an independent 1,984-byte public FCP endpoint identity.
    public byte[] PublicIdentity()
    {
        ThrowIfClosed();
        Native.Require(Native.SignerPublicIdentity(handle, out var output));
        return Native.CopyAndFree(ref output);
    }

    internal IntPtr Handle
    {
        get
        {
            ThrowIfClosed();
            return handle;
        }
    }

    /// Releases the native signer. Repeated calls are harmless.
    public void Dispose()
    {
        if (handle != IntPtr.Zero)
        {
            Native.SignerFree(ref handle);
        }
        GC.SuppressFinalize(this);
    }

    private void ThrowIfClosed()
    {
        ObjectDisposedException.ThrowIf(handle == IntPtr.Zero, this);
    }
}

/// One signer-backed federation/attempt/peer-pinned native FCP connection.
public sealed class Connection : IDisposable
{
    /// Canonical federation ID width.
    public const int FederationIdBytes = 32;
    /// Canonical attempt ID width.
    public const int AttemptIdBytes = 16;
    /// Exact FCP endpoint identity width.
    public const int EndpointIdentityBytes = 1_984;
    /// Exact WebRTC binding digest width.
    public const int WebRtcBindingBytes = 32;

    private IntPtr handle;

    /// Creates one FCP connection; signer fixes the local endpoint.
    public unsafe Connection(Signer signer, byte[] federation, byte[] attempt, byte[] remoteEndpoint)
    {
        ArgumentNullException.ThrowIfNull(signer);
        Native.RequireLength(federation, FederationIdBytes, nameof(federation));
        Native.RequireLength(attempt, AttemptIdBytes, nameof(attempt));
        Native.RequireLength(remoteEndpoint, EndpointIdentityBytes, nameof(remoteEndpoint));
        fixed (byte* federationPointer = federation)
        fixed (byte* attemptPointer = attempt)
        fixed (byte* remotePointer = remoteEndpoint)
        {
            var options = new Native.ConnectionOptions(
                Native.Borrow(federationPointer, federation.Length),
                Native.Borrow(attemptPointer, attempt.Length),
                Native.Borrow(remotePointer, remoteEndpoint.Length));
            Native.Require(Native.ConnectionCreate(signer.Handle, options, out handle));
        }
    }

    /// Starts a local offer and queues ordered signaling/WebRTC actions.
    public unsafe void BeginOffer(byte[] binding, byte[] description)
    {
        Native.RequireLength(binding, WebRtcBindingBytes, nameof(binding));
        ArgumentNullException.ThrowIfNull(description);
        fixed (byte* bindingPointer = binding)
        fixed (byte* descriptionPointer = description)
        {
            Native.Require(Native.ConnectionBeginOffer(
                Handle,
                Native.Borrow(bindingPointer, binding.Length),
                Native.Borrow(descriptionPointer, description.Length)));
        }
    }

    /// Queues a signed candidate envelope for the active negotiation.
    public unsafe void AddCandidate(uint sequence, byte[] candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        fixed (byte* candidatePointer = candidate)
        {
            Native.Require(Native.ConnectionCandidate(Handle, sequence, Native.Borrow(candidatePointer, candidate.Length)));
        }
    }

    /// Verifies an inbound envelope and queues exact ordered host actions.
    public unsafe void Receive(byte[] envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        fixed (byte* envelopePointer = envelope)
        {
            Native.Require(Native.ConnectionReceive(Handle, Native.Borrow(envelopePointer, envelope.Length)));
        }
    }

    /// Reports a real platform FCP control-channel connection.
    public void TransportConnected() => Native.Require(Native.ConnectionTransportConnected(Handle));

    /// Reports terminal local platform transport failure.
    public void TransportFailed() => Native.Require(Native.ConnectionTransportFailed(Handle));

    /// Returns the next copied action, or null only after the native FIFO is drained.
    public Action? TakeAction()
    {
        var raw = default(Native.ActionRaw);
        var status = Native.ConnectionTakeAction(Handle, ref raw);
        if (status == Native.StatusNoAction)
        {
            return null;
        }
        Native.Require(status);
        try
        {
            return new Action(raw.Kind, raw.BindingBytes(), raw.Sequence, raw.CloseCode, Native.Copy(raw.Payload));
        }
        finally
        {
            Native.ActionFree(ref raw);
        }
    }

    /// Returns phase 0 idle through 6 closed.
    public uint Phase()
    {
        Native.Require(Native.ConnectionPhase(Handle, out var phase));
        return phase;
    }

    /// Releases the native connection. Repeated calls are harmless.
    public void Dispose()
    {
        if (handle != IntPtr.Zero)
        {
            Native.ConnectionFree(ref handle);
        }
        GC.SuppressFinalize(this);
    }

    private IntPtr Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(handle == IntPtr.Zero, this);
            return handle;
        }
    }
}

internal static unsafe class Native
{
    internal const uint StatusOk = 0;
    internal const uint StatusNoAction = 6;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ByteSlice(IntPtr data, nuint length)
    {
        internal IntPtr Data = data;
        internal nuint Length = length;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OwnedBuffer
    {
        internal IntPtr Data;
        internal nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ConnectionOptions(ByteSlice federation, ByteSlice attempt, ByteSlice remoteEndpoint)
    {
        internal ByteSlice Federation = federation;
        internal ByteSlice Attempt = attempt;
        internal ByteSlice RemoteEndpoint = remoteEndpoint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct ActionRaw
    {
        internal uint Kind;
        internal fixed byte Binding[32];
        internal uint Sequence;
        internal ushort CloseCode;
        internal OwnedBuffer Payload;

        internal byte[] BindingBytes()
        {
            var output = new byte[32];
            fixed (byte* destination = output)
            {
                fixed (byte* source = Binding)
                {
                    Buffer.MemoryCopy(source, destination, output.Length, output.Length);
                }
            }
            return output;
        }
    }

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, static (name, _, _) =>
        {
            if (name != "fcp_ffi")
            {
                return IntPtr.Zero;
            }
            var explicitPath = Environment.GetEnvironmentVariable("LIBFCP_FFI_LIBRARY");
            return string.IsNullOrWhiteSpace(explicitPath) ? IntPtr.Zero : NativeLibrary.Load(explicitPath);
        });
    }

    internal static void EnsureVersions()
    {
        if (AbiVersion() != 1 || WireVersion() != 1)
        {
            throw new DllNotFoundException("libfcp native ABI or wire version is incompatible with this .NET façade");
        }
    }

    internal static void Require(uint status)
    {
        if (status != StatusOk)
        {
            throw new NativeFcpException(status);
        }
    }

    internal static ByteSlice Borrow(byte* data, int length) => new((IntPtr)data, checked((nuint)length));

    internal static void RequireLength(byte[] value, int expected, string name)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != expected)
        {
            throw new ArgumentException($"{name} must contain exactly {expected} bytes", name);
        }
    }

    internal static byte[] Copy(OwnedBuffer buffer)
    {
        if (buffer.Length > int.MaxValue)
        {
            throw new InvalidOperationException("FCP native output exceeds managed array bounds");
        }
        var output = new byte[(int)buffer.Length];
        if (output.Length != 0)
        {
            Marshal.Copy(buffer.Data, output, 0, output.Length);
        }
        return output;
    }

    internal static byte[] CopyAndFree(ref OwnedBuffer buffer)
    {
        try
        {
            return Copy(buffer);
        }
        finally
        {
            BufferFree(ref buffer);
        }
    }

    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_ffi_abi_version")]
    private static extern uint AbiVersion();
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_ffi_wire_version")]
    private static extern uint WireVersion();
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_buffer_free")]
    internal static extern void BufferFree(ref OwnedBuffer buffer);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_action_free")]
    internal static extern void ActionFree(ref ActionRaw action);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_signer_generate")]
    internal static extern uint SignerGenerate(out IntPtr signer);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_signer_public_identity")]
    internal static extern uint SignerPublicIdentity(IntPtr signer, out OwnedBuffer output);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_signer_free")]
    internal static extern void SignerFree(ref IntPtr signer);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_create")]
    internal static extern uint ConnectionCreate(IntPtr signer, ConnectionOptions options, out IntPtr connection);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_begin_offer")]
    internal static extern uint ConnectionBeginOffer(IntPtr connection, ByteSlice binding, ByteSlice description);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_candidate")]
    internal static extern uint ConnectionCandidate(IntPtr connection, uint sequence, ByteSlice candidate);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_receive")]
    internal static extern uint ConnectionReceive(IntPtr connection, ByteSlice envelope);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_transport_connected")]
    internal static extern uint ConnectionTransportConnected(IntPtr connection);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_transport_failed")]
    internal static extern uint ConnectionTransportFailed(IntPtr connection);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_take_action")]
    internal static extern uint ConnectionTakeAction(IntPtr connection, ref ActionRaw output);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_phase")]
    internal static extern uint ConnectionPhase(IntPtr connection, out uint phase);
    [DllImport("fcp_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "fcp_connection_free")]
    internal static extern void ConnectionFree(ref IntPtr connection);
}
