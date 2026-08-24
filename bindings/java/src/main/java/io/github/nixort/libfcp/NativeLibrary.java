// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

package io.github.nixort.libfcp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/** Loads the reviewed platform-native FCP library and validates its ABI before use. */
final class NativeLibrary {
    static final int ABI_VERSION = 2;
    static final int WIRE_VERSION = 1;
    private static Path extractedDirectory;

    static {
        load("io.github.nixort.libfcp.ffiPath", "fcp_ffi");
        load("io.github.nixort.libfcp.nativePath", "fcp_jni");
        if (abiVersion() != ABI_VERSION) {
            throw new UnsatisfiedLinkError("libfcp ABI major does not match this Java façade");
        }
        if (wireVersion() != WIRE_VERSION) {
            throw new UnsatisfiedLinkError("libfcp wire version does not match this Java façade");
        }
    }

    private NativeLibrary() {}

    private static void load(String property, String library) {
        final String explicit = System.getProperty(property);
        if (explicit != null && !explicit.isBlank()) {
            System.load(Path.of(explicit).toAbsolutePath().normalize().toString());
            return;
        }

        final Path resource = extractResource(library);
        if (resource != null) {
            System.load(resource.toString());
            return;
        }
        System.loadLibrary(library);
    }

    private static synchronized Path extractResource(String library) {
        final String resourceName = "/META-INF/native/" + platformClassifier() + "/"
                + System.mapLibraryName(library);
        try (InputStream input = NativeLibrary.class.getResourceAsStream(resourceName)) {
            if (input == null) {
                return null;
            }
            if (extractedDirectory == null) {
                extractedDirectory = Files.createTempDirectory("libfcp-jni-");
                extractedDirectory.toFile().deleteOnExit();
            }
            final Path output = extractedDirectory.resolve(System.mapLibraryName(library));
            Files.copy(input, output, StandardCopyOption.REPLACE_EXISTING);
            output.toFile().deleteOnExit();
            return output;
        } catch (IOException error) {
            final UnsatisfiedLinkError failure = new UnsatisfiedLinkError(
                    "cannot extract bundled " + library + " for " + platformClassifier());
            failure.initCause(error);
            throw failure;
        }
    }

    private static String platformClassifier() {
        final String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        final String architecture = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        final String normalizedArchitecture = switch (architecture) {
            case "amd64", "x86_64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> throw new UnsatisfiedLinkError("unsupported libfcp CPU architecture: " + architecture);
        };
        if (os.contains("linux")) {
            return "linux-" + normalizedArchitecture;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return "macos-" + normalizedArchitecture;
        }
        if (os.contains("win")) {
            return "windows-" + normalizedArchitecture;
        }
        throw new UnsatisfiedLinkError("unsupported libfcp operating system: " + os);
    }

    static void require(int status) {
        if (status != 0) {
            throw new NativeFcpException(status);
        }
    }

    static native int abiVersion();
    static native int wireVersion();
    static native long signerGenerate();
    static native byte[] signerPublicIdentity(long signer);
    static native void signerFree(long signer);
    static native long connectionCreate(long signer, byte[] federation, byte[] attempt, byte[] remoteEndpoint);
    static native void connectionBeginOffer(long connection, byte[] binding, byte[] description);
    static native void connectionAnswer(long connection, byte[] binding, byte[] description);
    static native void connectionCandidate(long connection, int sequence, byte[] candidate);
    static native void connectionCfrControl(long connection, byte[] payload);
    static native void connectionReceive(long connection, byte[] envelope);
    static native void connectionTransportConnected(long connection);
    static native void connectionTransportFailed(long connection);
    static native void connectionClose(long connection, int closeCode);
    static native Action connectionTakeAction(long connection);
    static native int connectionPhase(long connection);
    static native void connectionFree(long connection);
    static native void verifyEnvelope(byte[] envelope);
}
