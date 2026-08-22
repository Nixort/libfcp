// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

#ifndef LIBFCP_HPP
#define LIBFCP_HPP

#include "libfcp_ffi.h"

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace nixort::fcp {

/** Stable FCP native status converted to an idiomatic C++ exception. */
class Error final : public std::runtime_error {
public:
    explicit Error(FcpStatus status)
        : std::runtime_error("libfcp native operation failed"), status_(status) {}

    [[nodiscard]] FcpStatus status() const noexcept { return status_; }

private:
    FcpStatus status_;
};

/** Throws Error unless a native operation succeeded. */
inline void require(FcpStatus status) {
    if (status != FCP_STATUS_OK) {
        throw Error(status);
    }
}

/** Makes a byte slice that remains valid only for the native call that receives it. */
inline FcpByteSlice borrow(std::span<const std::uint8_t> bytes) noexcept {
    return FcpByteSlice{bytes.data(), bytes.size()};
}

/** Moves a returned FCP buffer into standard C++ storage before freeing native memory. */
inline std::vector<std::uint8_t> copy_and_free(FcpOwnedBuffer buffer) {
    std::vector<std::uint8_t> result;
    if (buffer.len != 0) {
        result.assign(buffer.data, buffer.data + buffer.len);
    }
    fcp_buffer_free(&buffer);
    return result;
}

/** Move-only opaque FCP signer. Its public identity may be shared; private keys remain native. */
class Signer final {
public:
    Signer() {
        require(fcp_signer_generate(&handle_));
    }

    ~Signer() { fcp_signer_free(&handle_); }
    Signer(const Signer&) = delete;
    Signer& operator=(const Signer&) = delete;

    Signer(Signer&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    Signer& operator=(Signer&& other) noexcept {
        if (this != &other) {
            fcp_signer_free(&handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] std::vector<std::uint8_t> public_identity() const {
        FcpOwnedBuffer output{};
        require(fcp_signer_public_identity(handle_, &output));
        return copy_and_free(output);
    }

    [[nodiscard]] const FcpSigner* native_handle() const noexcept { return handle_; }

private:
    FcpSigner* handle_ = nullptr;
};

/** Native action copied into C++ storage; no native buffer remains after return. */
struct Action final {
    std::uint32_t kind;
    std::vector<std::uint8_t> binding;
    std::uint32_t sequence;
    std::uint16_t close_code;
    std::vector<std::uint8_t> payload;
};

/** Move-only signer-backed FCP connection state machine. */
class Connection final {
public:
    Connection(
        const Signer& signer,
        std::span<const std::uint8_t> federation,
        std::span<const std::uint8_t> attempt,
        std::span<const std::uint8_t> remote_endpoint
    ) {
        const FcpConnectionOptions options{
            borrow(federation),
            borrow(attempt),
            borrow(remote_endpoint),
        };
        require(fcp_connection_create(signer.native_handle(), options, &handle_));
    }

    ~Connection() { fcp_connection_free(&handle_); }
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    Connection(Connection&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    Connection& operator=(Connection&& other) noexcept {
        if (this != &other) {
            fcp_connection_free(&handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    void begin_offer(std::span<const std::uint8_t> binding, std::span<const std::uint8_t> description) {
        require(fcp_connection_begin_offer(handle_, borrow(binding), borrow(description)));
    }

    void answer(std::span<const std::uint8_t> binding, std::span<const std::uint8_t> description) {
        require(fcp_connection_answer(handle_, borrow(binding), borrow(description)));
    }

    void add_candidate(std::uint32_t sequence, std::span<const std::uint8_t> candidate) {
        require(fcp_connection_candidate(handle_, sequence, borrow(candidate)));
    }

    void receive(std::span<const std::uint8_t> envelope) {
        require(fcp_connection_receive(handle_, borrow(envelope)));
    }

    void transport_connected() { require(fcp_connection_transport_connected(handle_)); }
    void transport_failed() { require(fcp_connection_transport_failed(handle_)); }
    void close(std::uint16_t close_code) { require(fcp_connection_close(handle_, close_code)); }

    [[nodiscard]] std::optional<Action> take_action() {
        FcpAction action{};
        const FcpStatus status = fcp_connection_take_action(handle_, &action);
        if (status == FCP_STATUS_NO_ACTION) {
            return std::nullopt;
        }
        require(status);
        Action result{
            action.kind,
            std::vector<std::uint8_t>(action.binding, action.binding + FCP_WEBRTC_BINDING_BYTES),
            action.sequence,
            action.close_code,
            copy_and_free(action.payload),
        };
        action.payload = FcpOwnedBuffer{};
        fcp_action_free(&action);
        return result;
    }

    [[nodiscard]] std::uint32_t phase() const {
        std::uint32_t output = 0;
        require(fcp_connection_phase(handle_, &output));
        return output;
    }

private:
    FcpConnection* handle_ = nullptr;
};

}  // namespace nixort::fcp

#endif  // LIBFCP_HPP
