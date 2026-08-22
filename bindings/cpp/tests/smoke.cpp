// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Federated CFR Connect Protocol (FCP).

#include "libfcp.hpp"

#include <array>
#include <cassert>
#include <cstdint>

int main() {
    nixort::fcp::Signer local;
    nixort::fcp::Signer remote;
    const auto remote_identity = remote.public_identity();
    const std::array<std::uint8_t, FCP_FEDERATION_ID_BYTES> federation{3};
    const std::array<std::uint8_t, FCP_ATTEMPT_ID_BYTES> attempt{7};
    const std::array<std::uint8_t, FCP_WEBRTC_BINDING_BYTES> binding{9};
    const std::array<std::uint8_t, 12> description{
        'o', 'p', 'a', 'q', 'u', 'e', '-', 'o', 'f', 'f', 'e', 'r'};

    nixort::fcp::Connection connection(local, federation, attempt, remote_identity);
    connection.begin_offer(binding, description);

    const auto first = connection.take_action();
    assert(first.has_value());
    assert(first->kind == FCP_ACTION_OPEN_CONTROL_CHANNEL);
    const auto second = connection.take_action();
    assert(second.has_value());
    assert(second->kind == FCP_ACTION_SEND_ENVELOPE);
    assert(fcp_envelope_verify(nixort::fcp::borrow(second->payload)) == FCP_STATUS_OK);
    assert(!connection.take_action().has_value());
    return 0;
}
