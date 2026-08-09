#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>

#include "rbxraknet/datagram.hpp"

namespace rbxraknet {

// what the Session figured out from one datagram. full_counter is the 64-bit
// nonce counter rebuilt from the 16-bit counter_hint on the wire. it's the value
// AeadCodec actually needs, and the piece the framing-only reference never
// bothered to model.
struct Observation {
    std::uint64_t full_counter{};  // the rebuilt nonce counter for this direction and epoch
    std::uint32_t epoch_index{};   // starts at 0, bumps every time epoch_tag changes
    bool epoch_boundary{};         // true on the datagram where epoch_tag changed from last time
    std::int64_t counter_delta{};  // signed step from the previous datagram this direction, 0 on a boundary or the first one
};

// the stateful part the reference repo doesn't have. for each direction it keeps
// the epoch_tag, an epoch index, and the running 64-bit counter, stretching the
// 16-bit wire hint across wraps. an epoch_tag change is treated as a re-key, so a
// fresh nonce stream whose counter starts over from the new hint. that lines up
// with the measurements: the per-direction counter jumps happen exactly when the
// epoch rotates.
class Session {
public:
    // feed one parsed datagram into the session state, get back what changed
    [[nodiscard]] Observation observe(const Datagram& datagram) noexcept;

    // a recovered key is bound per direction. the reference assumes one 32-byte
    // key per nonce stream. nothing in here checks that the key is any good
    void set_key(Direction direction, std::span<const std::byte, 32> key) noexcept;
    [[nodiscard]] std::optional<std::array<std::byte, 32>> key(Direction direction) const noexcept;
    [[nodiscard]] bool has_key(Direction direction) const noexcept;

private:
    struct DirectionState {
        bool seen = false;
        std::uint16_t last_hint = 0;
        std::uint64_t counter = 0;              // full rebuilt counter of the last datagram
        std::array<std::byte, 16> epoch_tag{};  // last epoch_tag in this direction
        std::uint32_t epoch_index = 0;
        std::optional<std::array<std::byte, 32>> key;
    };

    DirectionState& state_for(Direction direction) noexcept;

    std::map<std::uint8_t, DirectionState> directions_;
};

}  // namespace rbxraknet
