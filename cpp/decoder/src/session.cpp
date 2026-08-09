#include "rbxraknet/session.hpp"

namespace rbxraknet {

Session::DirectionState& Session::state_for(Direction direction) noexcept {
    return directions_[static_cast<std::uint8_t>(direction)];
}

Observation Session::observe(const Datagram& datagram) noexcept {
    DirectionState& s = state_for(datagram.direction());
    const std::uint16_t hint = datagram.counter_hint();
    const std::array<std::byte, 16>& tag = datagram.epoch_tag();

    Observation obs;

    if (!s.seen) {
        s.seen = true;
        s.epoch_tag = tag;
        s.epoch_index = 0;
        s.last_hint = hint;
        s.counter = hint;  // anchor the 64-bit counter to the first hint
        obs.full_counter = s.counter;
        return obs;
    }

    if (tag != s.epoch_tag) {
        // epoch_tag change means a re-key. per-direction counter discontinuities
        // coincide with these rotations, so the nonce stream restarts: the 64-bit
        // counter resets to this datagram's hint
        s.epoch_tag = tag;
        ++s.epoch_index;
        s.last_hint = hint;
        s.counter = hint;
        obs.full_counter = s.counter;
        obs.epoch_index = s.epoch_index;
        obs.epoch_boundary = true;
        return obs;
    }

    // same epoch: extend the 64-bit counter by the wrap-aware 16-bit step. +1 is
    // the norm; the signed cast makes a 0xFFFF to 0x0000 wrap read as +1. only
    // 16-bit wrap is handled, a real stream never steps by more than 32767 within
    // an epoch and an epoch change resets it anyway
    const std::int64_t delta = static_cast<std::int16_t>(hint - s.last_hint);
    s.counter = s.counter + static_cast<std::uint64_t>(delta);
    s.last_hint = hint;

    obs.full_counter = s.counter;
    obs.epoch_index = s.epoch_index;
    obs.counter_delta = delta;
    return obs;
}

void Session::set_key(Direction direction, std::span<const std::byte, 32> key) noexcept {
    std::array<std::byte, 32> copy{};
    std::copy(key.begin(), key.end(), copy.begin());
    state_for(direction).key = copy;
}

std::optional<std::array<std::byte, 32>> Session::key(Direction direction) const noexcept {
    const auto it = directions_.find(static_cast<std::uint8_t>(direction));
    if (it == directions_.end()) {
        return std::nullopt;
    }
    return it->second.key;
}

bool Session::has_key(Direction direction) const noexcept {
    const auto it = directions_.find(static_cast<std::uint8_t>(direction));
    return it != directions_.end() && it->second.key.has_value();
}

}  // namespace rbxraknet
