#include "rbxraknet/datagram.hpp"

#include <algorithm>

namespace rbxraknet {

namespace {
constexpr std::byte rupp_flag{0x01};
constexpr std::size_t epoch_tag_offset = 7;
constexpr std::size_t epoch_tag_size = 16;
}  // namespace

std::string_view to_string(FrameError error) noexcept {
    switch (error) {
        case FrameError::too_short:
            return "payload too short for the 4-byte self-describing outer header";
        case FrameError::not_rupp_flag:
            return "byte[0] is not the 0x01 UDMUX/RUPP flag";
        case FrameError::implausible_header_len:
            return "header_len (byte[3]) outside the plausible range";
        case FrameError::aead_body_too_short:
            return "AEAD body too short for counter_hint(2) + tag(16)";
    }
    return "unknown frame error";
}

std::expected<Datagram, FrameError> Datagram::parse(std::span<const std::byte> payload) noexcept {
    // need bytes[0..3] before the header length is even known
    if (payload.size() < 4) {
        return std::unexpected(FrameError::too_short);
    }
    if (payload[0] != rupp_flag) {
        return std::unexpected(FrameError::not_rupp_flag);
    }

    // 24-bit big-endian header length. bytes[1..2] were 0 across the whole
    // capture so in practice this is just byte[3], but reading all three means a
    // future capture that uses the high bytes still parses.
    const std::uint32_t header_len =
        (static_cast<std::uint32_t>(payload[1]) << 16) |
        (static_cast<std::uint32_t>(payload[2]) << 8) |
        static_cast<std::uint32_t>(payload[3]);

    // a real header is at least flag(1)+len(3)+subflags(3) = 7 bytes, and has to
    // leave room for the AEAD trailer after it
    if (header_len < epoch_tag_offset || header_len + aead_trailer > payload.size()) {
        return std::unexpected(FrameError::implausible_header_len);
    }

    const std::span<const std::byte> body = payload.subspan(header_len);
    if (body.size() < aead_trailer) {
        return std::unexpected(FrameError::aead_body_too_short);
    }

    Datagram out;
    out.flag_ = payload[0];
    out.direction_ = static_cast<Direction>(payload[3]);
    out.header_len_ = header_len;

    // epoch_tag is bytes[7..23), zero-padded if the header comes up short
    const std::size_t tag_bytes = std::min<std::size_t>(epoch_tag_size, header_len - epoch_tag_offset);
    std::copy_n(payload.begin() + epoch_tag_offset, tag_bytes, out.epoch_tag_.begin());

    // whatever sits between the epoch_tag and the body is the direction 0x1f
    // MUX-extra (8 bytes). 0x17 doesn't have any. header_len gives the bounds
    const std::size_t extra_offset = epoch_tag_offset + epoch_tag_size;
    if (header_len > extra_offset) {
        out.mux_extra_ = payload.subspan(extra_offset, header_len - extra_offset);
    }

    out.aead_body_ = body;
    out.ciphertext_ = body.first(body.size() - aead_trailer);
    // counter_hint is 2 little-endian bytes sitting right before the 16-byte tag
    const std::span<const std::byte> hint = body.subspan(body.size() - aead_trailer, 2);
    out.counter_hint_ = static_cast<std::uint16_t>(hint[0]) |
                        (static_cast<std::uint16_t>(hint[1]) << 8);
    out.tag_ = body.last(16);

    return out;
}

std::vector<std::byte> Datagram::serialize() const {
    std::vector<std::byte> out;
    out.reserve(header_len_ + aead_body_.size());

    // wire layout: UDMUX/RUPP flag | header_len as a big-endian u24, whose low byte
    // is also the direction id so direction_ round-trips without its own byte |
    // sub-flags 01 11 02, constant on every payload and thrown away by parse(), so
    // the constant goes back here | epoch_tag(16) | MUX-extra as-is (8 bytes on
    // 0x1f, empty on 0x17) | AEAD body as-is (ciphertext || counter || tag)
    out.push_back(flag_);
    out.push_back(static_cast<std::byte>((header_len_ >> 16) & 0xFF));
    out.push_back(static_cast<std::byte>((header_len_ >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(header_len_ & 0xFF));
    out.push_back(std::byte{0x01});
    out.push_back(std::byte{0x11});
    out.push_back(std::byte{0x02});
    out.insert(out.end(), epoch_tag_.begin(), epoch_tag_.end());
    out.insert(out.end(), mux_extra_.begin(), mux_extra_.end());
    out.insert(out.end(), aead_body_.begin(), aead_body_.end());

    return out;
}

}  // namespace rbxraknet
