#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace rbxraknet {

// the two nonce-counter streams, told apart by byte[3] of the outer header, which
// does double duty as both the header length and the direction id. the only
// values in the capture were 0x17 (23-byte header) and 0x1f (31-byte header).
// which one is client to server is unknown, so the names just echo the wire
// value. byte[3] matched header_len for all 16,797 datagrams (0x1f=8904,
// 0x17=7893).
enum class Direction : std::uint8_t {
    d17 = 0x17,
    d1f = 0x1f,
};

enum class FrameError {
    too_short,               // not even the 4 header bytes needed to read the length
    not_rupp_flag,           // byte[0] wasn't 0x01
    implausible_header_len,  // header_len fell outside [7, n - AEAD_TRAILER]
    aead_body_too_short,     // body can't fit counter_hint(2) + tag(16)
};

[[nodiscard]] std::string_view to_string(FrameError error) noexcept;

// one parsed Roblox UDMUX/RUPP datagram, which is just outer header then AEAD
// body.
//
// this is a view, it doesn't own anything. the ciphertext, tag, body and
// mux-extra spans all point back into the buffer passed to parse(), so keep that
// buffer alive longer than the Datagram. the 16-byte epoch_tag is copied out,
// since callers compare it to spot re-key boundaries.
class Datagram {
public:
    // counter_hint(2, little-endian) + tag(16), same size for every datagram in
    // the capture
    static constexpr std::size_t aead_trailer = 18;

    // parse the self-describing outer header. header_len is bytes[1..3] read as a
    // big-endian u24, and the top two bytes were always 0 so it's really byte[3]
    [[nodiscard]] static std::expected<Datagram, FrameError>
    parse(std::span<const std::byte> payload) noexcept;

    // the opposite of parse(), rebuilds the exact wire bytes from what's stored.
    // parse(p).serialize() came back equal to p for every payload in the capture
    // (see test_roundtrip), so the model isn't losing any field. the one thing not
    // stored is the constant sub-flag bytes[4..6] (01 11 02).
    [[nodiscard]] std::vector<std::byte> serialize() const;

    [[nodiscard]] std::byte flag() const noexcept { return flag_; }
    [[nodiscard]] Direction direction() const noexcept { return direction_; }
    [[nodiscard]] std::uint32_t header_len() const noexcept { return header_len_; }

    // bytes[7..22]. 25 distinct values in the session, and they flip right when
    // the counter jumps. reads as a re-key or MUX substream epoch id
    [[nodiscard]] const std::array<std::byte, 16>& epoch_tag() const noexcept { return epoch_tag_; }

    // bytes[23..header_len). 8 bytes on direction 0x1f, empty on 0x17. the
    // reference calls it a fixed constant, but it took at least two values per
    // session, first 6 bytes stable and last 2 tracking the epoch. test_frame
    // checks this.
    [[nodiscard]] std::span<const std::byte> mux_extra() const noexcept { return mux_extra_; }

    // payload[header_len..], laid out as ciphertext || counter_hint(2, LE) || tag(16)
    [[nodiscard]] std::span<const std::byte> aead_body() const noexcept { return aead_body_; }
    [[nodiscard]] std::span<const std::byte> ciphertext() const noexcept { return ciphertext_; }
    [[nodiscard]] std::uint16_t counter_hint() const noexcept { return counter_hint_; }
    [[nodiscard]] std::span<const std::byte> tag() const noexcept { return tag_; }

private:
    Datagram() = default;

    std::byte flag_{};
    Direction direction_{};
    std::uint32_t header_len_{};
    std::uint16_t counter_hint_{};
    std::array<std::byte, 16> epoch_tag_{};
    std::span<const std::byte> mux_extra_{};
    std::span<const std::byte> aead_body_{};
    std::span<const std::byte> ciphertext_{};
    std::span<const std::byte> tag_{};
};

}  // namespace rbxraknet
