#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace rbxraknet {

// every id here is a guess. packet ids sit inside the AEAD envelope, so you only
// see them after decryption, and no key ships with this repo. these come from an
// old reference, written down so an InnerParser can put names to ids. the ones
// actually seen in the capture are tagged verified. see PROVENANCE.md.
enum class Verification : std::uint8_t {
    verified,    // seen in the capture
    hypothesis,  // reference only, never checked against real traffic
};

struct PacketInfo {
    std::uint8_t id;
    std::string_view name;
    Verification verification;
};

// looks up metadata for both the outer RakNet message ids and the ID_DATA
// subpacket ids. two separate tables because the id spaces overlap, for example
// 0x02 is unused at the top level but means NEW_INST inside ID_DATA.
class PacketRegistry {
public:
    // pre-filled with the reference's guessed ids
    [[nodiscard]] static PacketRegistry with_reference_defaults();

    [[nodiscard]] const PacketInfo* top_level(std::uint8_t id) const noexcept;
    [[nodiscard]] const PacketInfo* data_subpacket(std::uint8_t id) const noexcept;

    [[nodiscard]] std::span<const PacketInfo> top_level_entries() const noexcept { return top_level_; }
    [[nodiscard]] std::span<const PacketInfo> data_subpacket_entries() const noexcept { return data_subpackets_; }

private:
    PacketRegistry() = default;
    std::span<const PacketInfo> top_level_{};
    std::span<const PacketInfo> data_subpackets_{};
};

// handles the RakNet reliability and message decode that happens after decrypt.
// just an interface for now: the inner framing lives inside the AEAD envelope and
// has never been seen as plaintext, so there's nothing to parse yet. once someone
// recovers a key, subclass this, use the PacketRegistry to name ids, and hand it
// to the Decoder.
class InnerParser {
public:
    virtual ~InnerParser() = default;
    virtual void parse(std::span<const std::byte> plaintext,
                       const PacketRegistry& registry) const = 0;
};

}  // namespace rbxraknet
