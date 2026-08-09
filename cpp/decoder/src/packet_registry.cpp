#include "rbxraknet/packet_registry.hpp"

#include <array>

namespace rbxraknet {

namespace {

// all guesses: ids only appear after decryption. from an old reference,
// unconfirmed against the captured traffic. to confirm, decrypt with a recovered
// key and check the leading byte of each plaintext against these
constexpr std::array<PacketInfo, 6> kTopLevel = {{
    {0x81, "ID_SET_GLOBALS", Verification::hypothesis},
    {0x83, "ID_DATA", Verification::hypothesis},
    {0x85, "ID_PHYSICS", Verification::hypothesis},
    {0x97, "ID_NEW_SCHEMA", Verification::hypothesis},
    {0x98, "ID_KICK_MESSAGE", Verification::hypothesis},
    {0x9B, "ID_LUAU_CHALLENGE", Verification::hypothesis},
}};

// ID_DATA subpacket ids, kept separate because they overlap the top-level space
constexpr std::array<PacketInfo, 4> kDataSubpackets = {{
    {0x02, "NEW_INST", Verification::hypothesis},
    {0x03, "PROP", Verification::hypothesis},
    {0x07, "EVENT", Verification::hypothesis},
    {0x0B, "JOIN_DATA", Verification::hypothesis},
}};

const PacketInfo* find(std::span<const PacketInfo> table, std::uint8_t id) noexcept {
    for (const PacketInfo& entry : table) {
        if (entry.id == id) {
            return &entry;
        }
    }
    return nullptr;
}

}  // namespace

PacketRegistry PacketRegistry::with_reference_defaults() {
    PacketRegistry registry;
    registry.top_level_ = kTopLevel;
    registry.data_subpackets_ = kDataSubpackets;
    return registry;
}

const PacketInfo* PacketRegistry::top_level(std::uint8_t id) const noexcept {
    return find(top_level_, id);
}

const PacketInfo* PacketRegistry::data_subpacket(std::uint8_t id) const noexcept {
    return find(data_subpackets_, id);
}

}  // namespace rbxraknet
