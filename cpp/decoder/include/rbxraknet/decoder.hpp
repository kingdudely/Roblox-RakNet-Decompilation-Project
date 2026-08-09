#pragma once

#include <optional>
#include <span>
#include <vector>

#include "rbxraknet/aead.hpp"
#include "rbxraknet/datagram.hpp"
#include "rbxraknet/packet_registry.hpp"
#include "rbxraknet/session.hpp"

namespace rbxraknet {

enum class DecodeStatus {
    parse_error,     // malformed outer header, check frame_error
    no_key,          // nothing bound for this direction
    decrypt_failed,  // AEAD rejected the body, check crypto_error
    decrypted,
};

struct DecodeResult {
    DecodeStatus status;
    std::optional<Datagram> datagram;        // both set unless parse_error
    std::optional<Observation> observation;
    std::vector<std::byte> plaintext;        // only on decrypted
    FrameError frame_error{};                // only means anything on parse_error
    CryptoError crypto_error{};              // ditto, on decrypt_failed
};

// the whole pipeline. raw payload becomes a Datagram, then the Session tracks
// counter and epoch, then it decrypts if a key was set, then an optional inner
// parse. no key set means it stops at framing.
class Decoder {
public:
    // inner_parser is optional and not owned here, nullptr until a real one
    // exists. registry gets copied in for that inner parser to use
    explicit Decoder(CipherAlgorithm algorithm,
                     const InnerParser* inner_parser = nullptr,
                     PacketRegistry registry = PacketRegistry::with_reference_defaults());

    [[nodiscard]] DecodeResult decode(std::span<const std::byte> payload) noexcept;

    [[nodiscard]] Session& session() noexcept { return session_; }
    [[nodiscard]] const PacketRegistry& registry() const noexcept { return registry_; }

private:
    Session session_;
    AeadCodec codec_;
    PacketRegistry registry_;
    const InnerParser* inner_parser_;
};

}  // namespace rbxraknet
