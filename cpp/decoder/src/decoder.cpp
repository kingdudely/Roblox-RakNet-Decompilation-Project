#include "rbxraknet/decoder.hpp"

#include <utility>

namespace rbxraknet {

Decoder::Decoder(CipherAlgorithm algorithm, const InnerParser* inner_parser, PacketRegistry registry)
    : codec_(algorithm), registry_(std::move(registry)), inner_parser_(inner_parser) {}

DecodeResult Decoder::decode(std::span<const std::byte> payload) noexcept {
    DecodeResult result;

    std::expected<Datagram, FrameError> parsed = Datagram::parse(payload);
    if (!parsed) {
        result.status = DecodeStatus::parse_error;
        result.frame_error = parsed.error();
        return result;
    }

    const Datagram& datagram = *parsed;
    const Observation observation = session_.observe(datagram);
    result.datagram = datagram;
    result.observation = observation;

    const Direction direction = datagram.direction();
    if (!session_.has_key(direction)) {
        result.status = DecodeStatus::no_key;
        return result;
    }

    const std::array<std::byte, 32> key = *session_.key(direction);
    std::expected<std::vector<std::byte>, CryptoError> plaintext =
        codec_.decrypt(std::span<const std::byte, 32>(key), observation.full_counter,
                       datagram.ciphertext(), datagram.tag());
    if (!plaintext) {
        result.status = DecodeStatus::decrypt_failed;
        result.crypto_error = plaintext.error();
        return result;
    }

    result.status = DecodeStatus::decrypted;
    result.plaintext = std::move(*plaintext);
    // hand the plaintext to the inner parser if one's installed. no default
    // parser here, the python side owns the inner grammar.
    if (inner_parser_ != nullptr) {
        inner_parser_->parse(result.plaintext, registry_);
    }
    return result;
}

}  // namespace rbxraknet
