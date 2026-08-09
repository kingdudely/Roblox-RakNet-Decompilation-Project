// exercises the OpenSSL EVP wiring and the guessed nonce layout against a
// synthetic key. once a real session key turns up: swap it in, drop the
// encrypt() side, feed real ciphertext to decrypt()

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "rbxraknet/aead.hpp"
#include "support.hpp"

using namespace rbxraknet;

namespace {

std::array<std::byte, 32> synthetic_key() {
    std::array<std::byte, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(0x40 + i);  // 0x40..0x5f, an obvious non-secret
    }
    return key;
}

std::vector<std::byte> sample_plaintext() {
    const std::string s = "ID_DATA round-trip: RakNet inner framing goes here once a key exists.";
    std::vector<std::byte> out(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) out[i] = static_cast<std::byte>(s[i]);
    return out;
}

void roundtrip(CipherAlgorithm algo) {
    const AeadCodec codec(algo);
    const auto key = synthetic_key();
    const auto pt = sample_plaintext();
    const std::uint64_t counter = 50476;  // a real counter value from the capture

    auto sealed = codec.encrypt(std::span<const std::byte, 32>(key), counter, pt);
    REQUIRE(sealed.has_value());
    REQUIRE(sealed->ciphertext.size() == pt.size());  // stream cipher: length preserved

    auto recovered = codec.decrypt(std::span<const std::byte, 32>(key), counter,
                                   sealed->ciphertext, sealed->tag);
    REQUIRE(recovered.has_value());
    REQUIRE(*recovered == pt);

    // wrong counter = different nonce, so auth must reject: the counter is bound in
    auto wrong_counter = codec.decrypt(std::span<const std::byte, 32>(key), counter + 1,
                                       sealed->ciphertext, sealed->tag);
    REQUIRE(!wrong_counter.has_value());
    REQUIRE(wrong_counter.error() == CryptoError::auth_failed);

    auto tampered_tag = sealed->tag;
    tampered_tag[0] = tampered_tag[0] ^ std::byte{0xFF};
    auto bad_tag = codec.decrypt(std::span<const std::byte, 32>(key), counter,
                                 sealed->ciphertext, tampered_tag);
    REQUIRE(!bad_tag.has_value());
    REQUIRE(bad_tag.error() == CryptoError::auth_failed);

    auto tampered_ct = sealed->ciphertext;
    tampered_ct[0] = tampered_ct[0] ^ std::byte{0x01};
    auto bad_ct = codec.decrypt(std::span<const std::byte, 32>(key), counter, tampered_ct, sealed->tag);
    REQUIRE(!bad_ct.has_value());
    REQUIRE(bad_ct.error() == CryptoError::auth_failed);

    // wrong length never reaches auth
    std::vector<std::byte> short_tag(15, std::byte{0});
    auto bad_len = codec.decrypt(std::span<const std::byte, 32>(key), counter, sealed->ciphertext, short_tag);
    REQUIRE(bad_len.error() == CryptoError::bad_tag_size);
}

void nonce_layout() {
    // le u64(counter) || "mbeR", spot-checked at 0x0102030405060708
    const AeadCodec codec(CipherAlgorithm::aes_256_gcm);
    const auto nonce = codec.build_nonce(0x0102030405060708ULL);
    const std::byte expect[12] = {
        std::byte{0x08}, std::byte{0x07}, std::byte{0x06}, std::byte{0x05},
        std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{'m'},  std::byte{'b'},  std::byte{'e'},  std::byte{'R'}};
    for (int i = 0; i < 12; ++i) REQUIRE(nonce[i] == expect[i]);
}

void algorithms_differ() {
    // same key, counter and plaintext under both suites must not collide: cheap
    // proof the two paths reach different primitives
    const auto key = synthetic_key();
    const auto pt = sample_plaintext();
    auto a = AeadCodec(CipherAlgorithm::aes_256_gcm).encrypt(std::span<const std::byte, 32>(key), 1, pt);
    auto b = AeadCodec(CipherAlgorithm::chacha20_poly1305).encrypt(std::span<const std::byte, 32>(key), 1, pt);
    REQUIRE(a.has_value() && b.has_value());
    REQUIRE(a->ciphertext != b->ciphertext);
}

}  // namespace

int main() {
    nonce_layout();
    roundtrip(CipherAlgorithm::aes_256_gcm);
    roundtrip(CipherAlgorithm::chacha20_poly1305);
    algorithms_differ();

    std::cout << "test_aead: " << rbxtest::check_count() << " checks passed "
              << "(AES-256-GCM + ChaCha20-Poly1305 round-trip, nonce layout, tamper rejection)\n";
    return 0;
}
