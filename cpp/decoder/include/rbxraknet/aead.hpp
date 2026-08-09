#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace rbxraknet {

// algorithm, 32-byte key size and nonce layout all match what the python side
// measured against real traffic, see PROVENANCE.md. no key ships with this repo
// though, so the tests here run on a synthetic one and only exercise the EVP
// plumbing. drop a real key in and it decodes the same capture python does.
enum class CipherAlgorithm {
    aes_256_gcm,
    chacha20_poly1305,
};

enum class CryptoError {
    bad_key_size,     // key wasn't 32 bytes
    bad_tag_size,     // tag wasn't 16 bytes
    auth_failed,      // GCM/Poly1305 didn't like the tag, so the message is bad
    openssl_failure,  // some EVP call blew up for a reason that isn't auth
};

[[nodiscard]] std::string_view to_string(CryptoError error) noexcept;

// encrypted output. the tag stays separate so the wire body can be laid out as
// ciphertext || counter_hint(2, LE) || tag(16)
struct Sealed {
    std::vector<std::byte> ciphertext;
    std::array<std::byte, 16> tag{};
};

// thin wrapper over EVP for the two AEAD suites. every call spins up its own
// EVP_CIPHER_CTX in a unique_ptr, so there's nothing to free by hand
class AeadCodec {
public:
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;

    // last 4 bytes of the 12-byte nonce are fixed. the reference says ASCII "mbeR"
    // sitting after a little-endian u64 counter. it's a parameter rather than a
    // literal so a real key that says otherwise is a one-spot change
    explicit AeadCodec(
        CipherAlgorithm algorithm,
        std::array<std::byte, 4> nonce_suffix = {std::byte{'m'}, std::byte{'b'},
                                                 std::byte{'e'}, std::byte{'R'}}) noexcept;

    [[nodiscard]] CipherAlgorithm algorithm() const noexcept { return algorithm_; }

    // nonce is little-endian u64(counter) || nonce_suffix, and the AAD is empty
    // like the reference says
    [[nodiscard]] std::expected<std::vector<std::byte>, CryptoError>
    decrypt(std::span<const std::byte, key_size> key, std::uint64_t counter,
            std::span<const std::byte> ciphertext, std::span<const std::byte> tag) const noexcept;

    // only exists to test the plumbing before a real key turns up. real traffic is
    // decrypt-only
    [[nodiscard]] std::expected<Sealed, CryptoError>
    encrypt(std::span<const std::byte, key_size> key, std::uint64_t counter,
            std::span<const std::byte> plaintext) const noexcept;

    // public so tests can look at the exact 12 bytes
    [[nodiscard]] std::array<std::byte, nonce_size> build_nonce(std::uint64_t counter) const noexcept;

private:
    CipherAlgorithm algorithm_;
    std::array<std::byte, 4> nonce_suffix_;
};

}  // namespace rbxraknet
