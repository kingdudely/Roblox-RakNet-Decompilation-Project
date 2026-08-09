#include "rbxraknet/aead.hpp"

#include <openssl/evp.h>

#include <cstring>
#include <memory>

namespace rbxraknet {

namespace {

using EvpCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

EvpCtx make_ctx() noexcept { return EvpCtx{EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free}; }

const EVP_CIPHER* cipher_for(CipherAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case CipherAlgorithm::aes_256_gcm:
            return EVP_aes_256_gcm();
        case CipherAlgorithm::chacha20_poly1305:
            return EVP_chacha20_poly1305();
    }
    return nullptr;
}

const unsigned char* uc(std::span<const std::byte> s) noexcept {
    return reinterpret_cast<const unsigned char*>(s.data());
}

}  // namespace

std::string_view to_string(CryptoError error) noexcept {
    switch (error) {
        case CryptoError::bad_key_size:
            return "key must be 32 bytes";
        case CryptoError::bad_tag_size:
            return "tag must be 16 bytes";
        case CryptoError::auth_failed:
            return "AEAD tag verification failed";
        case CryptoError::openssl_failure:
            return "OpenSSL EVP call failed";
    }
    return "unknown crypto error";
}

AeadCodec::AeadCodec(CipherAlgorithm algorithm, std::array<std::byte, 4> nonce_suffix) noexcept
    : algorithm_(algorithm), nonce_suffix_(nonce_suffix) {}

std::array<std::byte, AeadCodec::nonce_size> AeadCodec::build_nonce(std::uint64_t counter) const noexcept {
    // 12-byte nonce is little-endian u64(counter) then the 4-byte suffix ("mbeR").
    // guessed layout, see aead.hpp
    std::array<std::byte, nonce_size> nonce{};
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[i] = static_cast<std::byte>((counter >> (8 * i)) & 0xFF);
    }
    nonce[8] = nonce_suffix_[0];
    nonce[9] = nonce_suffix_[1];
    nonce[10] = nonce_suffix_[2];
    nonce[11] = nonce_suffix_[3];
    return nonce;
}

std::expected<std::vector<std::byte>, CryptoError>
AeadCodec::decrypt(std::span<const std::byte, key_size> key, std::uint64_t counter,
                   std::span<const std::byte> ciphertext, std::span<const std::byte> tag) const noexcept {
    if (tag.size() != tag_size) {
        return std::unexpected(CryptoError::bad_tag_size);
    }
    EvpCtx ctx = make_ctx();
    if (!ctx) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    const std::array<std::byte, nonce_size> nonce = build_nonce(counter);

    if (EVP_DecryptInit_ex(ctx.get(), cipher_for(algorithm_), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce_size), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, uc(key), uc(nonce)) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    std::vector<std::byte> plaintext(ciphertext.size());
    int out_len = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(plaintext.data()), &out_len,
                          uc(ciphertext), static_cast<int>(ciphertext.size())) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    // hand over the tag before finalizing, otherwise GCM/Poly1305 has nothing to
    // check against
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag_size),
                            const_cast<unsigned char*>(uc(tag))) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    int final_len = 0;
    // zero or less means the tag didn't verify
    if (EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(plaintext.data()) + out_len,
                            &final_len) <= 0) {
        return std::unexpected(CryptoError::auth_failed);
    }
    plaintext.resize(static_cast<std::size_t>(out_len + final_len));
    return plaintext;
}

std::expected<Sealed, CryptoError>
AeadCodec::encrypt(std::span<const std::byte, key_size> key, std::uint64_t counter,
                   std::span<const std::byte> plaintext) const noexcept {
    EvpCtx ctx = make_ctx();
    if (!ctx) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    const std::array<std::byte, nonce_size> nonce = build_nonce(counter);

    if (EVP_EncryptInit_ex(ctx.get(), cipher_for(algorithm_), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce_size), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, uc(key), uc(nonce)) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    Sealed sealed;
    sealed.ciphertext.resize(plaintext.size());
    int out_len = 0;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(sealed.ciphertext.data()), &out_len,
                          uc(plaintext), static_cast<int>(plaintext.size())) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(sealed.ciphertext.data()) + out_len,
                            &final_len) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }
    sealed.ciphertext.resize(static_cast<std::size_t>(out_len + final_len));

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag_size),
                            reinterpret_cast<unsigned char*>(sealed.tag.data())) != 1) {
        return std::unexpected(CryptoError::openssl_failure);
    }
    return sealed;
}

}  // namespace rbxraknet
