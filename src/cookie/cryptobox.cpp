#include "cookie_internal.hpp"

#include "../support/key_material.hpp"
#include "../crypto/crypto_support.hpp"

#include <array>

namespace d2r_offline {

std::optional<std::string> GenerateCryptoboxBodyBase64(const std::vector<std::uint8_t>& claimsProto, std::string_view password) {
    std::array<std::uint8_t, kCryptoboxSaltSize> salt{};
    if (!FillRandomBytes(salt.data(), salt.size())) {
        Log("cookie: RNG failed");
        return std::nullopt;
    }

    const auto derived = crypto::DerivePbkdf2Sha512(password, salt);
    if (!derived.has_value()) {
        return std::nullopt;
    }

    const auto ciphertext = crypto::SerpentCtrCrypt(
        std::span<const std::uint8_t>(derived->data(), 32),
        std::span<const std::uint8_t>(derived->data() + 64, 16),
        claimsProto);
    if (!ciphertext.has_value()) {
        return std::nullopt;
    }

    const auto mac = crypto::ComputeHmacSha512(
        std::span<const std::uint8_t>(derived->data() + 32, 32),
        *ciphertext);
    if (!mac.has_value()) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> body;
    body.reserve(kCryptoboxHeaderSize + ciphertext->size());
    body.push_back(0xEF);
    body.push_back(0xC2);
    body.push_back(0x24);
    body.push_back(0x00);
    body.insert(body.end(), salt.begin(), salt.end());
    body.insert(body.end(), mac->begin(), mac->begin() + kCryptoboxMacSize);
    body.insert(body.end(), ciphertext->begin(), ciphertext->end());

    return Base64EncodeStringWrapped64(body);
}

std::optional<std::vector<std::uint8_t>> SignBodySha224(std::string_view bodyBase64) {
    const auto signature = crypto::SignSha224(bodyBase64, ReplacementPrivateKeyPem());
    if (!signature.has_value()) {
        return std::nullopt;
    }

    return signature;
}

} // namespace d2r_offline
