#include "../support/d2r_offline.hpp"
#include "crypto_support.hpp"

#include <algorithm>
#include <array>
#include <string>

extern "C" {
#include "serpent.h"
}

namespace d2r_offline::crypto {
namespace {

std::string BytesToSerpentKeyMaterial(std::span<const std::uint8_t> bytes) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string text(bytes.size() * 2, '\0');
    std::size_t out = 0;

    // The AES-candidate Serpent API parses 32-bit words from the end of the hex string.
    // Emit reversed 32-bit chunks with bytes reversed inside each chunk so the resulting
    // key schedule matches Botan's load_le<byte>() semantics used by the original DLL.
    for (std::size_t word = bytes.size(); word > 0; word -= 4) {
        for (std::size_t i = 0; i < 4; ++i) {
            const std::uint8_t byte = bytes[word - 1 - i];
            text[out++] = kHexDigits[(byte >> 4U) & 0x0fU];
            text[out++] = kHexDigits[byte & 0x0fU];
        }
    }
    return text;
}

void IncrementCounterBigEndian(std::array<std::uint8_t, 16>& counter) {
    for (std::size_t i = counter.size(); i-- > 0;) {
        ++counter[i];
        if (counter[i] != 0) {
            break;
        }
    }
}

} // namespace

std::optional<std::vector<std::uint8_t>> SerpentCtrCrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> iv,
    std::span<const std::uint8_t> plaintext) {
    if (key.size() != 32 || iv.size() != 16) {
        Log("crypto: invalid Serpent key/iv size");
        return std::nullopt;
    }

    std::string keyMaterial = BytesToSerpentKeyMaterial(key);
    keyInstance keyState{};
    cipherInstance cipherState{};
    if (makeKey(&keyState, DIR_ENCRYPT, 256, keyMaterial.data()) != TRUE ||
        cipherInit(&cipherState, MODE_ECB, nullptr) != TRUE) {
        Log("crypto: Serpent makeKey/cipherInit failed");
        return std::nullopt;
    }

    std::array<std::uint8_t, 16> counter{};
    std::copy(iv.begin(), iv.end(), counter.begin());

    std::vector<std::uint8_t> ciphertext(plaintext.begin(), plaintext.end());
    std::array<std::uint8_t, 16> keystream{};
    for (std::size_t offset = 0; offset < ciphertext.size(); offset += keystream.size()) {
        if (blockEncrypt(&cipherState, &keyState, counter.data(), 128, keystream.data()) != 128) {
            Log("crypto: Serpent blockEncrypt failed");
            return std::nullopt;
        }

        const std::size_t chunkSize = std::min<std::size_t>(keystream.size(), ciphertext.size() - offset);
        for (std::size_t i = 0; i < chunkSize; ++i) {
            ciphertext[offset + i] ^= keystream[i];
        }
        IncrementCounterBigEndian(counter);
    }

    return ciphertext;
}

} // namespace d2r_offline::crypto
