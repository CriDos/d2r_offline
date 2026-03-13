#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace d2r_offline::crypto {

bool EnsureCryptoBackendInitialized();
std::optional<std::vector<std::uint8_t>> ComputeSha1(std::string_view text);
std::optional<std::array<std::uint8_t, 80>> DerivePbkdf2Sha512(
    std::string_view password,
    std::span<const std::uint8_t> salt);
std::optional<std::array<std::uint8_t, 64>> ComputeHmacSha512(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> data);
std::optional<std::vector<std::uint8_t>> SignSha224(
    std::string_view data,
    std::string_view privateKeyPem);
std::optional<std::vector<std::uint8_t>> SerpentCtrCrypt(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> iv,
    std::span<const std::uint8_t> plaintext);

} // namespace d2r_offline::crypto
