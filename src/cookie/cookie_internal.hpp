#pragma once

#include "../support/d2r_offline.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace d2r_offline {

inline constexpr char kTypeUrl[] = "classic.protocol.v1.d2r_connection.AuthSessionResponse";
inline constexpr char kClaimsRegion[] = "USA";
inline constexpr std::size_t kCryptoboxSaltSize = 10;
inline constexpr std::size_t kCryptoboxMacSize = 20;
inline constexpr std::size_t kCryptoboxHeaderSize = 4 + kCryptoboxSaltSize + kCryptoboxMacSize;

struct MachineContext {
    std::string passwordBase64;
};

struct ClaimsData {
    std::vector<std::string> entitlements;
    std::uint64_t accountId = kDefaultAccountId;
    std::uint64_t userId = kDefaultUserId;
    std::uint64_t expiry = 0;
    std::uint64_t gameId = kDefaultGameId;
    std::string region = kClaimsRegion;
};

std::vector<std::string> SplitEntitlements(std::wstring_view csv);
std::vector<std::string> DefaultEntitlements();
std::string Base64EncodeStringWrapped64(const std::vector<std::uint8_t>& data);

std::optional<MachineContext> BuildMachineContext();
ClaimsData BuildClaimsData();
std::vector<std::uint8_t> BuildSignedClaimsProto(const ClaimsData& claims);

std::optional<std::string> GenerateCryptoboxBodyBase64(
    const std::vector<std::uint8_t>& claimsProto,
    std::string_view password);
std::optional<std::vector<std::uint8_t>> SignBodySha224(std::string_view bodyBase64);

std::optional<CookieEntry> GenerateCookieEntry();
std::vector<std::uint8_t> BuildCookieFile(const CookieEntry& entry);
std::filesystem::path GetCookiePath();
bool WriteFileBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes);

} // namespace d2r_offline
