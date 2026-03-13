#include "cookie_internal.hpp"

#include <ctime>

namespace d2r_offline {
namespace {

bool IsAsciiWhitespace(wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
}

std::wstring TrimWide(std::wstring_view value) {
    std::size_t begin = 0;
    while (begin < value.size() && IsAsciiWhitespace(value[begin])) {
        ++begin;
    }

    std::size_t end = value.size();
    while (end > begin && IsAsciiWhitespace(value[end - 1])) {
        --end;
    }

    return std::wstring(value.substr(begin, end - begin));
}

void AppendVarint(std::vector<std::uint8_t>& out, std::uint64_t value) {
    do {
        std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
            byte |= 0x80U;
        }
        out.push_back(byte);
    } while (value != 0);
}

void AppendLengthDelimited(std::vector<std::uint8_t>& out, std::uint32_t fieldNumber, const void* data, std::size_t size) {
    AppendVarint(out, (static_cast<std::uint64_t>(fieldNumber) << 3U) | 2U);
    AppendVarint(out, size);
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    out.insert(out.end(), bytes, bytes + size);
}

void AppendLengthDelimited(std::vector<std::uint8_t>& out, std::uint32_t fieldNumber, std::string_view value) {
    AppendLengthDelimited(out, fieldNumber, value.data(), value.size());
}

void AppendVarintField(std::vector<std::uint8_t>& out, std::uint32_t fieldNumber, std::uint64_t value) {
    AppendVarint(out, (static_cast<std::uint64_t>(fieldNumber) << 3U));
    AppendVarint(out, value);
}

} // namespace

std::vector<std::string> SplitEntitlements(std::wstring_view csv) {
    std::vector<std::string> values;
    std::size_t start = 0;
    while (start <= csv.size()) {
        const std::size_t comma = csv.find(L',', start);
        const std::size_t end = (comma == std::wstring_view::npos) ? csv.size() : comma;
        const std::wstring token = TrimWide(csv.substr(start, end - start));
        if (!token.empty()) {
            values.push_back(WideToUtf8(token));
        }
        if (comma == std::wstring_view::npos) {
            break;
        }
        start = comma + 1;
    }
    return values;
}

std::vector<std::string> DefaultEntitlements() {
    return SplitEntitlements(kDefaultEntitlementsCsv);
}

ClaimsData BuildClaimsData() {
    ClaimsData claims;
    claims.entitlements = SplitEntitlements(g_config.entitlements);
    if (claims.entitlements.empty()) {
        claims.entitlements = DefaultEntitlements();
    }
    claims.expiry = static_cast<std::uint64_t>(std::time(nullptr)) + 0x278d00ULL;
    return claims;
}

std::vector<std::uint8_t> BuildSignedClaimsProto(const ClaimsData& claims) {
    std::vector<std::uint8_t> out;
    for (const auto& entitlement : claims.entitlements) {
        AppendLengthDelimited(out, 1, entitlement);
    }
    AppendVarintField(out, 4, claims.accountId);
    AppendVarintField(out, 5, claims.userId);
    AppendVarintField(out, 6, claims.expiry);
    AppendVarintField(out, 8, claims.gameId);
    AppendLengthDelimited(out, 9, claims.region);
    return out;
}

} // namespace d2r_offline
