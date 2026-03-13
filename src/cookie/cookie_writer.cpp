#include "cookie_internal.hpp"

#include <ShlObj.h>

#include <sstream>

namespace d2r_offline {

std::optional<CookieEntry> GenerateCookieEntry() {
    const auto machineContext = BuildMachineContext();
    if (!machineContext.has_value()) {
        Log("cookie: machine context generation failed");
        return std::nullopt;
    }

    const ClaimsData claims = BuildClaimsData();
    const auto claimsProto = BuildSignedClaimsProto(claims);
    const auto bodyBase64 = GenerateCryptoboxBodyBase64(claimsProto, machineContext->passwordBase64);
    if (!bodyBase64.has_value()) {
        Log("cookie: body generation failed");
        return std::nullopt;
    }

    const auto signature = SignBodySha224(*bodyBase64);
    if (!signature.has_value()) {
        Log("cookie: signing failed");
        return std::nullopt;
    }

    CookieEntry entry;
    entry.typeUrl = kTypeUrl;
    entry.bodyBase64 = *bodyBase64;
    entry.signature = *signature;
    entry.gameId = kDefaultGameId;
    return entry;
}

std::vector<std::uint8_t> BuildCookieFile(const CookieEntry& entry) {
    auto appendVarint = [](std::vector<std::uint8_t>& out, std::uint64_t value) {
        do {
            std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7fU);
            value >>= 7U;
            if (value != 0) {
                byte |= 0x80U;
            }
            out.push_back(byte);
        } while (value != 0);
    };

    auto appendLengthDelimited = [&appendVarint](std::vector<std::uint8_t>& out, std::uint32_t fieldNumber, const void* data, std::size_t size) {
        appendVarint(out, (static_cast<std::uint64_t>(fieldNumber) << 3U) | 2U);
        appendVarint(out, size);
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        out.insert(out.end(), bytes, bytes + size);
    };

    auto appendVarintField = [&appendVarint](std::vector<std::uint8_t>& out, std::uint32_t fieldNumber, std::uint64_t value) {
        appendVarint(out, (static_cast<std::uint64_t>(fieldNumber) << 3U));
        appendVarint(out, value);
    };

    std::vector<std::uint8_t> inner;
    appendLengthDelimited(inner, 1, entry.typeUrl.data(), entry.typeUrl.size());
    appendLengthDelimited(inner, 2, entry.bodyBase64.data(), entry.bodyBase64.size());
    appendLengthDelimited(inner, 3, entry.signature.data(), entry.signature.size());
    appendVarintField(inner, 4, entry.gameId);

    std::vector<std::uint8_t> outer;
    appendLengthDelimited(outer, 5, inner.data(), inner.size());
    return outer;
}

bool WriteFileBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);

    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    const BOOL ok = ::WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    ::CloseHandle(file);
    return ok && written == bytes.size();
}

std::filesystem::path GetCookiePath() {
    wchar_t localAppData[MAX_PATH] = {};
    if (FAILED(::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData))) {
        return {};
    }
    return std::filesystem::path(localAppData) / L"Blizzard Entertainment" / L"ClientSdk" / L"cookie.bin";
}

bool WriteGeneratedCookie() {
    const auto path = GetCookiePath();
    if (path.empty()) {
        Log("cookie: failed to resolve cookie path");
        return false;
    }

    const auto entry = GenerateCookieEntry();
    if (!entry.has_value()) {
        Log("cookie: GenerateCookieEntry returned no value");
        return false;
    }

    const auto bytes = BuildCookieFile(*entry);
    if (!WriteFileBytes(path, bytes)) {
        Log("cookie: write failed");
        return false;
    }

    std::ostringstream message;
    message << "cookie: cookie.bin written size=" << bytes.size();
    Log(message.str());
    return true;
}

} // namespace d2r_offline
