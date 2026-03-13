#include "cookie_internal.hpp"

#include "../crypto/crypto_support.hpp"

#include <array>
#include <optional>
#include <sstream>

namespace d2r_offline {
namespace {

std::vector<std::uint8_t> Base64EncodeWrapped64(const std::uint8_t* data, std::size_t size) {
    static constexpr char kBase64Alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    encoded.reserve(((size + 2) / 3) * 4 + 2);

    for (std::size_t i = 0; i < size; i += 3) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(data[i]) << 16U) |
            (static_cast<std::uint32_t>(i + 1 < size ? data[i + 1] : 0) << 8U) |
            (static_cast<std::uint32_t>(i + 2 < size ? data[i + 2] : 0));

        encoded.push_back(kBase64Alphabet[(chunk >> 18U) & 0x3fU]);
        encoded.push_back(kBase64Alphabet[(chunk >> 12U) & 0x3fU]);
        encoded.push_back(i + 1 < size ? kBase64Alphabet[(chunk >> 6U) & 0x3fU] : '=');
        encoded.push_back(i + 2 < size ? kBase64Alphabet[chunk & 0x3fU] : '=');
    }

    if (encoded.size() <= 64) {
        return std::vector<std::uint8_t>(encoded.begin(), encoded.end());
    }

    std::string wrapped;
    wrapped.reserve(encoded.size() + (encoded.size() / 64));
    for (std::size_t offset = 0; offset < encoded.size(); offset += 64) {
        const std::size_t chunkSize = std::min<std::size_t>(64, encoded.size() - offset);
        wrapped.append(encoded, offset, chunkSize);
        if (offset + chunkSize < encoded.size()) {
            wrapped.push_back('\n');
        }
    }

    return std::vector<std::uint8_t>(wrapped.begin(), wrapped.end());
}

std::optional<std::string> ReadRegistryStringValue(HKEY root, const wchar_t* subKey, const wchar_t* valueName) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        if (::RegOpenKeyExW(root, subKey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
            return std::nullopt;
        }
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    const LSTATUS queryStatus = ::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &dataSize);
    if (queryStatus != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || dataSize < sizeof(wchar_t)) {
        ::RegCloseKey(key);
        return std::nullopt;
    }

    std::wstring buffer(dataSize / sizeof(wchar_t), L'\0');
    const LSTATUS readStatus = ::RegQueryValueExW(
        key,
        valueName,
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(buffer.data()),
        &dataSize);
    ::RegCloseKey(key);
    if (readStatus != ERROR_SUCCESS) {
        return std::nullopt;
    }

    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    return WideToUtf8(buffer);
}

std::string GetVolumeRootSeed() {
    char modulePath[8] = {};
    if (::GetModuleFileNameA(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath))) == 0) {
        Log("cookie: GetModuleFileNameA failed");
        return "C:\\";
    }

    modulePath[3] = '\0';
    if (modulePath[1] != ':' || modulePath[2] != '\\') {
        Log("cookie: module root seed malformed, using fallback");
        return "C:\\";
    }

    return std::string(modulePath);
}

} // namespace

std::string Base64EncodeStringWrapped64(const std::vector<std::uint8_t>& data) {
    const auto encoded = Base64EncodeWrapped64(data.data(), data.size());
    return std::string(encoded.begin(), encoded.end());
}

std::optional<MachineContext> BuildMachineContext() {
    MachineContext context;
    const std::string volumeRoot = GetVolumeRootSeed();
    DWORD volumeSerial = 0;

    if (!::GetVolumeInformationA(
            volumeRoot.c_str(),
            nullptr,
            0,
            &volumeSerial,
            nullptr,
            nullptr,
            nullptr,
            0)) {
        Log("cookie: GetVolumeInformationA failed");
        return std::nullopt;
    }

    const auto machineGuid = ReadRegistryStringValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    if (!machineGuid.has_value() || machineGuid->empty()) {
        Log("cookie: MachineGuid read failed");
        return std::nullopt;
    }

    std::ostringstream preimage;
    preimage << *machineGuid << volumeSerial;

    const auto digest = crypto::ComputeSha1(preimage.str());
    if (!digest.has_value()) {
        return std::nullopt;
    }

    context.passwordBase64 = Base64EncodeStringWrapped64(*digest);
    return context;
}

} // namespace d2r_offline
