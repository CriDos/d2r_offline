#include "registry_internal.hpp"

#include <sstream>

namespace d2r_offline {
namespace {

constexpr OpenKeySpec kOpenKeySpecs[] = {
    {L"Software\\Valve\\Steam", kFakeRegistryHandleSteam},
    {L"Software\\Valve\\Steam\\ActiveProcess", kFakeRegistryHandleSteamActiveProcess},
    {L"Software\\Blizzard Entertainment\\Battle.net\\Launch Options\\OSI", kFakeRegistryHandleOsi},
    {L"Software\\Blizzard Entertainment\\Battle.net\\Launch Options\\BNA", kFakeRegistryHandleBna},
};

constexpr QueryValueSpec kSteamQuerySpecs[] = {
    {L"SteamClientDll", ValueSource::ModuleRelativePath, L"steamclient.dll"},
    {L"SteamClientDll64", ValueSource::ModuleRelativePath, L"steamclient64.dll"},
    {L"InstallPath", ValueSource::ModuleRoot, nullptr},
    {L"pid", ValueSource::ProcessId, nullptr},
};

constexpr QueryValueSpec kBattleNetQuerySpecs[] = {
    {L"locale", ValueSource::Locale, nullptr},
    {L"locale_audio", ValueSource::LocaleAudio, nullptr},
    {L"region", ValueSource::Literal, kDefaultRegion},
    {L"connection_string_us", ValueSource::Literal, kDefaultConnectionStringUs},
    {L"connection_status", ValueSource::Literal, kDefaultConnectionStringUs},
    {L"web_token", ValueSource::Literal, kDefaultWebToken},
};

const OpenKeySpec* FindOpenKeySpec(LPCWSTR subKey) {
    if (subKey == nullptr) {
        return nullptr;
    }

    for (const auto& spec : kOpenKeySpecs) {
        if (EqualsInsensitive(subKey, spec.subKey)) {
            return &spec;
        }
    }

    return nullptr;
}

const QueryValueSpec* FindQueryValueSpec(std::span<const QueryValueSpec> specs, LPCWSTR valueName) {
    if (valueName == nullptr) {
        return nullptr;
    }

    for (const auto& spec : specs) {
        if (EqualsInsensitive(valueName, spec.valueName)) {
            return &spec;
        }
    }

    return nullptr;
}

std::wstring ModuleRootString() {
    return g_moduleDirectory.wstring();
}

std::wstring BuildModuleRelativePath(const wchar_t* fileName) {
    return (g_moduleDirectory / fileName).wstring();
}

LSTATUS WriteValueFromSpec(const QueryValueSpec& spec, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    switch (spec.source) {
    case ValueSource::Literal:
        return WriteRegistryString(spec.payload, type, data, dataSize);
    case ValueSource::ModuleRelativePath: {
        const auto value = BuildModuleRelativePath(spec.payload);
        return WriteRegistryString(value.c_str(), type, data, dataSize);
    }
    case ValueSource::ModuleRoot: {
        const auto value = ModuleRootString();
        return WriteRegistryString(value.c_str(), type, data, dataSize);
    }
    case ValueSource::Locale:
        return WriteRegistryString(g_config.locale.c_str(), type, data, dataSize);
    case ValueSource::LocaleAudio:
        return WriteRegistryString(g_config.localeAudio.c_str(), type, data, dataSize);
    case ValueSource::ProcessId:
        return WriteRegistryDword(::GetCurrentProcessId(), type, data, dataSize);
    default:
        return ERROR_INVALID_PARAMETER;
    }
}

} // namespace

LSTATUS WINAPI HookedRegOpenKeyExW(HKEY key, LPCWSTR subKey, DWORD options, REGSAM samDesired, PHKEY result) {
    if (result != nullptr) {
        if (const auto* spec = FindOpenKeySpec(subKey); spec != nullptr) {
            *result = reinterpret_cast<HKEY>(spec->fakeHandle);
            return ERROR_SUCCESS;
        }
    }

    return g_originalRegOpenKeyExW(key, subKey, options, samDesired, result);
}

LSTATUS WINAPI HookedRegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    const FakeHandleKind handleKind = GetFakeHandleKind(key);
    if (handleKind == FakeHandleKind::None || valueName == nullptr) {
        return g_originalRegQueryValueExW(key, valueName, reserved, type, data, dataSize);
    }

    if (IsSteamHandle(handleKind)) {
        if (const auto* spec = FindQueryValueSpec(kSteamQuerySpecs, valueName); spec != nullptr) {
            return WriteValueFromSpec(*spec, type, data, dataSize);
        }
    } else if (IsBattleNetHandle(handleKind)) {
        if (const auto* spec = FindQueryValueSpec(kBattleNetQuerySpecs, valueName); spec != nullptr) {
            return WriteValueFromSpec(*spec, type, data, dataSize);
        }
        if (StartsWithInsensitive(valueName, L"connection_string_")) {
            return WriteRegistryString(kDefaultConnectionStringUs, type, data, dataSize);
        }
    }

    std::ostringstream message;
    message << "HookedRegQueryValueExW: unknown fake handle=" << FakeHandleName(handleKind)
            << " value=" << WideToUtf8(valueName);
    Log(message.str());
    return ERROR_FILE_NOT_FOUND;
}

LSTATUS WINAPI HookedRegCloseKey(HKEY key) {
    if (GetFakeHandleKind(key) != FakeHandleKind::None) {
        return ERROR_SUCCESS;
    }

    return g_originalRegCloseKey(key);
}

} // namespace d2r_offline
