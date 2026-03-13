#include "registry_internal.hpp"

#include <array>
#include <cstring>

namespace d2r_offline {
namespace {

constexpr std::size_t kAbsoluteJumpSize = 12;

bool DecodeImportThunkTarget(void* exportStub, void** target) {
    auto* const bytes = static_cast<std::uint8_t*>(exportStub);
    if (bytes == nullptr || target == nullptr) {
        return false;
    }

    if (bytes[0] != 0x48 || bytes[1] != 0xFF || bytes[2] != 0x25) {
        return false;
    }

    std::int32_t displacement = 0;
    std::memcpy(&displacement, bytes + 3, sizeof(displacement));
    auto** const slot = reinterpret_cast<void**>(bytes + 7 + displacement);
    *target = *slot;
    return *target != nullptr;
}

bool WriteAbsoluteJump(void* address, const void* target) {
    if (address == nullptr || target == nullptr) {
        return false;
    }

    std::array<std::uint8_t, kAbsoluteJumpSize> patch = {
        0x48, 0xB8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0
    };

    const auto addressValue = reinterpret_cast<std::uint64_t>(target);
    std::memcpy(patch.data() + 2, &addressValue, sizeof(addressValue));

    DWORD oldProtect = 0;
    if (!::VirtualProtect(address, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    std::memcpy(address, patch.data(), patch.size());
    ::FlushInstructionCache(::GetCurrentProcess(), address, patch.size());
    ::VirtualProtect(address, patch.size(), oldProtect, &oldProtect);
    return true;
}

} // namespace

RegOpenKeyExWFn g_originalRegOpenKeyExW = ::RegOpenKeyExW;
RegQueryValueExWFn g_originalRegQueryValueExW = ::RegQueryValueExW;
RegCloseKeyFn g_originalRegCloseKey = ::RegCloseKey;

bool EqualsInsensitive(const wchar_t* left, const wchar_t* right) {
    return left != nullptr && right != nullptr && ::_wcsicmp(left, right) == 0;
}

bool StartsWithInsensitive(std::wstring_view value, std::wstring_view prefix) {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (::towlower(value[index]) != ::towlower(prefix[index])) {
            return false;
        }
    }

    return true;
}

FakeHandleKind GetFakeHandleKind(HKEY key) {
    switch (reinterpret_cast<ULONG_PTR>(key)) {
    case kFakeRegistryHandleSteam:
        return FakeHandleKind::Steam;
    case kFakeRegistryHandleSteamActiveProcess:
        return FakeHandleKind::SteamActiveProcess;
    case kFakeRegistryHandleOsi:
        return FakeHandleKind::Osi;
    case kFakeRegistryHandleBna:
        return FakeHandleKind::Bna;
    default:
        return FakeHandleKind::None;
    }
}

bool IsSteamHandle(FakeHandleKind kind) {
    return kind == FakeHandleKind::Steam || kind == FakeHandleKind::SteamActiveProcess;
}

bool IsBattleNetHandle(FakeHandleKind kind) {
    return kind == FakeHandleKind::Osi || kind == FakeHandleKind::Bna;
}

const char* FakeHandleName(FakeHandleKind kind) {
    switch (kind) {
    case FakeHandleKind::Steam:
        return "Steam";
    case FakeHandleKind::SteamActiveProcess:
        return "SteamActiveProcess";
    case FakeHandleKind::Osi:
        return "OSI";
    case FakeHandleKind::Bna:
        return "BNA";
    default:
        return "None";
    }
}

LSTATUS WriteRegistryString(LPCWSTR value, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    if (type != nullptr) {
        *type = REG_SZ;
    }

    const DWORD required = static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t));
    if (dataSize == nullptr) {
        return ERROR_SUCCESS;
    }

    if (data == nullptr || *dataSize < required) {
        *dataSize = required;
        return data == nullptr ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }

    std::memcpy(data, value, required);
    *dataSize = required;
    return ERROR_SUCCESS;
}

LSTATUS WriteRegistryDword(DWORD value, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    if (type != nullptr) {
        *type = REG_DWORD;
    }

    constexpr DWORD required = sizeof(DWORD);
    if (dataSize == nullptr) {
        return ERROR_SUCCESS;
    }

    if (data == nullptr || *dataSize < required) {
        *dataSize = required;
        return data == nullptr ? ERROR_SUCCESS : ERROR_MORE_DATA;
    }

    std::memcpy(data, &value, sizeof(value));
    *dataSize = required;
    return ERROR_SUCCESS;
}

template <typename FunctionPointer>
bool InstallExportHook(HMODULE module, const char* exportName, FunctionPointer hook, FunctionPointer& original) {
    void* const exportStub = reinterpret_cast<void*>(::GetProcAddress(module, exportName));
    if (exportStub == nullptr) {
        return false;
    }

    void* implementation = nullptr;
    if (!DecodeImportThunkTarget(exportStub, &implementation)) {
        return false;
    }

    original = reinterpret_cast<FunctionPointer>(implementation);
    return WriteAbsoluteJump(exportStub, reinterpret_cast<const void*>(hook));
}

bool InstallRegOpenKeyExWHook(HMODULE module) {
    return InstallExportHook(module, "RegOpenKeyExW", &HookedRegOpenKeyExW, g_originalRegOpenKeyExW);
}

bool InstallRegQueryValueExWHook(HMODULE module) {
    return InstallExportHook(module, "RegQueryValueExW", &HookedRegQueryValueExW, g_originalRegQueryValueExW);
}

bool InstallRegCloseKeyHook(HMODULE module) {
    return InstallExportHook(module, "RegCloseKey", &HookedRegCloseKey, g_originalRegCloseKey);
}

} // namespace d2r_offline
