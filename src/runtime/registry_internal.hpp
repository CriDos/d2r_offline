#pragma once

#include "../support/d2r_offline.hpp"

#include <span>

namespace d2r_offline {

using RegOpenKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegQueryValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegCloseKeyFn = LSTATUS(WINAPI*)(HKEY);

extern RegOpenKeyExWFn g_originalRegOpenKeyExW;
extern RegQueryValueExWFn g_originalRegQueryValueExW;
extern RegCloseKeyFn g_originalRegCloseKey;

enum class FakeHandleKind {
    None,
    Steam,
    SteamActiveProcess,
    Osi,
    Bna,
};

enum class ValueSource {
    Literal,
    ModuleRelativePath,
    ModuleRoot,
    Locale,
    LocaleAudio,
    ProcessId,
};

struct OpenKeySpec {
    const wchar_t* subKey;
    ULONG_PTR fakeHandle;
};

struct QueryValueSpec {
    const wchar_t* valueName;
    ValueSource source;
    const wchar_t* payload;
};

bool EqualsInsensitive(const wchar_t* left, const wchar_t* right);
bool StartsWithInsensitive(std::wstring_view value, std::wstring_view prefix);

FakeHandleKind GetFakeHandleKind(HKEY key);
bool IsSteamHandle(FakeHandleKind kind);
bool IsBattleNetHandle(FakeHandleKind kind);
const char* FakeHandleName(FakeHandleKind kind);

LSTATUS WriteRegistryString(LPCWSTR value, LPDWORD type, LPBYTE data, LPDWORD dataSize);
LSTATUS WriteRegistryDword(DWORD value, LPDWORD type, LPBYTE data, LPDWORD dataSize);

bool InstallRegOpenKeyExWHook(HMODULE module);
bool InstallRegQueryValueExWHook(HMODULE module);
bool InstallRegCloseKeyHook(HMODULE module);

LSTATUS WINAPI HookedRegOpenKeyExW(HKEY key, LPCWSTR subKey, DWORD options, REGSAM samDesired, PHKEY result);
LSTATUS WINAPI HookedRegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize);
LSTATUS WINAPI HookedRegCloseKey(HKEY key);

} // namespace d2r_offline
