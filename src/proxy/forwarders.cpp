#include "../support/d2r_offline.hpp"

namespace d2r_offline {

HMODULE g_realWinHttp = nullptr;

extern "C" {
#define X(name, ordinal) void* g_forward_##name = nullptr;
#include "../exports/exports.inc"
#undef X
}

bool LoadForwarders() {
    wchar_t systemDirectory[MAX_PATH] = {};
    if (::GetSystemDirectoryW(systemDirectory, MAX_PATH) == 0) {
        Log("LoadForwarders: GetSystemDirectoryW failed");
        return false;
    }

    const std::filesystem::path realDll = std::filesystem::path(systemDirectory) / L"winhttp.dll";
    g_realWinHttp = ::LoadLibraryW(realDll.c_str());
    if (g_realWinHttp == nullptr) {
        Log("LoadForwarders: LoadLibraryW failed");
        return false;
    }

#define X(name, ordinal)                                                                                              \
    g_forward_##name = reinterpret_cast<void*>(::GetProcAddress(g_realWinHttp, #name));                              \
    if (g_forward_##name == nullptr) {                                                                                \
        Log("LoadForwarders: missing export " #name);                                                                 \
        return false;                                                                                                 \
    }
#include "../exports/exports.inc"
#undef X

    Log("LoadForwarders: resolved all exports");
    return true;
}

void PublishSteamEnvironment() {
    ::SetEnvironmentVariableW(L"SteamAppId", kSteamGameId);
    ::SetEnvironmentVariableW(L"SteamGameId", kSteamGameId);
    ::SetEnvironmentVariableW(L"SteamOverlayGameId", kSteamGameId);
}

} // namespace d2r_offline
