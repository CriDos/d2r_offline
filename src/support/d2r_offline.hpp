#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace d2r_offline {

inline constexpr char kProjectName[] = "d2r_offline";
inline constexpr char kProjectVersion[] = "1.0";
inline constexpr wchar_t kSettingsSection[] = L"Settings";
inline constexpr wchar_t kConfigFileName[] = L"d2r_offline.ini";
inline constexpr wchar_t kLogFileName[] = L"d2r_offline.log";
inline constexpr wchar_t kDefaultLocaleName[] = L"english";
inline constexpr wchar_t kDefaultLocaleAudioName[] = L"english";
inline constexpr wchar_t kDefaultEntitlementsCsv[] = L"hd,beta,rotw-dlc";
inline constexpr wchar_t kSteamGameId[] = L"2536520";
inline constexpr std::uint64_t kDefaultAccountId = 0x666ULL;
inline constexpr std::uint64_t kDefaultUserId = 0x667ULL;
inline constexpr std::uint32_t kDefaultGameId = 5198665U;
inline constexpr wchar_t kDefaultRegion[] = L"US";
inline constexpr wchar_t kDefaultConnectionStringUs[] = L"0.0.0.0";
inline constexpr wchar_t kDefaultWebToken[] = L"offline-web-token";
inline constexpr ULONG_PTR kFakeRegistryHandleSteam = 0x1337;
inline constexpr ULONG_PTR kFakeRegistryHandleSteamActiveProcess = 0x1338;
inline constexpr ULONG_PTR kFakeRegistryHandleOsi = 0x1339;
inline constexpr ULONG_PTR kFakeRegistryHandleBna = 0x133a;

struct Config {
    std::wstring locale = kDefaultLocaleName;
    std::wstring localeAudio = kDefaultLocaleAudioName;
    std::wstring entitlements = kDefaultEntitlementsCsv;
};

struct CookieEntry {
    std::string typeUrl;
    std::string bodyBase64;
    std::vector<std::uint8_t> signature;
    std::uint32_t gameId = kDefaultGameId;
};

extern HMODULE g_realWinHttp;
extern Config g_config;
extern std::filesystem::path g_moduleDirectory;

std::wstring GetModulePath(HMODULE module);
std::filesystem::path GetSelfPath();
std::string WideToUtf8(std::wstring_view value);
Config LoadConfig();
bool FillRandomBytes(std::uint8_t* data, std::size_t size);

void InitializeLogger(const std::filesystem::path& logPath);
void ShutdownLogger();
void Log(std::string_view message);

bool LoadForwarders();
void PublishSteamEnvironment();

bool SpoofModuleIdentity();
void InstallRegistryHooks();
bool PatchMainModulePublicKey();
bool WriteGeneratedCookie();
void InitializeProxy();

} // namespace d2r_offline

extern "C" {
#define X(name, ordinal) extern void* g_forward_##name;
#include "../exports/exports.inc"
#undef X
}
