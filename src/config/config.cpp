#include "../support/d2r_offline.hpp"

namespace d2r_offline {
namespace {

std::wstring ToLowerAscii(std::wstring_view value) {
    std::wstring lowered;
    lowered.reserve(value.size());
    for (wchar_t ch : value) {
        lowered.push_back(static_cast<wchar_t>(::towlower(ch)));
    }
    return lowered;
}

std::wstring NormalizeLocaleValue(std::wstring_view value) {
    if (value.empty()) {
        return L"enUS";
    }

    if (value.size() == 4) {
        return std::wstring(value);
    }

    static constexpr std::pair<std::wstring_view, std::wstring_view> kLocaleMap[] = {
        {L"english", L"enUS"},
        {L"german", L"deDE"},
        {L"spanish", L"esES"},
        {L"latam", L"esMX"},
        {L"french", L"frFR"},
        {L"italian", L"itIT"},
        {L"koreana", L"koKR"},
        {L"korean", L"koKR"},
        {L"polish", L"plPL"},
        {L"brazilian", L"ptBR"},
        {L"portuguese", L"ptPT"},
        {L"russian", L"ruRU"},
        {L"tchinese", L"zhTW"},
        {L"schinese", L"zhCN"},
        {L"japanese", L"jaJP"},
    };

    const std::wstring lowered = ToLowerAscii(value);
    for (const auto& [source, target] : kLocaleMap) {
        if (lowered == source) {
            return std::wstring(target);
        }
    }

    return L"enUS";
}

std::string BuildDefaultConfigText() {
    const Config defaults;
    return
        std::string("### The offline license is stored at: %LocalAppData%\\Blizzard Entertainment\\ClientSdk\\cookie.bin\r\n")
        + "###\r\n"
        + "[Settings]\r\n"
        + "###\r\n"
        + "### The main language that will be used in the game\r\n"
        + "###\r\n"
        + "Locale=" + WideToUtf8(defaults.locale) + "\r\n"
        + "###\r\n"
        + "### The audio language that will be used in the game\r\n"
        + "###\r\n"
        + "LocaleAudio=" + WideToUtf8(defaults.localeAudio) + "\r\n"
        + "###\r\n"
        + "### The game entitlements, separated by comma\r\n"
        + "###\r\n"
        + "Entitlements=" + WideToUtf8(defaults.entitlements) + "\r\n"
        + "###\r\n";
}

bool WriteDefaultConfigFile(const std::filesystem::path& path) {
    std::error_code ec;
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return false;
        }
    }

    const HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    const auto content = BuildDefaultConfigText();
    DWORD written = 0;
    const BOOL ok = ::WriteFile(
        file,
        content.data(),
        static_cast<DWORD>(content.size()),
        &written,
        nullptr);
    ::CloseHandle(file);
    return ok != FALSE && written == content.size();
}

std::wstring ReadIniString(const std::filesystem::path& path, const wchar_t* key, const wchar_t* fallback) {
    std::wstring buffer(4096, L'\0');
    const DWORD written = ::GetPrivateProfileStringW(
        kSettingsSection,
        key,
        fallback,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        path.c_str());
    buffer.resize(written);
    return buffer;
}

} // namespace

Config g_config{};

Config LoadConfig() {
    Config config{};
    const std::filesystem::path configPath = g_moduleDirectory / kConfigFileName;

    if (!std::filesystem::exists(configPath)) {
        if (WriteDefaultConfigFile(configPath)) {
            Log(std::string("LoadConfig: generated default english config at ") + WideToUtf8(configPath.wstring()));
        } else {
            Log("LoadConfig: config file not found and default generation failed, using in-memory defaults");
            return config;
        }
    }

    config.locale = ReadIniString(configPath, L"Locale", config.locale.c_str());
    config.localeAudio = ReadIniString(configPath, L"LocaleAudio", config.localeAudio.c_str());
    config.entitlements = ReadIniString(configPath, L"Entitlements", config.entitlements.c_str());
    config.locale = NormalizeLocaleValue(config.locale);
    config.localeAudio = NormalizeLocaleValue(config.localeAudio);
    Log(std::string("LoadConfig: using ") + WideToUtf8(configPath.wstring()));
    return config;
}

} // namespace d2r_offline
