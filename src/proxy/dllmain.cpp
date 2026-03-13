#include "../support/d2r_offline.hpp"

#include <mutex>
#include <sstream>

namespace d2r_offline {
namespace {

std::once_flag g_initializeOnce;

DWORD WINAPI DeferredInitWorker(LPVOID parameter) {
    (void)parameter;

    if (!WriteGeneratedCookie()) {
        Log("DeferredInitWorker: cookie generation failed");
        return 1;
    }
    return 0;
}

std::string NarrowOrPlaceholder(std::wstring_view value) {
    const auto utf8 = WideToUtf8(value);
    return utf8.empty() ? "<empty>" : utf8;
}

void LogConfiguration() {
    std::ostringstream message;
    message << "InitializeProxy: config"
            << " locale=" << NarrowOrPlaceholder(g_config.locale)
            << " localeAudio=" << NarrowOrPlaceholder(g_config.localeAudio)
            << " entitlements=" << NarrowOrPlaceholder(g_config.entitlements);
    Log(message.str());
}

} // namespace

void InitializeProxy() {
    std::call_once(g_initializeOnce, [] {
        g_moduleDirectory = GetSelfPath().parent_path();
        InitializeLogger(g_moduleDirectory / kLogFileName);
        Log("InitializeProxy: begin");

        g_config = LoadConfig();
        LogConfiguration();

        if (!LoadForwarders()) {
            Log("InitializeProxy: LoadForwarders failed");
            return;
        }

        if (!SpoofModuleIdentity()) {
            Log("InitializeProxy: module identity spoof not applied");
        }

        PublishSteamEnvironment();
        InstallRegistryHooks();

        if (!PatchMainModulePublicKey()) {
            Log("InitializeProxy: public key patch not applied");
        }

        HANDLE worker = ::CreateThread(nullptr, 0, &DeferredInitWorker, nullptr, 0, nullptr);
        if (worker == nullptr) {
            Log("InitializeProxy: CreateThread failed, running deferred init inline");
            if (!WriteGeneratedCookie()) {
                Log("InitializeProxy: cookie generation failed");
                return;
            }
        } else {
            ::CloseHandle(worker);
        }

        Log("InitializeProxy: ready");
    });
}

} // namespace d2r_offline

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        ::DisableThreadLibraryCalls(module);
        d2r_offline::InitializeProxy();
    } else if (reason == DLL_PROCESS_DETACH) {
        d2r_offline::ShutdownLogger();
    }

    return TRUE;
}
