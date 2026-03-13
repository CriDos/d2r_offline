#include "registry_internal.hpp"

#include <sstream>

namespace d2r_offline {

void InstallRegistryHooks() {
    HMODULE advapi32 = ::GetModuleHandleW(L"advapi32.dll");
    if (advapi32 == nullptr) {
        Log("InstallRegistryHooks: advapi32 not loaded");
        return;
    }

    int installedHooks = 0;
    if (InstallRegOpenKeyExWHook(advapi32)) {
        ++installedHooks;
    }
    if (InstallRegQueryValueExWHook(advapi32)) {
        ++installedHooks;
    }
    if (InstallRegCloseKeyHook(advapi32)) {
        ++installedHooks;
    }

    std::ostringstream message;
    message << "InstallRegistryHooks: installedHooks=" << installedHooks;
    Log(message.str());
}

} // namespace d2r_offline
