#include "../support/d2r_offline.hpp"
#include "../support/key_material.hpp"

#include <cstring>

namespace d2r_offline {

bool PatchMainModulePublicKey() {
    auto* const moduleBase = reinterpret_cast<std::uint8_t*>(::GetModuleHandleW(nullptr));
    if (moduleBase == nullptr) {
        Log("PatchMainModulePublicKey: no main module");
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        Log("PatchMainModulePublicKey: invalid DOS header");
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        Log("PatchMainModulePublicKey: invalid NT header");
        return false;
    }

    const std::size_t imageSize = nt->OptionalHeader.SizeOfImage;
    const std::string_view originalKey = OriginalPublicKeyPem();
    const std::string_view replacementKey = ReplacementPublicKeyPem();
    if (replacementKey.size() > originalKey.size()) {
        Log("PatchMainModulePublicKey: replacement key is too large");
        return false;
    }

    for (std::size_t offset = 0; offset + originalKey.size() <= imageSize; ++offset) {
        if (std::memcmp(moduleBase + offset, originalKey.data(), originalKey.size()) != 0) {
            continue;
        }

        DWORD oldProtect = 0;
        if (!::VirtualProtect(moduleBase + offset, replacementKey.size(), PAGE_READWRITE, &oldProtect)) {
            Log("PatchMainModulePublicKey: VirtualProtect failed");
            return false;
        }

        std::memcpy(moduleBase + offset, replacementKey.data(), replacementKey.size());
        ::VirtualProtect(moduleBase + offset, replacementKey.size(), oldProtect, &oldProtect);
        ::FlushInstructionCache(::GetCurrentProcess(), moduleBase + offset, replacementKey.size());
        Log("PatchMainModulePublicKey: patched");
        return true;
    }

    Log("PatchMainModulePublicKey: original key not found");
    return false;
}

} // namespace d2r_offline
