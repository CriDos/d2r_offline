#include "../support/d2r_offline.hpp"

#include <intrin.h>
#include <sstream>

namespace d2r_offline {
namespace {

struct UnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct LdrDataTableEntry {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UnicodeString FullDllName;
    UnicodeString BaseDllName;
};

struct PebLdrData {
    ULONG Length;
    BOOLEAN Initialized;
    void* SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
};

struct Peb {
    std::uint8_t Reserved1[0x18];
    PebLdrData* Ldr;
};

std::wstring g_spoofedFullDllName;
std::wstring g_spoofedBaseDllName;

Peb* CurrentPeb() {
#if defined(_M_X64)
    return reinterpret_cast<Peb*>(__readgsqword(0x60));
#else
    return nullptr;
#endif
}

bool UpdateUnicodeString(UnicodeString& target, std::wstring& storage) {
    if (storage.empty() || storage.size() > 0x7fff) {
        return false;
    }

    target.Buffer = storage.data();
    target.Length = static_cast<USHORT>(storage.size() * sizeof(wchar_t));
    target.MaximumLength = static_cast<USHORT>((storage.size() + 1) * sizeof(wchar_t));
    return true;
}

} // namespace

bool SpoofModuleIdentity() {
    if (g_realWinHttp == nullptr) {
        Log("SpoofModuleIdentity: real winhttp not loaded");
        return false;
    }

    Peb* const peb = CurrentPeb();
    if (peb == nullptr || peb->Ldr == nullptr) {
        Log("SpoofModuleIdentity: PEB/Ldr unavailable");
        return false;
    }

    HMODULE selfModule = reinterpret_cast<HMODULE>(&__ImageBase);
    const std::wstring realWinHttpPath = GetModulePath(g_realWinHttp);
    if (realWinHttpPath.empty()) {
        Log("SpoofModuleIdentity: real winhttp path unavailable");
        return false;
    }

    g_spoofedFullDllName = realWinHttpPath;
    g_spoofedBaseDllName = std::filesystem::path(realWinHttpPath).filename().wstring();
    if (g_spoofedBaseDllName.empty()) {
        g_spoofedBaseDllName = L"winhttp.dll";
    }

    LIST_ENTRY* const head = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* entry = head->Flink; entry != head; entry = entry->Flink) {
        auto* loaderEntry = CONTAINING_RECORD(entry, LdrDataTableEntry, InLoadOrderLinks);
        if (loaderEntry == nullptr || loaderEntry->DllBase != selfModule) {
            continue;
        }

        if (!UpdateUnicodeString(loaderEntry->FullDllName, g_spoofedFullDllName) ||
            !UpdateUnicodeString(loaderEntry->BaseDllName, g_spoofedBaseDllName)) {
            Log("SpoofModuleIdentity: failed to update UNICODE_STRING");
            return false;
        }

        std::ostringstream message;
        message << "SpoofModuleIdentity: patched FullDllName=" << WideToUtf8(g_spoofedFullDllName);
        Log(message.str());
        return true;
    }

    Log("SpoofModuleIdentity: loader entry not found");
    return false;
}

} // namespace d2r_offline
