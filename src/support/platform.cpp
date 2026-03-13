#include "d2r_offline.hpp"

namespace d2r_offline {
namespace {

extern "C" BOOLEAN NTAPI SystemFunction036(PVOID randomBuffer, ULONG randomBufferLength);

} // namespace

std::filesystem::path g_moduleDirectory;

std::wstring GetModulePath(HMODULE module) {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD written = ::GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (written == 0) {
            return {};
        }
        if (written < buffer.size() - 1) {
            buffer.resize(written);
            return buffer;
        }
        buffer.resize(buffer.size() * 2);
    }
}

std::filesystem::path GetSelfPath() {
    return std::filesystem::path(GetModulePath(reinterpret_cast<HMODULE>(&__ImageBase)));
}

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }

    const int bytes = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (bytes <= 0) {
        return {};
    }

    std::string out(bytes, '\0');
    ::WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        out.data(),
        bytes,
        nullptr,
        nullptr);
    return out;
}

bool FillRandomBytes(std::uint8_t* data, std::size_t size) {
    return SystemFunction036(data, static_cast<ULONG>(size)) != FALSE;
}

} // namespace d2r_offline
