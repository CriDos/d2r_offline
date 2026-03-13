#include "d2r_offline.hpp"

#include <array>
#include <cstdio>

namespace d2r_offline {
namespace {

SRWLOCK g_logLock = SRWLOCK_INIT;
HANDLE g_logFile = INVALID_HANDLE_VALUE;

void WriteRaw(std::string_view text) {
    if (g_logFile == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written = 0;
    ::WriteFile(g_logFile, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
}

std::string BuildPrefix() {
    SYSTEMTIME localTime{};
    ::GetLocalTime(&localTime);

    std::array<char, 64> buffer{};
    const int written = std::snprintf(
        buffer.data(),
        buffer.size(),
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
        static_cast<unsigned>(localTime.wYear),
        static_cast<unsigned>(localTime.wMonth),
        static_cast<unsigned>(localTime.wDay),
        static_cast<unsigned>(localTime.wHour),
        static_cast<unsigned>(localTime.wMinute),
        static_cast<unsigned>(localTime.wSecond),
        static_cast<unsigned>(localTime.wMilliseconds));
    return written > 0 ? std::string(buffer.data(), static_cast<std::size_t>(written)) : std::string{};
}

} // namespace

void InitializeLogger(const std::filesystem::path& logPath) {
    ::AcquireSRWLockExclusive(&g_logLock);

    if (g_logFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }

    std::error_code ec;
    std::filesystem::create_directories(logPath.parent_path(), ec);

    g_logFile = ::CreateFileW(
        logPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (g_logFile != INVALID_HANDLE_VALUE) {
        std::string banner = kProjectName;
        banner.push_back(' ');
        banner.append(kProjectVersion);
        banner.append(" log started\r\n");

        WriteRaw(BuildPrefix());
        WriteRaw(banner);
    }

    ::ReleaseSRWLockExclusive(&g_logLock);
}

void ShutdownLogger() {
    ::AcquireSRWLockExclusive(&g_logLock);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
    ::ReleaseSRWLockExclusive(&g_logLock);
}

void Log(std::string_view message) {
    ::AcquireSRWLockExclusive(&g_logLock);
    if (g_logFile == INVALID_HANDLE_VALUE) {
        ::ReleaseSRWLockExclusive(&g_logLock);
        return;
    }

    WriteRaw(BuildPrefix());
    WriteRaw(message);
    WriteRaw("\r\n");
    ::ReleaseSRWLockExclusive(&g_logLock);
}

} // namespace d2r_offline
