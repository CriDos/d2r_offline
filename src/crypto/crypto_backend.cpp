#include "../support/d2r_offline.hpp"
#include "crypto_support.hpp"

#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

#include <array>
#include <optional>
#include <sstream>

namespace d2r_offline::crypto {
namespace {

struct CryptoState {
    BCRYPT_ALG_HANDLE sha1 = nullptr;
    BCRYPT_ALG_HANDLE sha512 = nullptr;
    BCRYPT_ALG_HANDLE sha512Hmac = nullptr;
    NCRYPT_PROV_HANDLE keyStorage = 0;
    bool initialized = false;
};

CryptoState g_crypto{};

std::string FormatStatusHex(long status) {
    std::ostringstream message;
    message << "0x" << std::hex << std::uppercase << static_cast<unsigned long>(status);
    return message.str();
}

bool EnsureAlgorithmHandle(
    BCRYPT_ALG_HANDLE& handle,
    const wchar_t* algorithmName,
    ULONG flags,
    const char* label) {
    if (handle != nullptr) {
        return true;
    }

    const NTSTATUS status = ::BCryptOpenAlgorithmProvider(&handle, algorithmName, nullptr, flags);
    if (status < 0 || handle == nullptr) {
        Log(std::string("crypto: BCryptOpenAlgorithmProvider failed for ") + label + " status=" + FormatStatusHex(status));
        return false;
    }

    return true;
}

bool EnsureStorageProvider() {
    if (g_crypto.keyStorage != 0) {
        return true;
    }

    const SECURITY_STATUS status = ::NCryptOpenStorageProvider(
        &g_crypto.keyStorage,
        MS_KEY_STORAGE_PROVIDER,
        0);
    if (status != ERROR_SUCCESS || g_crypto.keyStorage == 0) {
        Log(std::string("crypto: NCryptOpenStorageProvider failed status=") + FormatStatusHex(status));
        return false;
    }

    return true;
}

std::optional<DWORD> QueryBcryptDwordProperty(BCRYPT_ALG_HANDLE handle, const wchar_t* propertyName) {
    DWORD value = 0;
    DWORD bytesWritten = 0;
    const NTSTATUS status = ::BCryptGetProperty(
        handle,
        propertyName,
        reinterpret_cast<PUCHAR>(&value),
        sizeof(value),
        &bytesWritten,
        0);
    if (status < 0 || bytesWritten != sizeof(value)) {
        Log(std::string("crypto: BCryptGetProperty failed for ") + WideToUtf8(propertyName) + " status=" + FormatStatusHex(status));
        return std::nullopt;
    }

    return value;
}

std::optional<std::vector<std::uint8_t>> HashBuffer(
    BCRYPT_ALG_HANDLE algorithm,
    std::span<const std::uint8_t> data,
    std::span<const std::uint8_t> secret = {}) {
    const auto objectLength = QueryBcryptDwordProperty(algorithm, BCRYPT_OBJECT_LENGTH);
    const auto hashLength = QueryBcryptDwordProperty(algorithm, BCRYPT_HASH_LENGTH);
    if (!objectLength.has_value() || !hashLength.has_value()) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> hashObject(*objectLength);
    BCRYPT_HASH_HANDLE hash = nullptr;
    const NTSTATUS createStatus = ::BCryptCreateHash(
        algorithm,
        &hash,
        hashObject.data(),
        static_cast<ULONG>(hashObject.size()),
        secret.empty() ? nullptr : const_cast<PUCHAR>(secret.data()),
        static_cast<ULONG>(secret.size()),
        0);
    if (createStatus < 0 || hash == nullptr) {
        Log(std::string("crypto: BCryptCreateHash failed status=") + FormatStatusHex(createStatus));
        return std::nullopt;
    }

    std::optional<std::vector<std::uint8_t>> result;
    do {
        const NTSTATUS hashStatus = ::BCryptHashData(
            hash,
            data.empty() ? nullptr : const_cast<PUCHAR>(data.data()),
            static_cast<ULONG>(data.size()),
            0);
        if (hashStatus < 0) {
            Log(std::string("crypto: BCryptHashData failed status=") + FormatStatusHex(hashStatus));
            break;
        }

        std::vector<std::uint8_t> digest(*hashLength);
        const NTSTATUS finishStatus = ::BCryptFinishHash(
            hash,
            digest.data(),
            static_cast<ULONG>(digest.size()),
            0);
        if (finishStatus < 0) {
            Log(std::string("crypto: BCryptFinishHash failed status=") + FormatStatusHex(finishStatus));
            break;
        }

        result = std::move(digest);
    } while (false);

    ::BCryptDestroyHash(hash);
    return result;
}

std::optional<std::vector<std::uint8_t>> DecodePemPkcs8(std::string_view pem) {
    DWORD derSize = 0;
    if (!::CryptStringToBinaryA(
            pem.data(),
            static_cast<DWORD>(pem.size()),
            CRYPT_STRING_BASE64HEADER,
            nullptr,
            &derSize,
            nullptr,
            nullptr) ||
        derSize == 0) {
        Log(std::string("crypto: CryptStringToBinaryA size probe failed error=") + std::to_string(::GetLastError()));
        return std::nullopt;
    }

    std::vector<std::uint8_t> der(derSize);
    if (!::CryptStringToBinaryA(
            pem.data(),
            static_cast<DWORD>(pem.size()),
            CRYPT_STRING_BASE64HEADER,
            der.data(),
            &derSize,
            nullptr,
            nullptr)) {
        Log(std::string("crypto: CryptStringToBinaryA decode failed error=") + std::to_string(::GetLastError()));
        return std::nullopt;
    }

    der.resize(derSize);
    return der;
}

std::optional<DWORD> QueryNcryptDwordProperty(NCRYPT_HANDLE handle, const wchar_t* propertyName) {
    DWORD value = 0;
    DWORD bytesWritten = 0;
    const SECURITY_STATUS status = ::NCryptGetProperty(
        handle,
        propertyName,
        reinterpret_cast<PBYTE>(&value),
        sizeof(value),
        &bytesWritten,
        0);
    if (status != ERROR_SUCCESS || bytesWritten != sizeof(value)) {
        Log(std::string("crypto: NCryptGetProperty failed for ") + WideToUtf8(propertyName) + " status=" + FormatStatusHex(status));
        return std::nullopt;
    }

    return value;
}

struct Sha224State {
    std::array<std::uint32_t, 8> h = {
        0xc1059ed8U, 0x367cd507U, 0x3070dd17U, 0xf70e5939U,
        0xffc00b31U, 0x68581511U, 0x64f98fa7U, 0xbefa4fa4U
    };
    std::array<std::uint8_t, 64> buffer{};
    std::uint64_t totalSize = 0;
    std::size_t buffered = 0;
};

constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

constexpr std::uint32_t RotateRight(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32U - bits));
}

void Sha224Transform(Sha224State& state, const std::uint8_t block[64]) {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] =
            (static_cast<std::uint32_t>(block[i * 4]) << 24U) |
            (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16U) |
            (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8U) |
            (static_cast<std::uint32_t>(block[i * 4 + 3]));
    }

    for (std::size_t i = 16; i < w.size(); ++i) {
        const std::uint32_t s0 = RotateRight(w[i - 15], 7) ^ RotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3U);
        const std::uint32_t s1 = RotateRight(w[i - 2], 17) ^ RotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10U);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state.h[0];
    std::uint32_t b = state.h[1];
    std::uint32_t c = state.h[2];
    std::uint32_t d = state.h[3];
    std::uint32_t e = state.h[4];
    std::uint32_t f = state.h[5];
    std::uint32_t g = state.h[6];
    std::uint32_t h = state.h[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
        const std::uint32_t choose = (e & f) ^ (~e & g);
        const std::uint32_t temp1 = h + s1 + choose + kSha256RoundConstants[i] + w[i];
        const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state.h[0] += a;
    state.h[1] += b;
    state.h[2] += c;
    state.h[3] += d;
    state.h[4] += e;
    state.h[5] += f;
    state.h[6] += g;
    state.h[7] += h;
}

void Sha224Update(Sha224State& state, std::span<const std::uint8_t> data) {
    state.totalSize += data.size();

    std::size_t offset = 0;
    while (offset < data.size()) {
        const std::size_t chunk = std::min<std::size_t>(state.buffer.size() - state.buffered, data.size() - offset);
        std::memcpy(state.buffer.data() + state.buffered, data.data() + offset, chunk);
        state.buffered += chunk;
        offset += chunk;

        if (state.buffered == state.buffer.size()) {
            Sha224Transform(state, state.buffer.data());
            state.buffered = 0;
        }
    }
}

std::array<std::uint8_t, 28> Sha224Final(Sha224State& state) {
    const std::uint64_t bitLength = state.totalSize * 8ULL;

    state.buffer[state.buffered++] = 0x80;
    if (state.buffered > 56) {
        std::fill(state.buffer.begin() + state.buffered, state.buffer.end(), static_cast<std::uint8_t>(0));
        Sha224Transform(state, state.buffer.data());
        state.buffered = 0;
    }

    std::fill(state.buffer.begin() + state.buffered, state.buffer.begin() + 56, static_cast<std::uint8_t>(0));
    for (std::size_t i = 0; i < 8; ++i) {
        state.buffer[56 + i] = static_cast<std::uint8_t>(bitLength >> ((7 - i) * 8U));
    }
    Sha224Transform(state, state.buffer.data());

    std::array<std::uint8_t, 28> digest{};
    for (std::size_t i = 0; i < 7; ++i) {
        digest[i * 4] = static_cast<std::uint8_t>(state.h[i] >> 24U);
        digest[i * 4 + 1] = static_cast<std::uint8_t>(state.h[i] >> 16U);
        digest[i * 4 + 2] = static_cast<std::uint8_t>(state.h[i] >> 8U);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(state.h[i]);
    }
    return digest;
}

std::array<std::uint8_t, 28> ComputeSha224Digest(std::span<const std::uint8_t> data) {
    Sha224State state;
    Sha224Update(state, data);
    return Sha224Final(state);
}

} // namespace

bool EnsureCryptoBackendInitialized() {
    if (g_crypto.initialized) {
        return true;
    }

    if (!EnsureAlgorithmHandle(g_crypto.sha1, BCRYPT_SHA1_ALGORITHM, 0, "SHA1") ||
        !EnsureAlgorithmHandle(g_crypto.sha512, BCRYPT_SHA512_ALGORITHM, 0, "SHA512") ||
        !EnsureAlgorithmHandle(g_crypto.sha512Hmac, BCRYPT_SHA512_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG, "SHA512-HMAC") ||
        !EnsureStorageProvider()) {
        return false;
    }

    g_crypto.initialized = true;
    Log("crypto: using Windows CNG/CryptoAPI backend");
    return true;
}

std::optional<std::vector<std::uint8_t>> ComputeSha1(std::string_view text) {
    if (!EnsureCryptoBackendInitialized()) {
        return std::nullopt;
    }

    return HashBuffer(
        g_crypto.sha1,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

std::optional<std::array<std::uint8_t, 80>> DerivePbkdf2Sha512(
    std::string_view password,
    std::span<const std::uint8_t> salt) {
    if (!EnsureCryptoBackendInitialized()) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 80> derived{};
    const NTSTATUS status = ::BCryptDeriveKeyPBKDF2(
        g_crypto.sha512Hmac,
        reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
        static_cast<ULONG>(password.size()),
        const_cast<PUCHAR>(salt.data()),
        static_cast<ULONG>(salt.size()),
        0x2000,
        derived.data(),
        static_cast<ULONG>(derived.size()),
        0);
    if (status < 0) {
        Log(std::string("crypto: BCryptDeriveKeyPBKDF2 failed status=") + FormatStatusHex(status));
        return std::nullopt;
    }

    return derived;
}

std::optional<std::array<std::uint8_t, 64>> ComputeHmacSha512(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> data) {
    if (!EnsureCryptoBackendInitialized()) {
        return std::nullopt;
    }

    const auto digest = HashBuffer(g_crypto.sha512Hmac, data, key);
    if (!digest.has_value() || digest->size() != 64) {
        Log("crypto: HMAC-SHA512 failed");
        return std::nullopt;
    }

    std::array<std::uint8_t, 64> result{};
    std::memcpy(result.data(), digest->data(), result.size());
    return result;
}

std::optional<std::vector<std::uint8_t>> SignSha224(
    std::string_view data,
    std::string_view privateKeyPem) {
    if (!EnsureCryptoBackendInitialized()) {
        return std::nullopt;
    }

    const auto der = DecodePemPkcs8(privateKeyPem);
    if (!der.has_value()) {
        return std::nullopt;
    }

    NCRYPT_KEY_HANDLE key = 0;
    const SECURITY_STATUS importStatus = ::NCryptImportKey(
        g_crypto.keyStorage,
        0,
        NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
        nullptr,
        &key,
        const_cast<PBYTE>(der->data()),
        static_cast<DWORD>(der->size()),
        0);
    if (importStatus != ERROR_SUCCESS || key == 0) {
        Log(std::string("crypto: NCryptImportKey failed status=") + FormatStatusHex(importStatus));
        return std::nullopt;
    }

    const auto digest = ComputeSha224Digest(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));

    const auto keyBits = QueryNcryptDwordProperty(key, NCRYPT_LENGTH_PROPERTY);
    if (!keyBits.has_value() || *keyBits == 0 || (*keyBits % 8) != 0) {
        ::NCryptFreeObject(key);
        Log("crypto: invalid RSA key length");
        return std::nullopt;
    }

    const DWORD signatureSize = *keyBits / 8;
    if (signatureSize < digest.size()) {
        ::NCryptFreeObject(key);
        Log("crypto: RSA modulus too small for EMSA1(SHA-224)");
        return std::nullopt;
    }

    // Botan requests EMSA1(SHA-224), not PKCS#1 v1.5 DigestInfo wrapping.
    // For RSA this means signing the hash value as a raw big-endian integer,
    // left-padded to the modulus width before the private operation.
    std::vector<std::uint8_t> encoded(signatureSize, 0x00);
    std::memcpy(
        encoded.data() + (signatureSize - digest.size()),
        digest.data(),
        digest.size());

    DWORD written = 0;
    std::vector<std::uint8_t> signature(signatureSize);
    const SECURITY_STATUS signStatus = ::NCryptDecrypt(
        key,
        encoded.data(),
        static_cast<DWORD>(encoded.size()),
        nullptr,
        signature.data(),
        static_cast<DWORD>(signature.size()),
        &written,
        NCRYPT_NO_PADDING_FLAG);
    ::NCryptFreeObject(key);
    if (signStatus != ERROR_SUCCESS) {
        Log(std::string("crypto: NCryptDecrypt(raw RSA sign) failed status=") + FormatStatusHex(signStatus));
        return std::nullopt;
    }

    signature.resize(written);
    return signature;
}

} // namespace d2r_offline::crypto
