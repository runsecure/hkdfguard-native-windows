#include "aes_gcm.h"
#include "hkdf_errors.h"
#include "handle_traits.h" // ScopedBCryptAlg, ScopedBCryptKey
#include <windows.h>
#include <bcrypt.h>
#include <utility> // std::in_range

namespace hkdfguard {
    namespace {
        // The NTSTATUS CNG returns when AES-GCM tag verification fails. It is
        // declared in ntstatus.h, which conflicts with windows.h unless
        // included carefully, so it is defined here.
        constexpr NTSTATUS kStatusAuthTagMismatch = static_cast<NTSTATUS>(0xC000A002L);

        // A CNG AES-GCM key together with the provider it was created from.
        // Members are destroyed in reverse declaration order, so `key` is
        // always released before `alg`, which it must not outlive.
        struct AesKey {
            ScopedBCryptAlg alg;
            ScopedBCryptKey key;
        };

        // CNG takes ULONG lengths; spans carry size_t. Rejects (rather than
        // truncates) a length that does not fit.
        [[nodiscard]] ULONG ToUlong(std::size_t n) {
            if (!std::in_range<ULONG>(n)) {
                throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "AES-GCM buffer too large for CNG");
            }
            return static_cast<ULONG>(n);
        }

        // Builds a CNG AES-GCM key object from raw key bytes.
        [[nodiscard]] AesKey OpenAesKey(std::span<const std::uint8_t, kAesKeyLen> key) {
            AesKey aes;
            if (const NTSTATUS status = BCryptOpenAlgorithmProvider(aes.alg.put(), BCRYPT_AES_ALGORITHM, nullptr, 0);
                !BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptOpenAlgorithmProvider(AES) failed");
            }

            // CNG's AES provider is not in GCM mode by default; select it.
            if (const NTSTATUS status = BCryptSetProperty(
                    aes.alg.get(), BCRYPT_CHAINING_MODE,
                    // CNG only reads this value; the casts satisfy the PUCHAR
                    // parameter type.
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                    sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
                !BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptSetProperty(GCM) failed");
            }

            // CNG copies the wrapping key into its own key object - the one
            // copy this code does not control. ScopedBCryptKey ensures
            // BCryptDestroyKey releases it as soon as it is no longer needed.
            if (const NTSTATUS status = BCryptGenerateSymmetricKey(
                    aes.alg.get(), aes.key.put(), nullptr, 0,
                    const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
                !BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenerateSymmetricKey failed");
            }
            return aes;
        }

        // GCM's nonce, tag and AAD go through the auth-mode info struct. An
        // empty `aad` means none. CNG's struct fields are non-const; callers
        // passing input-only buffers are responsible for the const_cast.
        [[nodiscard]] BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO MakeAuthInfo(
            PUCHAR nonce, PUCHAR tag, std::span<const std::uint8_t> aad) {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
            BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
            auth_info.pbNonce = nonce;
            auth_info.cbNonce = static_cast<ULONG>(kNonceLen);
            auth_info.pbTag = tag;
            auth_info.cbTag = static_cast<ULONG>(kTagLen);
            // CNG only reads the AAD.
            auth_info.pbAuthData = const_cast<PUCHAR>(aad.data());
            auth_info.cbAuthData = ToUlong(aad.size());
            return auth_info;
        }
    } // namespace

    void AesGcmEncrypt(
        std::span<const std::uint8_t, kAesKeyLen> key,
        std::span<const std::uint8_t> plaintext,
        std::span<const std::uint8_t> aad,
        std::span<std::uint8_t, kNonceLen> nonce_out,
        std::span<std::uint8_t> ciphertext_out,
        std::span<std::uint8_t, kTagLen> tag_out) {
        if (ciphertext_out.size() < plaintext.size()) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "AES-GCM ciphertext buffer too small");
        }
        const ULONG plaintext_len = ToUlong(plaintext.size());

        const AesKey aes = OpenAesKey(key);

        // A fresh random nonce from the system CSPRNG: a GCM nonce must never
        // repeat under the same key.
        if (const NTSTATUS status = BCryptGenRandom(
                nullptr, nonce_out.data(), static_cast<ULONG>(nonce_out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            !BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenRandom(nonce) failed");
        }

        // CNG writes the tag into `tag_out`.
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info = MakeAuthInfo(nonce_out.data(), tag_out.data(), aad);

        ULONG result_len = 0;
        const NTSTATUS status = BCryptEncrypt(
            aes.key.get(), const_cast<PUCHAR>(plaintext.data()), plaintext_len, &auth_info,
            // pbIV/cbIV unused: GCM takes the nonce from auth_info.
            nullptr, 0, ciphertext_out.data(), plaintext_len, &result_len, 0);
        if (!BCRYPT_SUCCESS(status) || result_len != plaintext_len) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptEncrypt failed");
        }
        // The plaintext DEK is read straight from the caller's buffer and
        // never copied here, so this function adds no copy of the secret.
    }

    void AesGcmDecrypt(
        std::span<const std::uint8_t, kAesKeyLen> key,
        std::span<const std::uint8_t, kNonceLen> nonce,
        std::span<const std::uint8_t> ciphertext,
        std::span<const std::uint8_t> aad,
        std::span<const std::uint8_t, kTagLen> tag,
        std::span<std::uint8_t> plaintext_out) {
        if (plaintext_out.size() < ciphertext.size()) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "AES-GCM plaintext buffer too small");
        }
        const ULONG ciphertext_len = ToUlong(ciphertext.size());

        const AesKey aes = OpenAesKey(key);

        // Nonce and tag are inputs here; CNG does not write through these
        // pointers on decrypt, so the const_casts are safe. The AAD must
        // match the AAD used in AesGcmEncrypt, or the tag check fails.
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info =
            MakeAuthInfo(const_cast<PUCHAR>(nonce.data()), const_cast<PUCHAR>(tag.data()), aad);

        ULONG result_len = 0;
        const NTSTATUS status = BCryptDecrypt(
            aes.key.get(), const_cast<PUCHAR>(ciphertext.data()), ciphertext_len, &auth_info,
            nullptr, 0, plaintext_out.data(), ciphertext_len, &result_len, 0);

        // BCryptDecrypt in GCM mode can still write unauthenticated plaintext
        // into plaintext_out even when it reports a tag mismatch; callers must
        // not trust plaintext_out unless this function returns normally, and
        // the ABI layer zeroes the caller's output buffer on any failure.
        if (status == kStatusAuthTagMismatch) {
            // Its own code, so a caller can tell tampering or a wrong key
            // apart from a failure of the crypto machinery itself.
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, "AES-GCM authentication failed");
        }
        if (!BCRYPT_SUCCESS(status) || result_len != ciphertext_len) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptDecrypt failed");
        }
        // The plaintext DEK exists only in `plaintext_out` - ultimately the
        // caller's buffer passed to hkdfguard_unwrap_dek.
    }
} // namespace hkdfguard
