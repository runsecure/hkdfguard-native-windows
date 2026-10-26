#include "aes_gcm.h"
#include "errors.h"
#include "handle_traits.h" // ScopedBCryptAlg, ScopedBCryptKey
#include <windows.h>
#include <bcrypt.h>

// The NTSTATUS CNG returns when AES-GCM tag verification fails. It is
// declared in ntstatus.h, which conflicts with windows.h unless included
// carefully, so it is defined here if nothing else has.
#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace hkdfguard {
    namespace {
        // Builds a CNG AES-GCM key object from 32 raw key bytes. Opens the AES
        // provider into the caller's `alg`, which must outlive the returned key.
        ScopedBCryptKey OpenAesKey(ScopedBCryptAlg &alg, const uint8_t key[32]) {
            NTSTATUS status = BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_AES_ALGORITHM, nullptr, 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptOpenAlgorithmProvider(AES) failed");
            }

            // CNG's AES provider is not in GCM mode by default; select it.
            status = BCryptSetProperty(
                alg.get(), BCRYPT_CHAINING_MODE,
                // CNG only reads this value; the casts satisfy the PUCHAR
                // parameter type.
                reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptSetProperty(GCM) failed");
            }

            // CNG copies the wrapping key into its own key object - the one
            // copy this code does not control. ScopedBCryptKey ensures
            // BCryptDestroyKey releases it as soon as it is no longer needed.
            ScopedBCryptKey aes_key;
            status = BCryptGenerateSymmetricKey(
                alg.get(), aes_key.put(), nullptr, 0,
                const_cast<PUCHAR>(key), 32, 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenerateSymmetricKey failed");
            }
            return aes_key;
        }
    } // namespace

    void AesGcmEncrypt(
        const uint8_t key[32],
        const uint8_t *plaintext, unsigned long plaintext_len,
        const uint8_t *aad, unsigned long aad_len,
        uint8_t nonce_out[kNonceLen],
        uint8_t *ciphertext_out,
        uint8_t tag_out[kTagLen]) {
        // `alg` is declared first so it is destroyed after `aes_key`, which
        // must not outlive its provider.
        ScopedBCryptAlg alg;
        ScopedBCryptKey aes_key = OpenAesKey(alg, key);

        // A fresh random nonce from the system CSPRNG: a GCM nonce must never
        // repeat under the same key.
        NTSTATUS status = BCryptGenRandom(
            nullptr, nonce_out, static_cast<ULONG>(kNonceLen), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenRandom(nonce) failed");
        }

        // GCM's nonce, tag and AAD go through the auth-mode info struct;
        // CNG writes the tag into `tag_out`. A null/0 AAD means none.
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = nonce_out;
        auth_info.cbNonce = static_cast<ULONG>(kNonceLen);
        auth_info.pbTag = tag_out;
        auth_info.cbTag = static_cast<ULONG>(kTagLen);
        auth_info.pbAuthData = const_cast<PUCHAR>(aad);
        auth_info.cbAuthData = aad_len;

        ULONG result_len = 0;
        status = BCryptEncrypt(
            aes_key.get(), const_cast<PUCHAR>(plaintext), plaintext_len, &auth_info,
            // pbIV/cbIV unused: GCM takes the nonce from auth_info.
            nullptr, 0, ciphertext_out, plaintext_len, &result_len, 0);
        if (!BCRYPT_SUCCESS(status) || result_len != plaintext_len) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptEncrypt failed");
        }
        // The plaintext DEK is read straight from the caller's buffer and
        // never copied here, so this function adds no copy of the secret.
    }

    void AesGcmDecrypt(
        const uint8_t key[32],
        const uint8_t nonce[kNonceLen],
        const uint8_t *ciphertext, unsigned long ciphertext_len,
        const uint8_t *aad, unsigned long aad_len,
        const uint8_t tag[kTagLen],
        uint8_t *plaintext_out) {
        ScopedBCryptAlg alg;
        ScopedBCryptKey aes_key = OpenAesKey(alg, key);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        // Nonce, tag and AAD are inputs here; CNG does not write through
        // these pointers on decrypt, so the const_casts are safe.
        auth_info.pbNonce = const_cast<PUCHAR>(nonce);
        auth_info.cbNonce = static_cast<ULONG>(kNonceLen);
        auth_info.pbTag = const_cast<PUCHAR>(tag);
        auth_info.cbTag = static_cast<ULONG>(kTagLen);
        // Must match the AAD used in AesGcmEncrypt, or the tag check fails.
        auth_info.pbAuthData = const_cast<PUCHAR>(aad);
        auth_info.cbAuthData = aad_len;

        ULONG result_len = 0;
        NTSTATUS status = BCryptDecrypt(
            aes_key.get(), const_cast<PUCHAR>(ciphertext), ciphertext_len, &auth_info,
            nullptr, 0, plaintext_out, ciphertext_len, &result_len, 0);

        // BCryptDecrypt in GCM mode can still write unauthenticated plaintext
        // into plaintext_out even when it reports a tag mismatch; callers must
        // not trust plaintext_out unless this function returns normally, and
        // the ABI layer zeroes the caller's output buffer on any failure.
        if (status == STATUS_AUTH_TAG_MISMATCH) {
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
