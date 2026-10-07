#pragma once

#include <cstdint>
#include "wire_format.h" // kNonceLen, kTagLen constants used in these signatures

namespace hkdfguard {
    // Encrypts `plaintext_len` bytes from `plaintext` with AES-256-GCM under
    // `key` (32 bytes), authenticating `aad_len` bytes of `aad` alongside it
    // (without encrypting them - `aad` may be null iff `aad_len` is 0).
    // Generates a fresh random nonce into `nonce_out` (12 bytes) and writes the
    // ciphertext (same length as the plaintext) into `ciphertext_out` and the
    // 16-byte authentication tag into `tag_out`. Reads directly from
    // `plaintext` and writes directly into `ciphertext_out` - no additional
    // staging buffer. Throws HkdfGuardError on failure.
    //
    // hkdfguard.cpp passes `normalized service name || KEK fingerprint` as
    // `aad` here - see its call sites and wire_format.h for why: it's what
    // binds a wrapped payload to both the exact service and the specific KEK
    // it was wrapped under, matching the construction this project's macOS
    // and Linux implementations use.
    //
    // `unsigned long` (rather than this project's usual uint32_t/int32_t) is
    // used for the length parameters purely because that's the literal type
    // Windows' own BCryptEncrypt/BCryptDecrypt functions declare their length
    // parameters as (as `ULONG`, which is itself just `unsigned long` on
    // Windows) - matching it here avoids an implicit conversion at every call
    // site in aes_gcm.cpp.
    void AesGcmEncrypt(
        const uint8_t key[32],
        const uint8_t *plaintext, unsigned long plaintext_len,
        const uint8_t *aad, unsigned long aad_len,
        uint8_t nonce_out[kNonceLen],
        uint8_t *ciphertext_out,
        uint8_t tag_out[kTagLen]);

    // Decrypts and authenticates `ciphertext_len` bytes from `ciphertext` with
    // AES-256-GCM under `key` (32 bytes), `nonce` (12 bytes) and `tag` (16
    // bytes), authenticating `aad_len` bytes of `aad` alongside it (`aad` may
    // be null iff `aad_len` is 0, and must match what was passed to
    // AesGcmEncrypt or authentication fails). Writes the plaintext directly
    // into `plaintext_out`. Throws HkdfGuardError(HKDFGUARD_ERR_AUTH_FAILED) if
    // the tag does not verify, or HkdfGuardError(HKDFGUARD_ERR_CRYPTO) on any
    // other failure. Callers must not trust the contents of `plaintext_out`
    // unless this function returns normally.
    void AesGcmDecrypt(
        const uint8_t key[32],
        const uint8_t nonce[kNonceLen],
        const uint8_t *ciphertext, unsigned long ciphertext_len,
        const uint8_t *aad, unsigned long aad_len,
        const uint8_t tag[kTagLen],
        uint8_t *plaintext_out);
} // namespace hkdfguard
