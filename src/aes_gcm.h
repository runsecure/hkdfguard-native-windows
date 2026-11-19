#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include "wire_format.h" // kNonceLen, kTagLen constants used in these signatures

namespace hkdfguard {
    // AES-256 key length in bytes.
    constexpr std::size_t kAesKeyLen = 32;

    // Encrypts `plaintext` with AES-256-GCM under `key`, authenticating `aad`
    // alongside it (without encrypting it - `aad` may be empty). Generates a
    // fresh random nonce into `nonce_out` and writes the ciphertext (same
    // length as the plaintext) into `ciphertext_out` and the authentication
    // tag into `tag_out`. Reads directly from `plaintext` and writes directly
    // into `ciphertext_out` - no additional staging buffer. Throws
    // HkdfGuardError on failure, including HKDFGUARD_ERR_INVALID_ARGUMENT if
    // `ciphertext_out` is smaller than `plaintext`.
    //
    // hkdfguard.cpp passes the payload's authenticated bytes, `header || KEK
    // fingerprint`, as `aad` (wire_format.h's BuildWrappedDekAuthenticated),
    // binding a payload to its version and routing fields and its KEK. The
    // service is bound through the key itself (ecdh_hkdf.h).
    void AesGcmEncrypt(
        std::span<const std::uint8_t, kAesKeyLen> key,
        std::span<const std::uint8_t> plaintext,
        std::span<const std::uint8_t> aad,
        std::span<std::uint8_t, kNonceLen> nonce_out,
        std::span<std::uint8_t> ciphertext_out,
        std::span<std::uint8_t, kTagLen> tag_out);

    // Decrypts and authenticates `ciphertext` with AES-256-GCM under `key`,
    // `nonce` and `tag`, authenticating `aad` alongside it (`aad` may be
    // empty, and must match what was passed to AesGcmEncrypt or
    // authentication fails). Writes the plaintext directly into
    // `plaintext_out`, which must be at least as large as `ciphertext`
    // (HKDFGUARD_ERR_INVALID_ARGUMENT otherwise). Throws
    // HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED) if the tag does not
    // verify, or HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR) on any other
    // failure. Callers must not trust the contents of `plaintext_out` unless
    // this function returns normally.
    void AesGcmDecrypt(
        std::span<const std::uint8_t, kAesKeyLen> key,
        std::span<const std::uint8_t, kNonceLen> nonce,
        std::span<const std::uint8_t> ciphertext,
        std::span<const std::uint8_t> aad,
        std::span<const std::uint8_t, kTagLen> tag,
        std::span<std::uint8_t> plaintext_out);
} // namespace hkdfguard
