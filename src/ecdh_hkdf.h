#pragma once

#include "handle_traits.h" // NCRYPT_KEY_HANDLE etc. (via bcrypt.h/ncrypt.h) and Scoped* RAII types
#include "secure_buffer.h" // SecureBuffer<N>
#include "wire_format.h"   // kSaltLen, kPublicPointLen, kFingerprintLen
#include <cstdint>

namespace hkdfguard {
    // Derives the 32-byte AES-256-GCM wrapping key for a payload with salt
    // `salt`, for wrap and unwrap alike:
    //
    //   H = PayloadEcdhPoint(salt)                          (hash_to_curve.h)
    //   Z = ECDH(KEK private key, H)                        (NCryptSecretAgreement)
    //   wrapping key = HKDF-SHA512(salt, Z big-endian,
    //                              "HkdfGuardWin-DEK-Wrap-v1" || KEK public key)
    //
    // `kek_key` is the KEK opened on `provider` - the agreement is the step
    // that runs inside the TPM for a Platform Crypto Provider KEK, and it
    // needs the KEK's private key, which is what makes a payload unforgeable
    // from the public key (see wire_format.h). The salt is copied once before
    // use, so a payload buffer changed by another thread can't make the point
    // and HKDF see different bytes. The shared secret and every intermediate
    // buffer are wiped before returning.
    //
    // `SecureBuffer<32>& wrapping_key_out` is an output parameter passed by
    // reference: the caller (hkdfguard.cpp) owns the one copy of the wrapping
    // key and decides how long it lives.
    //
    // Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR) if any step fails.
    void DeriveWrappingKey(
        NCRYPT_PROV_HANDLE provider,
        NCRYPT_KEY_HANDLE kek_key,
        const uint8_t salt[kSaltLen],
        SecureBuffer<32> &wrapping_key_out);

    // Whether `pub` (raw X||Y, 64 bytes) is a genuine point on P-256, judged
    // by importing it through the Microsoft software provider
    // (BCryptImportKeyPair) - the point-validation path this project has
    // fuzzed, see SecurityAssumptions.md. DeriveWrappingKey runs every
    // H(salt) through it before any KSP sees the point; exposed so tests can
    // exercise it directly. Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR)
    // only if the provider itself can't be opened.
    bool IsValidP256Point(const uint8_t pub[kPublicPointLen]);

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    // Test-only fault injection: while set, IsValidP256Point acts as if the
    // software ECDH provider could not be opened (BCryptOpenAlgorithmProvider
    // failing), so the resulting HKDFGUARD_ERR_CRYPTO_ERROR path of
    // DeriveWrappingKey can be tested. Same compile-time scope and caveats as
    // kek_store.h's SetTestTpmFaults: compiled in only when
    // HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE is defined (tests/CMakeLists.txt,
    // for test_roundtrip's own copy of this file), never in HkdfGuardV1.dll;
    // not thread-safe, by design.
    void SetTestEcdhProviderFault(bool failOpen);
#endif

    // Computes the KEK fingerprint carried in every wrapped payload (see
    // wire_format.h's layout comment): SHA-256 over the KEK's public key as
    // raw X || Y (64 bytes - exporting the public part is always permitted,
    // independent of export policy). Writes kFingerprintLen bytes to `out`.
    // Used identically on wrap (to stamp the payload and bind it into the
    // AAD) and on unwrap (to check the payload against the KEK actually
    // opened, before any ECDH). Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR)
    // if the export or the hash fails.
    void ComputeKekFingerprint(NCRYPT_KEY_HANDLE kek_key, uint8_t out[kFingerprintLen]);
} // namespace hkdfguard
