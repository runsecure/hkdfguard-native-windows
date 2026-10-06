#pragma once

#include "handle_traits.h" // NCRYPT_KEY_HANDLE etc. (via bcrypt.h/ncrypt.h) and Scoped* RAII types
#include "secure_buffer.h" // SecureBuffer<N>
#include "wire_format.h"   // kEphemeralPubLen
#include <cstdint>

namespace hkdfguard {
    // Wrap-side key agreement: generates a fresh ephemeral P-256 key pair,
    // exports the KEK's public key from `kek_key` (always permitted for ECC
    // regardless of export policy), performs ECDH entirely in software (the KEK
    // private key/TPM is never touched - only its public part is needed), and
    // derives a 32-byte AES wrapping key via HKDF-SHA512. Writes the ephemeral
    // public key bytes (64 bytes, raw X||Y) into `ephemeral_pub_out` for
    // inclusion in the wrapped payload. The ECDH shared secret and all
    // intermediate buffers are destroyed/zeroized before returning.
    //
    // `SecureBuffer<32>& wrapping_key_out` is an *output parameter passed by
    // reference*: rather than this function creating its own SecureBuffer and
    // returning it by value, the caller (hkdfguard.cpp) owns the SecureBuffer
    // and just hands this function a reference to write the result into. That
    // keeps the wrapping key's one-and-only copy under the caller's control, so
    // the caller decides exactly how long it stays alive (see hkdfguard.cpp's
    // nested `{ ... }` block, scoped as tightly as possible around its use).
    void DeriveWrappingKeyForWrap(
        NCRYPT_KEY_HANDLE kek_key,
        uint8_t ephemeral_pub_out[kEphemeralPubLen],
        SecureBuffer<32> &wrapping_key_out);

    // Validates that `pub` (raw X||Y, 64 bytes) is a genuine point on P-256,
    // by importing it through the Microsoft software provider
    // (BCryptImportKeyPair) - the point-validation path this project has
    // fuzzed, see SecurityAssumptions.md. Throws
    // HkdfGuardError(HKDFGUARD_ERR_MALFORMED) if it is not; throws
    // HkdfGuardError(HKDFGUARD_ERR_CRYPTO) only if the provider itself can't
    // be opened. DeriveWrappingKeyForUnwrap calls this unconditionally on the
    // payload's ephemeral key before any KSP ever sees it; it's exposed here
    // so tests can exercise the gate directly, without needing a KEK.
    void ValidateEphemeralPublicKey(const uint8_t pub[kEphemeralPubLen]);

    // Computes the KEK fingerprint carried in every wrapped payload (see
    // wire_format.h's layout comment): SHA-256 over the KEK's public key as
    // raw X || Y (64 bytes - exporting the public part is always permitted,
    // independent of export policy). Writes kFingerprintLen bytes to `out`.
    // Used identically on wrap (to stamp the payload and bind it into the
    // AAD) and on unwrap (to check the payload against the KEK actually
    // opened, before any ECDH). Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO)
    // if the export or the hash fails.
    void ComputeKekFingerprint(NCRYPT_KEY_HANDLE kek_key, uint8_t out[kFingerprintLen]);

    // Unwrap-side key agreement: validates the payload's ephemeral public key
    // (see ValidateEphemeralPublicKey above), imports it, performs ECDH
    // against the persistent KEK's private key (`kek_key`, opened on
    // `provider` - this is the step that may execute inside a TPM/vTPM), and
    // derives the 32-byte AES wrapping key via HKDF-SHA512 using the same
    // construction as the wrap side. The ECDH shared secret and all
    // intermediate buffers are destroyed/zeroized before returning.
    void DeriveWrappingKeyForUnwrap(
        NCRYPT_PROV_HANDLE provider,
        NCRYPT_KEY_HANDLE kek_key,
        const uint8_t ephemeral_pub[kEphemeralPubLen],
        SecureBuffer<32> &wrapping_key_out);
} // namespace hkdfguard
