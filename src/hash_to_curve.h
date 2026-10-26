#pragma once

#include "wire_format.h" // kSaltLen, kPublicPointLen
#include <cstdint>

namespace hkdfguard {
    // Hashes a payload's salt to a P-256 point H(salt), per the documented
    // HkdfGuard construction:
    //
    //   for counter = 0, 1, ..., 254:
    //       X = SHA-256("HkdfGuard-P256-payload-ECDH-point-v1:" || salt || counter)
    //       if X < p and X^3 - 3X + b is a square mod p:
    //           return (X, the even square root Y)     // SEC1 prefix 0x02
    //
    // Nobody knows the discrete logarithm of a hash output, which is what
    // makes Z = ECDH(KEK private key, H(salt)) computable only by the KEK's
    // holder (see wire_format.h). P-256 has cofactor 1, so every point found
    // is in the prime-order group. About half of all X candidates work, so
    // all 255 failing has probability 2^-255.
    //
    // Writes the point as raw X || Y (64 bytes, big-endian coordinates) into
    // `point_out`. Not constant-time, and need not be: the salt is public.
    // Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR) if SHA-256 fails or no
    // candidate is found.
    void PayloadEcdhPoint(const uint8_t salt[kSaltLen], uint8_t point_out[kPublicPointLen]);
} // namespace hkdfguard
