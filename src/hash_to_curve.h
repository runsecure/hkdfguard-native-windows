#pragma once

#include "wire_format.h" // kSaltLen, kPublicPointLen
#include <cstddef>
#include <cstdint>

namespace hkdfguard {
    // The domain separation tag for hashing a payload's salt to a point.
    // Cryptographic input: changing it changes every H(salt), and the
    // golden-payload test (tests/test_roundtrip.cpp section 29) fails.
    constexpr char kPayloadEcdhPointDst[] = "HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_";

    // RFC 9380 hash_to_curve with the suite P256_XMD:SHA-256_SSWU_RO_:
    // expand_message_xmd (SHA-256) to two field elements, the simplified
    // SWU map applied to each, and their sum (P-256 has cofactor 1, so
    // clear_cofactor is the identity). `dst` is `dst_len` bytes, at most 255.
    //
    // Writes the point as raw X || Y (64 bytes, big-endian coordinates) into
    // `point_out`. Not constant-time, and need not be for its one caller:
    // the salt is public. Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR)
    // if SHA-256 fails, or if the two mapped points cancel (probability
    // about 2^-256).
    void HashToCurveP256(const uint8_t *msg, size_t msg_len, const char *dst, size_t dst_len,
                         uint8_t point_out[kPublicPointLen]);

    // Hashes a payload's salt to a P-256 point H(salt), per the documented
    // HkdfGuard construction:
    //
    //   H(salt) = HashToCurveP256(salt, kPayloadEcdhPointDst)
    //
    // Nobody knows the discrete logarithm of a hash output, which is what
    // makes Z = ECDH(KEK private key, H(salt)) computable only by the KEK's
    // holder (see wire_format.h).
    void PayloadEcdhPoint(const uint8_t salt[kSaltLen], uint8_t point_out[kPublicPointLen]);
} // namespace hkdfguard
