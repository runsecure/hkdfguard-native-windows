#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

// AES-CMAC (NIST SP 800-38B) computed here over a key held elsewhere - the
// version 2 software KEK, a non-exportable AES-256 key in the Microsoft
// Software KSP (kek_v2.h), which offers AES encryption but no CMAC. The key
// never enters this process: only block encryptions with it are asked of
// the KSP, as two operations:
//
//   encrypt_block(in, out)       E_K of one 16-byte block (an ECB handle)
//   cbc_zero_iv(in, len, out)    AES-CBC with an all-zero IV over `len`
//                                bytes, a multiple of 16 (a CBC handle,
//                                given the IV explicitly on every call, so
//                                no chaining state carries between calls)
//
// CMAC is then: the subkeys K1, K2 from E_K(0^128); the message's last
// block XORed with K1 (complete) or padded 10* and XORed with K2; the tag is
// the last block of CBC-MAC over the result - one encrypt_block call and
// one cbc_zero_iv call per tag. Every intermediate value that depends on
// the key is wiped.
namespace hkdfguard {
    constexpr size_t kAesBlockSize = 16;

    struct AesBlockOperations {
        std::function<void(const uint8_t *in, uint8_t *out)> encrypt_block;
        std::function<void(const uint8_t *in, size_t len, uint8_t *out)> cbc_zero_iv;
    };

    // AES-CMAC of `message` (any length, including 0) into `tag`. Throws
    // whatever the operations throw.
    void AesCmac(const AesBlockOperations &aes, const uint8_t *message, size_t len, uint8_t tag[kAesBlockSize]);

    // Checks AesCmac itself against NIST SP 800-38B's AES-256 examples (D.3:
    // the 0-, 16-, 40- and 64-byte messages) using a BCrypt AES key with the
    // examples' known value, and against BCrypt's own AES-CMAC at the
    // lengths the KDF uses. Throws HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR)
    // on any mismatch. The KSP's AES itself is trusted, as BCrypt is.
    void CheckAesCmacImplementation();
} // namespace hkdfguard
