#include "aes_cmac.h"
#include "errors.h"
#include "handle_traits.h" // ScopedBCryptKey
#include "secure_buffer.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstring> // memcpy, memcmp
#include <vector>

namespace hkdfguard {
    namespace {
        // Doubling in GF(2^128) (SP 800-38B, 6.1): shift left one bit, and
        // fold the carry back in with the constant R_128 = 0x87.
        void Double(uint8_t b[kAesBlockSize]) {
            const uint8_t carry = static_cast<uint8_t>(b[0] & 0x80);
            for (size_t i = 0; i + 1 < kAesBlockSize; ++i) {
                b[i] = static_cast<uint8_t>((b[i] << 1) | (b[i + 1] >> 7));
            }
            b[kAesBlockSize - 1] = static_cast<uint8_t>(b[kAesBlockSize - 1] << 1);
            if (carry) {
                b[kAesBlockSize - 1] ^= 0x87;
            }
        }

        [[noreturn]] void Mismatch(const char *what) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, what);
        }
    } // namespace

    void AesCmac(const AesBlockOperations &aes, const uint8_t *message, size_t len, uint8_t tag[kAesBlockSize]) {
        // Subkeys: K1 = dbl(E_K(0)), K2 = dbl(K1).
        const uint8_t zero[kAesBlockSize] = {};
        SecureBuffer<kAesBlockSize> k1;
        aes.encrypt_block(zero, k1.data());
        Double(k1.data());
        SecureBuffer<kAesBlockSize> k2;
        std::memcpy(k2.data(), k1.data(), kAesBlockSize);
        Double(k2.data());

        // The message with its last block masked: complete -> XOR K1;
        // partial (or empty) -> pad 10* and XOR K2.
        const size_t blocks = len == 0 ? 1 : (len + kAesBlockSize - 1) / kAesBlockSize;
        const bool complete = len != 0 && len % kAesBlockSize == 0;
        std::vector<uint8_t> prepared(blocks * kAesBlockSize, 0);
        ScopedSecureZero wipe_prepared(prepared.data(), prepared.size());
        if (len != 0) {
            std::memcpy(prepared.data(), message, len);
        }
        if (!complete) {
            prepared[len] = 0x80;
        }
        const uint8_t *mask = complete ? k1.data() : k2.data();
        uint8_t *last = prepared.data() + (blocks - 1) * kAesBlockSize;
        for (size_t i = 0; i < kAesBlockSize; ++i) {
            last[i] ^= mask[i];
        }

        // CBC-MAC with a zero IV: the tag is the last ciphertext block.
        std::vector<uint8_t> chained(prepared.size());
        ScopedSecureZero wipe_chained(chained.data(), chained.size());
        aes.cbc_zero_iv(prepared.data(), prepared.size(), chained.data());
        std::memcpy(tag, chained.data() + chained.size() - kAesBlockSize, kAesBlockSize);
    }

    void CheckAesCmacImplementation() {
        // NIST SP 800-38B, appendix D.3: AES-256.
        static const uint8_t kKey[32] = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        static const uint8_t kMessage[64] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
        struct Example {
            size_t len;
            uint8_t tag[kAesBlockSize];
        };
        static const Example kExamples[] = {
            {0, {0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e, 0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83}},
            {16, {0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82, 0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c}},
            {40, {0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6}},
            {64, {0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5, 0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10}},
        };

        ScopedBCryptKey ecb;
        if (BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, ecb.put(), nullptr, 0, const_cast<PUCHAR>(kKey),
                                       sizeof(kKey), 0) != 0) {
            Mismatch("AES-CMAC self-test: AES key setup failed");
        }
        AesBlockOperations aes;
        aes.encrypt_block = [&](const uint8_t *in, uint8_t *out) {
            ULONG got = 0;
            if (BCryptEncrypt(ecb.get(), const_cast<PUCHAR>(in), kAesBlockSize, nullptr, nullptr, 0, out,
                              kAesBlockSize, &got, 0) != 0) {
                Mismatch("AES-CMAC self-test: AES block encryption failed");
            }
        };
        // CBC as the KSP is asked for it: a zero IV given on every call.
        aes.cbc_zero_iv = [&](const uint8_t *in, size_t len, uint8_t *out) {
            uint8_t chain[kAesBlockSize] = {};
            for (size_t off = 0; off < len; off += kAesBlockSize) {
                uint8_t x[kAesBlockSize];
                for (size_t i = 0; i < kAesBlockSize; ++i) {
                    x[i] = static_cast<uint8_t>(chain[i] ^ in[off + i]);
                }
                aes.encrypt_block(x, out + off);
                std::memcpy(chain, out + off, kAesBlockSize);
            }
        };

        for (const Example &e : kExamples) {
            uint8_t tag[kAesBlockSize];
            AesCmac(aes, kMessage, e.len, tag);
            if (std::memcmp(tag, e.tag, kAesBlockSize) != 0) {
                Mismatch("AES-CMAC self-test: an SP 800-38B example does not match");
            }
        }
        // And BCrypt's own AES-CMAC, at lengths around a block boundary and
        // the longest KDF block (196 bytes).
        for (size_t len : {1u, 15u, 17u, 33u, 196u}) {
            std::vector<uint8_t> message(len);
            for (size_t i = 0; i < len; ++i) {
                message[i] = static_cast<uint8_t>(i * 13 + 1);
            }
            uint8_t mine[kAesBlockSize];
            uint8_t reference[kAesBlockSize];
            AesCmac(aes, message.data(), len, mine);
            if (BCryptHash(BCRYPT_AES_CMAC_ALG_HANDLE, const_cast<PUCHAR>(kKey), sizeof(kKey), message.data(),
                           static_cast<ULONG>(len), reference, kAesBlockSize) != 0 ||
                std::memcmp(mine, reference, kAesBlockSize) != 0) {
                Mismatch("AES-CMAC self-test: disagrees with BCrypt AES-CMAC");
            }
        }
    }
} // namespace hkdfguard
