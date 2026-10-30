// libFuzzer target for payload version 2's key derivation inputs and its
// software PRF: src/sp800_108.cpp's block framing and src/aes_cmac.cpp's
// AES-CMAC composition. Built only with -DHKDFGUARD_BUILD_FUZZERS=ON, with
// AddressSanitizer.
//
// The input is read as: a service length byte, that service, a 40-byte
// header, a second service length byte, a second service, a second header;
// the remaining bytes are an AES-CMAC key (first 32, zero-padded) and
// message.
//
// Properties:
//   - Framing is injective: two different (service, header) pairs never
//     give the same wrap block, and no wrap block equals the fingerprint
//     block - so no two payloads, and no payload and the fingerprint, share
//     a wrapping key.
//   - Every block is [i]_32 || label || 0x00 || context || [256]_32.
//   - AesCmac, composed here from single-block and CBC operations, equals
//     BCrypt's own AES-CMAC for every key and message.
//
// Seeds: tests/fuzz/corpus/fuzz_v2_kdf.
#include "fuzz_common.h"
#include "aes_cmac.h"
#include "errors.h"
#include "handle_traits.h" // ScopedBCryptKey
#include "sp800_108.h"
#include "wire_format.h"   // kHeaderLen

#include <windows.h>
#include <bcrypt.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace hkdfguard;

namespace {
    // A bounded reader over the input; runs dry rather than past the end.
    struct Input {
        const uint8_t *p;
        size_t n;
        bool Take(size_t len, const uint8_t *&out) {
            if (len > n) return false;
            out = p;
            p += len;
            n -= len;
            return true;
        }
    };

    bool ReadPair(Input &in, std::string &service, const uint8_t *&header) {
        const uint8_t *len = nullptr;
        const uint8_t *name = nullptr;
        if (!in.Take(1, len) || *len == 0 || !in.Take(*len, name) || !in.Take(kHeaderLen, header)) {
            return false;
        }
        service.assign(reinterpret_cast<const char *>(name), *len);
        return true;
    }

    void CheckLayout(const std::vector<uint8_t> &block, uint32_t counter, const char *label) {
        const size_t label_len = std::strlen(label);
        FUZZ_REQUIRE(block.size() >= 4 + label_len + 1 + 4, "a block holds its fixed fields");
        FUZZ_REQUIRE(block[0] == (counter >> 24) && block[1] == ((counter >> 16) & 0xFF) &&
                         block[2] == ((counter >> 8) & 0xFF) && block[3] == (counter & 0xFF),
                     "a block starts with its big-endian counter");
        FUZZ_REQUIRE(std::memcmp(block.data() + 4, label, label_len) == 0 && block[4 + label_len] == 0x00,
                     "the counter is followed by the label and its 0x00");
        const uint8_t l256[4] = {0x00, 0x00, 0x01, 0x00};
        FUZZ_REQUIRE(std::memcmp(block.data() + block.size() - 4, l256, 4) == 0, "a block ends with [256]_32");
    }

    void CheckCmac(const uint8_t *key_bytes, size_t key_len, const uint8_t *message, size_t len) {
        uint8_t key[32] = {};
        std::memcpy(key, key_bytes, key_len < 32 ? key_len : 32);
        ScopedBCryptKey ecb;
        FUZZ_REQUIRE(BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, ecb.put(), nullptr, 0, key, 32, 0) == 0,
                     "an AES-256 key can be made");
        AesBlockOperations aes;
        aes.encrypt_block = [&](const uint8_t *in, uint8_t *out) {
            ULONG got = 0;
            FUZZ_REQUIRE(BCryptEncrypt(ecb.get(), const_cast<PUCHAR>(in), kAesBlockSize, nullptr, nullptr, 0, out,
                                       kAesBlockSize, &got, 0) == 0,
                         "AES block encryption works");
        };
        aes.cbc_zero_iv = [&](const uint8_t *in, size_t n, uint8_t *out) {
            FUZZ_REQUIRE(n % kAesBlockSize == 0 && n != 0, "CBC is asked only for whole blocks");
            uint8_t chain[kAesBlockSize] = {};
            for (size_t off = 0; off < n; off += kAesBlockSize) {
                uint8_t x[kAesBlockSize];
                for (size_t i = 0; i < kAesBlockSize; ++i) x[i] = static_cast<uint8_t>(chain[i] ^ in[off + i]);
                aes.encrypt_block(x, out + off);
                std::memcpy(chain, out + off, kAesBlockSize);
            }
        };
        uint8_t mine[kAesBlockSize];
        uint8_t reference[kAesBlockSize];
        AesCmac(aes, message, len, mine);
        FUZZ_REQUIRE(BCryptHash(BCRYPT_AES_CMAC_ALG_HANDLE, key, 32, const_cast<PUCHAR>(message),
                                static_cast<ULONG>(len), reference, kAesBlockSize) == 0,
                     "BCrypt AES-CMAC works");
        FUZZ_REQUIRE(std::memcmp(mine, reference, kAesBlockSize) == 0, "AesCmac equals BCrypt AES-CMAC");
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Input in{data, size};
    std::string service_a;
    std::string service_b;
    const uint8_t *header_a = nullptr;
    const uint8_t *header_b = nullptr;
    const bool have_a = ReadPair(in, service_a, header_a);
    const bool have_b = have_a && ReadPair(in, service_b, header_b);

    try {
        const std::vector<uint8_t> fingerprint = FingerprintBlock(1);
        CheckLayout(fingerprint, 1, kFingerprintLabel);
        if (have_a) {
            for (uint32_t counter : {1u, 2u}) {
                const std::vector<uint8_t> a = WrapBlock(counter, service_a, header_a, kHeaderLen);
                CheckLayout(a, counter, kWrapLabel);
                FUZZ_REQUIRE(a != FingerprintBlock(counter), "no wrap block is the fingerprint block");
                if (have_b) {
                    const std::vector<uint8_t> b = WrapBlock(counter, service_b, header_b, kHeaderLen);
                    const bool same_input =
                        service_a == service_b && std::memcmp(header_a, header_b, kHeaderLen) == 0;
                    FUZZ_REQUIRE((a == b) == same_input, "two wrap blocks are equal only for the same service and header");
                }
            }
        }
    } catch (const HkdfGuardError &) {
        FUZZ_REQUIRE(false, "framing a valid-length service never fails");
    } catch (...) {
        FUZZ_REQUIRE(false, "the KDF framing throws only HkdfGuardError");
    }

    // The rest: a CMAC key and message (any length, including none).
    const size_t key_len = in.n < 32 ? in.n : 32;
    CheckCmac(in.p, key_len, in.p + key_len, in.n - key_len);
    return 0;
}
