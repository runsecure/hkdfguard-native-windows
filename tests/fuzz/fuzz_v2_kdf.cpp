// libFuzzer target for payload version 2's key derivation inputs:
// src/sp800_108.cpp's block framing. Built only with
// -DHKDFGUARD_BUILD_FUZZERS=ON, with AddressSanitizer.
//
// The input is read as: a service length byte, that service, a 40-byte
// header, a second service length byte, a second service, a second header.
// Anything after that is ignored.
//
// Properties:
//   - Framing is injective: two different (service, header) pairs never
//     give the same wrap block, and no wrap block equals the fingerprint
//     block - so no two payloads, and no payload and the fingerprint, share
//     a wrapping key.
//   - Every block is [i]_32 || label || 0x00 || context || [256]_32.
//   - The wrap block is exactly Sp800108Block over WrapContext, the label
//     and context the software KSP's own SP 800-108 derivation is given
//     (kek_v2.cpp's KspDerive) - so the TPM's HMAC over WrapBlock and the
//     KSP's derivation see the same block.
//
// Seeds: tests/fuzz/corpus/fuzz_v2_kdf.
#include "fuzz_common.h"
#include "errors.h"
#include "sp800_108.h"
#include "wire_format.h"   // kHeaderLen

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
            const std::vector<uint8_t> a = WrapBlock(1, service_a, header_a, kHeaderLen);
            CheckLayout(a, 1, kWrapLabel);
            FUZZ_REQUIRE(a != fingerprint, "no wrap block is the fingerprint block");
            const std::vector<uint8_t> context = WrapContext(service_a, header_a, kHeaderLen);
            FUZZ_REQUIRE(a == Sp800108Block(1, kWrapLabel, context.data(), context.size()),
                         "the wrap block is the SP 800-108 block over WrapContext");
            if (have_b) {
                const std::vector<uint8_t> b = WrapBlock(1, service_b, header_b, kHeaderLen);
                const bool same_input =
                    service_a == service_b && std::memcmp(header_a, header_b, kHeaderLen) == 0;
                FUZZ_REQUIRE((a == b) == same_input, "two wrap blocks are equal only for the same service and header");
            }
        }
    } catch (const HkdfGuardError &) {
        FUZZ_REQUIRE(false, "framing a valid-length service never fails");
    } catch (...) {
        FUZZ_REQUIRE(false, "the KDF framing throws only HkdfGuardError");
    }

    return 0;
}
