// libFuzzer target for the storage root key rule (src/kek_v2.h,
// StorageRootKeyProblem) applied to whatever ParsePublicArea accepts, as
// OpenUsableTpm does with the TPM's answer to TPM2_ReadPublic(0x81000001).
// Built only with -DHKDFGUARD_BUILD_FUZZERS=ON, with AddressSanitizer.
//
// Properties:
//   - No input crashes the parser, the rule, the Name computation or the
//     session salt.
//   - The rule accepts a key only if it has every property the rule
//     promises, checked here independently.
//   - For an accepted RSA key, a session salt is either made at the key's
//     size or refused with an HkdfGuardError.
//
// Seeds: tests/fuzz/corpus/fuzz_srk_rule.
#include "fuzz_common.h"
#include "errors.h"
#include "kek_v2.h"
#include "tpm2_marshal.h"
#include "tpm2_session.h"

#include <cstddef>
#include <cstdint>

using namespace hkdfguard;
using namespace hkdfguard::tpm2;

namespace {
    bool HasEveryPromisedProperty(const PublicArea &a) {
        constexpr uint32_t kRequired = kObjFixedTpm | kObjFixedParent | kObjSensitiveDataOrigin | kObjUserWithAuth |
                                       kObjNoDa | kObjRestricted | kObjDecrypt;
        if (a.name_alg != kAlgSha256 || (a.attributes & kRequired) != kRequired || (a.attributes & kObjSign) != 0) {
            return false;
        }
        if (a.symmetric_alg != kAlgAes || a.symmetric_mode != kAlgCfb ||
            (a.symmetric_key_bits != 128 && a.symmetric_key_bits != 256) || a.scheme != kAlgNull) {
            return false;
        }
        if (a.type == kAlgRsa) {
            return a.rsa_key_bits >= 2048 && a.rsa_modulus.size() * 8 == a.rsa_key_bits &&
                   (a.rsa_modulus[0] & 0x80) != 0 &&
                   (a.rsa_exponent == 0 || a.rsa_exponent == 65537);
        }
        if (a.type == kAlgEcc) {
            return a.ecc_curve == 0x0003 && a.ecc_kdf == kAlgNull;
        }
        return false;
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const Bytes bytes(data, data + size);
    PublicArea area;
    try {
        area = ParsePublicArea(bytes);
    } catch (const HkdfGuardError &) {
        return 0;
    } catch (...) {
        FUZZ_REQUIRE(false, "ParsePublicArea throws only HkdfGuardError");
    }

    std::optional<std::string> problem;
    try {
        problem = StorageRootKeyProblem(area);
    } catch (...) {
        FUZZ_REQUIRE(false, "StorageRootKeyProblem never throws");
    }
    if (problem) {
        FUZZ_REQUIRE(!problem->empty(), "a refusal names its reason");
        return 0;
    }
    FUZZ_REQUIRE(HasEveryPromisedProperty(area), "an accepted storage root key has every property the rule promises");

    try {
        const Bytes name = ComputeName(bytes);
        FUZZ_REQUIRE(name.size() == 2 + kSha256Len, "an accepted key's Name is a SHA-256 Name");
    } catch (...) {
        FUZZ_REQUIRE(false, "an accepted key's Name can be computed");
    }

    try {
        SecureBuffer<kSha256Len> salt;
        Bytes encrypted;
        MakeSessionSalt(area, salt, encrypted);
        if (area.type == kAlgRsa) {
            FUZZ_REQUIRE(encrypted.size() == area.rsa_modulus.size(), "an RSA-encrypted salt is the modulus's size");
        }
    } catch (const HkdfGuardError &) {
        // A modulus BCrypt won't import, or a point off the curve: refused.
    } catch (...) {
        FUZZ_REQUIRE(false, "MakeSessionSalt throws only HkdfGuardError");
    }
    return 0;
}
