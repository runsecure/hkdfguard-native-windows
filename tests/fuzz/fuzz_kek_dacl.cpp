// libFuzzer target for the two DACL walks that decide whether a KEK's
// access control is acceptable: key_acl.h's VerifyExistingKekDacl (nothing
// over-broad) and VerifyKekDaclGrants (every policy principal present).
// Their input is a DACL read from a KSP or PCP key - Windows has validated
// it, but an administrator, or an attacker who was one, may have chosen it.
// Built only with -DHKDFGUARD_BUILD_FUZZERS=ON, with AddressSanitizer.
//
// The first input byte is unused (kept so the seed corpus stays valid); the
// rest, if IsValidAcl accepts it, is the DACL.
//
// Properties:
//   - No ACL Windows accepts as valid crashes either of them or makes one
//     read past an ACE.
//   - Each either accepts or throws HkdfGuardError: VerifyExistingKekDacl
//     only KEK_INVALID.
//
// Seeds: tests/fuzz/corpus/fuzz_kek_dacl.
#include "fuzz_common.h"
#include "errors.h"
#include "key_acl.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace hkdfguard;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 + sizeof(ACL)) {
        return 0;
    }
    const size_t acl_len = (size - 1) & ~static_cast<size_t>(3); // ACLs are DWORD-sized
    if (acl_len < sizeof(ACL) || acl_len > 0xFFFC) {
        return 0;
    }
    // DWORD-aligned, exactly the ACL's length, so ASan sees any overread.
    std::vector<DWORD> storage(acl_len / sizeof(DWORD));
    std::memcpy(storage.data(), data + 1, acl_len);
    auto *acl = reinterpret_cast<PACL>(storage.data());
    acl->AclSize = static_cast<WORD>(acl_len);
    if (!IsValidAcl(acl)) {
        return 0;
    }

    try {
        VerifyExistingKekDacl(acl);
    } catch (const HkdfGuardError &e) {
        FUZZ_REQUIRE(e.code() == HKDFGUARD_ERR_KEK_INVALID, "VerifyExistingKekDacl refuses only with KEK_INVALID");
    } catch (...) {
        FUZZ_REQUIRE(false, "VerifyExistingKekDacl throws only HkdfGuardError");
    }

    try {
        VerifyKekDaclGrants(acl, {});
    } catch (const HkdfGuardError &) {
    } catch (...) {
        FUZZ_REQUIRE(false, "VerifyKekDaclGrants throws only HkdfGuardError");
    }

    return 0;
}
