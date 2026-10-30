// libFuzzer target for the three DACL walks that decide whether a version
// 2 KEK's access control is acceptable: key_acl.h's VerifyExistingKekDacl
// (nothing over-broad) and VerifyKekDaclGrants (every policy principal
// present), and tpm_key_file.h's CheckKeyStoreDacl (no write, delete,
// ownership or create rights for others). Their input is a DACL read from
// a key file, a store folder or a KSP key - Windows has validated it, but
// an attacker may have chosen it. Built only with
// -DHKDFGUARD_BUILD_FUZZERS=ON, with AddressSanitizer.
//
// The first input byte picks `installer_ok` and which rights are
// forbidden; the rest, if IsValidAcl accepts it, is the DACL.
//
// Properties:
//   - No ACL Windows accepts as valid crashes any of them or makes one read
//     past an ACE.
//   - Each either accepts or throws HkdfGuardError: CheckKeyStoreDacl only
//     KekAccessControlError, VerifyExistingKekDacl only KEK_INVALID.
//
// Seeds: tests/fuzz/corpus/fuzz_kek_dacl.
#include "fuzz_common.h"
#include "errors.h"
#include "key_acl.h"
#include "tpm_key_file.h"

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
    const uint8_t mode = data[0];
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

    // The rights the store forbids: a file's write rights, a folder's
    // replace rights, or those plus its create rights.
    constexpr ACCESS_MASK kFileWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                                       DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    constexpr ACCESS_MASK kFolderReplace = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    constexpr ACCESS_MASK kFolderCreate = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE;
    const ACCESS_MASK forbidden[] = {kFileWrite, kFolderReplace, kFolderReplace | kFolderCreate};
    try {
        CheckKeyStoreDacl(acl, forbidden[(mode >> 1) % 3], (mode & 1) != 0, "fuzzed DACL");
    } catch (const KekAccessControlError &) {
    } catch (const HkdfGuardError &) {
        FUZZ_REQUIRE(false, "CheckKeyStoreDacl refuses only as an access-control failure");
    } catch (...) {
        FUZZ_REQUIRE(false, "CheckKeyStoreDacl throws only HkdfGuardError");
    }
    return 0;
}
