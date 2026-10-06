#pragma once

#include <windows.h>
#include <ncrypt.h>

#include <string>
#include <vector>

namespace hkdfguard {

    // Default local groups used when present.
    // These groups are optional and will be applied only if they exist.
    inline constexpr wchar_t kHkdfGuardAdminsGroup[] =
        L"HkdfGuardAdmins";

    inline constexpr wchar_t kHkdfGuardUsersGroup[] =
        L"HkdfGuardUsers";

    // Whether `domain` - a ReferencedDomainName as reported by
    // LookupAccountName/LookupAccountSid - is one this host's KEK protection
    // treats as local: this machine's own NetBIOS computer name, "BUILTIN",
    // "NT AUTHORITY" or "NT SERVICE" (case-insensitive). Anything else - a
    // real domain's name, or the empty domain that well-known SIDs such as
    // Everyone report - is not. Exposed for tests.
    bool IsHostLocalAccountDomain(
        const std::wstring& domain);

    // Resolves and vets every key-use principal in `groups` (as read from
    // machine policy by policy.h's LoadKeyUseGroupsPolicy: group names or
    // "S-1-..." SID strings) without touching any key. Each must resolve,
    // must be a group (SidTypeGroup / SidTypeAlias / SidTypeWellKnownGroup -
    // never a user or computer account), must not be an over-broad
    // principal (Everyone, Authenticated Users, BUILTIN\Users,
    // BUILTIN\Guests, Anonymous, the NULL SID, or the logon-type groups
    // INTERACTIVE/NETWORK/BATCH/SERVICE), and must be host-local (see
    // IsHostLocalAccountDomain): this protection is host-specific, so domain
    // groups are refused even on a domain-joined machine, however the entry
    // was spelled. Throws HkdfGuardError(HKDFGUARD_ERR_GROUP_INVALID) on the
    // first entry that fails. CreateKek calls this before it opens the key
    // store at all, so a bad policy never results in a half-created key.
    void ValidateKeyUseGroups(
        const std::vector<std::wstring>& groups);

    // Applies the complete HKDFGuard ACL policy to a newly-created KEK.
    //
    // Full Control:
    //   SYSTEM
    //   BUILTIN\Administrators
    //   HkdfGuardAdmins (if present, a group, and in this host's own SAM)
    //
    // Key Use / Unwrap:
    //   HkdfGuardUsers (if present, a group, and in this host's own SAM)
    //   additionalGroups - each vetted exactly as ValidateKeyUseGroups does
    //
    // Throws HkdfGuardError on failure.
    void ApplyKeyAcl(
        NCRYPT_KEY_HANDLE key,
        const std::vector<std::wstring>& additionalGroups);

    // Checks an *already-existing* KEK's ACL against the invariants every KEK
    // this library creates satisfies regardless of the KeyUseGroups policy in
    // force when it was made: a real (non-NULL) DACL is present, SYSTEM and
    // BUILTIN\Administrators are on it, and it grants nothing - at any access
    // level - to an over-broad principal (the same list ValidateKeyUseGroups
    // refuses: Everyone, Authenticated Users, BUILTIN\Users, ...).
    //
    // Deliberately does NOT compare against the *current* KeyUseGroups
    // policy: the ACL is applied only at creation, and a later policy change
    // leaving an existing KEK untouched is documented, intended behavior (see
    // hkdfguard_create_kek in hkdfguard.h). This catches a pre-planted or
    // later-widened key, not policy drift.
    //
    // Throws HkdfGuardError(HKDFGUARD_ERR_KEK_ACL_INVALID) on a violation, or
    // HKDFGUARD_ERR_ACCESS_DENIED if the caller can't read the ACL at all.
    void VerifyExistingKeyAcl(
        NCRYPT_KEY_HANDLE key);

    // Verifies that the expected principals exist on the key ACL.
    //
    // Intended to be called when opening a KEK to ensure the key
    // still conforms to HKDFGuard authorization requirements.
    //
    // Throws HkdfGuardError on verification failure.
    void VerifyKeyAcl(
        NCRYPT_KEY_HANDLE key,
        const std::vector<std::wstring>& additionalGroups);

}