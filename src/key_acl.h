#pragma once

#include <windows.h>
#include <ncrypt.h>

#include <string>
#include <vector>

namespace hkdfguard {

    // Optional default local groups, applied only if they exist.
    inline constexpr wchar_t kHkdfGuardAdminsGroup[] =
        L"HkdfGuardAdmins";

    inline constexpr wchar_t kHkdfGuardUsersGroup[] =
        L"HkdfGuardUsers";

    // The local group whose members deploy key files (see SecurityModel in
    // policy.h). Like the two above it is honored only if it exists, is a
    // group, and is in this machine's own SAM. The MSI creates it.
    inline constexpr wchar_t kHkdfGuardDeployersGroup[] =
        L"HkdfGuardDeployers";

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
    // BUILTIN\Guests, Anonymous, the NULL SID, Local account, This
    // Organization, NT SERVICE\ALL SERVICES, LOCAL, CONSOLE LOGON, or the
    // logon-type groups INTERACTIVE/NETWORK/BATCH/SERVICE/REMOTE INTERACTIVE
    // LOGON), and must be host-local (see IsHostLocalAccountDomain): this protection is host-specific, so domain
    // groups are refused even on a domain-joined machine, however the entry
    // was spelled. Throws HkdfGuardError(HKDFGUARD_ERR_WIN_GROUP_INVALID) on the
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
    //   HkdfGuardDeployers (likewise) - deployers wrap, so they need key use
    //   additionalGroups - each vetted exactly as ValidateKeyUseGroups does
    //     (CreateKek passes KeyUseGroups and DeployerGroups together)
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
    // Throws HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID) on a violation, or
    // HKDFGUARD_ERR_KEK_ACCESS_DENIED if the caller can't read the ACL at all.
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

    // Every principal the production security model trusts to have written
    // a key file (see SecurityModel in policy.h): the SID of
    // HkdfGuardDeployers (if present - see the constant above) and of each
    // DeployerGroups entry, each vetted exactly as ValidateKeyUseGroups
    // vets a key-use entry, plus the SID of each *direct* member that is a
    // single account: a user account, or one service's own NT SERVICE SID.
    // A group nested inside a deployer group - local, domain or well-known
    // (Authenticated Users, Domain Users, ...) - is not trusted at all,
    // neither as a principal nor through its members, and nothing
    // over-broad ever is. Members are read from this machine's group
    // database (NetLocalGroupGetMembers, level 1); resolving a domain
    // member's account type asks its domain controller over LSA, and a
    // member whose type can't be determined is not trusted. A well-known
    // deployer group (an NT SERVICE or NT AUTHORITY principal) has no
    // enumerable members and contributes only its own SID.
    // Throws HkdfGuardError(HKDFGUARD_ERR_WIN_GROUP_INVALID) for an entry
    // that fails vetting, or a group whose members can't be read.
    std::vector<std::vector<BYTE>> ResolveDeployerPrincipals(
        const std::vector<std::wstring>& deployerGroups);

}