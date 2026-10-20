#include "key_acl.h"
#include "errors.h"

#include <windows.h>
#include <aclapi.h>
#include <lm.h>   // NetLocalGroupGetMembers - ResolveDeployerPrincipals
#include <sddl.h> // ConvertStringSidToSidW

#include <cstring> // memcmp - IsDomainUsersRid compares SID identifier authorities
#include <cwchar> // _wcsicmp
#include <optional>
#include <string>
#include <vector>

namespace hkdfguard {
    namespace {
        using SidBuffer = std::vector<BYTE>;

        constexpr ACCESS_MASK kKekAdminAccess =
                GENERIC_ALL;

        constexpr ACCESS_MASK kKekUseAccess =
                GENERIC_READ;

        SidBuffer CreateWellKnownSidBuffer(
            WELL_KNOWN_SID_TYPE type) {
            DWORD size = SECURITY_MAX_SID_SIZE;

            SidBuffer sid(size);

            if (!CreateWellKnownSid(
                type,
                nullptr,
                sid.data(),
                &size)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "CreateWellKnownSid failed");
            }

            sid.resize(size);

            return sid;
        }

        // Only these SID_NAME_USE kinds are groups. Anything else a name can
        // resolve to - a user, a computer, a domain, a deleted account, an
        // unknown - must never be granted key use, whatever the policy says.
        bool IsGroupSidType(SID_NAME_USE type) {
            return type == SidTypeGroup ||
                   type == SidTypeAlias ||
                   type == SidTypeWellKnownGroup;
        }

        // Principals that must never be granted key-use access, regardless of
        // policy: each is effectively "everybody" (or every user of a logon
        // type), so granting it would make the KEK usable by any process on
        // the machine and defeat the point of a machine-scoped, ACL-gated
        // key. BUILTIN\Users is included deliberately - on a workstation it
        // is every standard user, which is Everyone in all but name.
        //
        // Most of these (Authenticated Users, Local account, This
        // Organization, ALL SERVICES, the logon-type groups) resolve as
        // SidTypeWellKnownGroup in a domain IsHostLocalAccountDomain accepts
        // (NT AUTHORITY or NT SERVICE), so for them this list - not the
        // group-type or host-local checks - is the only thing standing
        // between them and a key-use grant. This list is also the only check
        // VerifyExistingKeyAcl applies to an existing key's ACEs.
        constexpr WELL_KNOWN_SID_TYPE kOverBroadSids[] = {
            WinNullSid,
            WinWorldSid, // Everyone
            WinAnonymousSid,
            WinAuthenticatedUserSid,
            WinInteractiveSid,
            WinNetworkSid,
            WinBatchSid,
            WinServiceSid,
            WinBuiltinUsersSid,
            WinBuiltinGuestsSid,
            WinLocalAccountSid,     // S-1-5-113 "Local account": every local account
            WinThisOrganizationSid, // S-1-5-15 "This Organization": every account in the forest
            WinRemoteLogonIdSid,    // S-1-5-14 "REMOTE INTERACTIVE LOGON": every RDP user
            WinLocalSid,            // S-1-2-0 "LOCAL": every locally logged-on user
            WinConsoleLogonSid,     // S-1-2-1 "CONSOLE LOGON": every console user
            WinTerminalServerSid,   // S-1-5-13 "TERMINAL SERVER USER": every RDP session (older sibling of S-1-5-14)
            // The authentication-package groups: a token carries one for
            // whichever package authenticated it, so each is every account
            // that logged on that way. NTLM is every local-account logon.
            WinNTLMAuthenticationSid,     // S-1-5-64-10 "NTLM Authentication"
            WinSChannelAuthenticationSid, // S-1-5-64-14 "SChannel Authentication"
            WinDigestAuthenticationSid,   // S-1-5-64-21 "Digest Authentication"
        };

        // tools/hkdfguard_cli.cpp keeps a copy of both lists and of
        // IsDomainUsersRid for its --group check (it depends only on the
        // public ABI); keep them in sync.
        //
        // Over-broad principals with no WELL_KNOWN_SID_TYPE constant of their
        // own, given as SID strings instead.
        constexpr const wchar_t *kOverBroadSidStrings[] = {
            L"S-1-5-80-0", // NT SERVICE\ALL SERVICES: every service process
        };

        // Whether `sid` is S-1-5-21-<domain>-513: "Domain Users", which the
        // local SAM calls "None". It is the primary group of every account in
        // its domain and is in every such account's token, so on this host
        // it is every local user - the same population as Local account
        // (S-1-5-113). It has no fixed SID (the domain part is per machine),
        // so it is recognized by shape: an NT-authority SID of five
        // sub-authorities starting with 21 and ending in RID 513. Domain
        // groups are refused anyway by IsHostLocalAccountDomain; this check
        // closes the local one, which that test accepts.
        bool IsDomainUsersRid(PSID sid) {
            static const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
            if (!IsValidSid(sid)) {
                return false;
            }
            const PSID_IDENTIFIER_AUTHORITY authority = GetSidIdentifierAuthority(sid);
            if (memcmp(authority->Value, nt.Value, sizeof(nt.Value)) != 0) {
                return false;
            }
            const PUCHAR count = GetSidSubAuthorityCount(sid);
            if (*count != 5) {
                return false;
            }
            return *GetSidSubAuthority(sid, 0) == SECURITY_NT_NON_UNIQUE &&
                   *GetSidSubAuthority(sid, 4) == DOMAIN_GROUP_RID_USERS;
        }

        // Whether `sid` is any principal on the two lists above, or a
        // domain's "Domain Users"/"None" group. The single implementation
        // behind both policy validation (ResolveKeyUseGroupSid) and the
        // existing-key ACL check (VerifyExistingKeyAcl), so the two can never
        // disagree about what counts as over-broad.
        bool IsOverBroadSid(PSID sid) {
            if (IsDomainUsersRid(sid)) {
                return true;
            }

            for (WELL_KNOWN_SID_TYPE overBroad: kOverBroadSids) {
                SidBuffer known = CreateWellKnownSidBuffer(overBroad);
                if (EqualSid(sid, known.data())) {
                    return true;
                }
            }

            for (const wchar_t *sidString: kOverBroadSidStrings) {
                PSID known = nullptr;
                if (!ConvertStringSidToSidW(sidString, &known)) {
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_PROVIDER_ERROR,
                        "ConvertStringSidToSidW failed for a built-in over-broad SID");
                }
                const bool match = EqualSid(sid, known) != FALSE;
                LocalFree(known);
                if (match) {
                    return true;
                }
            }

            return false;
        }

        // The NetBIOS name of this machine - what LookupAccountName* report
        // as ReferencedDomainName for accounts in the local SAM.
        std::wstring LocalComputerName() {
            wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
            if (!GetComputerNameW(name, &size)) {
                return L"";
            }
            return std::wstring(name, size);
        }

        // Resolves an account NAME to its SID, SID type, and the domain
        // Windows says it belongs to (ReferencedDomainName - the local
        // computer name for SAM accounts, "BUILTIN", "NT AUTHORITY", or a
        // real domain's NetBIOS name). Throws HKDFGUARD_ERR_WIN_GROUP_INVALID if
        // the name doesn't resolve at all.
        SidBuffer ResolveAccountSid(
            const std::wstring &accountName,
            SID_NAME_USE &sidType,
            std::wstring &domain) {
            DWORD sidSize = 0;
            DWORD domainSize = 0;

            LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                nullptr,
                &sidSize,
                nullptr,
                &domainSize,
                &sidType);

            if (sidSize == 0) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy entry does not resolve to any account");
            }

            SidBuffer sid(sidSize);

            // The size query counts the terminating NUL; the real call then
            // reports the length without it, so `domain` is trimmed to that
            // afterwards - otherwise a stray L'\0' rides along and defeats
            // the exact domain comparison in IsHostLocalAccountDomain.
            domain.assign(domainSize, L'\0');

            if (!LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                sid.data(),
                &sidSize,
                domain.data(),
                &domainSize,
                &sidType)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy entry does not resolve to any account");
            }

            sid.resize(sidSize);
            domain.resize(domainSize);

            return sid;
        }

        // Resolves a SID (given as a "S-1-..." string) back to its account,
        // purely to learn its SID type and domain - a SID string alone says
        // neither whether it names a group nor where it lives.
        SidBuffer ResolveSidString(
            const std::wstring &sidString,
            SID_NAME_USE &sidType,
            std::wstring &domain) {
            PSID raw = nullptr;

            if (!ConvertStringSidToSidW(sidString.c_str(), &raw)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy entry is not a valid SID string");
            }

            DWORD length = GetLengthSid(raw);
            SidBuffer sid(
                static_cast<BYTE *>(raw),
                static_cast<BYTE *>(raw) + length);
            LocalFree(raw);

            DWORD nameSize = 0;
            DWORD domainSize = 0;

            LookupAccountSidW(
                nullptr,
                sid.data(),
                nullptr,
                &nameSize,
                nullptr,
                &domainSize,
                &sidType);

            if (nameSize == 0) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy SID does not resolve to any account");
            }

            std::wstring name(nameSize, L'\0');
            domain.assign(domainSize, L'\0');

            if (!LookupAccountSidW(
                nullptr,
                sid.data(),
                name.data(),
                &nameSize,
                domain.data(),
                &domainSize,
                &sidType)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy SID does not resolve to any account");
            }

            domain.resize(domainSize);

            return sid;
        }

        // Resolves one key-use policy entry (name or SID string) and vets it:
        // must be a group, must not be over-broad, must be host-local. See
        // ValidateKeyUseGroups in key_acl.h for the contract; this is the
        // single implementation behind it, ApplyKeyAcl and VerifyKeyAcl, so
        // all three agree exactly on what is acceptable.
        SidBuffer ResolveKeyUseGroupSid(
            const std::wstring &entry) {
            SID_NAME_USE sidType = SidTypeUnknown;
            std::wstring domain;

            SidBuffer sid =
                    (entry.rfind(L"S-1-", 0) == 0)
                        ? ResolveSidString(entry, sidType, domain)
                        : ResolveAccountSid(entry, sidType, domain);

            if (!IsGroupSidType(sidType)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy entry is not a group");
            }

            if (IsOverBroadSid(sid.data())) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy entry is an over-broad principal");
            }

            // Checked on the resolved result rather than on how the entry
            // was spelled, so an unqualified name that happens to resolve to
            // a domain group (because no local group has that name) is
            // caught just the same as an explicitly domain-qualified one.
            if (!IsHostLocalAccountDomain(domain)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_WIN_GROUP_INVALID,
                    "key-use policy entry is not a host-local group; domain principals are not permitted");
            }

            return sid;
        }

        // For the two optional, fixed-name groups: absent, unresolvable,
        // resolving to something that isn't a group, or resolving to a
        // group outside this host's own SAM all mean "not present" - a
        // *user* account, or a *domain* group, that happens to be named
        // HkdfGuardAdmins must not inherit full control over every KEK just
        // by having that name.
        std::optional<SidBuffer> TryResolveAccountSid(
            const std::wstring &accountName) {
            DWORD sidSize = 0;
            DWORD domainSize = 0;
            SID_NAME_USE sidType;

            LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                nullptr,
                &sidSize,
                nullptr,
                &domainSize,
                &sidType);

            if (sidSize == 0) {
                return std::nullopt;
            }

            SidBuffer sid(sidSize);

            std::wstring domain(
                domainSize,
                L'\0');

            if (!LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                sid.data(),
                &sidSize,
                domain.data(),
                &domainSize,
                &sidType)) {
                return std::nullopt;
            }

            domain.resize(domainSize);

            if (!IsGroupSidType(sidType) ||
                !IsHostLocalAccountDomain(domain)) {
                return std::nullopt;
            }

            sid.resize(sidSize);

            return sid;
        }

        EXPLICIT_ACCESSW BuildAccessEntry(
            PSID sid,
            ACCESS_MASK accessMask) {
            EXPLICIT_ACCESSW entry{};

            entry.grfAccessPermissions =
                    accessMask;

            entry.grfAccessMode =
                    GRANT_ACCESS;

            entry.grfInheritance =
                    NO_INHERITANCE;

            entry.Trustee.TrusteeForm =
                    TRUSTEE_IS_SID;

            entry.Trustee.TrusteeType =
                    TRUSTEE_IS_GROUP;

            entry.Trustee.ptstrName =
                    static_cast<LPWSTR>(sid);

            return entry;
        }

        void AddFullControlAce(
            std::vector<EXPLICIT_ACCESSW> &entries,
            SidBuffer &sid) {
            entries.push_back(
                BuildAccessEntry(
                    sid.data(),
                    kKekAdminAccess));
        }

        void AddKeyUseAce(
            std::vector<EXPLICIT_ACCESSW> &entries,
            SidBuffer &sid) {
            entries.push_back(
                BuildAccessEntry(
                    sid.data(),
                    kKekUseAccess));
        }

        bool DaclContainsSid(
            PACL acl,
            PSID expectedSid) {
            for (DWORD i = 0;
                 i < acl->AceCount;
                 ++i) {
                void *ace = nullptr;

                if (!GetAce(
                    acl,
                    i,
                    &ace)) {
                    continue;
                }

                auto *header =
                        static_cast<ACE_HEADER *>(ace);

                if (header->AceType !=
                    ACCESS_ALLOWED_ACE_TYPE) {
                    continue;
                }

                auto *allowed =
                        static_cast<ACCESS_ALLOWED_ACE *>(ace);

                PSID sid =
                        &allowed->SidStart;

                if (EqualSid(
                    sid,
                    expectedSid)) {
                    return true;
                }
            }

            return false;
        }

        void VerifyPrincipalPresent(
            PACL acl,
            const SidBuffer &sid) {
            if (!DaclContainsSid(
                acl,
                const_cast<BYTE *>(
                    sid.data()))) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "expected princip*l missing from key ACL");
            }
        }

        std::vector<BYTE> BuildSecurityDescriptor(
            const std::vector<std::wstring> &additionalGroups) {
            std::vector<EXPLICIT_ACCESSW> entries;

            auto systemSid =
                    CreateWellKnownSidBuffer(
                        WinLocalSystemSid);

            AddFullControlAce(
                entries,
                systemSid);

            auto adminSid =
                    CreateWellKnownSidBuffer(
                        WinBuiltinAdministratorsSid);

            AddFullControlAce(
                entries,
                adminSid);

            std::vector<SidBuffer> optionalSids;

            if (auto group =
                    TryResolveAccountSid(
                        kHkdfGuardAdminsGroup)) {
                optionalSids.push_back(
                    std::move(*group));

                AddFullControlAce(
                    entries,
                    optionalSids.back());
            }

            for (const wchar_t *keyUseGroup: {kHkdfGuardUsersGroup, kHkdfGuardDeployersGroup}) {
                if (auto group =
                        TryResolveAccountSid(
                            keyUseGroup)) {
                    optionalSids.push_back(
                        std::move(*group));

                    AddKeyUseAce(
                        entries,
                        optionalSids.back());
                }
            }

            for (const auto &name: additionalGroups) {
                optionalSids.push_back(
                    ResolveKeyUseGroupSid(name));

                AddKeyUseAce(
                    entries,
                    optionalSids.back());
            }

            PACL acl = nullptr;

            DWORD status =
                    SetEntriesInAclW(
                        static_cast<ULONG>(entries.size()),
                        entries.data(),
                        nullptr,
                        &acl);

            if (status != ERROR_SUCCESS) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "SetEntriesInAclW failed");
            }

            SECURITY_DESCRIPTOR sd{};

            if (!InitializeSecurityDescriptor(
                &sd,
                SECURITY_DESCRIPTOR_REVISION)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "InitializeSecurityDescriptor failed");
            }

            if (!SetSecurityDescriptorDacl(
                &sd,
                TRUE,
                acl,
                FALSE)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "SetSecurityDescriptorDacl failed");
            }

            DWORD requiredSize = 0;

            MakeSelfRelativeSD(
                &sd,
                nullptr,
                &requiredSize);

            std::vector<BYTE> result(
                requiredSize);

            if (!MakeSelfRelativeSD(
                &sd,
                reinterpret_cast<PSECURITY_DESCRIPTOR>(
                    result.data()),
                &requiredSize)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "MakeSelfRelativeSD failed");
            }

            LocalFree(acl);

            return result;
        }
    } // namespace

    bool IsHostLocalAccountDomain(const std::wstring &domain) {
        // An empty domain is what well-known SIDs such as Everyone (S-1-1-0)
        // or CREATOR OWNER report - none of which is a host-local group.
        if (domain.empty()) {
            return false;
        }

        // NT AUTHORITY and NT SERVICE principals are host-local by nature
        // (logon-type SIDs, service accounts, per-service virtual accounts);
        // the over-broad ones among them are still refused by
        // IsOverBroadSid, which is checked first. Everything else must be
        // this machine's own SAM. On a domain controller, whose "local" SAM
        // is the domain itself, only BUILTIN/NT AUTHORITY/NT SERVICE
        // principals therefore qualify - which is the intended reading of
        // "host-local" there too.
        static const wchar_t *const kFixedLocalDomains[] = {
            L"BUILTIN",
            L"NT AUTHORITY",
            L"NT SERVICE",
        };

        for (const wchar_t *fixed: kFixedLocalDomains) {
            if (_wcsicmp(domain.c_str(), fixed) == 0) {
                return true;
            }
        }

        std::wstring computer = LocalComputerName();
        return !computer.empty() && _wcsicmp(domain.c_str(), computer.c_str()) == 0;
    }

    void ApplyKeyAcl(
        NCRYPT_KEY_HANDLE key,
        const std::vector<std::wstring> &additionalGroups) {
        auto descriptor =
                BuildSecurityDescriptor(
                    additionalGroups);

        SECURITY_STATUS status =
                NCryptSetProperty(
                    key,
                    NCRYPT_SECURITY_DESCR_PROPERTY,
                    descriptor.data(),
                    static_cast<DWORD>(descriptor.size()),
                    DACL_SECURITY_INFORMATION);

        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER_ERROR,
                "failed to apply key ACL");
        }
    }

    namespace {
        // Reads a key's security descriptor (DACL only). `descriptor` owns the
        // bytes the returned PACL points into, so it must outlive any use of
        // that PACL. Throws `missingCode` if the key has no DACL at all, or a
        // NULL DACL - which Windows treats as "everyone, full access" and is
        // therefore never acceptable on a KEK. A read refused by the provider
        // as access-denied is reported as HKDFGUARD_ERR_KEK_ACCESS_DENIED, not
        // as a provider fault.
        PACL ReadKeyDacl(
            NCRYPT_KEY_HANDLE key,
            std::vector<BYTE> &descriptor,
            int32_t missingCode) {
            DWORD size = 0;

            SECURITY_STATUS status = NCryptGetProperty(
                key,
                NCRYPT_SECURITY_DESCR_PROPERTY,
                nullptr,
                0,
                &size,
                DACL_SECURITY_INFORMATION);

            if (status == ERROR_SUCCESS) {
                descriptor.assign(size, 0);
                status = NCryptGetProperty(
                    key,
                    NCRYPT_SECURITY_DESCR_PROPERTY,
                    descriptor.data(),
                    size,
                    &size,
                    DACL_SECURITY_INFORMATION);
            }

            if (status == NTE_PERM ||
                status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_KEK_ACCESS_DENIED,
                    "not authorized to read the key ACL");
            }

            if (status != ERROR_SUCCESS) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "unable to read key ACL");
            }

            PACL acl = nullptr;
            BOOL present = FALSE;
            BOOL defaulted = FALSE;

            if (!GetSecurityDescriptorDacl(
                reinterpret_cast<PSECURITY_DESCRIPTOR>(
                    descriptor.data()),
                &present,
                &acl,
                &defaulted)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "unable to parse key ACL");
            }

            if (!present || acl == nullptr) {
                throw HkdfGuardError(
                    missingCode,
                    "key ACL missing or NULL (grants everyone full access)");
            }

            return acl;
        }
    } // namespace

    void VerifyExistingKeyAcl(
        NCRYPT_KEY_HANDLE key) {
        std::vector<BYTE> descriptor;
        PACL acl = ReadKeyDacl(key, descriptor, HKDFGUARD_ERR_KEK_INVALID);

        // The two principals every KEK this library creates grants, whatever
        // the policy was at the time.
        const SidBuffer required[] = {
            CreateWellKnownSidBuffer(WinLocalSystemSid),
            CreateWellKnownSidBuffer(WinBuiltinAdministratorsSid),
        };
        for (const SidBuffer &sid: required) {
            if (!DaclContainsSid(acl, const_cast<BYTE *>(sid.data()))) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_KEK_INVALID,
                    "existing KEK's ACL is missing SYSTEM or Administrators - not created by this library");
            }
        }

        // Nothing may be granted to a principal this library would never
        // grant - checked against every allow ACE, whatever its mask, since
        // even read access on the KEK means the ability to unwrap.
        //
        // Covers conditional (callback) allow ACEs too: AccessCheck honors
        // them, so "allow Everyone if <condition>" grants access just as
        // surely as a plain allow ACE. Object and compound allow ACEs carry
        // their SID at a variable offset and are never produced by this
        // library or meaningful on a key object, so their presence alone
        // fails the check rather than being skipped unexamined. So does an
        // ACE that cannot be read. Deny and audit ACEs grant nothing and are
        // ignored.
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *ace = nullptr;
            if (!GetAce(acl, i, &ace)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_KEK_INVALID,
                    "existing KEK's ACL contains an unreadable entry");
            }
            auto *header = static_cast<ACE_HEADER *>(ace);

            PSID sid = nullptr;
            switch (header->AceType) {
                case ACCESS_ALLOWED_ACE_TYPE:
                    sid = &static_cast<ACCESS_ALLOWED_ACE *>(ace)->SidStart;
                    break;
                case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                    // Same layout as ACCESS_ALLOWED_ACE up to and including
                    // the SID; the condition follows it.
                    sid = &static_cast<ACCESS_ALLOWED_CALLBACK_ACE *>(ace)->SidStart;
                    break;
                case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_KEK_INVALID,
                        "existing KEK's ACL contains an object or compound allow entry");
                default:
                    continue; // deny, audit, alarm, label: grants nothing
            }

            if (IsOverBroadSid(sid)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_KEK_INVALID,
                    "existing KEK's ACL grants access to an over-broad principal");
            }
        }
    }

    void VerifyKeyAcl(
        NCRYPT_KEY_HANDLE key,
        const std::vector<std::wstring> &additionalGroups) {
        //
        // Read security descriptor
        //

        std::vector<BYTE> descriptor;
        PACL acl = ReadKeyDacl(key, descriptor, HKDFGUARD_ERR_PROVIDER_ERROR);

        //
        // Verify SYSTEM
        //

        VerifyPrincipalPresent(
            acl,
            CreateWellKnownSidBuffer(
                WinLocalSystemSid));

        //
        // Verify Administrators
        //

        VerifyPrincipalPresent(
            acl,
            CreateWellKnownSidBuffer(
                WinBuiltinAdministratorsSid));

        //
        // Optional groups
        //

        if (auto sid =
                TryResolveAccountSid(
                    kHkdfGuardAdminsGroup)) {
            VerifyPrincipalPresent(
                acl,
                *sid);
        }

        for (const wchar_t *keyUseGroup: {kHkdfGuardUsersGroup, kHkdfGuardDeployersGroup}) {
            if (auto sid =
                    TryResolveAccountSid(
                        keyUseGroup)) {
                VerifyPrincipalPresent(
                    acl,
                    *sid);
            }
        }

        for (const auto &group: additionalGroups) {
            VerifyPrincipalPresent(
                acl,
                ResolveKeyUseGroupSid(group));
        }
    }

    void ValidateKeyUseGroups(
        const std::vector<std::wstring> &groups) {
        for (const auto &entry: groups) {
            // Resolution is the validation; the SID itself isn't needed here.
            ResolveKeyUseGroupSid(entry);
        }
    }

    namespace {
        // Appends the SID of every direct member of the local group `sid`.
        // Level 0 returns members by SID only, so nothing is resolved by
        // name and no domain controller is contacted, even for a domain
        // account that is a direct member. A well-known group (NT SERVICE,
        // NT AUTHORITY) isn't in the local group database and has no
        // enumerable members: it contributes only its own SID.
        // Whether a direct member of a deployer group may be trusted to have
        // written a key file: a single account, never a group. Trusted: a
        // user account, and an individual service's own SID (NT SERVICE\x,
        // S-1-5-80-<...>) - which Windows reports as a well-known group but
        // which names exactly one service. Never trusted: a nested group of
        // any kind (local, domain or well-known - Authenticated Users,
        // Domain Users, ...), whose members would otherwise all become key
        // file authors, nor anything over-broad, nor a member whose type
        // couldn't be determined (deleted, unknown, unresolvable).
        bool IsTrustableDeployerMember(PSID member, SID_NAME_USE use) {
            if (IsOverBroadSid(member)) {
                return false;
            }
            if (use == SidTypeUser) {
                return true;
            }
            const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
            const PSID_IDENTIFIER_AUTHORITY authority = GetSidIdentifierAuthority(member);
            return std::memcmp(authority, &nt, sizeof(nt)) == 0 && *GetSidSubAuthorityCount(member) >= 2 &&
                   *GetSidSubAuthority(member, 0) == SECURITY_SERVICE_ID_BASE_RID;
        }

        void AppendDirectMembers(const SidBuffer &sid, std::vector<SidBuffer> &out) {
            wchar_t name[256] = {};
            wchar_t domain[256] = {};
            DWORD name_len = ARRAYSIZE(name);
            DWORD domain_len = ARRAYSIZE(domain);
            SID_NAME_USE use = SidTypeUnknown;
            if (!LookupAccountSidW(nullptr, const_cast<BYTE *>(sid.data()), name, &name_len, domain, &domain_len,
                                   &use)) {
                throw HkdfGuardError(HKDFGUARD_ERR_WIN_GROUP_INVALID, "a deployer group could not be resolved");
            }
            if (use == SidTypeWellKnownGroup) {
                return;
            }

            DWORD_PTR resume = 0;
            NET_API_STATUS status = ERROR_MORE_DATA;
            while (status == ERROR_MORE_DATA) {
                BYTE *buffer = nullptr;
                DWORD read = 0;
                DWORD total = 0;
                // Level 1: each member's SID and account type. Resolving the
                // type of a domain member asks its domain controller (LSA,
                // never SMB); a member whose type can't be determined is
                // simply not trusted.
                status = NetLocalGroupGetMembers(nullptr, name, 1, &buffer, MAX_PREFERRED_LENGTH, &read, &total,
                                                 &resume);
                if (status != NERR_Success && status != ERROR_MORE_DATA) {
                    if (buffer != nullptr) NetApiBufferFree(buffer);
                    throw HkdfGuardError(HKDFGUARD_ERR_WIN_GROUP_INVALID,
                                         "the members of a deployer group could not be read");
                }
                const auto *members = reinterpret_cast<const LOCALGROUP_MEMBERS_INFO_1 *>(buffer);
                for (DWORD i = 0; i < read; ++i) {
                    PSID member = members[i].lgrmi1_sid;
                    if (member != nullptr && IsValidSid(member) &&
                        IsTrustableDeployerMember(member, members[i].lgrmi1_sidusage)) {
                        const auto *bytes = static_cast<const BYTE *>(member);
                        out.emplace_back(bytes, bytes + GetLengthSid(member));
                    }
                }
                if (buffer != nullptr) NetApiBufferFree(buffer);
            }
        }
    } // namespace

    std::vector<std::vector<BYTE>> ResolveDeployerPrincipals(
        const std::vector<std::wstring> &deployerGroups) {
        std::vector<SidBuffer> groups;
        if (auto fixed = TryResolveAccountSid(kHkdfGuardDeployersGroup)) {
            groups.push_back(std::move(*fixed));
        }
        for (const auto &entry: deployerGroups) {
            groups.push_back(ResolveKeyUseGroupSid(entry));
        }

        std::vector<SidBuffer> principals;
        for (const SidBuffer &group: groups) {
            principals.push_back(group);
            AppendDirectMembers(group, principals);
        }
        return principals;
    }
} // namespace hkdfguard
