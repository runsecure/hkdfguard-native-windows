#include "key_acl.h"
#include "errors.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h> // ConvertStringSidToSidW

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
                    HKDFGUARD_ERR_PROVIDER,
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
        };

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
        // real domain's NetBIOS name). Throws HKDFGUARD_ERR_GROUP_INVALID if
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
                    HKDFGUARD_ERR_GROUP_INVALID,
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
                    HKDFGUARD_ERR_GROUP_INVALID,
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
                    HKDFGUARD_ERR_GROUP_INVALID,
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
                    HKDFGUARD_ERR_GROUP_INVALID,
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
                    HKDFGUARD_ERR_GROUP_INVALID,
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
                    HKDFGUARD_ERR_GROUP_INVALID,
                    "key-use policy entry is not a group");
            }

            for (WELL_KNOWN_SID_TYPE overBroad: kOverBroadSids) {
                SidBuffer known = CreateWellKnownSidBuffer(overBroad);
                if (EqualSid(sid.data(), known.data())) {
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_GROUP_INVALID,
                        "key-use policy entry is an over-broad principal");
                }
            }

            // Checked on the resolved result rather than on how the entry
            // was spelled, so an unqualified name that happens to resolve to
            // a domain group (because no local group has that name) is
            // caught just the same as an explicitly domain-qualified one.
            if (!IsHostLocalAccountDomain(domain)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_GROUP_INVALID,
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
                    HKDFGUARD_ERR_PROVIDER,
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

            if (auto group =
                    TryResolveAccountSid(
                        kHkdfGuardUsersGroup)) {
                optionalSids.push_back(
                    std::move(*group));

                AddKeyUseAce(
                    entries,
                    optionalSids.back());
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
                    HKDFGUARD_ERR_PROVIDER,
                    "SetEntriesInAclW failed");
            }

            SECURITY_DESCRIPTOR sd{};

            if (!InitializeSecurityDescriptor(
                &sd,
                SECURITY_DESCRIPTOR_REVISION)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "InitializeSecurityDescriptor failed");
            }

            if (!SetSecurityDescriptorDacl(
                &sd,
                TRUE,
                acl,
                FALSE)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
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
                    HKDFGUARD_ERR_PROVIDER,
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
        // kOverBroadSids, which is checked first. Everything else must be
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
                HKDFGUARD_ERR_PROVIDER,
                "failed to apply key ACL");
        }
    }

    namespace {
        // Reads a key's security descriptor (DACL only). `descriptor` owns the
        // bytes the returned PACL points into, so it must outlive any use of
        // that PACL. Throws `missingCode` if the key has no DACL at all, or a
        // NULL DACL - which Windows treats as "everyone, full access" and is
        // therefore never acceptable on a KEK. A read refused by the provider
        // as access-denied is reported as HKDFGUARD_ERR_ACCESS_DENIED, not
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
                    HKDFGUARD_ERR_ACCESS_DENIED,
                    "not authorized to read the key ACL");
            }

            if (status != ERROR_SUCCESS) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
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
                    HKDFGUARD_ERR_PROVIDER,
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
        PACL acl = ReadKeyDacl(key, descriptor, HKDFGUARD_ERR_KEK_ACL_INVALID);

        // The two principals every KEK this library creates grants, whatever
        // the policy was at the time.
        const SidBuffer required[] = {
            CreateWellKnownSidBuffer(WinLocalSystemSid),
            CreateWellKnownSidBuffer(WinBuiltinAdministratorsSid),
        };
        for (const SidBuffer &sid: required) {
            if (!DaclContainsSid(acl, const_cast<BYTE *>(sid.data()))) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_KEK_ACL_INVALID,
                    "existing KEK's ACL is missing SYSTEM or Administrators - not created by this library");
            }
        }

        // Nothing may be granted to a principal this library would never
        // grant - checked against every allow ACE, whatever its mask, since
        // even read access on the KEK means the ability to unwrap.
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void *ace = nullptr;
            if (!GetAce(acl, i, &ace)) {
                continue;
            }
            auto *header = static_cast<ACE_HEADER *>(ace);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                continue;
            }
            PSID sid = &static_cast<ACCESS_ALLOWED_ACE *>(ace)->SidStart;

            for (WELL_KNOWN_SID_TYPE overBroad: kOverBroadSids) {
                SidBuffer known = CreateWellKnownSidBuffer(overBroad);
                if (EqualSid(sid, known.data())) {
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_KEK_ACL_INVALID,
                        "existing KEK's ACL grants access to an over-broad principal");
                }
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
        PACL acl = ReadKeyDacl(key, descriptor, HKDFGUARD_ERR_PROVIDER);

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

        if (auto sid =
                TryResolveAccountSid(
                    kHkdfGuardUsersGroup)) {
            VerifyPrincipalPresent(
                acl,
                *sid);
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
} // namespace hkdfguard
