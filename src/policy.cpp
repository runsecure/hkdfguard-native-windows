#include "policy.h"

#include <windows.h>

namespace hkdfguard {

    namespace {

        // Administratively managed policy location, deployable via Group
        // Policy Preferences, Intune, DSC, SCCM or manual registry edits.
        constexpr wchar_t kPolicyKey[] =
            L"Software\\Policies\\HkdfGuard";

        constexpr wchar_t kPolicyValue[] =
            L"KeyStoragePolicy";

        // REG_MULTI_SZ under the same key: see LoadKeyUseGroupsPolicy in
        // policy.h.
        constexpr wchar_t kKeyUseGroupsValue[] =
            L"KeyUseGroups";

        // REG_DWORD under the same key: see LoadAuditUnwrapSuccess in
        // policy.h.
        constexpr wchar_t kAuditUnwrapSuccessValue[] =
            L"AuditUnwrapSuccess";

        // REG_DWORD under the same key: see LoadSetupMinDelayMs in policy.h.
        constexpr wchar_t kSetupMinDelayMsValue[] =
            L"SetupMinDelayMs";

        // REG_DWORD under the same key: see LoadSecurityModel in policy.h.
        constexpr wchar_t kSecurityModelValue[] =
            L"SecurityModel";

        // REG_MULTI_SZ under the same key: see LoadDeployerGroupsPolicy in
        // policy.h.
        constexpr wchar_t kDeployerGroupsValue[] =
            L"DeployerGroups";

        // Default when no policy is configured: the TPM if available,
        // otherwise the software provider.
        constexpr KeyStoragePolicy kDefaultPolicy =
            KeyStoragePolicy::PreferTpm;

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        // See SetTestPolicyOverride in policy.h. Empty by default, so a test
        // binary that never sets it still reads the registry.
        std::optional<KeyStoragePolicy> g_testPolicyOverride;

        // Same, for LoadKeyUseGroupsPolicy.
        std::optional<std::vector<std::wstring>> g_testKeyUseGroupsOverride;

        // Same, for LoadSecurityModel and LoadDeployerGroupsPolicy.
        std::optional<SecurityModel> g_testSecurityModelOverride;
        std::optional<std::vector<std::wstring>> g_testDeployerGroupsOverride;
#endif

        std::wstring TrimW(const std::wstring& s)
        {
            const wchar_t* ws = L" \t\r\n";
            size_t begin = s.find_first_not_of(ws);
            if (begin == std::wstring::npos)
            {
                return L"";
            }
            size_t end = s.find_last_not_of(ws);
            return s.substr(begin, end - begin + 1);
        }

        // The normalization every source of the key-use list gets: trim
        // surrounding whitespace, drop empties. Applied to the registry
        // value and to the test override alike, so tests exercise exactly
        // the behavior the registry path has.
        std::vector<std::wstring> NormalizeEntries(const std::vector<std::wstring>& raw)
        {
            std::vector<std::wstring> result;
            for (const std::wstring& entry : raw)
            {
                std::wstring trimmed = TrimW(entry);
                if (!trimmed.empty())
                {
                    result.push_back(std::move(trimmed));
                }
            }
            return result;
        }

        // Maps a raw REG_DWORD value to a KeyStoragePolicy, or
        // KeyStoragePolicy::Invalid if it isn't one of the three recognized
        // values (see LoadEffectivePolicy in policy.h for why).
        KeyStoragePolicy ParsePolicyValue(DWORD value) noexcept
        {
            switch (value)
            {
                case static_cast<DWORD>(KeyStoragePolicy::PreferTpm):
                    return KeyStoragePolicy::PreferTpm;

                case static_cast<DWORD>(KeyStoragePolicy::RequireTpm):
                    return KeyStoragePolicy::RequireTpm;

                case static_cast<DWORD>(KeyStoragePolicy::SoftwareOnly):
                    return KeyStoragePolicy::SoftwareOnly;

                default:
                    return KeyStoragePolicy::Invalid;
            }
        }

    } // namespace

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestKeyUseGroupsOverride(std::optional<std::vector<std::wstring>> groups)
    {
        g_testKeyUseGroupsOverride = std::move(groups);
    }
#endif

    namespace {
        // Reads one REG_MULTI_SZ policy value of group entries - KeyUseGroups
        // or DeployerGroups - normalized (trimmed, empties dropped). A
        // missing value, a value of the wrong type, or any read failure
        // yields an empty list (fail closed: no additional principals),
        // never an exception.
        std::vector<std::wstring> LoadGroupListValue(const wchar_t *valueName)
        {
            std::vector<std::wstring> result;

            HKEY key = nullptr;

            // KEY_WOW64_64KEY: read the 64-bit view of HKLM whether this
            // process is 32- or 64-bit, so 32-bit and 64-bit HkdfGuard.dll on
            // one machine see the same policy, never a WOW6432Node copy.
            // Software\Policies is documented as excluded from WOW64
            // redirection; the flag is defense in depth against relying on
            // that.
            if (RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    kPolicyKey,
                    0,
                    KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                    &key) != ERROR_SUCCESS)
            {
                return result;
            }

            DWORD type = 0;
            DWORD size = 0;

            LONG status = RegQueryValueExW(
                key,
                valueName,
                nullptr,
                &type,
                nullptr,
                &size);

            if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || size == 0)
            {
                RegCloseKey(key);
                return result;
            }

            // Two extra zeroed wchar_t of padding guarantee the walk below always
            // hits a terminator, even for a value stored without the trailing
            // double NUL that REG_MULTI_SZ is supposed to end with, and even if
            // `size` isn't a whole number of wchar_t.
            std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');

            status = RegQueryValueExW(
                key,
                valueName,
                nullptr,
                &type,
                reinterpret_cast<LPBYTE>(buffer.data()),
                &size);

            RegCloseKey(key);

            // A size change between the two queries surfaces as ERROR_MORE_DATA
            // here; treated like any other failure - fail closed, grant nothing.
            if (status != ERROR_SUCCESS || type != REG_MULTI_SZ)
            {
                return result;
            }

            for (const wchar_t* p = buffer.data(); *p != L'\0'; p += wcslen(p) + 1)
            {
                result.emplace_back(p);
            }

            return NormalizeEntries(result);
        }
    } // namespace

    std::vector<std::wstring> LoadKeyUseGroupsPolicy()
    {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testKeyUseGroupsOverride.has_value())
        {
            return NormalizeEntries(*g_testKeyUseGroupsOverride);
        }
#endif
        return LoadGroupListValue(kKeyUseGroupsValue);
    }

    std::vector<std::wstring> LoadDeployerGroupsPolicy()
    {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testDeployerGroupsOverride.has_value())
        {
            return NormalizeEntries(*g_testDeployerGroupsOverride);
        }
#endif
        return LoadGroupListValue(kDeployerGroupsValue);
    }

    SecurityModel ParseSecurityModel(bool found, unsigned long type, unsigned long value) noexcept
    {
        // Absent: a production install. Present: only an exact REG_DWORD 0
        // or 1 picks a model; anything else is a configuration error, not
        // a default - an administrator who wrote *something* meant a
        // specific model, and guessing could quietly loosen trust.
        if (!found)
        {
            return SecurityModel::Production;
        }
        if (type != REG_DWORD)
        {
            return SecurityModel::Invalid;
        }
        switch (value)
        {
            case static_cast<unsigned long>(SecurityModel::Production):
                return SecurityModel::Production;
            case static_cast<unsigned long>(SecurityModel::Developer):
                return SecurityModel::Developer;
            default:
                return SecurityModel::Invalid;
        }
    }

    SecurityModel LoadSecurityModel() noexcept
    {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testSecurityModelOverride.has_value())
        {
            return *g_testSecurityModelOverride;
        }
#endif
        HKEY key = nullptr;

        // KEY_WOW64_64KEY: see LoadGroupListValue.
        if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                kPolicyKey,
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &key) != ERROR_SUCCESS)
        {
            return ParseSecurityModel(false, 0, 0);
        }

        DWORD value = 0;
        DWORD type = 0;
        DWORD size = sizeof(value);

        LONG status = RegQueryValueExW(
            key,
            kSecurityModelValue,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);

        RegCloseKey(key);

        if (status == ERROR_FILE_NOT_FOUND)
        {
            return ParseSecurityModel(false, 0, 0);
        }
        // Present but unreadable as a DWORD (too large: ERROR_MORE_DATA, or
        // any other failure): never a silent default.
        if (status != ERROR_SUCCESS || size != sizeof(value))
        {
            return SecurityModel::Invalid;
        }
        return ParseSecurityModel(true, type, value);
    }

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestSecurityModelOverride(std::optional<SecurityModel> model) noexcept
    {
        g_testSecurityModelOverride = model;
    }

    void SetTestDeployerGroupsOverride(std::optional<std::vector<std::wstring>> groups)
    {
        g_testDeployerGroupsOverride = std::move(groups);
    }
#endif

    bool ParseAuditUnwrapSuccess(bool found, unsigned long type, unsigned long value) noexcept
    {
        // Off only for an unambiguous, deliberate REG_DWORD 0. Everything
        // else - including a value that's present but malformed - keeps
        // auditing on, the direction that can't hide activity.
        return !(found && type == REG_DWORD && value == 0);
    }

    bool LoadAuditUnwrapSuccess() noexcept
    {
        HKEY key = nullptr;

        // KEY_WOW64_64KEY: see LoadGroupListValue.
        if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                kPolicyKey,
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &key) != ERROR_SUCCESS)
        {
            return ParseAuditUnwrapSuccess(false, 0, 0);
        }

        DWORD value = 0;
        DWORD type = 0;
        DWORD size = sizeof(value);

        LONG status = RegQueryValueExW(
            key,
            kAuditUnwrapSuccessValue,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);

        RegCloseKey(key);

        // A value too large for a DWORD (ERROR_MORE_DATA) or any other read
        // failure is "not found" here, i.e. auditing stays on.
        if (status != ERROR_SUCCESS || size != sizeof(value))
        {
            return ParseAuditUnwrapSuccess(false, 0, 0);
        }

        return ParseAuditUnwrapSuccess(true, type, value);
    }

    unsigned long ParseSetupMinDelayMs(bool found, unsigned long type, unsigned long value) noexcept
    {
        // Only a REG_DWORD within range is honored. Anything else keeps the
        // default: a typo must neither remove the floor nor turn application
        // startup into a long hang.
        if (found && type == REG_DWORD && value <= kMaxSetupMinDelayMs)
        {
            return value;
        }
        return kDefaultSetupMinDelayMs;
    }

    unsigned long LoadSetupMinDelayMs() noexcept
    {
        HKEY key = nullptr;

        // KEY_WOW64_64KEY: see LoadGroupListValue.
        if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                kPolicyKey,
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &key) != ERROR_SUCCESS)
        {
            return ParseSetupMinDelayMs(false, 0, 0);
        }

        DWORD value = 0;
        DWORD type = 0;
        DWORD size = sizeof(value);

        LONG status = RegQueryValueExW(
            key,
            kSetupMinDelayMsValue,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);

        RegCloseKey(key);

        // A value too large for a DWORD (ERROR_MORE_DATA) or any other read
        // failure is "not found" here, i.e. the default floor.
        if (status != ERROR_SUCCESS || size != sizeof(value))
        {
            return ParseSetupMinDelayMs(false, 0, 0);
        }

        return ParseSetupMinDelayMs(true, type, value);
    }

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestPolicyOverride(std::optional<KeyStoragePolicy> policy) noexcept
    {
        g_testPolicyOverride = policy;
    }
#endif

    KeyStoragePolicy LoadEffectivePolicy() noexcept
    {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testPolicyOverride.has_value())
        {
            return *g_testPolicyOverride;
        }
#endif

        HKEY key = nullptr;

        // KEY_WOW64_64KEY: see LoadGroupListValue.
        LONG status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kPolicyKey,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &key);

        // A missing key means the policy was never configured, so the
        // default applies. Any other failure to open it (access denied by a
        // hardened registry ACL, say) leaves a possibly configured policy -
        // maybe RequireTpm - unread, so it fails closed rather than running
        // under PreferTpm.
        if (status != ERROR_SUCCESS) {
            return KeyStoragePolicyForUnopenedKey(status);
        }

        DWORD value = 0;
        DWORD type = 0;
        DWORD size = sizeof(value);

        status = RegQueryValueExW(
            key,
            kPolicyValue,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);

        RegCloseKey(key);

        // Likewise only a missing *value* is "never configured". Any other
        // failure - e.g. a REG_QWORD or long REG_SZ that doesn't fit a DWORD
        // (ERROR_MORE_DATA) - is a value set to *something*, so it is
        // "present but invalid", never the default.
        return ParseKeyStoragePolicy(
            status != ERROR_FILE_NOT_FOUND,
            status == ERROR_SUCCESS && size == sizeof(value),
            type,
            value);
    }

    KeyStoragePolicy KeyStoragePolicyForUnopenedKey(long openStatus) noexcept
    {
        return openStatus == ERROR_FILE_NOT_FOUND || openStatus == ERROR_PATH_NOT_FOUND
            ? kDefaultPolicy
            : KeyStoragePolicy::Invalid;
    }

    KeyStoragePolicy ParseKeyStoragePolicy(bool found, bool readable, unsigned long type, unsigned long value) noexcept
    {
        if (!found) {
            return kDefaultPolicy;
        }
        // Present but unreadable as a DWORD, or of another REG_* type: it
        // was deliberately set to something, just not a policy this code
        // knows - report it rather than defaulting.
        if (!readable || type != REG_DWORD) {
            return KeyStoragePolicy::Invalid;
        }
        return ParsePolicyValue(value);
    }

} // namespace hkdfguard