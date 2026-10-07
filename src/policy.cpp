#include "policy.h"

#include <windows.h>

namespace hkdfguard {

    namespace {

        // Administratively-managed policy location.
        //
        // Intended to be deployable via:
        //
        //   Group Policy Preferences
        //   Intune
        //   DSC
        //   SCCM
        //   Manual registry configuration
        //
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

        // Security-focused default.
        //
        // Existing behavior today is:
        //   TPM if available
        //   otherwise software provider
        //
        constexpr KeyStoragePolicy kDefaultPolicy =
            KeyStoragePolicy::PreferTpm;

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        // See SetTestPolicyOverride/LoadEffectivePolicy in policy.h. Empty by
        // default, so a test binary that never calls SetTestPolicyOverride
        // still falls through to the real registry read below.
        std::optional<KeyStoragePolicy> g_testPolicyOverride;

        // Same, for LoadKeyUseGroupsPolicy.
        std::optional<std::vector<std::wstring>> g_testKeyUseGroupsOverride;
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
        // values - see policy.h's comment on LoadEffectivePolicy for why
        // that's returned rather than silently substituting the default.
        // Pulled out of LoadEffectivePolicy as its own pure function (no
        // registry I/O) so the value-to-policy mapping itself is a small,
        // obviously-correct piece independent of how the DWORD was obtained.
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

    std::vector<std::wstring> LoadKeyUseGroupsPolicy()
    {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testKeyUseGroupsOverride.has_value())
        {
            return NormalizeEntries(*g_testKeyUseGroupsOverride);
        }
#endif

        std::vector<std::wstring> result;

        HKEY key = nullptr;

        // KEY_WOW64_64KEY: makes this read the "real" 64-bit view of HKLM
        // regardless of whether this process itself is 32- or 64-bit, so a
        // 32-bit and a 64-bit hkdfguard.dll on the same machine are
        // guaranteed to see the identical policy rather than one of them
        // silently reading a WOW64-redirected Software\WOW6432Node copy.
        // (Software\Policies specifically is documented by Microsoft as
        // excluded from WOW64 registry redirection in the first place, so
        // this is defense in depth against relying on that exclusion,
        // rather than a fix for an observed divergence.)
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
            kKeyUseGroupsValue,
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
            kKeyUseGroupsValue,
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

        // KEY_WOW64_64KEY - see LoadKeyUseGroupsPolicy's comment on the
        // identical flag on its own RegOpenKeyExW call.
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

        // KEY_WOW64_64KEY - see LoadKeyUseGroupsPolicy's comment on the
        // identical flag on its own RegOpenKeyExW call.
        LONG status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kPolicyKey,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &key);

        // The key itself missing means the policy has never been
        // configured on this machine at all - that is the "missing" case
        // the default applies to, not the "present but invalid" case
        // ParsePolicyValue's Invalid sentinel is for.
        if (status != ERROR_SUCCESS) {
            return kDefaultPolicy;
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

        // Same reasoning: the *value* missing under an existing key is
        // still "never configured," not "configured wrong."
        if (status != ERROR_SUCCESS) {
            return kDefaultPolicy;
        }

        // A value of the wrong REG_* type was, unambiguously, deliberately
        // set to something - just not a DWORD - so this is the "present but
        // invalid" case: report it as such rather than defaulting.
        if (type != REG_DWORD) {
            return KeyStoragePolicy::Invalid;
        }

        return ParsePolicyValue(value);
    }

} // namespace hkdfguard