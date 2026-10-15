// This is a small hand-rolled test program, not built on a testing
// framework like GoogleTest - it's a plain `main()` that runs a sequence of
// checks and reports pass/fail for each, then exits 0 (success, the
// standard "everything's fine" exit code a shell/CI system checks) or 1
// (failure) depending on whether anything failed. CMake's `ctest` (see
// tests/CMakeLists.txt) just runs this .exe and treats exit code 0 as a
// passing test.
#include "hkdfguard.h"  // the public ABI under test
#include "kek_store.h"  // CreateKek/KekExists/OpenKekForWrap/DeleteKek - internal helpers, used directly below
#include "policy.h"     // SetTestPolicyOverride - internal test-only seam, used directly below
#include "ecdh_hkdf.h"  // IsValidP256Point, DeriveWrappingKey - the point gate and the derivation, tested directly below
#include "hash_to_curve.h" // PayloadEcdhPoint - checked against the Linux implementation's vectors below
#include "key_file.h"   // ReadWrappedKeyFile - hkdfguard_open_file's implementation, called directly in section 24c
#include "errors.h"     // HkdfGuardError - caught by PointGateResult and CodeOf below to read error codes
#include "key_acl.h"    // ValidateKeyUseGroups - vets the key-use policy list without touching any key

#include <aclapi.h>  // SetEntriesInAclW - section 25d widens an existing KEK's ACL
#include <winioctl.h> // FSCTL_SET_REPARSE_POINT - section 24c plants a junction
#include <sddl.h>    // ConvertStringSecurityDescriptorToSecurityDescriptorW - section 28
#include <algorithm> // std::equal - section 24c
#include <chrono>    // steady_clock - section 0c2 times the setup floor
#include <thread>    // std::thread - section 0c2 checks setup calls are serialized
#include <cstdio>
#include <cstring>
#include <stdexcept> // std::exception, caught in CleanupKek and CheckPolicyCreatesKek
#include <vector>
#include <string>

// Anonymous namespace: everything in this block is private to this one
// file (see aes_gcm.cpp for the fuller explanation of what this construct
// does) - not that it matters much in a standalone test .exe with no other
// translation units to collide with, but it's the same convention used
// throughout the rest of the project.
namespace {

// A running count of failed checks, incremented by Check() below and read
// back in main() to decide the process's final exit code.
int g_failures = 0;

// The test harness's one primitive: print PASS or FAIL for a labeled
// condition, and keep count of failures. `const char* what` is a
// human-readable label describing what's being checked, printed alongside
// the result.
void Check(bool condition, const char* what) {
    if (condition) {
        std::printf("[PASS] %s\n", what);
    } else {
        std::printf("[FAIL] %s\n", what);
        ++g_failures;
    }
}

// Builds a deterministic (not random) 32-byte test DEK: each byte is some
// simple, distinct function of its index, purely so bugs that shuffle or
// truncate bytes are easy to spot rather than every byte looking the same.
// Returned as a `std::vector<uint8_t>` - a plain (non-secure) dynamic byte
// buffer is fine here since this is test data, not a real secret to
// protect.
std::vector<uint8_t> MakeDek() {
    std::vector<uint8_t> dek(HKDFGUARD_DEK_LEN);
    for (int i = 0; i < HKDFGUARD_DEK_LEN; ++i) {
        dek[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 7 + 11);
    }
    return dek;
}

// Used to verify the "output buffer zeroed on failure" requirement: scans
// `len` bytes starting at `buf` and returns true only if every single one
// is 0.
bool AllZero(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != 0) return false;
    }
    return true;
}

// Two distinct service names used across the checks below, each in both
// its UTF-8 form (`char`, passed to the public ABI functions) and wide
// form (`wchar_t`, passed to the internal DeleteKek for cleanup - see
// kek_store.h). Because both are plain ASCII text, the UTF-8 bytes and the
// UTF-16 code units happen to correspond 1:1 character-for-character, so
// writing out both literals by hand here (rather than converting one from
// the other at runtime) is a safe shortcut for test code specifically.
//
// Only alphanumeric characters and '.' are used - hkdfguard.cpp's
// IsValidServiceChar rejects everything else, including '-' (see check 17
// below).
constexpr char kService[] = "hkdfguardwin.test.service";
constexpr wchar_t kServiceWide[] = L"hkdfguardwin.test.service";
constexpr char kServiceOther[] = "hkdfguardwin.test.service.other";
constexpr wchar_t kServiceOtherWide[] = L"hkdfguardwin.test.service.other";

// Dedicated service names for the hkdfguard_kek_exists/hkdfguard_create_kek
// lifecycle checks (0) and the key-use group policy checks (0d) below -
// kept separate from kService so those checks can rely on the service
// having no KEK yet at the point they run.
constexpr char kServiceLifecycle[] = "hkdfguardwin.test.lifecycle";
constexpr wchar_t kServiceLifecycleWide[] = L"hkdfguardwin.test.lifecycle";
constexpr char kServiceNoKek[] = "hkdfguardwin.test.nokek";
constexpr char kServiceUseGroups[] = "hkdfguardwin.test.usegroups";
constexpr wchar_t kServiceUseGroupsWide[] = L"hkdfguardwin.test.usegroups";

// Deletes the KEK created for `service` during this test run, so repeated
// runs don't accumulate persisted keys in the user's key storage. Uses the
// internal kek_store API directly (not part of the public C ABI). The KEK
// only exists under whichever single provider actually created it
// (`provider_type`, read back from a payload wrapped for this service), so
// only that provider is queried.
void CleanupKek(const wchar_t* service_wide, uint8_t provider_type, const char* label) {
    try {
        // `std::wstring(service_wide)` constructs a std::wstring by copying
        // from the `const wchar_t*` literal - DeleteKek's parameter type is
        // `const std::wstring&` (see kek_store.h), so this conversion has
        // to happen somewhere, and it's simplest to do it right here at the
        // one call site rather than changing DeleteKek's signature just for
        // this test.
        hkdfguard::DeleteKek(std::wstring(service_wide), provider_type, hkdfguard::kCurrentKeyId);
        std::printf("[INFO] cleaned up KEK for %s\n", label);
    } catch (const std::exception& e) {
        // Cleanup failing doesn't fail the test itself (it's not what this
        // test is checking) - it's just surfaced as a warning so it's
        // visible in the test log if something about deletion is broken.
        // `e.what()` retrieves the message HkdfGuardError's constructor
        // stored via std::runtime_error - see errors.h.
        std::printf("[WARN] failed to clean up KEK for %s: %s\n", label, e.what());
    }
}

// Forces LoadEffectivePolicy() to return `policy` for the duration of this
// call (via the test-only SetTestPolicyOverride seam - see policy.h), then
// exercises CreateKek/KekExists/OpenKekForWrap directly against the
// internal kek_store API - the same internal API CleanupKek's DeleteKek
// call above uses, bypassing HkdfGuardV1.dll entirely - so this test can
// cover all three KeyStoragePolicy branches deterministically, regardless
// of this machine's actual registry policy or TPM/vTPM availability.
// Cleans up whatever it creates before returning, and always clears the
// override on the way out.
//
// `tpmMayBeUnavailable` accepts CreateKek throwing as a legitimate outcome
// rather than a test failure: RequireTpm's documented contract is "use the
// TPM-backed provider or fail outright, never fall back to software," and
// this test has no way to know whether the machine it's running on
// actually has a TPM/vTPM.
void CheckPolicyCreatesKek(
    hkdfguard::KeyStoragePolicy policy,
    const wchar_t* serviceWide,
    const std::string& label,
    bool tpmMayBeUnavailable) {
    hkdfguard::SetTestPolicyOverride(policy);

    try {
        hkdfguard::CreateKek(serviceWide);
        Check(true, (label + ": create_kek succeeds").c_str());

        Check(hkdfguard::KekExists(serviceWide), (label + ": kek_exists reports true afterward").c_str());

        hkdfguard::ResolvedKek kek = hkdfguard::OpenKekForWrap(serviceWide);
        std::printf("    (%s: provider_type = %d)\n", label.c_str(), kek.provider_type);

        if (policy == hkdfguard::KeyStoragePolicy::RequireTpm) {
            Check(
                kek.provider_type == hkdfguard::kProviderTypeTpm,
                (label + ": RequireTpm never falls back to the software provider").c_str());
        }
        if (policy == hkdfguard::KeyStoragePolicy::SoftwareOnly) {
            Check(
                kek.provider_type == hkdfguard::kProviderTypeSoftware,
                (label + ": SoftwareOnly uses the software provider").c_str());
        }

        hkdfguard::DeleteKek(serviceWide, kek.provider_type, hkdfguard::kCurrentKeyId);
    } catch (const std::exception& e) {
        if (tpmMayBeUnavailable) {
            std::printf(
                "[INFO] %s: create_kek failed - acceptable without real TPM/vTPM hardware on this machine: %s\n",
                label.c_str(), e.what());
        } else {
            Check(false, (label + ": create_kek should not fail on this policy").c_str());
            std::printf("    (%s)\n", e.what());
        }
    }

    hkdfguard::SetTestPolicyOverride(std::nullopt);
}

// Generates a genuine, freshly-random P-256 public point (raw X||Y, 64
// bytes) via BCrypt, as known-good input for the IsValidP256Point checks.
// Returns an empty vector if any BCrypt step fails, which the caller
// reports as its own failed check rather than silently skipping the section.
std::vector<uint8_t> MakeValidP256Point() {
    hkdfguard::ScopedBCryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0))) return {};
    hkdfguard::ScopedBCryptKey key;
    if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(alg.get(), key.put(), 256, 0))) return {};
    if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(key.get(), 0))) return {};
    ULONG cb = 0;
    if (!BCRYPT_SUCCESS(BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &cb, 0))) return {};
    std::vector<uint8_t> blob(cb);
    if (!BCRYPT_SUCCESS(BCryptExportKey(key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), cb, &cb, 0))) return {};
    if (blob.size() < sizeof(BCRYPT_ECCKEY_BLOB) + hkdfguard::kPublicPointLen) return {};
    return std::vector<uint8_t>(
        blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB),
        blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + hkdfguard::kPublicPointLen);
}

// Runs the point gate on `point`: 1 if it accepted the point, 0 if it
// rejected it, or the thrown HKDFGUARD_* code (negative) if the gate itself
// failed, or a sentinel if something other than HkdfGuardError escaped.
int32_t PointGateResult(const std::vector<uint8_t>& point) {
    try {
        return hkdfguard::IsValidP256Point(point.data()) ? 1 : 0;
    } catch (const hkdfguard::HkdfGuardError& e) {
        return e.code();
    } catch (...) {
        return -9999;
    }
}

// Runs the internal CreateKek - which reads the key-use group list through
// the same test-only override seam CheckPolicyCreatesKek uses for the
// storage policy - and returns the HKDFGUARD_* code it produced. Has to be
// the internal call: the DLL behind hkdfguard_create_kek reads the real
// registry and can't see this process's override.
int32_t InternalCreateKekResult(const wchar_t* serviceWide) {
    try {
        hkdfguard::CreateKek(serviceWide);
        return HKDFGUARD_OK;
    } catch (const hkdfguard::HkdfGuardError& e) {
        return e.code();
    } catch (...) {
        return -9999;
    }
}

// Picks a real, narrow local group for the key-use-policy accept case: the
// first candidate that resolves on this machine. The test can't hardcode
// one - edition-dependent groups such as "Cryptographic Operators" or
// "Backup Operators" don't exist on Windows Home, for instance.
// BUILTIN\Administrators is the last resort because it exists everywhere;
// it's already granted full control by ApplyKeyAcl regardless, but the
// policy path still has to resolve, vet and grant it like any other entry.
std::wstring PickNarrowGroup() {
    for (const wchar_t* candidate : {L"Performance Log Users", L"Administrators"}) {
        DWORD sidSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE type;
        LookupAccountNameW(nullptr, candidate, nullptr, &sidSize, nullptr, &domainSize, &type);
        if (sidSize != 0) {
            return candidate;
        }
    }
    return L"Administrators";
}

// ---- Helpers for sections 26-29 (fault injection, pre-planted keys, ACL ----
//      entries, golden payload). Elevation-dependent checks in those
//      sections print [SKIP] instead of failing when not elevated, so a
//      non-elevated run only fails on real problems.

void Skip(const char* what) {
    std::printf("[SKIP] %s\n", what);
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    bool elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
                    elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

// Whether the real Platform Crypto Provider opens on this machine.
bool HasTpmProvider() {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS) return false;
    NCryptFreeObject(prov);
    return true;
}

// The HKDFGUARD_* code a call produces: OK if it returns normally, the
// HkdfGuardError's code if it throws one, a sentinel otherwise.
template <typename F>
int32_t CodeOf(F&& f) {
    try {
        f();
        return HKDFGUARD_OK;
    } catch (const hkdfguard::HkdfGuardError& e) {
        return e.code();
    } catch (...) {
        return -9999;
    }
}

// The persisted key name kek_store.cpp's KeyName builds for a service.
std::wstring KekNameFor(const wchar_t* serviceWide) {
    return std::wstring(L"hkdfguardwin_") + serviceWide + L"_v1";
}

// Whether a machine key by this name exists on `provider`, opened directly
// rather than through the library, so the answer can't be affected by the
// library behavior under test.
bool MachineKeyExists(LPCWSTR provider, const std::wstring& keyName) {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, provider, 0) != ERROR_SUCCESS) return false;
    NCRYPT_KEY_HANDLE key = 0;
    SECURITY_STATUS st = NCryptOpenKey(prov, &key, keyName.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
    if (key) NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return st == ERROR_SUCCESS;
}

void DeleteMachineKeyQuiet(LPCWSTR provider, const std::wstring& keyName) {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, provider, 0) != ERROR_SUCCESS) return;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenKey(prov, &key, keyName.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        NCryptDeleteKey(key, 0); // frees the handle even on failure
    }
    NCryptFreeObject(prov);
}

// Pre-plants a machine key on the Software KSP under `keyName`, the way an
// administrator (or an attacker with admin rights) could before the library
// ever provisions that service. `curve` is set only for the generic "ECDH"
// algorithm; `exportable` grants plaintext export.
bool PlantSoftwareKey(const std::wstring& keyName, LPCWSTR algorithm, LPCWSTR curve, bool exportable) {
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return false;
    NCRYPT_KEY_HANDLE key = 0;
    bool ok = NCryptCreatePersistedKey(prov, &key, algorithm, keyName.c_str(), 0,
                                       NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS;
    if (ok && curve != nullptr) {
        ok = NCryptSetProperty(key, NCRYPT_ECC_CURVE_NAME_PROPERTY,
                               reinterpret_cast<PBYTE>(const_cast<wchar_t*>(curve)),
                               static_cast<DWORD>((wcslen(curve) + 1) * sizeof(wchar_t)), 0) == ERROR_SUCCESS;
    }
    if (ok && exportable) {
        DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        ok = NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&policy),
                               sizeof(policy), 0) == ERROR_SUCCESS;
    }
    if (ok) {
        ok = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS;
    }
    if (key) NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return ok;
}

// Replaces an existing Software KSP machine key's DACL with one written in
// SDDL, as an administrator could after creation.
bool SetSoftwareKeyDacl(const std::wstring& keyName, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, &sdSize)) return false;
    bool ok = false;
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS &&
        NCryptOpenKey(prov, &key, keyName.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        ok = NCryptSetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, static_cast<PBYTE>(sd), sdSize,
                               DACL_SECURITY_INFORMATION) == ERROR_SUCCESS;
    }
    if (key) NCryptFreeObject(key);
    if (prov) NCryptFreeObject(prov);
    LocalFree(sd);
    return ok;
}

// Helpers for section 24c (hkdfguard_open_file). The ABI takes UTF-8 paths,
// while the test builds them with the wide Win32 APIs.
std::string ToUtf8(const std::wstring& wide) {
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), len, nullptr, nullptr);
    return out;
}

bool WriteTestFile(const std::wstring& path, const std::vector<uint8_t>& bytes) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = bytes.empty() ||
              (WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
               written == bytes.size());
    CloseHandle(file);
    return ok;
}

// Text forms of a DEK, for section 24c's plaintext-key checks - written
// here independently of src/key_file.cpp's detector.
std::string HexOf(const std::vector<uint8_t>& bytes, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string out;
    for (uint8_t b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 0xF];
    }
    return out;
}

std::string Base64Of(const std::vector<uint8_t>& bytes, bool url_safe, bool pad) {
    const char* alphabet = url_safe ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                                    : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        uint32_t v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
        out += alphabet[(v >> 6) & 63];
        out += alphabet[v & 63];
    }
    size_t rest = bytes.size() - i;
    if (rest > 0) {
        uint32_t v = bytes[i] << 16;
        if (rest == 2) v |= bytes[i + 1] << 8;
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
        if (rest == 2) out += alphabet[(v >> 6) & 63];
        if (pad) out += (rest == 2) ? "=" : "==";
    }
    return out;
}

std::vector<uint8_t> BytesOf(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }

// This process's user SID as an SDDL string, for section 24d's descriptors.
std::wstring CurrentUserSidString() {
    DWORD size = 0;
    GetTokenInformation(GetCurrentProcessToken(), TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    wchar_t* text = nullptr;
    if (size == 0 || !GetTokenInformation(GetCurrentProcessToken(), TokenUser, buffer.data(), size, &size) ||
        !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) {
        return L"";
    }
    std::wstring sid(text);
    LocalFree(text);
    return sid;
}

// Replaces an existing file's or folder's DACL with `sddl`'s, protected
// from inheritance, so exactly those ACEs apply. (Setting an owner other
// than oneself needs privileges, so only the DACL is set.)
bool SetProtectedDacl(const std::wstring& path, const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return false;
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) &&
              SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                    nullptr, dacl, nullptr) == ERROR_SUCCESS;
    LocalFree(sd);
    return ok;
}

// The 8.3 short name of `path`, or empty if it has none. Where the volume
// doesn't generate short names (8.3 creation is off by default on
// container and many server volumes), one is assigned explicitly with
// SetFileShortNameW, which works regardless of that setting but needs an
// elevated process (SeRestorePrivilege) - so section 24c's short-name
// checks run on every elevated run instead of only on some machines.
std::wstring ShortNameFor(const std::wstring& path, const wchar_t* assign_if_missing) {
    // Only `path`'s own last component counts: GetShortPathName shortens
    // every folder above it too, so a short *folder* name alone must not be
    // mistaken for the item itself having one.
    auto leaf = [](const std::wstring& p) { return p.substr(p.find_last_of(L'\\') + 1); };
    auto current = [&]() -> std::wstring {
        wchar_t buf[MAX_PATH + 1] = {};
        DWORD len = GetShortPathNameW(path.c_str(), buf, MAX_PATH + 1);
        if (len == 0 || len > MAX_PATH) return {};
        std::wstring s(buf, len);
        return CompareStringOrdinal(leaf(s).c_str(), -1, leaf(path).c_str(), -1, TRUE) == CSTR_EQUAL ? std::wstring() : s;
    };
    std::wstring found = current();
    if (!found.empty()) return found;

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        // L"SeRestorePrivilege": SE_RESTORE_NAME is narrow in this non-UNICODE target.
        if (LookupPrivilegeValueW(nullptr, L"SeRestorePrivilege", &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(token);
    }
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return {};
    SetFileShortNameW(handle, assign_if_missing);
    CloseHandle(handle);
    return current();
}

// Creates an NTFS junction (mount-point reparse point) at `junction`
// pointing at the directory `target`, the way `mklink /J` does. Junctions
// are the link type a non-administrator can create, so section 24c uses one
// to show a planted link in the key folder is refused.
bool CreateJunction(const std::wstring& junction, const std::wstring& target) {
    // The mount-point form of REPARSE_DATA_BUFFER, which only the driver
    // kit's ntifs.h declares.
    struct MountPointReparse {
        ULONG ReparseTag;
        USHORT ReparseDataLength;
        USHORT Reserved;
        USHORT SubstituteNameOffset;
        USHORT SubstituteNameLength;
        USHORT PrintNameOffset;
        USHORT PrintNameLength;
        WCHAR PathBuffer[1];
    };
    const std::wstring substitute = L"\\??\\" + target; // NT object-manager form
    const size_t names_bytes = (substitute.size() + 1 + target.size() + 1) * sizeof(WCHAR);
    std::vector<uint8_t> buffer(offsetof(MountPointReparse, PathBuffer) + names_bytes);
    auto* data = reinterpret_cast<MountPointReparse*>(buffer.data());
    data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    data->ReparseDataLength = static_cast<USHORT>(8 + names_bytes); // the four USHORTs + names
    data->SubstituteNameOffset = 0;
    data->SubstituteNameLength = static_cast<USHORT>(substitute.size() * sizeof(WCHAR));
    data->PrintNameOffset = static_cast<USHORT>((substitute.size() + 1) * sizeof(WCHAR));
    data->PrintNameLength = static_cast<USHORT>(target.size() * sizeof(WCHAR));
    std::memcpy(data->PathBuffer, substitute.c_str(), (substitute.size() + 1) * sizeof(WCHAR));
    std::memcpy(data->PathBuffer + substitute.size() + 1, target.c_str(), (target.size() + 1) * sizeof(WCHAR));

    if (!CreateDirectoryW(junction.c_str(), nullptr)) return false;
    HANDLE handle = CreateFileW(junction.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(junction.c_str());
        return false;
    }
    DWORD returned = 0;
    const bool ok = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(), static_cast<DWORD>(buffer.size()),
                                    nullptr, 0, &returned, nullptr) != FALSE;
    CloseHandle(handle);
    if (!ok) RemoveDirectoryW(junction.c_str());
    return ok;
}

std::vector<uint8_t> FromHex(const char* hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; hex[i] != '\0' && hex[i + 1] != '\0'; i += 2) {
        auto nibble = [](char c) -> uint8_t {
            return static_cast<uint8_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
        };
        out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

std::string ToHex(const std::vector<uint8_t>& bytes) {
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

// A fixed P-256 KEK for the golden payload (section 29), generated once with
// BCrypt and frozen here. Test-only key: it protects nothing.
constexpr char kGoldenKekX[] = "a55c04e4b2113126f3ea5244034decd0c0c9f55cd25d2e0396a365a7e265082f";
constexpr char kGoldenKekY[] = "4ab897ae67c14350a0213b0a67d416472aa053a16992018ac4d874dc8529569d";
constexpr char kGoldenKekD[] = "9639379738995d1017b34a6398b444cf9cd0c82acb0dc0cd5d40c91b513f4e90";
constexpr char kGoldenSalt[] = "4242424242424242424242424242424242424242424242424242424242424242";
// H(kGoldenSalt): produced by the Linux implementation's payload_ecdh_point
// on the RustCrypto p256 0.14 crate - NOT by this project's
// hash_to_curve.cpp - so the golden payload pins Windows to the Linux
// hash-to-curve as well as to the rest of the construction.
constexpr char kGoldenPointX[] = "23705f112056934aef2059c9c3ffa610ccb2f070d266d4ffa06210d37e9a0de5";
constexpr char kGoldenPointY[] = "df412b76994469fb7c27385e2d8f389f3da716076c79a19bb57249c9755f032a";
constexpr char kGoldenNonce[] = "977bcd31c21caffe32bc3f6a";
constexpr char kGoldenService[] = "hkdfguardwin.test.golden";
constexpr wchar_t kGoldenServiceWide[] = L"hkdfguardwin.test.golden";

// The golden WrappedDekV1 payload: MakeDek() wrapped under the golden KEK
// for kGoldenService, with the golden salt and nonce. Frozen. If a code
// change makes this stop unwrapping, that change breaks every payload
// already deployed - fix the change, never this constant.
constexpr char kGoldenPayloadHex[] =
    "010200000100000042424242424242424242424242424242424242424242424242424242"
    "42424242977bcd31c21caffe32bc3f6a0e565cb000978ea50f780da588daece0022d5929"
    "f9404d50f87daf7c78383cd97fcd39e16d6890acb44cf9306b945a0838d1ef5a8d210826"
    "eeabdd24b8676833717a7ecedb999ae3b9b3012a0d4353c4";

// BCRYPT_ECCPRIVATE_BLOB for a P-256 ECDH key from hex X, Y, d.
std::vector<uint8_t> EccPrivateBlob(const char* x, const char* y, const char* d) {
    std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB));
    auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    header->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
    header->cbKey = 32;
    for (const char* part : {x, y, d}) {
        std::vector<uint8_t> bytes = FromHex(part);
        blob.insert(blob.end(), bytes.begin(), bytes.end());
    }
    return blob;
}

bool HmacSha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
    out.assign(64, 0);
    return BCRYPT_SUCCESS(BCryptHash(BCRYPT_HMAC_SHA512_ALG_HANDLE, const_cast<PUCHAR>(key.data()),
                                     static_cast<ULONG>(key.size()), const_cast<PUCHAR>(data.data()),
                                     static_cast<ULONG>(data.size()), out.data(), 64));
}

// The wrapping key, derived from the *documented* construction written
// independently of src/ (no library function is called): Z = ECDH(KEK d,
// point) as big-endian X -> HKDF-SHA512 (RFC 5869, salt = the payload salt,
// info = "HkdfGuardWin-DEK-Wrap-v1" || KEK X||Y) -> first 32 bytes. Shared by
// the golden payload and the forgery test (section 24b). `kekPub` is the
// KEK's public key (X||Y). With `kekD` (the KEK's private scalar) this is
// the genuine derivation, Z = ECDH(d, point). Without it - `kekD` null - Z
// is instead ECDH(e, KEK public) for a fresh random e: exactly what someone
// holding only the KEK's public key can compute, as the earlier ECIES
// construction allowed.
bool IndependentWrappingKey(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& point,
                            const std::vector<uint8_t>& kekPub, const std::vector<uint8_t>* kekD,
                            std::vector<uint8_t>& aesKey) {
    BCRYPT_ALG_HANDLE ecdh = BCRYPT_ECDH_P256_ALG_HANDLE;
    hkdfguard::ScopedBCryptKey priv, pub;
    if (kekD != nullptr) {
        std::vector<uint8_t> kekBlob(sizeof(BCRYPT_ECCKEY_BLOB));
        auto* privHeader = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(kekBlob.data());
        privHeader->dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        privHeader->cbKey = 32;
        kekBlob.insert(kekBlob.end(), kekPub.begin(), kekPub.end());
        kekBlob.insert(kekBlob.end(), kekD->begin(), kekD->end());
        if (!BCRYPT_SUCCESS(BCryptImportKeyPair(ecdh, nullptr, BCRYPT_ECCPRIVATE_BLOB, priv.put(), kekBlob.data(),
                                                static_cast<ULONG>(kekBlob.size()), 0))) {
            return false;
        }
    } else if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(ecdh, priv.put(), 256, 0)) ||
               !BCRYPT_SUCCESS(BCryptFinalizeKeyPair(priv.get(), 0))) {
        return false;
    }
    std::vector<uint8_t> pubBlob(sizeof(BCRYPT_ECCKEY_BLOB));
    auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pubBlob.data());
    header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    header->cbKey = 32;
    const std::vector<uint8_t>& peer = kekD != nullptr ? point : kekPub;
    pubBlob.insert(pubBlob.end(), peer.begin(), peer.end());
    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(ecdh, nullptr, BCRYPT_ECCPUBLIC_BLOB, pub.put(), pubBlob.data(),
                                            static_cast<ULONG>(pubBlob.size()), 0))) {
        return false;
    }
    hkdfguard::ScopedBCryptSecret secret;
    if (!BCRYPT_SUCCESS(BCryptSecretAgreement(priv.get(), pub.get(), secret.put(), 0))) return false;
    std::vector<uint8_t> z(32);
    ULONG got = 0;
    if (!BCRYPT_SUCCESS(BCryptDeriveKey(secret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, z.data(), 32, &got, 0)) ||
        got != 32) {
        return false;
    }
    // BCRYPT_KDF_RAW_SECRET is little-endian; the construction uses the
    // conventional big-endian X coordinate (as the Linux implementation does).
    std::reverse(z.begin(), z.end());

    const char context[] = "HkdfGuardWin-DEK-Wrap-v1";
    std::vector<uint8_t> info(context, context + sizeof(context) - 1);
    info.insert(info.end(), kekPub.begin(), kekPub.end());

    std::vector<uint8_t> prk, t1;
    if (!HmacSha512(salt, z, prk)) return false;
    std::vector<uint8_t> t1Input = info;
    t1Input.push_back(0x01);
    if (!HmacSha512(prk, t1Input, t1)) return false;
    aesKey.assign(t1.begin(), t1.begin() + 32);
    return true;
}

// Seals `dek` into a WrappedDekV1 payload with a given wrapping key, salt and
// nonce, independently of src/: AAD = header (bytes 0..39: version,
// provider, reserved, KeyId, salt) || SHA-256(KEK X||Y) || service, then the
// documented 132-byte layout. `providerType` must name the provider the KEK
// actually lives on (1 = TPM, 2 = Software KSP): unwrap routes by it, so a
// wrong value sends unwrap looking for the KEK on the wrong provider.
bool SealPayloadIndependently(const std::vector<uint8_t>& aesKey, const std::vector<uint8_t>& salt,
                              const std::vector<uint8_t>& nonceIn, const char* service,
                              const std::vector<uint8_t>& kekPub, const std::vector<uint8_t>& dek,
                              uint8_t providerType, std::vector<uint8_t>& payload) {
    // CNG takes non-const input pointers; work on copies.
    std::vector<uint8_t> pub = kekPub, key = aesKey;
    std::vector<uint8_t> fingerprint(32);
    if (!BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, pub.data(),
                                   static_cast<ULONG>(pub.size()), fingerprint.data(), 32))) {
        return false;
    }
    std::vector<uint8_t> header = {0x01, providerType, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}; // version, provider, reserved, KeyId 1 (LE)
    header.insert(header.end(), salt.begin(), salt.end());
    std::vector<uint8_t> aad = header;
    aad.insert(aad.end(), fingerprint.begin(), fingerprint.end());
    aad.insert(aad.end(), service, service + std::strlen(service));

    hkdfguard::ScopedBCryptAlg aes;
    hkdfguard::ScopedBCryptKey aesHandle;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(aes.put(), BCRYPT_AES_ALGORITHM, nullptr, 0)) ||
        !BCRYPT_SUCCESS(BCryptSetProperty(aes.get(), BCRYPT_CHAINING_MODE,
                                          reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) ||
        !BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(aes.get(), aesHandle.put(), nullptr, 0, key.data(), 32, 0))) {
        return false;
    }
    std::vector<uint8_t> nonce = nonceIn;
    std::vector<uint8_t> plaintext = dek;
    std::vector<uint8_t> ciphertext(32), tag(16);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info_gcm;
    BCRYPT_INIT_AUTH_MODE_INFO(info_gcm);
    info_gcm.pbNonce = nonce.data();
    info_gcm.cbNonce = 12;
    info_gcm.pbTag = tag.data();
    info_gcm.cbTag = 16;
    info_gcm.pbAuthData = aad.data();
    info_gcm.cbAuthData = static_cast<ULONG>(aad.size());
    ULONG written = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(aesHandle.get(), plaintext.data(), 32, &info_gcm, nullptr, 0, ciphertext.data(), 32,
                                      &written, 0)) ||
        written != 32) {
        return false;
    }

    payload = header; // the same header bytes the AAD covers
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    payload.insert(payload.end(), tag.begin(), tag.end());
    payload.insert(payload.end(), fingerprint.begin(), fingerprint.end());
    return payload.size() == HKDFGUARD_WRAPPED_LEN;
}

// The golden payload, built entirely from the constants above.
bool BuildGoldenPayloadIndependently(std::vector<uint8_t>& payload) {
    std::vector<uint8_t> salt = FromHex(kGoldenSalt);
    std::vector<uint8_t> point = FromHex(kGoldenPointX), pointY = FromHex(kGoldenPointY);
    point.insert(point.end(), pointY.begin(), pointY.end());
    std::vector<uint8_t> kekPub = FromHex(kGoldenKekX), kekY = FromHex(kGoldenKekY);
    kekPub.insert(kekPub.end(), kekY.begin(), kekY.end());
    std::vector<uint8_t> kekD = FromHex(kGoldenKekD);
    std::vector<uint8_t> aesKey;
    return IndependentWrappingKey(salt, point, kekPub, &kekD, aesKey) &&
           SealPayloadIndependently(aesKey, salt, FromHex(kGoldenNonce), kGoldenService, kekPub, MakeDek(),
                                    hkdfguard::kProviderTypeSoftware, payload); // the golden KEK is imported on the Software KSP
}

// Persists the golden KEK on the Software KSP as a machine key under the
// name the library would use for kGoldenService, non-exportable, usable for
// key agreement - so the shipped DLL's unwrap can find and use it.
bool ImportGoldenKek() {
    std::vector<uint8_t> blob = EccPrivateBlob(kGoldenKekX, kGoldenKekY, kGoldenKekD);
    std::wstring name = KekNameFor(kGoldenServiceWide);
    NCryptBuffer nameBuffer{};
    nameBuffer.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
    nameBuffer.cbBuffer = static_cast<ULONG>((name.size() + 1) * sizeof(wchar_t));
    nameBuffer.pvBuffer = const_cast<wchar_t*>(name.c_str());
    NCryptBufferDesc params{};
    params.ulVersion = NCRYPTBUFFER_VERSION;
    params.cBuffers = 1;
    params.pBuffers = &nameBuffer;

    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return false;
    NCRYPT_KEY_HANDLE key = 0;
    bool ok = NCryptImportKey(prov, 0, BCRYPT_ECCPRIVATE_BLOB, &params, &key, blob.data(),
                              static_cast<DWORD>(blob.size()),
                              NCRYPT_MACHINE_KEY_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS;
    if (ok) {
        DWORD exportPolicy = 0;
        ok = NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&exportPolicy),
                               sizeof(exportPolicy), 0) == ERROR_SUCCESS;
    }
    if (ok) {
        DWORD usage = NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
        NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0);
        ok = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS;
    }
    if (key) NCryptFreeObject(key);
    NCryptFreeObject(prov);
    SecureZeroMemory(blob.data(), blob.size());
    return ok;
}

} // namespace

int main() {
    std::vector<uint8_t> dek = MakeDek();
    int32_t rc;

    // ---- -2. The AuditUnwrapSuccess switch: only an explicit REG_DWORD 0 ----
    //           turns the unwrap-success event off; absent, non-zero, wrong
    //           type, or unreadable all keep it on. Tested on the pure rule
    //           (no registry I/O), since setting the real HKLM policy value
    //           would change this machine's configuration.
    Check(hkdfguard::ParseAuditUnwrapSuccess(false, 0, 0), "AuditUnwrapSuccess absent: unwrap auditing on");
    Check(!hkdfguard::ParseAuditUnwrapSuccess(true, REG_DWORD, 0), "AuditUnwrapSuccess REG_DWORD 0: unwrap auditing off");
    Check(hkdfguard::ParseAuditUnwrapSuccess(true, REG_DWORD, 1), "AuditUnwrapSuccess REG_DWORD 1: unwrap auditing on");
    Check(hkdfguard::ParseAuditUnwrapSuccess(true, REG_DWORD, 7), "AuditUnwrapSuccess any other non-zero DWORD: unwrap auditing on");
    Check(hkdfguard::ParseAuditUnwrapSuccess(true, REG_SZ, 0), "AuditUnwrapSuccess of the wrong type (even \"0\"): unwrap auditing stays on");
    Check(hkdfguard::ParseAuditUnwrapSuccess(true, REG_QWORD, 0), "AuditUnwrapSuccess REG_QWORD 0: unwrap auditing stays on");
    // The real registry read must agree with "absent" on a machine where the
    // policy isn't set - true on this test machine unless someone set it.
    std::printf("    (this machine's effective AuditUnwrapSuccess: %s)\n",
                hkdfguard::LoadAuditUnwrapSuccess() ? "on" : "off");

#if defined(_MSC_VER)
    // ---- -1. The DLL carries the event log message table. ----
    // The MSI registers HkdfGuardV1.dll as the event source's
    // EventMessageFile, so Event Viewer renders each event by looking its ID
    // up in the DLL's message table. Missing IDs would show as "the
    // description for Event ID ... cannot be found". Checked against the
    // DLL this test actually loaded (it links against it), for every ID
    // event_log.cpp writes. Needs no elevation and no KEK. MSVC builds
    // only: other toolchains don't compile the message table at all.
    {
        HMODULE dll = GetModuleHandleW(L"HkdfGuardV1.dll");
        Check(dll != nullptr, "the HkdfGuard DLL is loaded in this test process");
        const DWORD ids[] = {1000, 1001, 1002, 1003, 2000, 2002, 2003, 2004, 2005, 2006, 2007};
        bool allPresent = dll != nullptr;
        for (DWORD id : ids) {
            if (dll == nullptr) break;
            // With FORMAT_MESSAGE_ARGUMENT_ARRAY the last parameter is
            // really an array of insertion pointers, typed as va_list*.
            DWORD_PTR args[1] = {reinterpret_cast<DWORD_PTR>(L"probe-text")};
            wchar_t text[64] = {};
            DWORD n = FormatMessageW(
                FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ARGUMENT_ARRAY, dll, id,
                MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), text, 64,
                reinterpret_cast<va_list *>(args));
            if (n == 0 || std::wcsncmp(text, L"probe-text", 10) != 0) {
                std::printf("    (event ID %lu: FormatMessage returned %lu, error %lu)\n", id, n, GetLastError());
                allPresent = false;
            }
        }
        Check(allPresent, "the DLL's message table renders every event ID event_log.cpp writes");
    }
#endif

    // ---- 0. hkdfguard_kek_exists / hkdfguard_create_kek lifecycle. ----
    // kServiceLifecycle has never been used before this point in the test,
    // so kek_exists is expected to genuinely report "not found" here, not
    // just "didn't error."
    int32_t lifecycle_exists = -1;
    rc = hkdfguard_kek_exists(kServiceLifecycle, &lifecycle_exists);
    Check(rc == HKDFGUARD_OK, "kek_exists succeeds for a service with no KEK yet");
    Check(lifecycle_exists == 0, "kek_exists reports false before the KEK is created");

    rc = hkdfguard_create_kek(kServiceLifecycle);
    Check(rc == HKDFGUARD_OK, "create_kek provisions a new KEK");

    lifecycle_exists = -1;
    rc = hkdfguard_kek_exists(kServiceLifecycle, &lifecycle_exists);
    Check(rc == HKDFGUARD_OK, "kek_exists succeeds after the KEK is created");
    Check(lifecycle_exists == 1, "kek_exists reports true after the KEK is created");

    // create_kek is safe to call again for an already-provisioned service:
    // it verifies rather than failing or re-creating.
    rc = hkdfguard_create_kek(kServiceLifecycle);
    Check(rc == HKDFGUARD_OK, "create_kek is idempotent for an already-provisioned service");

    // wrap now succeeds, since create_kek has provisioned the KEK it needs.
    std::vector<uint8_t> lifecycle_wrapped(HKDFGUARD_WRAPPED_LEN);
    int32_t lifecycle_wrapped_len = static_cast<int32_t>(lifecycle_wrapped.size());
    rc = hkdfguard_wrap_dek(
        kServiceLifecycle, dek.data(), static_cast<int32_t>(dek.size()), lifecycle_wrapped.data(),
        &lifecycle_wrapped_len);
    Check(rc == HKDFGUARD_OK, "wrap succeeds once create_kek has provisioned the KEK");

    // ---- 0b. wrap fails outright for a service with no KEK - wrap never ----
    //          creates one implicitly (only create_kek does).
    std::vector<uint8_t> no_kek_scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t no_kek_scratch_len = static_cast<int32_t>(no_kek_scratch.size());
    rc = hkdfguard_wrap_dek(
        kServiceNoKek, dek.data(), static_cast<int32_t>(dek.size()), no_kek_scratch.data(), &no_kek_scratch_len);
    Check(rc == HKDFGUARD_ERR_KEK_NOT_FOUND, "wrap fails with KEK_NOT_FOUND when no KEK has been provisioned for the service");

    // ---- 0c. kek_exists / create_kek argument validation. ----
    rc = hkdfguard_kek_exists(nullptr, &lifecycle_exists);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "kek_exists rejects null service");

    rc = hkdfguard_kek_exists(kServiceLifecycle, nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "kek_exists rejects null out_exists");

    rc = hkdfguard_kek_exists("", &lifecycle_exists);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "kek_exists rejects empty service");

    rc = hkdfguard_create_kek(nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "create_kek rejects null service");

    // ---- 0c2. Setup calls are deliberately slow and serialized. ----
    // The DLL reads the floor from HKLM\...\SetupMinDelayMs like any
    // deployment, so the expected value is read the same way (1000 ms when
    // the value is absent). The value-to-setting rule is checked first,
    // without the registry.
    {
        using hkdfguard::ParseSetupMinDelayMs;
        Check(ParseSetupMinDelayMs(false, 0, 0) == 1000, "SetupMinDelayMs: absent means 1000 ms");
        Check(ParseSetupMinDelayMs(true, REG_DWORD, 0) == 0, "SetupMinDelayMs: 0 disables the floor");
        Check(ParseSetupMinDelayMs(true, REG_DWORD, 250) == 250, "SetupMinDelayMs: an in-range DWORD is used as is");
        Check(ParseSetupMinDelayMs(true, REG_DWORD, 60000) == 60000, "SetupMinDelayMs: 60000 is the largest honored");
        Check(ParseSetupMinDelayMs(true, REG_DWORD, 60001) == 1000, "SetupMinDelayMs: above 60000 keeps the 1000 ms default");
        Check(ParseSetupMinDelayMs(true, REG_DWORD, 0xFFFFFFFFu) == 1000, "SetupMinDelayMs: 0xFFFFFFFF keeps the default");
        Check(ParseSetupMinDelayMs(true, REG_SZ, 0) == 1000, "SetupMinDelayMs: the wrong type keeps the default");
        Check(ParseSetupMinDelayMs(true, REG_QWORD, 5) == 1000, "SetupMinDelayMs: a QWORD keeps the default");

        const unsigned long floor_ms = hkdfguard::LoadSetupMinDelayMs();
        std::printf("    (setup floor on this machine: %lu ms)\n", floor_ms);
        auto elapsed_ms = [](auto&& call) {
            const auto start = std::chrono::steady_clock::now();
            call();
            return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        };

        int32_t timed_exists = -1;
        long long t = elapsed_ms([&] { rc = hkdfguard_kek_exists(kServiceNoKek, &timed_exists); });
        Check(rc == HKDFGUARD_OK && timed_exists == 0, "kek_exists (timed) reports no KEK for an unprovisioned service");
        Check(t >= static_cast<long long>(floor_ms), "kek_exists takes at least the setup floor when there is no KEK");
        if (t < static_cast<long long>(floor_ms)) std::printf("    (took %lld ms)\n", t);

        t = elapsed_ms([&] { rc = hkdfguard_kek_exists(kServiceLifecycle, &timed_exists); });
        Check(t >= static_cast<long long>(floor_ms), "kek_exists takes at least the setup floor whatever it finds");

        // Not elevated, a new KEK can't be created: KEK_ACCESS_DENIED. Elevated,
        // this is the idempotent verify of an existing KEK. Either way, the
        // floor applies to the outcome.
        t = elapsed_ms([&] { rc = hkdfguard_create_kek(kServiceLifecycle); });
        Check(t >= static_cast<long long>(floor_ms), "create_kek takes at least the setup floor, success or failure");

        if (floor_ms >= 200) {
            t = elapsed_ms([&] { rc = hkdfguard_kek_exists(nullptr, &timed_exists); });
            Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME && t < static_cast<long long>(floor_ms) / 2,
                  "an argument error returns immediately, without the setup floor");
            t = elapsed_ms([&] { rc = hkdfguard_create_kek("..bad"); });
            Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME && t < static_cast<long long>(floor_ms) / 2,
                  "an invalid service name returns immediately, without the setup floor");
            // wrap is the hot path and is never slowed.
            std::vector<uint8_t> fast(HKDFGUARD_WRAPPED_LEN);
            int32_t fast_len = static_cast<int32_t>(fast.size());
            t = elapsed_ms([&] {
                rc = hkdfguard_wrap_dek(kServiceNoKek, dek.data(), static_cast<int32_t>(dek.size()), fast.data(), &fast_len);
            });
            Check(rc == HKDFGUARD_ERR_KEK_NOT_FOUND && t < static_cast<long long>(floor_ms) / 2,
                  "wrap is not slowed by the setup floor (KEK_NOT_FOUND at once)");

            // Two threads at once: serialized, so together at least twice the floor.
            int32_t a_exists = -1, b_exists = -1;
            t = elapsed_ms([&] {
                std::thread a([&] { hkdfguard_kek_exists(kServiceNoKek, &a_exists); });
                std::thread b([&] { hkdfguard_kek_exists(kServiceLifecycle, &b_exists); });
                a.join();
                b.join();
            });
            Check(t >= 2 * static_cast<long long>(floor_ms), "concurrent setup calls run one at a time");
            if (t < 2 * static_cast<long long>(floor_ms)) std::printf("    (two concurrent calls took %lld ms)\n", t);
        } else {
            Skip("setup-floor fast paths and serialization (SetupMinDelayMs is below 200 ms on this machine)");
        }
    }

    // ---- 0d. Key-use group policy (HKLM\Software\Policies\HkdfGuard\ ----
    //          KeyUseGroups). Which principals may unwrap is machine policy,
    //          vetted before any key is created. Forced via the test-only
    //          override (see policy.h) so this doesn't depend on this
    //          machine's real registry. Every rejection below fires before
    //          the key store is touched, so these are meaningful even
    //          without elevation.
    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"Everyone"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects Everyone as a key-use group");

    // The same principal given as a SID string must be caught the same way -
    // the over-broad check is by SID, not by spelling.
    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"S-1-1-0"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects Everyone given as a SID string");

    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"Authenticated Users"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects Authenticated Users as a key-use group");

    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"Users"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects BUILTIN\\Users as a key-use group");

    // Broad well-known groups that are reported as SidTypeWellKnownGroup in
    // a domain IsHostLocalAccountDomain accepts, so only the over-broad
    // denylist can stop them. Each is checked by SID string, which works
    // whatever the display language of this machine.
    {
        struct BroadPrincipal {
            const wchar_t *sid;
            const char *label;
        };
        const BroadPrincipal broad[] = {
            {L"S-1-5-113", "create_kek rejects NT AUTHORITY\\Local account (S-1-5-113)"},
            {L"S-1-5-80-0", "create_kek rejects NT SERVICE\\ALL SERVICES (S-1-5-80-0)"},
            {L"S-1-5-15", "create_kek rejects NT AUTHORITY\\This Organization (S-1-5-15)"},
            {L"S-1-5-14", "create_kek rejects NT AUTHORITY\\REMOTE INTERACTIVE LOGON (S-1-5-14)"},
            {L"S-1-2-0", "create_kek rejects LOCAL (S-1-2-0)"},
            {L"S-1-2-1", "create_kek rejects CONSOLE LOGON (S-1-2-1)"},
        };
        for (const BroadPrincipal &p: broad) {
            hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{p.sid});
            Check(InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID, p.label);
        }
    }

    // And by name, for the two most likely to be typed into a policy.
    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"NT AUTHORITY\\Local account"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects NT AUTHORITY\\Local account given by name");

    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"NT SERVICE\\ALL SERVICES"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects NT SERVICE\\ALL SERVICES given by name");

    // A user account - even a perfectly real one - is not a group.
    wchar_t current_user[256] = {};
    DWORD current_user_len = static_cast<DWORD>(sizeof(current_user) / sizeof(current_user[0]));
    if (GetUserNameW(current_user, &current_user_len)) {
        hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{current_user});
        Check(
            InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
            "create_kek rejects a user account as a key-use group");
    }

    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"hkdfguard.no.such.group.x"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects an unresolvable key-use group");

    // One bad entry anywhere in the list fails the whole call, even when
    // it's preceded by a good one.
    const std::wstring narrow_group = PickNarrowGroup();
    std::printf("    (narrow key-use group used by this run: %ls)\n", narrow_group.c_str());
    hkdfguard::SetTestKeyUseGroupsOverride(
        std::vector<std::wstring>{narrow_group, L"Everyone"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects a list containing one over-broad entry among valid ones");

    // None of the rejected attempts may have left a key behind.
    bool use_groups_exists_after_rejects = true;
    try {
        use_groups_exists_after_rejects = hkdfguard::KekExists(kServiceUseGroupsWide);
    } catch (...) {
    }
    Check(!use_groups_exists_after_rejects, "rejected key-use group policies create no KEK");

    // A legitimate, narrow, universally-present group - with stray
    // whitespace, which policy entries are trimmed of - is accepted and
    // granted, and the resulting KEK is usable through the public ABI.
    // Host-local only: which account domains the vetting treats as local.
    // This is where "domain groups do not apply" is decided, on the
    // ReferencedDomainName Windows reports for the resolved principal.
    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD computer_name_len = MAX_COMPUTERNAME_LENGTH + 1;
    Check(GetComputerNameW(computer_name, &computer_name_len) != FALSE, "test harness can read the local computer name");
    Check(hkdfguard::IsHostLocalAccountDomain(computer_name), "this machine's own computer name counts as host-local");
    Check(hkdfguard::IsHostLocalAccountDomain(L"BUILTIN"), "BUILTIN counts as host-local");
    Check(hkdfguard::IsHostLocalAccountDomain(L"nt authority"), "NT AUTHORITY counts as host-local (case-insensitive)");
    Check(hkdfguard::IsHostLocalAccountDomain(L"NT SERVICE"), "NT SERVICE counts as host-local");
    Check(!hkdfguard::IsHostLocalAccountDomain(L"CORP"), "a domain's name does not count as host-local");
    Check(!hkdfguard::IsHostLocalAccountDomain(L""), "the empty domain well-known SIDs report does not count as host-local");

    // A domain-qualified spelling of a local group must validate. Default
    // Windows keeps every built-in local group in the BUILTIN domain (the
    // machine's own SAM domain holds accounts, not groups), and Windows
    // does not resolve "COMPUTERNAME\<builtin alias>" at all - so BUILTIN
    // is the qualifier that actually exists for `narrow_group`.
    hkdfguard::SetTestKeyUseGroupsOverride(
        std::vector<std::wstring>{L"BUILTIN\\" + narrow_group});
    bool qualified_local_validates = false;
    try {
        hkdfguard::ValidateKeyUseGroups(hkdfguard::LoadKeyUseGroupsPolicy());
        qualified_local_validates = true;
    } catch (...) {
    }
    Check(qualified_local_validates, "a BUILTIN-qualified local group validates");

    // ...and a foreign-domain-qualified one must not. (On a machine that
    // isn't domain-joined this fails at resolution; on a joined one a real
    // domain group would resolve and then fail the host-local check - the
    // IsHostLocalAccountDomain checks above cover that branch directly.)
    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"NOSUCHDOMAIN\\Users"});
    Check(
        InternalCreateKekResult(kServiceUseGroupsWide) == HKDFGUARD_ERR_WIN_GROUP_INVALID,
        "create_kek rejects a group qualified with a foreign domain");

    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{L"  " + narrow_group + L"  "});

    // Prove the entry is accepted by the vetting itself - trimmed, resolved,
    // a group, not over-broad - independently of whether this process can
    // actually create a key (which needs elevation). This is the check that
    // separates "the policy is fine" from "the environment can't provision".
    bool trimmed_entry_validates = false;
    try {
        hkdfguard::ValidateKeyUseGroups(hkdfguard::LoadKeyUseGroupsPolicy());
        trimmed_entry_validates = true;
    } catch (...) {
    }
    Check(trimmed_entry_validates, "key-use policy entry with surrounding whitespace is trimmed and validates as a real group");

    rc = InternalCreateKekResult(kServiceUseGroupsWide);
    Check(rc == HKDFGUARD_OK, "create_kek accepts a real group from the key-use policy (whitespace trimmed)");
    if (rc != HKDFGUARD_OK) {
        // HKDFGUARD_ERR_KEK_ACCESS_DENIED (-13) here with the validation check
        // above passing means the environment couldn't provision (this
        // process isn't elevated - NCryptFinalizeKey is the call that
        // actually enforces that for a new machine-scoped key, see
        // kek_store.cpp's ThrowForNCryptFailure); HKDFGUARD_ERR_WIN_GROUP_INVALID
        // (-10) would mean the vetting inside ApplyKeyAcl disagreed with
        // ValidateKeyUseGroups - a real bug.
        std::printf("    (create_kek returned %d)\n", rc);
    }
    bool use_groups_service_created = (rc == HKDFGUARD_OK);
    hkdfguard::SetTestKeyUseGroupsOverride(std::nullopt);

    std::vector<uint8_t> use_groups_wrapped(HKDFGUARD_WRAPPED_LEN);
    int32_t use_groups_wrapped_len = static_cast<int32_t>(use_groups_wrapped.size());
    if (use_groups_service_created) {
        rc = hkdfguard_wrap_dek(
            kServiceUseGroups, dek.data(), static_cast<int32_t>(dek.size()), use_groups_wrapped.data(),
            &use_groups_wrapped_len);
        Check(rc == HKDFGUARD_OK, "wrap succeeds against the key-use-policy test service's newly-created KEK");
    }

    // ---- 1. Provision kService's KEK, then a basic wrap -> unwrap ----
    //         roundtrip.
    rc = hkdfguard_create_kek(kService);
    Check(rc == HKDFGUARD_OK, "create_kek provisions kService's KEK");

    std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_LEN);
    // `wrapped_len` is initialized to the buffer's actual capacity before
    // the call - this is the "in" half of the in/out `out_len` parameter
    // (see hkdfguard.h); hkdfguard_wrap_dek reads this to know how much
    // room it has, then overwrites it with the real output length.
    int32_t wrapped_len = static_cast<int32_t>(wrapped.size());

    // `&wrapped_len` - the address-of operator - is how a plain local
    // variable is turned into the `int32_t*` the function signature
    // requires for its in/out parameter.
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrapped_len);
    Check(rc == HKDFGUARD_OK, "wrap succeeds");
    Check(wrapped_len == HKDFGUARD_WRAPPED_LEN, "wrap produces fixed-size payload");

    // Byte offset 1 of the wrapped payload is ProviderType (see
    // wire_format.h's layout table) - reading it directly out of the
    // wrapped bytes like this, rather than through any library function, is
    // deliberate: it's testing the actual on-the-wire output, the same
    // thing any other language's binding would see.
    uint8_t provider_type = wrapped[1];
    Check(provider_type == 1 || provider_type == 2, "provider type is TPM(1) or Software(2)");
    std::printf("    (provider_type = %d)\n", provider_type);

    std::vector<uint8_t> unwrapped(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped.data(), &unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds");
    Check(unwrapped_len == HKDFGUARD_DEK_LEN, "unwrap produces 32-byte DEK");
    // std::memcmp (declared in <cstring>) compares raw bytes and returns 0
    // when they're identical - the standard way to check two byte buffers
    // are equal, since operator== isn't defined for raw pointers/arrays the
    // way it is for e.g. std::vector or std::string.
    Check(std::memcmp(dek.data(), unwrapped.data(), HKDFGUARD_DEK_LEN) == 0, "unwrapped DEK matches original");

    // ---- 1b. Service names are case-insensitive: a service name that only ----
    //          differs in case from kService resolves to the exact same KEK,
    //          and wrap/unwrap can mix casing freely across calls - not just
    //          "same KEK, but the AAD only matches if the casing happens to
    //          be identical too" (see hkdfguard.cpp's NormalizeService,
    //          which normalizes the AAD bytes as well as the KEK name).
    constexpr char kServiceMixedCase[] = "HkdfGuardWin.Test.SERVICE";

    int32_t mixed_case_exists = -1;
    rc = hkdfguard_kek_exists(kServiceMixedCase, &mixed_case_exists);
    Check(rc == HKDFGUARD_OK, "kek_exists succeeds for a differently-cased alias of an existing service");
    Check(mixed_case_exists == 1, "kek_exists reports true for a differently-cased alias of an existing service");

    rc = hkdfguard_create_kek(kServiceMixedCase);
    Check(rc == HKDFGUARD_OK, "create_kek is idempotent for a differently-cased alias of an existing service");

    // Wrap using the mixed-case alias; it must reuse kService's existing KEK
    // (same provider), not provision a second, independent one.
    std::vector<uint8_t> wrapped_mixed_case(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_mixed_case_len = static_cast<int32_t>(wrapped_mixed_case.size());
    rc = hkdfguard_wrap_dek(
        kServiceMixedCase, dek.data(), static_cast<int32_t>(dek.size()), wrapped_mixed_case.data(),
        &wrapped_mixed_case_len);
    Check(rc == HKDFGUARD_OK, "wrap succeeds using a differently-cased alias of an existing service");
    Check(wrapped_mixed_case[1] == provider_type, "wrap via a differently-cased alias reuses the same provider/KEK");

    // Unwrap that payload using the original lowercase form.
    std::vector<uint8_t> unwrapped_via_lowercase(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_via_lowercase_len = static_cast<int32_t>(unwrapped_via_lowercase.size());
    rc = hkdfguard_unwrap_dek(
        kService, wrapped_mixed_case.data(), wrapped_mixed_case_len, unwrapped_via_lowercase.data(),
        &unwrapped_via_lowercase_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds using the lowercase form of a payload wrapped via a mixed-case alias");
    Check(
        std::memcmp(dek.data(), unwrapped_via_lowercase.data(), HKDFGUARD_DEK_LEN) == 0,
        "unwrapped DEK matches original when wrap/unwrap use differently-cased service names");

    // And the reverse direction: unwrap `wrapped` (from check 1 above,
    // wrapped under the original lowercase kService) using the mixed-case
    // alias instead.
    std::vector<uint8_t> unwrapped_via_mixed_case(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_via_mixed_case_len = static_cast<int32_t>(unwrapped_via_mixed_case.size());
    rc = hkdfguard_unwrap_dek(
        kServiceMixedCase, wrapped.data(), wrapped_len, unwrapped_via_mixed_case.data(),
        &unwrapped_via_mixed_case_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds using a mixed-case alias of the service a payload was wrapped under");
    Check(
        std::memcmp(dek.data(), unwrapped_via_mixed_case.data(), HKDFGUARD_DEK_LEN) == 0,
        "unwrapped DEK matches original when unwrap uses a differently-cased alias of the wrapping service");

    // ---- 2. Unwrapping the same payload again is idempotent: the payload ----
    //         isn't mutated/consumed by a successful unwrap, so a second,
    //         independent unwrap of the exact same bytes must succeed again
    //         and recover the identical DEK.
    std::vector<uint8_t> unwrapped_again(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_again_len = static_cast<int32_t>(unwrapped_again.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped_again.data(), &unwrapped_again_len);
    Check(rc == HKDFGUARD_OK, "unwrapping the same payload a second time succeeds");
    Check(
        std::memcmp(dek.data(), unwrapped_again.data(), HKDFGUARD_DEK_LEN) == 0,
        "second unwrap of the same payload recovers the identical DEK");

    // ---- 3. Repeated wrap reuses the same (provider, KeyId). ----
    // KeyId is fixed for this format version, and provider selection should
    // be stable across calls rather than flip-flopping.
    std::vector<uint8_t> wrapped2(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped2_len = static_cast<int32_t>(wrapped2.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped2.data(), &wrapped2_len);
    Check(rc == HKDFGUARD_OK, "second wrap succeeds");
    Check(wrapped2[1] == provider_type, "second wrap reuses the same provider type");

    // ---- 4. hkdfguard_generate_and_wrap_dek: generates its own DEK, wraps
    //         it under the same KEK as the calls above, and never hands
    //         the plaintext back. ----
    std::vector<uint8_t> generated1(HKDFGUARD_WRAPPED_LEN);
    int32_t generated1_len = static_cast<int32_t>(generated1.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, generated1.data(), &generated1_len);
    Check(rc == HKDFGUARD_OK, "generate_and_wrap succeeds");
    Check(generated1_len == HKDFGUARD_WRAPPED_LEN, "generate_and_wrap produces fixed-size payload");
    Check(generated1[1] == provider_type, "generate_and_wrap reuses the same provider type");

    // Unwrapping it recovers a real 32-byte DEK - proving the payload
    // generate_and_wrap_dek produced is a genuine, independently unwrappable
    // WrappedDekV1, not just a plausible-looking buffer.
    std::vector<uint8_t> generated1_unwrapped(HKDFGUARD_DEK_LEN);
    int32_t generated1_unwrapped_len = static_cast<int32_t>(generated1_unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, generated1.data(), generated1_len, generated1_unwrapped.data(), &generated1_unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap of a generate_and_wrap_dek payload succeeds");
    Check(generated1_unwrapped_len == HKDFGUARD_DEK_LEN, "unwrap of a generate_and_wrap_dek payload produces 32-byte DEK");

    // A second call generates an *independent* random DEK - not the fixed
    // MakeDek() test vector, and not a repeat of the first call's DEK. This
    // is the actual check that fresh randomness was sourced each time
    // (rather than e.g. an all-zero or otherwise fixed buffer slipping
    // through): with a 32-byte CSPRNG-sourced DEK, two calls producing the
    // same bytes is astronomically unlikely, so any match indicates a real
    // bug.
    std::vector<uint8_t> generated2(HKDFGUARD_WRAPPED_LEN);
    int32_t generated2_len = static_cast<int32_t>(generated2.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, generated2.data(), &generated2_len);
    Check(rc == HKDFGUARD_OK, "second generate_and_wrap succeeds");
    std::vector<uint8_t> generated2_unwrapped(HKDFGUARD_DEK_LEN);
    int32_t generated2_unwrapped_len = static_cast<int32_t>(generated2_unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, generated2.data(), generated2_len, generated2_unwrapped.data(), &generated2_unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap of the second generate_and_wrap_dek payload succeeds");
    Check(
        std::memcmp(generated1_unwrapped.data(), generated2_unwrapped.data(), HKDFGUARD_DEK_LEN) != 0,
        "two generate_and_wrap_dek calls produce different DEKs");
    Check(
        std::memcmp(dek.data(), generated1_unwrapped.data(), HKDFGUARD_DEK_LEN) != 0,
        "generate_and_wrap_dek's DEK differs from the fixed test vector");

    // ---- 5. generate_and_wrap_dek argument validation. ----
    std::vector<uint8_t> gen_scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t gen_scratch_len = static_cast<int32_t>(gen_scratch.size());
    rc = hkdfguard_generate_and_wrap_dek(nullptr, gen_scratch.data(), &gen_scratch_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "generate_and_wrap rejects null service");

    std::vector<uint8_t> gen_tiny_buf(HKDFGUARD_WRAPPED_LEN - 1);
    int32_t gen_tiny_buf_len = static_cast<int32_t>(gen_tiny_buf.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, gen_tiny_buf.data(), &gen_tiny_buf_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "generate_and_wrap rejects too-small output buffer");

    // ---- 6. Invalid dek_len. ----
    int32_t bad_len = 16;
    std::vector<uint8_t> scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t scratch_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), bad_len, scratch.data(), &scratch_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "wrap rejects wrong dek_len");

    // ---- 7. Buffer too small on wrap. ----
    // (Named `tiny_buf`/`tiny_out`, not `small`/`small_out`, because
    // <windows.h> - pulled in transitively through kek_store.h - #defines
    // the plain identifier `small` as a legacy MIDL type; using it as a
    // variable name here would fail to compile.)
    std::vector<uint8_t> tiny_buf(HKDFGUARD_WRAPPED_LEN - 1);
    int32_t tiny_buf_len = static_cast<int32_t>(tiny_buf.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), tiny_buf.data(), &tiny_buf_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "wrap rejects too-small output buffer");
    Check(tiny_buf_len == HKDFGUARD_WRAPPED_LEN, "wrap reports the required size through out_len on BUFFER_TOO_SMALL");

    // ---- 8. Buffer too small on unwrap. ----
    std::vector<uint8_t> tiny_out(HKDFGUARD_DEK_LEN - 1);
    int32_t tiny_out_len = static_cast<int32_t>(tiny_out.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, tiny_out.data(), &tiny_out_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "unwrap rejects too-small output buffer");
    Check(tiny_out_len == HKDFGUARD_DEK_LEN, "unwrap reports the required size through out_len on BUFFER_TOO_SMALL");

    // ---- 9. Malformed payload (truncated). ----
    // `std::vector<uint8_t> truncated(wrapped.begin(), wrapped.begin() +
    // wrapped_len - 1)` builds a *new* vector from a range of `wrapped`'s
    // elements - here, every element except the last one - using the
    // "iterator pair" constructor: `.begin()` is an iterator (a
    // pointer-like object) to the first element, and `.begin() + N` one
    // pointing N elements later; the constructor copies everything from the
    // first iterator up to (but not including) the second.
    std::vector<uint8_t> truncated(wrapped.begin(), wrapped.begin() + wrapped_len - 1);
    // Pre-filled with 0xAA (not 0) specifically so the AllZero() check below
    // is actually testing something - if the buffer already started at all
    // zeros, seeing zeros afterward wouldn't prove the library did anything.
    std::vector<uint8_t> out_for_malformed(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t malformed_out_len = static_cast<int32_t>(out_for_malformed.size());
    rc = hkdfguard_unwrap_dek(kService, truncated.data(), static_cast<int32_t>(truncated.size()),
                              out_for_malformed.data(), &malformed_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap rejects truncated payload");
    Check(AllZero(out_for_malformed.data(), out_for_malformed.size()), "output buffer zeroed after malformed payload");

    // ---- 10. Corrupted ciphertext -> authentication failure, output zeroed. ----
    // `std::vector<uint8_t> corrupted = wrapped;` copies the whole vector
    // (std::vector's copy constructor, unlike SecureBuffer's, is not
    // deleted - it's perfectly fine to copy plain wrapped-payload bytes,
    // which aren't secret).
    std::vector<uint8_t> corrupted = wrapped;
    // `^= 0xFF` flips every bit of that one byte (XOR-assignment) -
    // guaranteed to change its value no matter what it was, corrupting one
    // byte in the middle of the ciphertext region. Computed from
    // wire_format.h's offsets, never written as a number, so a layout
    // change can't silently move it into a different field.
    corrupted[hkdfguard::kCiphertextOffset + hkdfguard::kCiphertextLen / 2] ^= 0xFF; // inside the ciphertext region
    std::vector<uint8_t> out_for_auth(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t auth_out_len = static_cast<int32_t>(out_for_auth.size());
    rc = hkdfguard_unwrap_dek(kService, corrupted.data(), static_cast<int32_t>(corrupted.size()),
                              out_for_auth.data(), &auth_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, "unwrap rejects corrupted ciphertext");
    Check(AllZero(out_for_auth.data(), out_for_auth.size()), "output buffer zeroed after auth failure");

    // ---- 11. Corrupted tag -> authentication failure, output zeroed. ----
    std::vector<uint8_t> corrupted_tag = wrapped;
    corrupted_tag[hkdfguard::kTagOffset + hkdfguard::kTagLen - 1] ^= 0xFF; // last byte of the tag region
    std::vector<uint8_t> out_for_tag(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t tag_out_len = static_cast<int32_t>(out_for_tag.size());
    rc = hkdfguard_unwrap_dek(kService, corrupted_tag.data(), static_cast<int32_t>(corrupted_tag.size()),
                              out_for_tag.data(), &tag_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, "unwrap rejects corrupted tag");
    Check(AllZero(out_for_tag.data(), out_for_tag.size()), "output buffer zeroed after tag failure");

    // ---- 11b. Corrupted KEK fingerprint -> KEK_FINGERPRINT_MISMATCH (not PAYLOAD_AUTH_FAILED), ----
    //           output zeroed. The fingerprint is checked against the opened
    //           KEK before any ECDH/decryption, so a payload that doesn't
    //           belong to this KEK is distinguishable from a tampered one.
    std::vector<uint8_t> corrupted_fingerprint = wrapped;
    corrupted_fingerprint[wrapped_len - 1] ^= 0xFF; // the payload's very last byte is now fingerprint, not tag
    std::vector<uint8_t> out_for_fingerprint(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t fingerprint_out_len = static_cast<int32_t>(out_for_fingerprint.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_fingerprint.data(), static_cast<int32_t>(corrupted_fingerprint.size()),
        out_for_fingerprint.data(), &fingerprint_out_len);
    Check(rc == HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH, "unwrap rejects a payload whose KEK fingerprint doesn't match as KEK_FINGERPRINT_MISMATCH");
    Check(AllZero(out_for_fingerprint.data(), out_for_fingerprint.size()), "output buffer zeroed after fingerprint mismatch");

    // ---- 11c. Non-zero reserved bytes -> malformed, output zeroed. ----
    std::vector<uint8_t> nonzero_reserved = wrapped;
    nonzero_reserved[hkdfguard::kReservedOffset + 1] = 0x01;
    std::vector<uint8_t> out_for_reserved(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t reserved_out_len = static_cast<int32_t>(out_for_reserved.size());
    rc = hkdfguard_unwrap_dek(
        kService, nonzero_reserved.data(), static_cast<int32_t>(nonzero_reserved.size()),
        out_for_reserved.data(), &reserved_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap rejects non-zero reserved bytes");
    Check(AllZero(out_for_reserved.data(), out_for_reserved.size()), "output buffer zeroed after reserved-bytes failure");

    // ---- 12. Invalid service (null / empty) is rejected on wrap. ----
    // Both a null service (the null-pointer check) and an empty (but
    // non-null) one (the length check) are reported by hkdfguard.cpp's
    // ValidateAndConvertService as HKDFGUARD_ERR_INVALID_SERVICE_NAME, not
    // the generic HKDFGUARD_ERR_INVALID_ARGUMENT - matching the Linux and
    // macOS builds of this ABI. See check 17 below for the charset check
    // that same function applies.
    int32_t null_service_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(nullptr, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &null_service_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "wrap rejects null service");

    int32_t empty_service_out_len = static_cast<int32_t>(scratch.size());
    // `""` is a valid, non-null pointer to a single '\0' byte - a distinct
    // case from `nullptr` above, and this checks the length-based rejection
    // rather than the null-pointer rejection.
    rc = hkdfguard_wrap_dek("", dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &empty_service_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "wrap rejects empty service");

    // ---- 13. A different service gets its own independent KEK, and a ----
    //          payload wrapped under one service cannot be unwrapped under
    //          another.
    rc = hkdfguard_create_kek(kServiceOther);
    Check(rc == HKDFGUARD_OK, "create_kek provisions kServiceOther's KEK");

    bool other_service_wrapped = false;
    std::vector<uint8_t> wrapped_other(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_other_len = static_cast<int32_t>(wrapped_other.size());
    rc = hkdfguard_wrap_dek(kServiceOther, dek.data(), static_cast<int32_t>(dek.size()), wrapped_other.data(), &wrapped_other_len);
    Check(rc == HKDFGUARD_OK, "wrap with a different service succeeds");
    other_service_wrapped = (rc == HKDFGUARD_OK);

    std::vector<uint8_t> out_wrong_service(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t out_wrong_service_len = static_cast<int32_t>(out_wrong_service.size());
    rc = hkdfguard_unwrap_dek(kServiceOther, wrapped.data(), wrapped_len, out_wrong_service.data(), &out_wrong_service_len);
    // kServiceOther's own KEK now exists (created just above), so this
    // legitimately opens *that* KEK - whose fingerprint doesn't match the
    // payload's - and is rejected as KEK_FINGERPRINT_MISMATCH before any ECDH, rather
    // than failing to find a key at all (KEK_NOT_FOUND, the only other
    // correct outcome, if kServiceOther's KEK couldn't be created - e.g.
    // this process isn't elevated).
    Check(rc == HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH || rc == HKDFGUARD_ERR_KEK_NOT_FOUND, "unwrap with the wrong service fails with KEK_FINGERPRINT_MISMATCH");
    Check(AllZero(out_wrong_service.data(), out_wrong_service.size()), "output buffer zeroed after wrong-service failure");

    // ---- 14. Null-pointer argument validation, wrap side. ----
    // Each of dek/out/out_len is checked independently, with the other two
    // arguments otherwise valid, so a bug that only guards one of the three
    // pointers can't hide behind another argument also being invalid.
    int32_t null_arg_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, nullptr, HKDFGUARD_DEK_LEN, scratch.data(), &null_arg_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "wrap rejects null dek");

    null_arg_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), nullptr, &null_arg_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "wrap rejects null out");

    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "wrap rejects null out_len");

    // ---- 15. Negative dek_len is rejected the same way as any other wrong ----
    //          length (not just a too-small positive one) - a signed/unsigned
    //          confusion here could otherwise let a negative length slip past
    //          the `!= HKDFGUARD_DEK_LEN` check.
    int32_t neg_len_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), -1, scratch.data(), &neg_len_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "wrap rejects negative dek_len");

    // ---- 16. Service name length boundary: exactly 128 bytes (the documented ----
    //          maximum) succeeds; 129 bytes fails. Uses its own dedicated
    //          service names so cleanup doesn't collide with the KEKs created
    //          above.
    const std::string service128(128, 'a');
    const std::string service129(129, 'a');

    rc = hkdfguard_create_kek(service128.c_str());
    Check(rc == HKDFGUARD_OK, "create_kek accepts a service name exactly at the 128-byte maximum");
    bool service128_created = (rc == HKDFGUARD_OK);

    std::vector<uint8_t> wrapped_128(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_128_len = static_cast<int32_t>(wrapped_128.size());
    bool service128_wrapped = false;
    if (service128_created) {
        rc = hkdfguard_wrap_dek(
            service128.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped_128.data(), &wrapped_128_len);
        Check(rc == HKDFGUARD_OK, "wrap accepts a service name exactly at the 128-byte maximum");
        service128_wrapped = (rc == HKDFGUARD_OK);
    }

    int32_t service129_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        service129.c_str(), dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &service129_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "wrap rejects a service name one byte over the 128-byte maximum");

    // ---- 17. A service name outside the alphanumeric-or-'.' allowlist is ----
    //          rejected - including one that's otherwise perfectly valid
    //          UTF-8. hkdfguard.cpp's IsValidServiceChar charset check runs
    //          before the separate UTF-8-decoding step, and rejects any byte
    //          outside ASCII alphanumeric/'.', so both this check and check
    //          18 below are, today, exercising that same charset rejection
    //          rather than the UTF-8-specific one.
    // 0x80 alone is a bare UTF-8 continuation byte with no preceding lead
    // byte - never valid at that position in any well-formed UTF-8 string,
    // and also simply not an allowed service-name character either way.
    const char kInvalidUtf8Service[] = "\x80\x80";
    int32_t invalid_utf8_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        kInvalidUtf8Service, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &invalid_utf8_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "wrap rejects a service name that is not valid UTF-8");

    // ---- 18. A well-formed but non-ASCII UTF-8 service name is rejected. ----
    // UTF-8 bytes for U+00E9 (e-acute), U+65E5 (a CJK character), and
    // U+1F511 (the "key" emoji) - written as hex escapes, not literal source
    // characters, so this doesn't depend on the compiler's assumed
    // source-file encoding. Every one of these bytes has the high bit set,
    // so IsValidServiceChar rejects all of them, even though the sequence as
    // a whole is valid UTF-8 - proving the charset restriction is in fact
    // stricter than "valid UTF-8", not merely a rephrasing of it.
    constexpr char kNonAsciiService[] = "hkdfguardwin.test.\xC3\xA9\xE6\x97\xA5\xF0\x9F\x94\x91";
    int32_t non_ascii_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        kNonAsciiService, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &non_ascii_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "wrap rejects a well-formed but non-ASCII UTF-8 service name");

    // ---- 18b. Dot rules: no leading '.', no "..". ----
    // The same list the Linux library's tests reject. Validation runs before
    // any KEK is opened, so none of this needs elevation. A single trailing
    // '.' stays legal, as on Linux: kek_exists must answer for it (OK, not
    // INVALID_SERVICE_NAME).
    for (const char *bad : {".", "..", "...", ".hidden", ".com.example", "..parent", "com..example",
                            "com.example..", "a...b"}) {
        const std::string label = std::string(" \"") + bad + "\"";
        int32_t dot_exists = -1;
        Check(hkdfguard_kek_exists(bad, &dot_exists) == HKDFGUARD_ERR_INVALID_SERVICE_NAME,
              ("kek_exists rejects" + label).c_str());
        Check(hkdfguard_create_kek(bad) == HKDFGUARD_ERR_INVALID_SERVICE_NAME,
              ("create_kek rejects" + label).c_str());
        int32_t dot_out_len = static_cast<int32_t>(scratch.size());
        Check(hkdfguard_wrap_dek(bad, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &dot_out_len) ==
              HKDFGUARD_ERR_INVALID_SERVICE_NAME,
              ("wrap rejects" + label).c_str());
        std::vector<uint8_t> dot_wrapped(HKDFGUARD_WRAPPED_LEN, 0);
        std::vector<uint8_t> dot_unwrapped(HKDFGUARD_DEK_LEN, 0);
        int32_t dot_unwrap_len = static_cast<int32_t>(dot_unwrapped.size());
        Check(hkdfguard_unwrap_dek(bad, dot_wrapped.data(), static_cast<int32_t>(dot_wrapped.size()),
                                   dot_unwrapped.data(), &dot_unwrap_len) == HKDFGUARD_ERR_INVALID_SERVICE_NAME,
              ("unwrap rejects" + label).c_str());
    }
    {
        int32_t trailing_exists = -1;
        Check(hkdfguard_kek_exists("hkdfguardwin.test.trailing.", &trailing_exists) == HKDFGUARD_OK,
              "kek_exists accepts a single trailing '.'");
    }

    // ---- 19. Null-pointer argument validation, unwrap side. ----
    int32_t null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "unwrap rejects null out_len");

    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, nullptr, &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "unwrap rejects null out");

    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, nullptr, wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "unwrap rejects null wrapped");

    // ---- 20. Invalid service (null / empty) is rejected on the unwrap side too. ----
    // Check 12 above only checked this for wrap; unwrap validates `service`
    // through the exact same ValidateAndConvertService helper, but that's an
    // implementation detail this test shouldn't assume - each public entry
    // point gets its own check.
    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(nullptr, wrapped.data(), wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "unwrap rejects null service");

    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek("", wrapped.data(), wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_SERVICE_NAME, "unwrap rejects empty service");

    // ---- 21. Negative wrapped_len is rejected as malformed, not treated as ----
    //          an enormous unsigned length - ParseWrappedDek checks the sign
    //          explicitly before ever casting it to size_t (see
    //          wire_format.cpp), and this is what proves that check is live.
    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), -1, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap rejects negative wrapped_len");

    // ---- 22. Corrupted Version byte is rejected as unsupported. ----
    std::vector<uint8_t> corrupted_version = wrapped;
    corrupted_version[0] ^= 0xFF; // Version is byte offset 0 (see wire_format.h)
    std::vector<uint8_t> out_for_version(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t version_out_len = static_cast<int32_t>(out_for_version.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_version.data(), static_cast<int32_t>(corrupted_version.size()),
        out_for_version.data(), &version_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED, "unwrap rejects a corrupted version byte as unsupported");
    Check(AllZero(out_for_version.data(), out_for_version.size()), "output buffer zeroed after corrupted-version failure");

    // ---- 23. Corrupted ProviderType byte is rejected as malformed. ----
    // Set to 0, a value neither kProviderTypeTpm(1) nor kProviderTypeSoftware(2)
    // ever takes on for a genuine payload.
    std::vector<uint8_t> corrupted_provider = wrapped;
    corrupted_provider[1] = 0; // ProviderType is byte offset 1 (see wire_format.h)
    std::vector<uint8_t> out_for_provider(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t provider_out_len = static_cast<int32_t>(out_for_provider.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_provider.data(), static_cast<int32_t>(corrupted_provider.size()),
        out_for_provider.data(), &provider_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap rejects an unrecognized provider type byte");
    Check(AllZero(out_for_provider.data(), out_for_provider.size()), "output buffer zeroed after unrecognized-provider-type failure");

    // ---- 23b. A KeyId other than kCurrentKeyId is rejected as malformed. ----
    //           HkdfGuard has no key-rotation mechanism (a new KEK means a
    //           versioned service name, not a new KeyId under the same
    //           service - see wire_format.h's kCurrentKeyId), so any other
    //           KeyId value is rejected outright rather than being used to
    //           look up a persisted key that, by design, could never exist.
    std::vector<uint8_t> corrupted_key_id = wrapped;
    corrupted_key_id[hkdfguard::kKeyIdOffset] ^= 0xFF; // KeyId is little-endian at this offset (see wire_format.h)
    std::vector<uint8_t> out_for_key_id(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t key_id_out_len = static_cast<int32_t>(out_for_key_id.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_key_id.data(), static_cast<int32_t>(corrupted_key_id.size()),
        out_for_key_id.data(), &key_id_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unwrap rejects a KeyId other than kCurrentKeyId");
    Check(AllZero(out_for_key_id.data(), out_for_key_id.size()), "output buffer zeroed after unrecognized-KeyId failure");

    // ---- 24. Null-pointer argument validation, generate_and_wrap_dek. ----
    int32_t gen_null_out_len = static_cast<int32_t>(gen_scratch.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, nullptr, &gen_null_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "generate_and_wrap rejects null out");

    rc = hkdfguard_generate_and_wrap_dek(kService, gen_scratch.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "generate_and_wrap rejects null out_len");

    // ---- 24b. The ECDH construction: Z = ECDH(KEK private key, H(salt)). ----
    //          First the pieces with no KEK - hash-to-curve against the
    //          Linux implementation, and the point gate - then, against the
    //          real KEK, that a payload can't be forged from the public key.
    {
        // Points produced by the Linux implementation's payload_ecdh_point on
        // the RustCrypto p256 0.14 crate (hkdfguard-native-linux), for three
        // fixed salts. Windows must hash every salt to exactly these points.
        std::vector<uint8_t> sequential(hkdfguard::kSaltLen);
        for (size_t i = 0; i < sequential.size(); ++i) sequential[i] = static_cast<uint8_t>(i);
        struct LinuxVector {
            std::vector<uint8_t> salt;
            const char* x;
            const char* y;
        };
        const LinuxVector vectors[] = {
            {std::vector<uint8_t>(hkdfguard::kSaltLen, 0x00),
             "c68960c82e7e3d5395da61ee0f2024fb5e9ec0e45e2f104e33c65cca87c93620",
             "ef42f3f44d5c434e04ef8d0ffb90b23b4a7d7517d32f65e0c645c610bb370982"},
            {std::vector<uint8_t>(hkdfguard::kSaltLen, 0x42),
             "23705f112056934aef2059c9c3ffa610ccb2f070d266d4ffa06210d37e9a0de5",
             "df412b76994469fb7c27385e2d8f389f3da716076c79a19bb57249c9755f032a"},
            {sequential,
             "074508261589a2c703bcb88966769c27f980a528de99cd3dc92d93d3de8fa2a6",
             "06260ec7bdd3a303f376430f01bdb5aafba4d1b6688f550077279977b1c9de88"},
        };
        for (const LinuxVector& v : vectors) {
            std::vector<uint8_t> expected = FromHex(v.x), expectedY = FromHex(v.y);
            expected.insert(expected.end(), expectedY.begin(), expectedY.end());
            std::vector<uint8_t> point(hkdfguard::kPublicPointLen);
            int32_t code = CodeOf([&] { hkdfguard::PayloadEcdhPoint(v.salt.data(), point.data()); });
            Check(code == HKDFGUARD_OK && point == expected,
                  ("hash-to-curve matches the Linux implementation for salt " + ToHex(v.salt).substr(0, 8) + "...").c_str());
        }

        // Any salt maps to a valid P-256 point, and different salts to
        // different points.
        bool all_valid = true, all_distinct = true;
        std::vector<std::vector<uint8_t>> seen;
        for (int i = 0; i < 32; ++i) {
            std::vector<uint8_t> salt(hkdfguard::kSaltLen);
            BCryptGenRandom(nullptr, salt.data(), static_cast<ULONG>(salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            std::vector<uint8_t> point(hkdfguard::kPublicPointLen);
            if (CodeOf([&] { hkdfguard::PayloadEcdhPoint(salt.data(), point.data()); }) != HKDFGUARD_OK ||
                PointGateResult(point) != 1) {
                all_valid = false;
            }
            for (const auto& other : seen) all_distinct = all_distinct && other != point;
            seen.push_back(point);
        }
        Check(all_valid, "32 random salts all hash to valid P-256 points");
        Check(all_distinct, "32 random salts hash to 32 different points");
    }

    // The point gate every H(salt) passes through before any KSP sees it:
    // a genuine point is accepted, malformed ones are refused.
    std::vector<uint8_t> valid_point = MakeValidP256Point();
    Check(valid_point.size() == hkdfguard::kPublicPointLen, "test harness can generate a valid P-256 point");
    if (valid_point.size() == hkdfguard::kPublicPointLen) {
        Check(PointGateResult(valid_point) == 1, "point gate accepts a genuine P-256 point");

        std::vector<uint8_t> all_ff(hkdfguard::kPublicPointLen, 0xFF);
        Check(PointGateResult(all_ff) == 0, "point gate rejects all-0xFF coordinates");

        std::vector<uint8_t> all_zero(hkdfguard::kPublicPointLen, 0x00);
        Check(PointGateResult(all_zero) == 0, "point gate rejects all-zero coordinates");

        // A single flipped bit in X, and separately in Y, leaves a point
        // that is off the curve with overwhelming probability (~1 - 2^-256).
        std::vector<uint8_t> flipped_x = valid_point;
        flipped_x[0] ^= 0x01;
        Check(PointGateResult(flipped_x) == 0, "point gate rejects a single-bit mutation in X");

        std::vector<uint8_t> flipped_y = valid_point;
        flipped_y[hkdfguard::kPublicPointLen - 1] ^= 0x01;
        Check(PointGateResult(flipped_y) == 0, "point gate rejects a single-bit mutation in Y");
    }

    // Forgery. The KEK's public key is readable by any account allowed to
    // use the KEK. Under the earlier ECIES construction that was enough to
    // build a payload unwrap accepted; now Z needs the private key. Built
    // here entirely outside the library: a payload sealed with the right
    // wrapping key must unwrap (proving the independent sealing is correct),
    // and one sealed with a key derived from the public key alone must not.
    {
        std::vector<uint8_t> kek_pub;
        std::vector<uint8_t> genuine_key;
        std::vector<uint8_t> salt(hkdfguard::kSaltLen);
        BCryptGenRandom(nullptr, salt.data(), static_cast<ULONG>(salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        int32_t setup = CodeOf([&] {
            hkdfguard::ResolvedKek kek = hkdfguard::OpenKekForWrap(kServiceWide);
            DWORD cb = 0;
            std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + hkdfguard::kPublicPointLen);
            if (NCryptExportKey(kek.key.get(), 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(),
                                static_cast<DWORD>(blob.size()), &cb, 0) != ERROR_SUCCESS) {
                throw std::runtime_error("export");
            }
            kek_pub.assign(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end());
            // The genuine wrapping key for this salt, from the library's own
            // derivation on the real KEK (inside the TPM for a TPM KEK).
            hkdfguard::SecureBuffer<32> key;
            hkdfguard::DeriveWrappingKey(kek.provider.get(), kek.key.get(), salt.data(), key);
            genuine_key.assign(key.data(), key.data() + key.size());
        });
        Check(setup == HKDFGUARD_OK, "test setup: read the KEK's public key and derive a genuine wrapping key");

        if (setup == HKDFGUARD_OK) {
            // The provider kService's KEK actually lives on (TPM on a machine
            // with one, software otherwise), as a genuine payload records it.
            const uint8_t provider = wrapped[hkdfguard::kProviderTypeOffset];
            std::vector<uint8_t> nonce(hkdfguard::kNonceLen, 0x5A);
            std::vector<uint8_t> honest;
            bool sealed = SealPayloadIndependently(genuine_key, salt, nonce, kService, kek_pub, dek, provider, honest);
            std::vector<uint8_t> out(HKDFGUARD_DEK_LEN, 0xAA);
            int32_t out_len = static_cast<int32_t>(out.size());
            rc = hkdfguard_unwrap_dek(kService, honest.data(), static_cast<int32_t>(honest.size()), out.data(), &out_len);
            Check(sealed && rc == HKDFGUARD_OK && std::memcmp(out.data(), dek.data(), HKDFGUARD_DEK_LEN) == 0,
                  "control: a payload sealed outside the library with the genuine wrapping key unwraps");
            if (rc != HKDFGUARD_OK) std::printf("    (provider type %u, hkdfguard_unwrap_dek returned %d)\n", provider, rc);

            bool all_rejected = true;
            for (int attempt = 0; attempt < 3; ++attempt) {
                std::vector<uint8_t> forged_salt(hkdfguard::kSaltLen), forged_key, forged;
                BCryptGenRandom(nullptr, forged_salt.data(), static_cast<ULONG>(forged_salt.size()),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                // Z from the public key only: ECDH(random e, KEK public).
                bool built = IndependentWrappingKey(forged_salt, {}, kek_pub, nullptr, forged_key) &&
                             SealPayloadIndependently(forged_key, forged_salt, nonce, kService, kek_pub,
                                                      std::vector<uint8_t>(HKDFGUARD_DEK_LEN, 0x66), provider, forged);
                std::vector<uint8_t> forged_out(HKDFGUARD_DEK_LEN, 0xAA);
                int32_t forged_out_len = static_cast<int32_t>(forged_out.size());
                rc = hkdfguard_unwrap_dek(kService, forged.data(), static_cast<int32_t>(forged.size()),
                                          forged_out.data(), &forged_out_len);
                if (rc != HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED) {
                    std::printf("    (forgery %d: hkdfguard_unwrap_dek returned %d)\n", attempt + 1, rc);
                }
                all_rejected = all_rejected && built && rc == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED &&
                               AllZero(forged_out.data(), forged_out.size());
            }
            Check(all_rejected,
                  "a payload forged from the KEK's public key alone is rejected (PAYLOAD_AUTH_FAILED, output zeroed), 3 of 3");
        }
    }

    // The salt is authenticated through the key it derives: change one bit
    // of it and the wrapping key changes, so unwrap fails authentication -
    // with the output zeroed.
    std::vector<uint8_t> tampered_salt_payload = wrapped;
    tampered_salt_payload[hkdfguard::kSaltOffset] ^= 0x01;
    std::vector<uint8_t> out_for_salt(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t salt_out_len = static_cast<int32_t>(out_for_salt.size());
    rc = hkdfguard_unwrap_dek(
        kService, tampered_salt_payload.data(), static_cast<int32_t>(tampered_salt_payload.size()),
        out_for_salt.data(), &salt_out_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, "unwrap rejects a payload whose salt was changed (PAYLOAD_AUTH_FAILED)");
    Check(AllZero(out_for_salt.data(), out_for_salt.size()), "output buffer zeroed after a changed-salt failure");

    // Every wrap draws a fresh salt.
    {
        std::vector<uint8_t> again(HKDFGUARD_WRAPPED_LEN);
        int32_t again_len = static_cast<int32_t>(again.size());
        rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), again.data(), &again_len);
        Check(rc == HKDFGUARD_OK &&
                  std::memcmp(again.data() + hkdfguard::kSaltOffset, wrapped.data() + hkdfguard::kSaltOffset,
                              hkdfguard::kSaltLen) != 0,
              "two wraps of the same DEK use different salts");
    }

    // ---- 24c. hkdfguard_open_file: reads a wrapped-key file's bytes - ----
    //          still wrapped - checking size and structure, never
    //          unwrapping. Files are written to a scratch folder under %TEMP%.
    {
        // %TEMP% itself may be spelled with an 8.3 short name - on GitHub's
        // hosted runners it is C:\Users\RUNNER~1\... - and open_file refuses
        // short names, so it's expanded to its long form first.
        wchar_t temp[MAX_PATH + 1] = {};
        GetTempPathW(MAX_PATH + 1, temp);
        wchar_t temp_long[MAX_PATH + 1] = {};
        DWORD temp_long_len = GetLongPathNameW(temp, temp_long, MAX_PATH + 1);
        const std::wstring temp_dir = (temp_long_len > 0 && temp_long_len <= MAX_PATH) ? temp_long : temp;
        const std::wstring dir = temp_dir + L"hkdfguard-openfile-" + std::to_wstring(GetCurrentProcessId());
        CreateDirectoryW(dir.c_str(), nullptr);
        std::vector<std::wstring> created;
        auto fileFor = [&](const wchar_t* name, const std::vector<uint8_t>& bytes) {
            std::wstring path = dir + L"\\" + name;
            Check(WriteTestFile(path, bytes), ("test setup: write " + ToUtf8(name)).c_str());
            created.push_back(path);
            return ToUtf8(path);
        };
        // Calls hkdfguard_open_file into a buffer pre-filled with 0xAA, so
        // a failure that doesn't zero it is visible.
        struct OpenResult {
            int32_t rc;
            int32_t len;
            std::vector<uint8_t> out;
        };
        auto open = [](const std::string& path, int32_t capacity = HKDFGUARD_WRAPPED_LEN) {
            // A negative capacity is passed through as-is, over a 1-byte
            // buffer, so the library's handling of it is what's tested.
            OpenResult r{0, capacity, std::vector<uint8_t>(static_cast<size_t>(capacity > 0 ? capacity : 1), 0xAA)};
            r.rc = hkdfguard_open_file(path.c_str(), r.out.data(), &r.len);
            return r;
        };
        auto expectFailure = [&](const std::string& path, int32_t code, const std::string& what) {
            OpenResult r = open(path);
            Check(r.rc == code, ("open_file: " + what).c_str());
            if (r.rc != code) std::printf("    (hkdfguard_open_file returned %d)\n", r.rc);
            Check(r.len == HKDFGUARD_WRAPPED_LEN && AllZero(r.out.data(), r.out.size()),
                  ("open_file: " + what + " - output zeroed and out_len left unchanged").c_str());
        };

        // The happy path: exactly the wrapped bytes, unchanged...
        const std::string good = fileFor(L"good.key", wrapped);
        OpenResult r = open(good);
        Check(r.rc == HKDFGUARD_OK, "open_file reads a valid wrapped-key file");
        Check(r.len == HKDFGUARD_WRAPPED_LEN, "open_file reports HKDFGUARD_WRAPPED_LEN bytes read");
        Check(r.out == wrapped, "open_file returns the wrapped bytes exactly as stored (not unwrapped)");
        // ...which a later, separate unwrap call accepts.
        std::vector<uint8_t> from_file_dek(HKDFGUARD_DEK_LEN);
        int32_t from_file_dek_len = static_cast<int32_t>(from_file_dek.size());
        rc = hkdfguard_unwrap_dek(kService, r.out.data(), r.len, from_file_dek.data(), &from_file_dek_len);
        Check(rc == HKDFGUARD_OK && std::memcmp(from_file_dek.data(), dek.data(), HKDFGUARD_DEK_LEN) == 0,
              "bytes from open_file unwrap to the original DEK in a separate unwrap call");

        // Plaintext-key size, and the sizes either side of it.
        expectFailure(fileFor(L"plain.key", std::vector<uint8_t>(HKDFGUARD_DEK_LEN, 0x42)),
                      HKDFGUARD_ERR_FILE_PLAINTEXT_KEY, "a DEK-sized (32-byte) file is reported as a plaintext key");
        expectFailure(fileFor(L"len31.key", std::vector<uint8_t>(31, 0x42)),
                      HKDFGUARD_ERR_FILE_TOO_SHORT, "a 31-byte file is too short (not a plaintext key)");
        expectFailure(fileFor(L"len33.key", std::vector<uint8_t>(33, 0x42)),
                      HKDFGUARD_ERR_FILE_TOO_SHORT, "a 33-byte file is too short (not a plaintext key)");
        expectFailure(fileFor(L"empty.key", {}), HKDFGUARD_ERR_FILE_TOO_SHORT, "an empty file is too short");
        expectFailure(fileFor(L"len163.key", std::vector<uint8_t>(wrapped.begin(), wrapped.end() - 1)),
                      HKDFGUARD_ERR_FILE_TOO_SHORT, "a file one byte short of a payload is too short");
        std::vector<uint8_t> longer = wrapped;
        longer.push_back(0x00);
        expectFailure(fileFor(L"len165.key", longer), HKDFGUARD_ERR_FILE_TOO_LONG,
                      "a valid payload with one trailing byte is too long");
        expectFailure(fileFor(L"len4096.key", std::vector<uint8_t>(4096, 0x00)), HKDFGUARD_ERR_FILE_TOO_LONG,
                      "a 4096-byte file is too long");

        // A DEK written as text is a plaintext key too, whatever the
        // surrounding whitespace - the same forms the Linux build refuses.
        // The DEK starts FB EF BE FF FF FF so its standard and URL-safe
        // encodings really differ ("++++////" vs "----____").
        {
            std::vector<uint8_t> text_dek = {0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF};
            for (uint8_t b = 0; text_dek.size() < HKDFGUARD_DEK_LEN; ++b) text_dek.push_back(static_cast<uint8_t>(b * 37 + 11));
            const std::pair<const char*, std::string> forms[] = {
                {"base64", Base64Of(text_dek, false, true)},
                {"base64, no padding", Base64Of(text_dek, false, false)},
                {"URL-safe base64", Base64Of(text_dek, true, true)},
                {"URL-safe base64, no padding", Base64Of(text_dek, true, false)},
                {"hex", HexOf(text_dek, false)},
                {"HEX", HexOf(text_dek, true)},
            };
            int n = 0;
            for (const auto& [what, text] : forms) {
                for (const char* ws : {"", "\n", "\r\n", " \t", "\f"}) {
                    std::wstring name = L"text" + std::to_wstring(n++) + L".key";
                    expectFailure(fileFor(name.c_str(), BytesOf(std::string(ws) + text + ws)),
                                  HKDFGUARD_ERR_FILE_PLAINTEXT_KEY,
                                  std::string("a DEK as ") + what + " (whitespace variant) is a plaintext key");
                }
            }
            const std::string hex = HexOf(text_dek, false);
            const std::string near_misses[] = {
                Base64Of(std::vector<uint8_t>(31, 0x5A), false, true),  // base64, but of 31 bytes
                Base64Of(std::vector<uint8_t>(33, 0x5A), false, true),  // base64, but of 33 bytes
                std::string(44, '!'),                                   // 44 bytes, not base64
                hex.substr(1),                                          // 63 hex digits
                hex.substr(1) + "g",                                    // 64 characters, one not hex
                hex.substr(0, 32) + "\n" + hex.substr(32),              // hex split by a newline inside
            };
            for (const std::string& miss : near_misses) {
                std::wstring name = L"near" + std::to_wstring(n++) + L".key";
                expectFailure(fileFor(name.c_str(), BytesOf(miss)), HKDFGUARD_ERR_FILE_TOO_SHORT,
                              "a near miss of a text DEK (" + std::to_string(miss.size()) + " bytes) is just too short");
            }
        }

        // Who could have written the file: an ACE letting Everyone write it,
        // or a folder letting Everyone delete its entries, is refused; a
        // folder letting Everyone only create entries (C:\ProgramData-style)
        // is fine. The owner is this account either way (or Administrators,
        // elevated), both trusted; owners that would need privileges to set
        // are covered by section 24d. The content is the golden payload
        // (section 29): well-formed without any KEK, so the accepted cases
        // mean something on a non-elevated run too, where `wrapped` is empty.
        {
            const std::vector<uint8_t> well_formed = FromHex(kGoldenPayloadHex);
            const std::wstring me = CurrentUserSidString();
            Check(!me.empty(), "test setup: read this account's SID");
            const std::wstring trusted_aces = L"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + L")";

            const std::string writable = fileFor(L"everyone-writes.key", well_formed);
            Check(SetProtectedDacl(dir + L"\\everyone-writes.key", L"D:" + trusted_aces + L"(A;;FW;;;WD)"),
                  "test setup: let Everyone write everyone-writes.key");
            expectFailure(writable, HKDFGUARD_ERR_FILE_UNTRUSTED, "a file Everyone may write is untrusted");

            const std::string readable = fileFor(L"everyone-reads.key", well_formed);
            Check(SetProtectedDacl(dir + L"\\everyone-reads.key", L"D:" + trusted_aces + L"(A;;FR;;;WD)"),
                  "test setup: let Everyone read everyone-reads.key");
            r = open(readable);
            Check(r.rc == HKDFGUARD_OK && r.out == well_formed, "a file Everyone may only read is trusted (it's ciphertext)");

            const std::wstring sub = dir + L"\\acl-folder";
            Check(CreateDirectoryW(sub.c_str(), nullptr) != FALSE, "test setup: create acl-folder");
            const std::wstring sub_key = sub + L"\\in-folder.key";
            Check(WriteTestFile(sub_key, well_formed), "test setup: write acl-folder\\in-folder.key");
            Check(SetProtectedDacl(sub_key, L"D:" + trusted_aces), "test setup: protect in-folder.key");

            Check(SetProtectedDacl(sub, L"D:" + trusted_aces + L"(A;;0x40;;;WD)"),
                  "test setup: let Everyone delete entries in acl-folder");
            expectFailure(ToUtf8(sub_key), HKDFGUARD_ERR_FILE_UNTRUSTED,
                          "a file in a folder where Everyone may delete entries is untrusted");
            Check(SetProtectedDacl(sub, L"D:" + trusted_aces + L"(A;;SD;;;WD)"),
                  "test setup: let Everyone delete acl-folder itself");
            expectFailure(ToUtf8(sub_key), HKDFGUARD_ERR_FILE_UNTRUSTED,
                          "a file in a folder Everyone may delete or rename is untrusted");
            Check(SetProtectedDacl(sub, L"D:" + trusted_aces + L"(A;;0x116;;;WD)"),
                  "test setup: let Everyone only create entries in acl-folder");
            r = open(ToUtf8(sub_key));
            Check(r.rc == HKDFGUARD_OK && r.out == well_formed,
                  "a file in a folder where Everyone may only create entries is trusted");

            DeleteFileW(sub_key.c_str());
            RemoveDirectoryW(sub.c_str());
        }

        // Right size, wrong contents.
        std::vector<uint8_t> bad_version = wrapped;
        bad_version[hkdfguard::kVersionOffset] ^= 0xFF;
        expectFailure(fileFor(L"badversion.key", bad_version), HKDFGUARD_ERR_FILE_MALFORMED,
                      "a payload-sized file with a corrupted version byte is malformed");
        expectFailure(fileFor(L"zeros.key", std::vector<uint8_t>(HKDFGUARD_WRAPPED_LEN, 0x00)),
                      HKDFGUARD_ERR_FILE_MALFORMED, "a payload-sized file of zero bytes is malformed");
        // The salt has no structure, so a changed salt is still a well-formed
        // file: open_file returns it, and the later unwrap is what rejects it.
        {
            OpenResult o = open(fileFor(L"changedsalt.key", tampered_salt_payload));
            Check(o.rc == HKDFGUARD_OK && o.out == tampered_salt_payload,
                  "open_file returns a payload with a changed salt (any 32 bytes are a well-formed salt)");
        }

        // Opening problems.
        expectFailure(ToUtf8(dir + L"\\missing.key"), HKDFGUARD_ERR_FILE_NOT_FOUND, "a missing file is not found");
        expectFailure(ToUtf8(dir + L"\\nosuchdir\\x.key"), HKDFGUARD_ERR_FILE_NOT_FOUND,
                      "a file in a missing folder is not found");
        expectFailure(ToUtf8(dir), HKDFGUARD_ERR_FILE_IO, "a directory is refused");
        // Device and network paths are refused before anything is opened -
        // so these are deterministic with no pipe server and no network.
        expectFailure("NUL", HKDFGUARD_ERR_FILE_UNTRUSTED, "a DOS device name (NUL) is refused");
        expectFailure("\\\\.\\pipe\\hkdfguard-no-such-pipe", HKDFGUARD_ERR_FILE_UNTRUSTED, "a named-pipe path is refused");
        expectFailure("\\\\?\\GLOBALROOT\\Device\\Null", HKDFGUARD_ERR_FILE_UNTRUSTED, "a device-namespace path is refused");
        expectFailure("\\\\localhost\\C$\\Windows\\hkdfguard.key", HKDFGUARD_ERR_FILE_UNTRUSTED, "a UNC path is refused");
        expectFailure("\\\\?\\UNC\\localhost\\C$\\Windows\\hkdfguard.key", HKDFGUARD_ERR_FILE_UNTRUSTED,
                      "an extended-prefix UNC path is refused");

        {
            // A writer holding the file open: refused rather than read mid-write.
            HANDLE writer = CreateFileW((dir + L"\\good.key").c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Check(writer != INVALID_HANDLE_VALUE, "test setup: hold good.key open for writing");
            expectFailure(good, HKDFGUARD_ERR_FILE_IO, "a file open for writing elsewhere is refused");
            if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
        }

        {
            // A file this account may not read. Everyone is denied read
            // first; Administrators and SYSTEM keep everything else so the
            // test can still delete it.
            const std::string denied = fileFor(L"denied.key", wrapped);
            PSECURITY_DESCRIPTOR sd = nullptr;
            bool set = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                           L"D:P(D;;FR;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)", SDDL_REVISION_1, &sd, nullptr) &&
                       SetFileSecurityW((dir + L"\\denied.key").c_str(), DACL_SECURITY_INFORMATION, sd);
            if (sd) LocalFree(sd);
            Check(set, "test setup: deny read access on denied.key");
            expectFailure(denied, HKDFGUARD_ERR_FILE_ACCESS_DENIED, "an unreadable file is access denied");
        }

        // A non-ASCII path is passed through as UTF-8.
        const std::string unicode = fileFor(L"clé-ключ.key", wrapped);
        r = open(unicode);
        Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file reads a file whose name is non-ASCII UTF-8");

        // Argument checks.
        int32_t len = HKDFGUARD_WRAPPED_LEN;
        std::vector<uint8_t> buf(HKDFGUARD_WRAPPED_LEN);
        Check(hkdfguard_open_file(nullptr, buf.data(), &len) == HKDFGUARD_ERR_INVALID_ARGUMENT, "open_file rejects a null path");
        len = HKDFGUARD_WRAPPED_LEN;
        Check(hkdfguard_open_file(good.c_str(), nullptr, &len) == HKDFGUARD_ERR_INVALID_ARGUMENT, "open_file rejects a null out");
        Check(hkdfguard_open_file(good.c_str(), buf.data(), nullptr) == HKDFGUARD_ERR_INVALID_ARGUMENT, "open_file rejects a null out_len");
        expectFailure("", HKDFGUARD_ERR_INVALID_ARGUMENT, "an empty path is rejected");
        expectFailure("bad\xC3\x28.key", HKDFGUARD_ERR_INVALID_ARGUMENT, "a path that is not valid UTF-8 is rejected");
        r = open(good, HKDFGUARD_WRAPPED_LEN - 1);
        Check(r.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL && r.len == HKDFGUARD_WRAPPED_LEN,
              "open_file reports BUFFER_TOO_SMALL with the required size");
        Check(AllZero(r.out.data(), r.out.size()), "open_file zeroes a too-small buffer");
        r = open(good, -1);
        Check(r.rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL && r.len == HKDFGUARD_WRAPPED_LEN,
              "open_file treats a negative capacity as too small");

        // A larger buffer: exactly HKDFGUARD_WRAPPED_LEN bytes are written and reported, and
        // nothing past them is touched.
        r = open(good, HKDFGUARD_WRAPPED_LEN + 36);
        Check(r.rc == HKDFGUARD_OK && r.len == HKDFGUARD_WRAPPED_LEN, "open_file into a larger buffer reports HKDFGUARD_WRAPPED_LEN bytes");
        Check(std::equal(wrapped.begin(), wrapped.end(), r.out.begin()), "open_file into a larger buffer writes the payload at the start");
        bool tail_untouched = true;
        for (size_t i = HKDFGUARD_WRAPPED_LEN; i < r.out.size(); ++i) tail_untouched &= (r.out[i] == 0xAA);
        Check(tail_untouched, "open_file leaves bytes past the payload untouched");

        // Every structural rule ParseWrappedDek enforces, one at a time.
        {
            struct Corruption {
                const wchar_t* file;
                size_t offset;
                uint8_t value;
                const char* what;
            };
            const Corruption corruptions[] = {
                {L"provider0.key", hkdfguard::kProviderTypeOffset, 0, "a provider type of 0 is malformed"},
                {L"provider3.key", hkdfguard::kProviderTypeOffset, 3, "a provider type of 3 is malformed"},
                {L"reserved.key", hkdfguard::kReservedOffset, 1, "a non-zero reserved byte is malformed"},
                {L"reserved2.key", hkdfguard::kReservedOffset + 1, 0x80, "a non-zero second reserved byte is malformed"},
                {L"keyid.key", hkdfguard::kKeyIdOffset, 2, "a KeyId other than 1 is malformed"},
                {L"keyidhigh.key", hkdfguard::kKeyIdOffset + 3, 1, "a KeyId with a high byte set is malformed"},
            };
            for (const Corruption& c : corruptions) {
                std::vector<uint8_t> bytes = wrapped;
                bytes[c.offset] = c.value;
                expectFailure(fileFor(c.file, bytes), HKDFGUARD_ERR_FILE_MALFORMED, c.what);
            }
        }

        // More sizes.
        expectFailure(fileFor(L"len1.key", std::vector<uint8_t>(1, 0x01)), HKDFGUARD_ERR_FILE_TOO_SHORT, "a 1-byte file is too short");
        std::vector<uint8_t> doubled = wrapped;
        doubled.insert(doubled.end(), wrapped.begin(), wrapped.end());
        expectFailure(fileFor(L"doubled.key", doubled), HKDFGUARD_ERR_FILE_TOO_LONG,
                      "two valid payloads back to back are too long");

        // open_file never touches a KEK: a payload with a wrong KEK
        // fingerprint is still well-formed, so it opens fine; it is the
        // later, separate unwrap that rejects it.
        {
            std::vector<uint8_t> other_kek = wrapped;
            other_kek[hkdfguard::kFingerprintOffset] ^= 0x01;
            OpenResult o = open(fileFor(L"otherkek.key", other_kek));
            Check(o.rc == HKDFGUARD_OK && o.out == other_kek,
                  "open_file returns a well-formed payload without checking it against any KEK");
            std::vector<uint8_t> dek_out(HKDFGUARD_DEK_LEN);
            int32_t dek_out_len = static_cast<int32_t>(dek_out.size());
            rc = hkdfguard_unwrap_dek(kService, o.out.data(), o.len, dek_out.data(), &dek_out_len);
            Check(rc == HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH, "...and the later unwrap is what rejects it (KEK_FINGERPRINT_MISMATCH)");
        }

        // Sharing: other readers are fine; any writer blocks the read, and
        // the file reads again once the writer is gone.
        {
            const std::wstring goodWide = dir + L"\\good.key";
            HANDLE reader = CreateFileW(goodWide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
            Check(reader != INVALID_HANDLE_VALUE, "test setup: hold good.key open for reading");
            r = open(good);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file succeeds while another process only reads the file");
            if (reader != INVALID_HANDLE_VALUE) CloseHandle(reader);

            HANDLE sharedWriter = CreateFileW(goodWide.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Check(sharedWriter != INVALID_HANDLE_VALUE, "test setup: hold good.key open for writing, sharing read and write");
            expectFailure(good, HKDFGUARD_ERR_FILE_IO, "a file open for writing is refused even when the writer shares access");
            if (sharedWriter != INVALID_HANDLE_VALUE) CloseHandle(sharedWriter);

            r = open(good);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file succeeds again once the writer closes the file");
        }

        // Read-only, hidden files are ordinary files to read.
        {
            const std::string ro = fileFor(L"readonly-hidden.key", wrapped);
            SetFileAttributesW((dir + L"\\readonly-hidden.key").c_str(), FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN);
            r = open(ro);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file reads a read-only, hidden file");
        }

        // Path spellings.
        {
            std::string slashes = ToUtf8(dir) + "/good.key";
            r = open(slashes);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file accepts forward slashes in the path");

            r = open("\\\\?\\" + ToUtf8(dir) + "\\good.key");
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file accepts a \\\\?\\-prefixed path");

            wchar_t saved_cwd[MAX_PATH + 1] = {};
            GetCurrentDirectoryW(MAX_PATH + 1, saved_cwd);
            if (SetCurrentDirectoryW(dir.c_str())) {
                r = open("good.key");
                Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file resolves a relative path against the current directory");
                SetCurrentDirectoryW(saved_cwd);
            } else {
                Check(false, "test setup: change into the scratch folder");
            }

            expectFailure(std::string(32767 * 3 + 1, 'a'), HKDFGUARD_ERR_INVALID_ARGUMENT,
                          "a path longer than the Win32 limit is rejected before any file access");

            // 8.3 short names are refused, never expanded. The scratch
            // folder ("hkdfguard-openfile-<pid>") and the file below have
            // long names; ShortNameFor finds or assigns their short names.
            // Skipped only on a non-elevated run of a volume that doesn't
            // generate them.
            const std::wstring short_folder = ShortNameFor(dir, L"HKOPEN~1");
            const std::string long_file = fileFor(L"long-file-name.wrapped.key", wrapped);
            const std::wstring short_file = ShortNameFor(dir + L"\\long-file-name.wrapped.key", L"LONGFI~1.KEY");
            if (!short_folder.empty()) {
                expectFailure(ToUtf8(short_folder + L"\\good.key"), HKDFGUARD_ERR_FILE_UNTRUSTED,
                              "a path with an 8.3 short folder name is refused");
                expectFailure(ToUtf8(short_folder + L"\\missing.key"), HKDFGUARD_ERR_FILE_UNTRUSTED,
                              "a short folder name is refused even when the file doesn't exist (not just NOT_FOUND)");
            } else {
                Skip("open_file refuses an 8.3 short folder name (no short names here, and not elevated to assign one)");
            }
            size_t leaf_sep = short_file.find_last_of(L'\\');
            if (leaf_sep != std::wstring::npos) {
                // Long folder, short file name: only the leaf is short.
                expectFailure(ToUtf8(dir + short_file.substr(leaf_sep)), HKDFGUARD_ERR_FILE_UNTRUSTED,
                              "a path with an 8.3 short file name is refused");
            } else {
                Skip("open_file refuses an 8.3 short file name (no short names here, and not elevated to assign one)");
            }
            r = open(long_file);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "the same file opens by its long name");

            // The check is exact, not a "~" heuristic: a real long name that
            // happens to look like a short one is accepted.
            const std::string tilde = fileFor(L"report~1.key", wrapped);
            r = open(tilde);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "a genuine file name containing \"~1\" is accepted");
        }

        // Links are refused, never followed - at the file, and anywhere
        // above it. A junction needs no privilege to create (so it's the
        // tool a non-admin would plant); symbolic links need
        // SeCreateSymbolicLinkPrivilege, which an elevated process has.
        {
            const std::wstring junction = dir + L"\\junction";
            if (CreateJunction(junction, dir)) {
                expectFailure(ToUtf8(junction + L"\\good.key"), HKDFGUARD_ERR_FILE_UNTRUSTED,
                              "a file reached through a junction is refused");
                RemoveDirectoryW(junction.c_str());
            } else {
                Check(false, "test setup: create a junction");
            }

            const std::wstring file_link = dir + L"\\link.key";
            if (CreateSymbolicLinkW(file_link.c_str(), (dir + L"\\good.key").c_str(), 0)) {
                expectFailure(ToUtf8(file_link), HKDFGUARD_ERR_FILE_UNTRUSTED,
                              "a file symbolic link is refused, not followed");
                DeleteFileW(file_link.c_str());
            } else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD) {
                Skip("a file symbolic link is refused (needs SeCreateSymbolicLinkPrivilege)");
            } else {
                Check(false, "test setup: create a file symbolic link");
            }

            const std::wstring dir_link = dir + L"\\dirlink";
            if (CreateSymbolicLinkW(dir_link.c_str(), dir.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY)) {
                expectFailure(ToUtf8(dir_link + L"\\good.key"), HKDFGUARD_ERR_FILE_UNTRUSTED,
                              "a file reached through a directory symbolic link is refused");
                RemoveDirectoryW(dir_link.c_str());
            } else if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD) {
                Skip("a file reached through a directory symbolic link is refused (needs SeCreateSymbolicLinkPrivilege)");
            } else {
                Check(false, "test setup: create a directory symbolic link");
            }

            // A SUBST drive aliases a directory; the handle's canonical path
            // is the real directory, so it's refused too.
            DWORD drives = GetLogicalDrives();
            wchar_t letter = 0;
            for (wchar_t c = L'Z'; c >= L'D'; --c) {
                if (!(drives & (1u << (c - L'A')))) { letter = c; break; }
            }
            if (letter == 0) {
                Skip("a file reached through a SUBST drive is refused (no free drive letter)");
            } else {
                const std::wstring device = std::wstring(1, letter) + L":";
                if (DefineDosDeviceW(0, device.c_str(), dir.c_str())) {
                    expectFailure(ToUtf8(device + L"\\good.key"), HKDFGUARD_ERR_FILE_UNTRUSTED,
                                  "a file reached through a SUBST drive is refused");
                    DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, device.c_str(), dir.c_str());
                } else {
                    Check(false, "test setup: define a SUBST drive");
                }
            }

            // The real file at the real path still opens after all that.
            r = open(good);
            Check(r.rc == HKDFGUARD_OK && r.out == wrapped, "open_file still reads the real file at its real path");
        }

        // Reading is read-only: the file is unchanged afterwards, and every
        // read returns the same bytes.
        {
            const std::wstring goodWide = dir + L"\\good.key";
            WIN32_FILE_ATTRIBUTE_DATA before{};
            GetFileAttributesExW(goodWide.c_str(), GetFileExInfoStandard, &before);
            OpenResult first = open(good);
            OpenResult second = open(good);
            WIN32_FILE_ATTRIBUTE_DATA after{};
            GetFileAttributesExW(goodWide.c_str(), GetFileExInfoStandard, &after);
            Check(first.rc == HKDFGUARD_OK && second.rc == HKDFGUARD_OK && first.out == second.out,
                  "repeated open_file calls return identical bytes");
            Check(CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0 &&
                      before.nFileSizeLow == after.nFileSizeLow,
                  "open_file does not modify the file");
        }

        // The ECDH provider the point gate uses can't be opened: the
        // derivation reports CRYPTO_ERROR (an infrastructure failure), and
        // open_file - which checks only structure - is unaffected. Injected
        // through the test-only SetTestEcdhProviderFault seam, so this calls
        // this test's own compiled copies of DeriveWrappingKey and
        // ReadWrappedKeyFile, not the DLL - the DLL has no such seam, which
        // the unwrap check below confirms.
        {
            std::vector<uint8_t> direct(HKDFGUARD_WRAPPED_LEN, 0xAA);
            hkdfguard::SetTestEcdhProviderFault(true);
            Check(PointGateResult(valid_point) == HKDFGUARD_ERR_CRYPTO_ERROR,
                  "ECDH provider unavailable: the point gate reports CRYPTO_ERROR rather than a verdict");
            int32_t derive = CodeOf([&] {
                hkdfguard::ResolvedKek kek = hkdfguard::OpenKekForWrap(kServiceWide);
                hkdfguard::SecureBuffer<32> key;
                hkdfguard::DeriveWrappingKey(kek.provider.get(), kek.key.get(), wrapped.data() + hkdfguard::kSaltOffset, key);
            });
            Check(derive == HKDFGUARD_ERR_CRYPTO_ERROR,
                  "ECDH provider unavailable: the wrapping-key derivation reports CRYPTO_ERROR");
            Check(CodeOf([&] { hkdfguard::ReadWrappedKeyFile(good.c_str(), direct.data()); }) == HKDFGUARD_OK,
                  "ECDH provider unavailable: open_file (test copy) still reads a valid file - it checks only structure");
            // The shipped DLL has no seam: its own unwrap is unaffected.
            std::vector<uint8_t> dll_out(HKDFGUARD_DEK_LEN);
            int32_t dll_out_len = static_cast<int32_t>(dll_out.size());
            rc = hkdfguard_unwrap_dek(kService, wrapped.data(), static_cast<int32_t>(wrapped.size()), dll_out.data(), &dll_out_len);
            Check(rc == HKDFGUARD_OK, "the fault is test-only: the DLL's hkdfguard_unwrap_dek still unwraps");
            hkdfguard::SetTestEcdhProviderFault(false);

            Check(PointGateResult(valid_point) == 1, "the point gate works again once the fault is cleared");
        }
        for (const std::wstring& path : created) {
            SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(path.c_str());
        }
        RemoveDirectoryW(dir.c_str());
    }

    // ---- 24d. The key-file trust rule and plaintext detector, directly. ----
    // CheckKeyFileSecurity on descriptors built from SDDL, so owners that
    // would need SeRestorePrivilege to set on a real file can be tried
    // without elevation; and the plaintext detector on edge cases that
    // never need a file.
    {
        const std::wstring me = CurrentUserSidString();
        const std::wstring trusted_installer = L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        auto verdict = [](const std::wstring& sddl, bool folder) {
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
                return static_cast<int32_t>(1); // the test's own SDDL is wrong
            }
            int32_t code = CodeOf([&] { hkdfguard::CheckKeyFileSecurity(sd, folder); });
            LocalFree(sd);
            return code;
        };
        struct Case {
            std::wstring sddl;
            bool folder;
            int32_t want;
            const char* what;
        };
        const Case cases[] = {
            // Owners.
            {L"O:SYD:P(A;;FA;;;SY)", false, HKDFGUARD_OK, "a file owned by SYSTEM is trusted"},
            {L"O:BAD:P(A;;FA;;;BA)", false, HKDFGUARD_OK, "a file owned by Administrators is trusted"},
            {L"O:" + trusted_installer + L"D:P(A;;FA;;;SY)", false, HKDFGUARD_OK, "a file owned by TrustedInstaller is trusted"},
            {L"O:" + me + L"D:P(A;;FA;;;" + me + L")", false, HKDFGUARD_OK, "a file owned by this account is trusted"},
            {L"O:BUD:P(A;;FA;;;SY)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "a file owned by BUILTIN\\Users is untrusted"},
            {L"O:WDD:P(A;;FA;;;SY)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "a file owned by Everyone is untrusted"},
            {L"O:BUD:P(A;;FA;;;SY)", true, HKDFGUARD_ERR_FILE_UNTRUSTED, "a folder owned by BUILTIN\\Users is untrusted"},
            {L"O:LSD:P(A;;FA;;;SY)", true, HKDFGUARD_ERR_FILE_UNTRUSTED, "a folder owned by LocalService is untrusted"},
            // No DACL, or a NULL one, is unrestricted access.
            {L"O:SY", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "a file with no DACL is untrusted"},
            {L"O:SYD:NO_ACCESS_CONTROL", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "a file with a NULL DACL is untrusted"},
            {L"O:SYD:P", false, HKDFGUARD_OK, "a file with an empty DACL is trusted (only its owner can change it)"},
            // File rights, one at a time.
            {L"O:SYD:P(A;;FR;;;WD)", false, HKDFGUARD_OK, "Everyone reading a file is fine (it's ciphertext)"},
            {L"O:SYD:P(A;;0x2;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with FILE_WRITE_DATA on a file is untrusted"},
            {L"O:SYD:P(A;;0x4;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with FILE_APPEND_DATA on a file is untrusted"},
            {L"O:SYD:P(A;;0x10;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with FILE_WRITE_EA on a file is untrusted"},
            {L"O:SYD:P(A;;0x100;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with FILE_WRITE_ATTRIBUTES on a file is untrusted"},
            {L"O:SYD:P(A;;SD;;;AU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Authenticated Users with DELETE on a file is untrusted"},
            {L"O:SYD:P(A;;WD;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with WRITE_DAC on a file is untrusted"},
            {L"O:SYD:P(A;;WO;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with WRITE_OWNER on a file is untrusted"},
            {L"O:SYD:P(A;;GW;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with GENERIC_WRITE on a file is untrusted"},
            {L"O:SYD:P(A;;GA;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with GENERIC_ALL on a file is untrusted"},
            {L"O:SYD:P(A;;FA;;;S-1-5-21-1-2-3-1001)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "another user with full control of a file is untrusted"},
            // Trusted principals may hold any right.
            {L"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + trusted_installer + L")(A;;FA;;;" + me + L")(A;;FA;;;OW)", false,
             HKDFGUARD_OK, "SYSTEM, Administrators, TrustedInstaller, this account and OWNER RIGHTS may write a file"},
            // ACE kinds.
            {L"O:SYD:P(D;;FA;;;WD)(A;;FA;;;SY)", false, HKDFGUARD_OK, "a deny ACE is never a reason to refuse"},
            {L"O:SYD:P(A;OIIO;FA;;;WD)", true, HKDFGUARD_OK, "an inherit-only ACE does not apply to the folder itself"},
            {L"O:SYD:P(XA;;FA;;;WD;(Member_of {SID(BA)}))", false, HKDFGUARD_ERR_FILE_UNTRUSTED,
             "a conditional allow ACE is judged as if its condition held"},
            // Folder rights: replacing entries is refused, creating them is not.
            {L"O:SYD:P(A;;0x40;;;BU)", true, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with FILE_DELETE_CHILD on a folder is untrusted"},
            {L"O:SYD:P(A;;SD;;;BU)", true, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with DELETE on a folder is untrusted"},
            {L"O:SYD:P(A;;WD;;;BU)", true, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with WRITE_DAC on a folder is untrusted"},
            {L"O:SYD:P(A;;WO;;;BU)", true, HKDFGUARD_ERR_FILE_UNTRUSTED, "Users with WRITE_OWNER on a folder is untrusted"},
            {L"O:SYD:P(A;;0x1301bf;;;AU)", true, HKDFGUARD_ERR_FILE_UNTRUSTED,
             "Authenticated Users: Modify on a folder (what a new folder under C:\\ inherits) is untrusted"},
            {L"O:SYD:P(A;;0x116;;;BU)", true, HKDFGUARD_OK,
             "Users creating files and folders in a folder (C:\\ProgramData-style) is fine"},
            {L"O:SYD:P(A;;0x116;;;BU)", false, HKDFGUARD_ERR_FILE_UNTRUSTED, "...but the same mask on a file is write access"},
            {L"O:SYD:P(A;;GW;;;BU)", true, HKDFGUARD_OK, "GENERIC_WRITE on a folder maps only to creating entries"},
            // C:\ as it ships.
            {L"O:" + trusted_installer + L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"
                                         L"(A;OICIIO;SDGXGWGR;;;AU)(A;;0x4;;;AU)", true, HKDFGUARD_OK,
             "the system drive root's shipped ACL is trusted"},
        };
        for (const Case& c : cases) {
            int32_t got = verdict(c.sddl, c.folder);
            Check(got == c.want, (std::string("key-file trust: ") + c.what).c_str());
            if (got != c.want) std::printf("    (CheckKeyFileSecurity returned %d)\n", got);
        }

        auto plain = [](const std::string& s) {
            return hkdfguard::LooksLikePlaintextKeyForTest(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        };
        std::vector<uint8_t> zeros(HKDFGUARD_DEK_LEN, 0);
        const std::string b64 = Base64Of(zeros, false, true); // "AAAA...A="
        Check(plain(b64), "detector: base64 of a DEK");
        Check(plain(std::string(30, ' ') + b64 + std::string(22, '\n')), "detector: base64 with 96 bytes in all");
        Check(!plain(std::string(31, ' ') + b64 + std::string(22, '\n')), "detector: nothing over 96 bytes is a text DEK");
        Check(!plain(b64.substr(0, 42) + "B="), "detector: base64 whose unused trailing bits are set is not a DEK");
        Check(plain(b64.substr(0, 42) + "E="), "detector: base64 ending in a character with zero trailing bits is a DEK");
        Check(plain("+" + b64.substr(1, 41) + "A"), "detector: 43 characters of standard-alphabet base64 is a DEK");
        Check(!plain("+" + b64.substr(1, 40) + "-A"), "detector: base64 mixing the standard and URL-safe alphabets is not a DEK");
        Check(!plain(b64.substr(0, 42) + "=="), "detector: 44 characters ending \"==\" is not a 32-byte DEK");
        Check(!plain(b64 + "="), "detector: an extra '=' is not a DEK");
        Check(!plain("\v" + b64), "detector: vertical tab is not trimmed (as Rust's trim_ascii)");
        Check(plain(std::string(HKDFGUARD_DEK_LEN, '\0')), "detector: any 32 raw bytes");
    }

    // ---- 25. KeyStoragePolicy is honored for all three values, forced via ----
    //          a test-only override so this doesn't depend on this
    //          machine's real registry policy setting or TPM/vTPM
    //          availability (see policy.h's SetTestPolicyOverride and
    //          CheckPolicyCreatesKek above). Every check above this point
    //          already exercises the real, registry-reading
    //          LoadEffectivePolicy() inside HkdfGuardV1.dll on every wrap/
    //          unwrap/create_kek call - HkdfGuardV1.dll never calls
    //          SetTestPolicyOverride itself, and the override lives in a
    //          separate copy of policy.cpp's state compiled directly into
    //          this .exe (see tests/CMakeLists.txt), so it has no way to
    //          affect the DLL even if it wanted to. This section is the
    //          only place that test-only override is exercised.
    CheckPolicyCreatesKek(
        hkdfguard::KeyStoragePolicy::SoftwareOnly,
        L"hkdfguardwin.test.policy.softwareonly",
        "SoftwareOnly policy",
        /*tpmMayBeUnavailable=*/false);

    CheckPolicyCreatesKek(
        hkdfguard::KeyStoragePolicy::PreferTpm,
        L"hkdfguardwin.test.policy.prefertpm",
        "PreferTpm policy",
        /*tpmMayBeUnavailable=*/false); // always succeeds: falls back to software when there's no TPM

    CheckPolicyCreatesKek(
        hkdfguard::KeyStoragePolicy::RequireTpm,
        L"hkdfguardwin.test.policy.requiretpm",
        "RequireTpm policy",
        /*tpmMayBeUnavailable=*/true); // no fallback - may legitimately fail without real TPM hardware

    // ---- 25b. An invalid KeyStoragePolicy value fails closed with ----
    //           HKDFGUARD_ERR_POLICY_INVALID, rather than being silently
    //           treated as PreferTpm. KeyStoragePolicy::Invalid is exactly
    //           what policy.cpp's ParsePolicyValue returns for a REG_DWORD
    //           value that isn't 0/1/2, or what LoadEffectivePolicy returns
    //           for a value of the wrong registry type - see policy.h's
    //           comment on why that's a deliberate fail-closed choice
    //           rather than a default substitution. Forced via the same
    //           test-only override as section 25 above, so this needs
    //           neither a real bad registry value nor elevation:
    //           KekExists/CreateKek/OpenKekForWrap all read policy and
    //           react to it immediately, before ever calling into NCrypt.
    //           (OpenKekForUnwrap has the identical `if (policy ==
    //           KeyStoragePolicy::Invalid) throw ...` guard - see
    //           kek_store.cpp - but only reaches it after successfully
    //           opening a real key, so exercising it here would need a
    //           provisioned KEK; not duplicated as a separate check.)
    hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::Invalid);

    bool kek_exists_rejects_invalid_policy = false;
    try {
        hkdfguard::KekExists(kServiceLifecycleWide);
    } catch (const hkdfguard::HkdfGuardError &e) {
        kek_exists_rejects_invalid_policy = (e.code() == HKDFGUARD_ERR_POLICY_INVALID);
    } catch (...) {
    }
    Check(kek_exists_rejects_invalid_policy, "KekExists fails closed with POLICY_INVALID for an unrecognized policy value");

    Check(
        InternalCreateKekResult(kServiceLifecycleWide) == HKDFGUARD_ERR_POLICY_INVALID,
        "create_kek fails closed with POLICY_INVALID for an unrecognized policy value");

    bool wrap_rejects_invalid_policy = false;
    try {
        hkdfguard::OpenKekForWrap(kServiceLifecycleWide);
    } catch (const hkdfguard::HkdfGuardError &e) {
        wrap_rejects_invalid_policy = (e.code() == HKDFGUARD_ERR_POLICY_INVALID);
    } catch (...) {
    }
    Check(wrap_rejects_invalid_policy, "wrap fails closed with POLICY_INVALID for an unrecognized policy value");

    hkdfguard::SetTestPolicyOverride(std::nullopt);

    // ---- 25c. A machine with no usable TPM (bare server, VM without a ----
    //           vTPM, container) under the default PreferTpm policy: every
    //           entry point must agree on falling through to the software
    //           provider. Simulated by redirecting the "TPM" provider name
    //           at one no provider is registered under (see kek_store.h's
    //           SetTestTpmProviderNameOverride - a test-only seam, absent
    //           from HkdfGuardV1.dll), so this is deterministic on hardware
    //           that does have a TPM. Guards against the regression where
    //           KekExists threw HKDFGUARD_ERR_PROVIDER_ERROR here while CreateKek
    //           and OpenKekForWrap on the same host happily fell back -
    //           which made hkdfguard_kek_exists, and so the CLI's
    //           `provision`, fail on exactly the hosts the fallback is for.
    //           The RequireTpm half checks the opposite contract: with no
    //           TPM, "exists?" must fail closed with PROVIDER_ERROR rather than
    //           answer from the software provider.
    constexpr const wchar_t* kServiceNoTpmWide = L"hkdfguardwin.test.policy.notpm";
    hkdfguard::SetTestTpmProviderNameOverride(L"hkdfguard-native-windows test: no such provider");

    hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::PreferTpm);
    bool no_tpm_exists_is_false = false;
    try {
        no_tpm_exists_is_false = !hkdfguard::KekExists(kServiceNoTpmWide);
    } catch (const hkdfguard::HkdfGuardError &e) {
        std::printf("    (KekExists threw code %d: %s)\n", e.code(), e.what());
    } catch (...) {
    }
    Check(no_tpm_exists_is_false, "PreferTpm with no TPM: KekExists falls through to software and reports false (not PROVIDER_ERROR)");

    // The create/exists/open/delete sequence needs elevation like every other
    // KEK creation in this suite; without it, this reports a failure that is
    // part of the known non-elevated cascade.
    try {
        hkdfguard::CreateKek(kServiceNoTpmWide);
        Check(true, "PreferTpm with no TPM: create_kek falls back to the software provider");
        Check(hkdfguard::KekExists(kServiceNoTpmWide), "PreferTpm with no TPM: KekExists reports true via the software provider afterward");
        hkdfguard::ResolvedKek kek = hkdfguard::OpenKekForWrap(kServiceNoTpmWide);
        Check(kek.provider_type == hkdfguard::kProviderTypeSoftware, "PreferTpm with no TPM: the KEK actually opened is software-backed");
        hkdfguard::DeleteKek(kServiceNoTpmWide, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId);
    } catch (const std::exception &e) {
        Check(false, "PreferTpm with no TPM: create/exists/open/delete sequence should succeed (elevated)");
        std::printf("    (%s)\n", e.what());
    }

    hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::RequireTpm);
    bool require_tpm_no_tpm_fails_closed = false;
    try {
        hkdfguard::KekExists(kServiceNoTpmWide);
    } catch (const hkdfguard::HkdfGuardError &e) {
        require_tpm_no_tpm_fails_closed = (e.code() == HKDFGUARD_ERR_PROVIDER_ERROR);
    } catch (...) {
    }
    Check(require_tpm_no_tpm_fails_closed, "RequireTpm with no TPM: KekExists fails closed with PROVIDER_ERROR, never answers from software");

    hkdfguard::SetTestPolicyOverride(std::nullopt);
    hkdfguard::SetTestTpmProviderNameOverride(std::nullopt);

    // ---- 25d. Re-provisioning a KEK whose ACL has been widened since ----
    //           creation (or that was pre-planted with a wide ACL) fails
    //           with HKDFGUARD_ERR_KEK_INVALID, and the key is left
    //           exactly where it was - never deleted or replaced. Before
    //           this check, create_kek accepted any existing key under the
    //           service's name as "already provisioned" without looking at
    //           who it admits. SoftwareOnly keeps this off the TPM so it's
    //           deterministic; elevated-only (KEK creation), so it's part of
    //           the known cascade when not elevated.
    constexpr const wchar_t* kServiceAclWidenedWide = L"hkdfguardwin.test.aclwidened";
    hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::SoftwareOnly);
    bool acl_widened_created = false;
    try {
        hkdfguard::CreateKek(kServiceAclWidenedWide);
        acl_widened_created = true;

        // Re-provisioning an untouched KEK is still fine (baseline for the
        // check below - the new ACL check must not reject our own keys).
        Check(
            InternalCreateKekResult(kServiceAclWidenedWide) == HKDFGUARD_OK,
            "create_kek accepts its own, unmodified existing KEK");

        // Widen the finalized key's DACL to include Everyone, as an
        // administrator (or a pre-planted key) could.
        NCRYPT_PROV_HANDLE prov = 0;
        NCRYPT_KEY_HANDLE key = 0;
        SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
        if (st == ERROR_SUCCESS) {
            st = NCryptOpenKey(prov, &key, L"hkdfguardwin_hkdfguardwin.test.aclwidened_v1", 0,
                               NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        }
        bool widened = false;
        if (st == ERROR_SUCCESS) {
            BYTE sys[SECURITY_MAX_SID_SIZE], adm[SECURITY_MAX_SID_SIZE], world[SECURITY_MAX_SID_SIZE];
            DWORD s1 = sizeof(sys), s2 = sizeof(adm), s3 = sizeof(world);
            CreateWellKnownSid(WinLocalSystemSid, nullptr, sys, &s1);
            CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adm, &s2);
            CreateWellKnownSid(WinWorldSid, nullptr, world, &s3);
            EXPLICIT_ACCESSW ea[3] = {};
            PSID sids[3] = {sys, adm, world};
            ACCESS_MASK masks[3] = {GENERIC_ALL, GENERIC_ALL, GENERIC_READ};
            for (int i = 0; i < 3; ++i) {
                ea[i].grfAccessPermissions = masks[i];
                ea[i].grfAccessMode = GRANT_ACCESS;
                ea[i].grfInheritance = NO_INHERITANCE;
                ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
                ea[i].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
                ea[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
            }
            PACL acl = nullptr;
            if (SetEntriesInAclW(3, ea, nullptr, &acl) == ERROR_SUCCESS) {
                SECURITY_DESCRIPTOR sd{};
                InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE);
                DWORD need = 0;
                MakeSelfRelativeSD(&sd, nullptr, &need);
                std::vector<BYTE> rel(need);
                if (MakeSelfRelativeSD(&sd, rel.data(), &need)) {
                    widened = NCryptSetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, rel.data(),
                                                static_cast<DWORD>(rel.size()), DACL_SECURITY_INFORMATION) ==
                              ERROR_SUCCESS;
                }
                LocalFree(acl);
            }
        }
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
        Check(widened, "test setup: existing KEK's ACL widened to grant Everyone read");

        if (widened) {
            Check(
                InternalCreateKekResult(kServiceAclWidenedWide) == HKDFGUARD_ERR_KEK_INVALID,
                "create_kek rejects an existing KEK whose ACL grants an over-broad principal (KEK_INVALID)");
            Check(
                hkdfguard::KekExists(kServiceAclWidenedWide),
                "a KEK rejected for its ACL is left in place, not deleted");
        }
    } catch (const std::exception &e) {
        Check(false, "widened-ACL scenario: KEK setup should succeed (elevated)");
        std::printf("    (%s)\n", e.what());
    }
    if (acl_widened_created) {
        try {
            hkdfguard::DeleteKek(kServiceAclWidenedWide, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId);
        } catch (...) {
        }
    }
    hkdfguard::SetTestPolicyOverride(std::nullopt);

    const bool elevated = IsElevated();
    const bool hasTpm = HasTpmProvider();
    std::printf("    (elevated: %s, TPM provider available: %s)\n", elevated ? "yes" : "no", hasTpm ? "yes" : "no");

    // ---- 26. PreferTpm falls back to software only when the TPM is ----
    //          provably unusable (kek_store.cpp's TpmUnusableError). Faults
    //          are injected through the test-only SetTestTpmFaults seam.
    {
        hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::PreferTpm);

        // 26a. A TPM that errors while being probed (here: not ready) may
        //      have a KEK behind it, so nothing may fall back. Before the
        //      fix, KekExists answered "false" from software, wrap opened
        //      the software provider, and create made a software KEK.
        //      The fault is injected at NCryptOpenKey, which is only reached
        //      once the TPM provider itself has opened. Without one (e.g. a
        //      hosted CI runner), opening the provider fails first - which is
        //      correctly treated as "no TPM" and falls back - so the injected
        //      fault is never hit and this scenario can't be staged.
        constexpr const wchar_t* kServiceProbeFault = L"hkdfguardwin.test.fallback.probefault";
        if (hasTpm) {
            hkdfguard::TestTpmFaults notReady;
            notReady.openKeyStatus = NTE_DEVICE_NOT_READY;
            hkdfguard::SetTestTpmFaults(notReady);
            Check(CodeOf([&] { hkdfguard::KekExists(kServiceProbeFault); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "PreferTpm, TPM probe error: KekExists fails with PROVIDER_ERROR instead of answering from software");
            Check(CodeOf([&] { hkdfguard::OpenKekForWrap(kServiceProbeFault); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "PreferTpm, TPM probe error: wrap fails with PROVIDER_ERROR instead of falling back");
            Check(CodeOf([&] { hkdfguard::CreateKek(kServiceProbeFault); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "PreferTpm, TPM probe error: create_kek fails with PROVIDER_ERROR instead of falling back");
            Check(!MachineKeyExists(MS_KEY_STORAGE_PROVIDER, KekNameFor(kServiceProbeFault)),
                  "PreferTpm, TPM probe error: no software KEK is created");
        } else {
            Skip("PreferTpm, TPM probe error: no fallback (needs the TPM provider to open on this machine)");
        }
        hkdfguard::SetTestTpmFaults({});
        DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, KekNameFor(kServiceProbeFault));

        // 26b. A TPM that reports no device does fall back.
        constexpr const wchar_t* kServiceNoDevice = L"hkdfguardwin.test.fallback.nodevice";
        hkdfguard::TestTpmFaults noDevice;
        noDevice.openKeyStatus = TBS_E_TPM_NOT_FOUND;
        hkdfguard::SetTestTpmFaults(noDevice);
        bool noDeviceExists = true;
        Check(CodeOf([&] { noDeviceExists = hkdfguard::KekExists(kServiceNoDevice); }) == HKDFGUARD_OK && !noDeviceExists,
              "PreferTpm, TPM reports no device: KekExists falls back to software and reports false");
        if (elevated) {
            Check(CodeOf([&] { hkdfguard::CreateKek(kServiceNoDevice); }) == HKDFGUARD_OK,
                  "PreferTpm, TPM reports no device: create_kek falls back to the software provider");
            uint8_t openedType = 0;
            Check(CodeOf([&] { openedType = hkdfguard::OpenKekForWrap(kServiceNoDevice).provider_type; }) ==
                          HKDFGUARD_OK &&
                      openedType == hkdfguard::kProviderTypeSoftware,
                  "PreferTpm, TPM reports no device: wrap opens the software KEK");
        } else {
            Skip("PreferTpm, TPM reports no device: create_kek falls back (needs elevation)");
        }
        hkdfguard::SetTestTpmFaults({});
        DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, KekNameFor(kServiceNoDevice));

        // 26c. An existing TPM KEK that fails verification must not be
        //      sidestepped by a software KEK. Needs a real TPM KEK.
        constexpr const wchar_t* kServiceVerifyFault = L"hkdfguardwin.test.fallback.verifyfault";
        if (elevated && hasTpm) {
            bool tpmCreated = CodeOf([&] { hkdfguard::CreateKek(kServiceVerifyFault); }) == HKDFGUARD_OK &&
                              MachineKeyExists(MS_PLATFORM_CRYPTO_PROVIDER, KekNameFor(kServiceVerifyFault));
            Check(tpmCreated, "test setup: PreferTpm creates a real TPM KEK");
            if (tpmCreated) {
                hkdfguard::TestTpmFaults verifyFails;
                verifyFails.failVerification = true;
                hkdfguard::SetTestTpmFaults(verifyFails);
                Check(CodeOf([&] { hkdfguard::CreateKek(kServiceVerifyFault); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                      "PreferTpm, existing TPM KEK fails verification: create_kek fails instead of falling back");
                Check(!MachineKeyExists(MS_KEY_STORAGE_PROVIDER, KekNameFor(kServiceVerifyFault)),
                      "PreferTpm, existing TPM KEK fails verification: no software KEK is created beside it");
                Check(CodeOf([&] { hkdfguard::OpenKekForWrap(kServiceVerifyFault); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                      "PreferTpm, existing TPM KEK fails verification: wrap fails instead of falling back");
                Check(MachineKeyExists(MS_PLATFORM_CRYPTO_PROVIDER, KekNameFor(kServiceVerifyFault)),
                      "PreferTpm, existing TPM KEK fails verification: the TPM KEK is left in place");
                hkdfguard::SetTestTpmFaults({});
            }
        } else {
            Skip("PreferTpm, existing TPM KEK fails verification: no fallback (needs elevation and a TPM)");
        }
        hkdfguard::SetTestTpmFaults({});
        DeleteMachineKeyQuiet(MS_PLATFORM_CRYPTO_PROVIDER, KekNameFor(kServiceVerifyFault));
        DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, KekNameFor(kServiceVerifyFault));

        hkdfguard::SetTestPolicyOverride(std::nullopt);
    }

    // ---- 27. A pre-planted key under a service's name that this library ----
    //          would never create is refused by create and wrap, and left in
    //          place. SoftwareOnly keeps it deterministic. Planting a
    //          machine key needs elevation.
    {
        struct Planted {
            const wchar_t* service;
            LPCWSTR algorithm;
            LPCWSTR curve;
            bool exportable;
            const char* label;
        };
        const Planted planted[] = {
            {L"hkdfguardwin.test.planted.brainpool", NCRYPT_ECDH_ALGORITHM, BCRYPT_ECC_CURVE_BRAINPOOLP256R1, false,
             "a brainpoolP256r1 key (256-bit, wrong curve)"},
            {L"hkdfguardwin.test.planted.p384", NCRYPT_ECDH_P384_ALGORITHM, nullptr, false, "a P-384 key"},
            {L"hkdfguardwin.test.planted.exportable", NCRYPT_ECDH_P256_ALGORITHM, nullptr, true,
             "an exportable P-256 key"},
        };
        hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::SoftwareOnly);
        for (const Planted& p : planted) {
            const std::wstring name = KekNameFor(p.service);
            const std::string label(p.label);
            if (!elevated) {
                Skip(("pre-planted " + label + " is refused (needs elevation)").c_str());
                continue;
            }
            DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, name);
            bool plantedOk = PlantSoftwareKey(name, p.algorithm, p.curve, p.exportable);
            Check(plantedOk, ("test setup: plant " + label).c_str());
            if (plantedOk) {
                Check(CodeOf([&] { hkdfguard::CreateKek(p.service); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                      ("create_kek refuses a pre-planted " + label).c_str());
                Check(CodeOf([&] { hkdfguard::OpenKekForWrap(p.service); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                      ("wrap refuses a pre-planted " + label).c_str());
                Check(MachineKeyExists(MS_KEY_STORAGE_PROVIDER, name),
                      ("a refused pre-planted " + label + " is left in place").c_str());
            }
            DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, name);
        }
        hkdfguard::SetTestPolicyOverride(std::nullopt);
    }

    // ---- 28. Re-provisioning refuses an existing KEK whose ACL grants an ----
    //          over-broad principal through a conditional (callback) allow
    //          ACE, or grants one of the broad groups added to the denylist.
    //          Complements 25d, which covers a plain grant to Everyone.
    {
        constexpr const wchar_t* kServiceAclEntries = L"hkdfguardwin.test.aclentries";
        const std::wstring name = KekNameFor(kServiceAclEntries);
        struct AclCase {
            const wchar_t* sddl;
            const char* label;
        };
        const AclCase cases[] = {
            {L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(XA;;GR;;;WD;(Member_of {SID(BA)}))",
             "a conditional allow ACE for Everyone"},
            {L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;S-1-5-80-0)", "a grant to NT SERVICE\\ALL SERVICES"},
            {L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;S-1-5-113)", "a grant to NT AUTHORITY\\Local account"},
        };
        if (!elevated) {
            Skip("existing-KEK ACL checks for conditional and newly denied grants (needs elevation)");
        } else {
            hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::SoftwareOnly);
            DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, name);
            bool created = CodeOf([&] { hkdfguard::CreateKek(kServiceAclEntries); }) == HKDFGUARD_OK;
            Check(created, "test setup: create a KEK for the ACL-entry checks");
            if (created) {
                // A legitimate ACL (no over-broad grants) must still pass, so
                // each case is a real rejection, not a broken check.
                bool baselineSet = SetSoftwareKeyDacl(name, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
                Check(baselineSet && CodeOf([&] { hkdfguard::CreateKek(kServiceAclEntries); }) == HKDFGUARD_OK,
                      "create_kek accepts an existing KEK whose ACL is just SYSTEM and Administrators");
                for (const AclCase& c : cases) {
                    const std::string label(c.label);
                    bool set = SetSoftwareKeyDacl(name, c.sddl);
                    Check(set, ("test setup: set an ACL with " + label).c_str());
                    if (set) {
                        Check(CodeOf([&] { hkdfguard::CreateKek(kServiceAclEntries); }) ==
                                  HKDFGUARD_ERR_KEK_INVALID,
                              ("create_kek rejects an existing KEK whose ACL has " + label).c_str());
                        Check(MachineKeyExists(MS_KEY_STORAGE_PROVIDER, name),
                              ("a KEK rejected for " + label + " is left in place").c_str());
                    }
                }
            }
            DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, name);
            hkdfguard::SetTestPolicyOverride(std::nullopt);
        }
    }

    // ---- 29. Golden payload: the derivation and wire format are pinned. ----
    //          Wrap and unwrap share the library's code, so a change to the
    //          HKDF info, hash, salt, AAD, IKM byte order or layout would
    //          still round-trip - while silently breaking every payload
    //          already deployed (and rollback depends on those). Two checks:
    //          (a) the documented construction, computed independently of
    //          src/ with fixed keys and nonce, reproduces the frozen payload;
    //          (b) the shipped DLL unwraps the frozen payload to the known
    //          DEK, once the golden KEK is imported (needs elevation).
    {
        std::vector<uint8_t> independent;
        bool built = BuildGoldenPayloadIndependently(independent);
        Check(built, "golden payload: the documented construction can be computed independently");
        if (std::strlen(kGoldenPayloadHex) == 0) {
            std::printf("    (golden payload not frozen yet; computed: %s)\n", ToHex(independent).c_str());
            Check(false, "golden payload: kGoldenPayloadHex is frozen in the test source");
        } else {
            std::vector<uint8_t> golden = FromHex(kGoldenPayloadHex);
            Check(built && independent == golden,
                  "golden payload: the documented construction reproduces the frozen payload byte for byte");

            if (elevated) {
                DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, KekNameFor(kGoldenServiceWide));
                bool imported = ImportGoldenKek();
                Check(imported, "test setup: import the golden KEK as a Software KSP machine key");
                if (imported) {
                    std::vector<uint8_t> out(HKDFGUARD_DEK_LEN, 0xAA);
                    int32_t outLen = static_cast<int32_t>(out.size());
                    rc = hkdfguard_unwrap_dek(kGoldenService, golden.data(), static_cast<int32_t>(golden.size()),
                                              out.data(), &outLen);
                    Check(rc == HKDFGUARD_OK, "golden payload: the shipped DLL unwraps the frozen payload");
                    if (rc != HKDFGUARD_OK) {
                        std::printf("    (hkdfguard_unwrap_dek returned %d)\n", rc);
                    }
                    Check(rc == HKDFGUARD_OK && std::memcmp(out.data(), dek.data(), HKDFGUARD_DEK_LEN) == 0,
                          "golden payload: unwrapping it recovers the known DEK");
                }
                DeleteMachineKeyQuiet(MS_KEY_STORAGE_PROVIDER, KekNameFor(kGoldenServiceWide));
            } else {
                Skip("golden payload: the shipped DLL unwraps the frozen payload (needs elevation)");
            }
        }
    }

    // ---- Cleanup. ----
    // Remove the KEKs this test run created so they don't accumulate in the
    // user's key storage across repeated runs. (CheckPolicyCreatesKek above
    // already cleans up after itself.)
    CleanupKek(kServiceLifecycleWide, lifecycle_wrapped[1], "lifecycle test service");
    if (use_groups_service_created) {
        CleanupKek(kServiceUseGroupsWide, use_groups_wrapped[1], "key-use-policy test service");
    }
    CleanupKek(kServiceWide, provider_type, "primary test service");
    if (other_service_wrapped) {
        // wrapped_other[1] is the second service's own ProviderType byte -
        // may differ from `provider_type` above in principle, so it's read
        // independently rather than assumed to match.
        CleanupKek(kServiceOtherWide, wrapped_other[1], "secondary test service");
    }
    if (service128_wrapped) {
        const std::wstring service128_wide(128, L'a');
        CleanupKek(service128_wide.c_str(), wrapped_128[1], "128-byte-service-name test service");
    }

    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
