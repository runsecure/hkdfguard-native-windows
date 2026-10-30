// Hand-rolled test program (no test framework), like test_roundtrip: checks
// payload version 2 (docs/adr/0001-post-quantum-payload-version-2.md), the
// default since ClassicalMode was introduced. Exits 0 if every check passed,
// 1 otherwise.
//
// Offline, on any machine:
//   1. The SP 800-108 construction against the Linux library's known-answer
//      values (hkdfguard-native-linux, src/crypto.rs, known_answer): the
//      fingerprint, the wrapping-key block for its header, and the wrapping
//      key - so this build and Linux's derive identically.
//   2. The Software KSP's SP800_108_CTR_HMAC derivation, the software KEK's
//      PRF, against HMAC-SHA-256 over those blocks
//      (CheckSoftwareKdfImplementation, with a throwaway key).
//   3. The ClassicalMode rule, and the wire format's version 2.
// Elevated, through HkdfGuard.dll with ClassicalMode set to 0 (version 2):
//   4. The TPM KEK (KeyStoragePolicy RequireTpm), when the Platform Crypto
//      Provider offers HMAC-SHA-256 keys: create, exists, fingerprint, wrap,
//      unwrap, tampering, relabeling, and the ClassicalMode rule both ways;
//      and a KEK whose ACL is widened is inspected as an access-control
//      failure, not as corrupt.
//   5. The software KEK (SoftwareOnly): the same; and a key of another type
//      planted under its name is inspected as invalid.
//   6. Provider choice through the internal API, with a TPM made unusable
//      for version 2: PreferTpm falls back to the software KEK, and
//      RequireTpm fails with PROVIDER_UNAVAILABLE.
// Unelevated:
//   7. Creating a version 2 KEK is refused (KEK_ACCESS_DENIED).
#include "hkdfguard.h"
#include "errors.h"
#include "kek_v2.h"
#include "policy.h"
#include "sp800_108.h"
#include "wire_format.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <sddl.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

using hkdfguard::HkdfGuardError;

namespace {

int g_failures = 0;

void Check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("[PASS] %s\n", what.c_str());
    } else {
        std::printf("[FAIL] %s\n", what.c_str());
        ++g_failures;
    }
}

void Skip(const std::string& what) {
    std::printf("[SKIP] %s\n", what.c_str());
}

constexpr int kOtherException = 1;
int CodeOf(const std::function<void()>& f) {
    try {
        f();
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError& e) {
        return e.code();
    } catch (...) {
        return kOtherException;
    }
}

void Guarded(const std::string& section, const std::function<void()>& body) {
    try {
        body();
    } catch (const HkdfGuardError& e) {
        Check(false, section + ": HkdfGuardError, code " + std::to_string(e.code()) + ": " + e.what());
    } catch (const std::exception& e) {
        Check(false, section + ": exception: " + e.what());
    }
}

std::vector<uint8_t> FromHex(const char* hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; hex[i] != '\0' && hex[i + 1] != '\0'; i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(std::string(hex + i, 2), nullptr, 16)));
    }
    return out;
}

std::string ToHex(const uint8_t* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += digits[p[i] >> 4];
        s += digits[p[i] & 15];
    }
    return s;
}

bool IsElevated() {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    return GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) &&
           elevation.TokenIsElevated != 0;
}

// Whether the Platform Crypto Provider is here and offers HMAC-SHA-256 keys.
bool HasTpm() {
    NCRYPT_PROV_HANDLE provider = 0;
    if (NCryptOpenStorageProvider(&provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS) {
        return false;
    }
    const bool supported = NCryptIsAlgSupported(provider, NCRYPT_HMAC_SHA256_ALGORITHM, 0) == ERROR_SUCCESS;
    NCryptFreeObject(provider);
    return supported;
}

// Sets a REG_DWORD under HKLM\Software\Policies\HkdfGuard for as long as the
// object lives, then puts back whatever was there - as test_roundtrip's
// helper of the same name. Needs elevation; active() says whether it took.
class ScopedMachinePolicyDword {
public:
    ScopedMachinePolicyDword(const wchar_t* name, DWORD value) : name_(name) {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Policies\\HkdfGuard", 0, nullptr, 0,
                            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key_, nullptr) != ERROR_SUCCESS) {
            key_ = nullptr;
            return;
        }
        DWORD size = 0;
        if (RegQueryValueExW(key_, name_, nullptr, &old_type_, nullptr, &size) == ERROR_SUCCESS) {
            old_.resize(size);
            had_old_ = RegQueryValueExW(key_, name_, nullptr, &old_type_, old_.data(), &size) == ERROR_SUCCESS;
        }
        active_ = RegSetValueExW(key_, name_, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) ==
                  ERROR_SUCCESS;
    }
    ~ScopedMachinePolicyDword() { restore(); }
    ScopedMachinePolicyDword(const ScopedMachinePolicyDword&) = delete;
    ScopedMachinePolicyDword& operator=(const ScopedMachinePolicyDword&) = delete;

    bool active() const { return active_; }

    void restore() {
        if (key_ == nullptr) return;
        if (active_) {
            if (had_old_) {
                RegSetValueExW(key_, name_, 0, old_type_, old_.data(), static_cast<DWORD>(old_.size()));
            } else {
                RegDeleteValueW(key_, name_);
            }
        }
        RegCloseKey(key_);
        key_ = nullptr;
        active_ = false;
    }

private:
    const wchar_t* name_;
    HKEY key_ = nullptr;
    bool active_ = false;
    bool had_old_ = false;
    DWORD old_type_ = 0;
    std::vector<BYTE> old_;
};

std::vector<uint8_t> BcryptHmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out(32);
    BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
               const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), out.data(), 32);
    return out;
}

// The DACL of a machine key on `provider_name`, as SDDL, and setting one.
std::wstring KeyDaclSddl(LPCWSTR provider_name, const std::wstring& name) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    std::wstring out;
    if (NCryptOpenStorageProvider(&provider, provider_name, 0) == ERROR_SUCCESS &&
        NCryptOpenKey(provider, &key, name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        DWORD size = 0;
        NCryptGetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, nullptr, 0, &size, DACL_SECURITY_INFORMATION);
        std::vector<BYTE> sd(size);
        if (size != 0 && NCryptGetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, sd.data(), size, &size,
                                           DACL_SECURITY_INFORMATION) == ERROR_SUCCESS) {
            LPWSTR text = nullptr;
            ConvertSecurityDescriptorToStringSecurityDescriptorW(sd.data(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                                 &text, nullptr);
            out = text ? text : L"";
            LocalFree(text);
        }
    }
    if (key) NCryptFreeObject(key);
    if (provider) NCryptFreeObject(provider);
    return out;
}

bool SetKeyDaclSddl(LPCWSTR provider_name, const std::wstring& name, const std::wstring& sddl) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    PSECURITY_DESCRIPTOR sd = nullptr;
    bool ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr) &&
              NCryptOpenStorageProvider(&provider, provider_name, 0) == ERROR_SUCCESS &&
              NCryptOpenKey(provider, &key, name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG) ==
                  ERROR_SUCCESS &&
              NCryptSetProperty(key, NCRYPT_SECURITY_DESCR_PROPERTY, static_cast<PBYTE>(sd),
                                GetSecurityDescriptorLength(sd), DACL_SECURITY_INFORMATION | NCRYPT_SILENT_FLAG) ==
                  ERROR_SUCCESS;
    if (key) NCryptFreeObject(key);
    if (provider) NCryptFreeObject(provider);
    LocalFree(sd);
    return ok;
}

using State = hkdfguard::V2KekInspection::State;

// Widens a KEK's ACL with an Everyone allow ACE (`widen`), inspects it,
// puts the ACL back (`restore`) and inspects it again: the widened key must
// be an access-control failure - never Invalid, which retire --corrupt would
// delete - and the restored one valid again.
void CheckWidenedAclIsNotCorrupt(const std::wstring& service, uint8_t provider_type, const std::string& label,
                                 const std::function<bool()>& widen, const std::function<bool()>& restore) {
    if (!widen()) {
        Check(false, label + ": test setup: give Everyone read access to the KEK");
        return;
    }
    hkdfguard::V2KekInspection widened;
    const int code = CodeOf([&] { widened = hkdfguard::InspectV2Kek(service, provider_type); });
    Check(code == HKDFGUARD_OK && widened.state == State::AccessControlInvalid,
          label + ": a KEK Everyone may read is inspected as an access-control failure, not as corrupt (code " +
              std::to_string(code) + ", state " + std::to_string(static_cast<int>(widened.state)) + ")");
    Check(restore(), label + ": test setup: its ACL restored");
    hkdfguard::V2KekInspection restored;
    Check(CodeOf([&] { restored = hkdfguard::InspectV2Kek(service, provider_type); }) == HKDFGUARD_OK &&
              restored.state == State::Valid,
          label + ": ...and with its ACL restored it is valid again, the key untouched");
}

void OfflineChecks() {
    // ---- 1. SP 800-108 against the Linux known-answer values ----
    {
        // hkdfguard-native-linux, src/crypto.rs, mod known_answer.
        const std::vector<uint8_t> kek(32, 0x2a);
        const std::string service = "com.hkdfguard.kat";
        const std::vector<uint8_t> linux_header = FromHex(
            "01031a0065787465726e616c3a636f6d2e686b646667756172642e6b6174"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "222222222222222222222222"
            "30000000");
        const char* wrap_block =
            "00000001686b646667756172642d777261702d7631001100636f6d2e686b646667756172642e6b617401031a0065787465726e616c3a"
            "636f6d2e686b646667756172642e6b61741111111111111111111111111111111111111111111111111111111111111111222222222222"
            "2222222222223000000000000100";
        const std::vector<uint8_t> fp_block = hkdfguard::FingerprintBlock(1);
        Check(ToHex(BcryptHmac(kek, fp_block).data(), 32) ==
                  "59aa2ac550f7c40ea3d52b6c56720fa8c62b4c2e78be0ef64b77dc40eb01145b",
              "SP 800-108: the fingerprint matches the Linux known answer");
        const std::vector<uint8_t> block = hkdfguard::WrapBlock(1, service, linux_header.data(), linux_header.size());
        Check(ToHex(block.data(), block.size()) == wrap_block, "SP 800-108: the wrapping-key block matches Linux's byte for byte");
        Check(ToHex(BcryptHmac(kek, block).data(), 32) == "a2790d8f1306fbb0f234811df731e4104e2cf1bc5883c75f6c8248312710b684",
              "SP 800-108: the wrapping key matches the Linux known answer");
        const std::vector<uint8_t> context = hkdfguard::WrapContext(service, linux_header.data(), linux_header.size());
        Check(hkdfguard::Sp800108Block(1, hkdfguard::kWrapLabel, context.data(), context.size()) == block,
              "SP 800-108: the wrap block is the label and WrapContext the software KSP is given");
        Check(CodeOf([] { hkdfguard::WrapBlock(1, "", nullptr, 0); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "SP 800-108: an empty service name is refused");
    }

    // ---- 2. The Software KSP's SP 800-108 derivation ----
    {
        const int code = CodeOf([] { hkdfguard::CheckSoftwareKdfImplementation(); });
        Check(code == HKDFGUARD_OK,
              "the Software KSP's SP 800-108 derivation is HMAC-SHA-256 over the Linux blocks, with a 32-byte key (code " +
                  std::to_string(code) + ")");
    }

    // ---- 3. ClassicalMode, and the wire format ----
    {
        using hkdfguard::ParsePayloadVersionPolicy;
        using hkdfguard::PayloadVersionPolicy;
        Check(ParsePayloadVersionPolicy(false, 0, 0) == PayloadVersionPolicy::Version2, "ClassicalMode absent: version 2");
        Check(ParsePayloadVersionPolicy(true, REG_DWORD, 0) == PayloadVersionPolicy::Version2, "ClassicalMode 0: version 2");
        Check(ParsePayloadVersionPolicy(true, REG_DWORD, 1) == PayloadVersionPolicy::Version1, "ClassicalMode 1: version 1");
        Check(ParsePayloadVersionPolicy(true, REG_DWORD, 2) == PayloadVersionPolicy::Invalid, "ClassicalMode 2: invalid");
        Check(ParsePayloadVersionPolicy(true, REG_SZ, 1) == PayloadVersionPolicy::Invalid,
              "ClassicalMode of the wrong type (even \"1\"): invalid");

        uint8_t salt[hkdfguard::kSaltLen] = {};
        uint8_t payload[hkdfguard::kTotalLen] = {};
        uint8_t zeros[32] = {};
        hkdfguard::SerializeWrappedDek(hkdfguard::kFormatVersion2, hkdfguard::kProviderTypeTpm, hkdfguard::kCurrentKeyId,
                                       salt, zeros, zeros, zeros, zeros, payload);
        Check(payload[0] == 2 && hkdfguard::ParseWrappedDek(payload, hkdfguard::kTotalLen).version == 2,
              "wire format: a version 2 payload is written and parsed");
        payload[0] = 3;
        Check(CodeOf([&] { hkdfguard::ParseWrappedDek(payload, hkdfguard::kTotalLen); }) == HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED,
              "wire format: version 3 is unsupported");
    }
}

// One round of the DLL's version 2 path for `service` under the policy in
// force: create, exists, fingerprint, wrap, unwrap, tampering, relabeling.
void RoundTrip(const char* service, uint8_t expected_provider, const std::string& label) {
    Check(hkdfguard_create_kek(service) == HKDFGUARD_OK, label + ": create_kek provisions the version 2 KEK");
    Check(hkdfguard_create_kek(service) == HKDFGUARD_OK, label + ": create_kek again only verifies it");
    int exists = -1;
    Check(hkdfguard_kek_exists(service, &exists) == HKDFGUARD_OK && exists == 1, label + ": kek_exists reports it");

    uint8_t fp1[32] = {}, fp2[32] = {};
    int fp_len = 32;
    Check(hkdfguard_kek_fingerprint(service, fp1, &fp_len) == HKDFGUARD_OK && fp_len == 32, label + ": kek_fingerprint");
    fp_len = 32;
    hkdfguard_kek_fingerprint(service, fp2, &fp_len);
    Check(std::memcmp(fp1, fp2, 32) == 0, label + ": the fingerprint is stable");

    std::vector<uint8_t> dek(HKDFGUARD_DEK_LEN);
    BCryptGenRandom(nullptr, dek.data(), static_cast<ULONG>(dek.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_MAX_LEN), again(HKDFGUARD_WRAPPED_MAX_LEN);
    int len = HKDFGUARD_WRAPPED_MAX_LEN;
    int rc = hkdfguard_wrap_dek(service, dek.data(), HKDFGUARD_DEK_LEN, wrapped.data(), &len);
    Check(rc == HKDFGUARD_OK && len == 132, label + ": wrap succeeds (" + std::to_string(rc) + ")");
    Check(wrapped[0] == 2 && wrapped[1] == expected_provider, label + ": the payload is version 2, on the expected provider");
    Check(std::memcmp(wrapped.data() + hkdfguard::kFingerprintOffset, fp1, 32) == 0,
          label + ": the payload carries the KEK's fingerprint");
    len = HKDFGUARD_WRAPPED_MAX_LEN;
    hkdfguard_wrap_dek(service, dek.data(), HKDFGUARD_DEK_LEN, again.data(), &len);
    Check(again != wrapped, label + ": every wrap is fresh");

    auto unwrap = [&](const std::vector<uint8_t>& payload, std::vector<uint8_t>& out) {
        out.assign(HKDFGUARD_DEK_LEN, 0xAA);
        int out_len = HKDFGUARD_DEK_LEN;
        return hkdfguard_unwrap_dek(service, payload.data(), static_cast<int>(payload.size()), out.data(), &out_len);
    };
    std::vector<uint8_t> back;
    Check(unwrap(wrapped, back) == HKDFGUARD_OK && back == dek, label + ": unwrap recovers the DEK");

    std::vector<uint8_t> tampered = wrapped;
    tampered[hkdfguard::kSaltOffset] ^= 0x01;
    rc = unwrap(tampered, back);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, label + ": a changed salt fails authentication (" + std::to_string(rc) + ")");
    tampered = wrapped;
    tampered[hkdfguard::kCiphertextOffset] ^= 0x01;
    Check(unwrap(tampered, back) == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, label + ": a changed ciphertext fails authentication");
    tampered = wrapped;
    tampered[hkdfguard::kFingerprintOffset] ^= 0x01;
    Check(unwrap(tampered, back) == HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH, label + ": a changed fingerprint is a mismatch");
    tampered = wrapped;
    tampered[0] = 1;
    rc = unwrap(tampered, back);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED && back == std::vector<uint8_t>(HKDFGUARD_DEK_LEN, 0),
          label + ": relabeled as version 1, it is refused (-13) before any key is opened, output zeroed");
    int back_len = HKDFGUARD_DEK_LEN;
    rc = hkdfguard_unwrap_dek("hkdfguardwin.test.v2.nokek", tampered.data(), 132, back.data(), &back_len);
    Check(rc == HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED, label + ": ...even for a service with no KEK at all");

    {
        ScopedMachinePolicyDword classical(L"ClassicalMode", 1);
        rc = unwrap(wrapped, back);
        Check(classical.active() && rc == HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED,
              label + ": with ClassicalMode 1, the version 2 payload is refused (-13)");
    }
    {
        ScopedMachinePolicyDword invalid(L"ClassicalMode", 7);
        Check(invalid.active() && unwrap(wrapped, back) == HKDFGUARD_ERR_POLICY_INVALID &&
                  hkdfguard_create_kek(service) == HKDFGUARD_ERR_POLICY_INVALID,
              label + ": ClassicalMode 7 fails closed (POLICY_INVALID) for unwrap and create");
    }
    Check(unwrap(wrapped, back) == HKDFGUARD_OK && back == dek, label + ": back under version 2, it unwraps again");
}

void ElevatedChecks() {
    using hkdfguard::DeleteV2Kek;
    ScopedMachinePolicyDword v2(L"ClassicalMode", 0);
    Check(v2.active(), "test setup: ClassicalMode 0 (version 2) for the run");

    // ---- 4. The TPM KEK ----
    const char* tpm_service = "hkdfguardwin.test.v2.tpm";
    const std::wstring tpm_service_w = L"hkdfguardwin.test.v2.tpm";
    if (HasTpm()) {
        Guarded("4. TPM KEK", [&] {
            ScopedMachinePolicyDword require_tpm(L"KeyStoragePolicy", 1);
            DeleteV2Kek(tpm_service_w, hkdfguard::kProviderTypeTpm, hkdfguard::kCurrentKeyId);
            RoundTrip(tpm_service, hkdfguard::kProviderTypeTpm, "TPM");
            {
                const std::wstring key_name = hkdfguard::V2TpmKeyName(tpm_service_w, hkdfguard::kCurrentKeyId);
                const std::wstring original = KeyDaclSddl(MS_PLATFORM_CRYPTO_PROVIDER, key_name);
                Check(!original.empty(), "TPM: the KEK is a machine key in the Platform Crypto Provider");
                CheckWidenedAclIsNotCorrupt(
                    tpm_service_w, hkdfguard::kProviderTypeTpm, "TPM",
                    [&] {
                        return !original.empty() &&
                               SetKeyDaclSddl(MS_PLATFORM_CRYPTO_PROVIDER, key_name, original + L"(A;;GR;;;WD)");
                    },
                    [&] { return SetKeyDaclSddl(MS_PLATFORM_CRYPTO_PROVIDER, key_name, original); });
            }
            Check(DeleteV2Kek(tpm_service_w, hkdfguard::kProviderTypeTpm, hkdfguard::kCurrentKeyId), "TPM: test KEK removed");
            int exists = -1;
            Check(hkdfguard_kek_exists(tpm_service, &exists) == HKDFGUARD_OK && exists == 0, "TPM: ...and no longer exists");
        });
    } else {
        Skip("4. TPM KEK: the Platform Crypto Provider offers no HMAC-SHA-256 keys here");
    }

    // ---- 5. The software KEK ----
    const char* sw_service = "hkdfguardwin.test.v2.software";
    const std::wstring sw_service_w = L"hkdfguardwin.test.v2.software";
    Guarded("5. software KEK", [&] {
        ScopedMachinePolicyDword software(L"KeyStoragePolicy", 2);
        DeleteV2Kek(sw_service_w, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId);
        RoundTrip(sw_service, hkdfguard::kProviderTypeSoftware, "software");
        const std::wstring key_name = hkdfguard::V2SoftwareKeyName(sw_service_w, hkdfguard::kCurrentKeyId);
        {
            const std::wstring original = KeyDaclSddl(MS_KEY_STORAGE_PROVIDER, key_name);
            CheckWidenedAclIsNotCorrupt(
                sw_service_w, hkdfguard::kProviderTypeSoftware, "software",
                [&] {
                    return !original.empty() &&
                           SetKeyDaclSddl(MS_KEY_STORAGE_PROVIDER, key_name, original + L"(A;;GR;;;WD)");
                },
                [&] { return SetKeyDaclSddl(MS_KEY_STORAGE_PROVIDER, key_name, original); });
        }
        Check(DeleteV2Kek(sw_service_w, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId), "software: test KEK removed");

        // A key of another type under the KEK's name - planted, or left by
        // an earlier design - is invalid, never used, and can be deleted
        // (retire --corrupt).
        {
            NCRYPT_PROV_HANDLE provider = 0;
            NCRYPT_KEY_HANDLE key = 0;
            const bool planted =
                NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS &&
                NCryptCreatePersistedKey(provider, &key, NCRYPT_AES_ALGORITHM, key_name.c_str(), 0,
                                         NCRYPT_MACHINE_KEY_FLAG) == ERROR_SUCCESS &&
                NCryptFinalizeKey(key, 0) == ERROR_SUCCESS;
            if (key) NCryptFreeObject(key);
            if (provider) NCryptFreeObject(provider);
            Check(planted, "software: test setup: an AES key planted under the KEK's name");
            hkdfguard::V2KekInspection inspection;
            const int code =
                CodeOf([&] { inspection = hkdfguard::InspectV2Kek(sw_service_w, hkdfguard::kProviderTypeSoftware); });
            Check(code == HKDFGUARD_OK && inspection.state == State::Invalid,
                  "software: a key of another type under the name is inspected as invalid (" + inspection.problem + ")");
            std::vector<uint8_t> dek(HKDFGUARD_DEK_LEN), wrapped(HKDFGUARD_WRAPPED_MAX_LEN);
            int len = HKDFGUARD_WRAPPED_MAX_LEN;
            const int rc = hkdfguard_wrap_dek(sw_service, dek.data(), HKDFGUARD_DEK_LEN, wrapped.data(), &len);
            Check(rc == HKDFGUARD_ERR_KEK_INVALID, "software: ...and wrap refuses it (" + std::to_string(rc) + ")");
            Check(DeleteV2Kek(sw_service_w, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId),
                  "software: ...and it can be deleted");
        }
    });

    // ---- 6. Provider choice, with the TPM unusable for version 2 ----
    const std::wstring fb_service = L"hkdfguardwin.test.v2.fallback";
    Guarded("6. provider choice", [&] {
        DeleteV2Kek(fb_service, hkdfguard::kProviderTypeTpm, hkdfguard::kCurrentKeyId);
        DeleteV2Kek(fb_service, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId);
        hkdfguard::SetTestV2TpmUnusable(std::string("simulated by test_v2_kek"));

        hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::RequireTpm);
        Check(CodeOf([&] { hkdfguard::CreateV2Kek(fb_service); }) == HKDFGUARD_ERR_PROVIDER_UNAVAILABLE,
              "RequireTpm, TPM unusable: create fails with PROVIDER_UNAVAILABLE (and logs event 2008)");
        Check(CodeOf([&] { hkdfguard::V2KekExists(fb_service); }) == HKDFGUARD_ERR_PROVIDER_UNAVAILABLE,
              "RequireTpm, TPM unusable: kek_exists can't answer either (PROVIDER_UNAVAILABLE), as version 1's throws");

        hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::PreferTpm);
        Check(!hkdfguard::V2KekExists(fb_service), "...and the failed create left no software KEK behind");
        Check(CodeOf([&] { hkdfguard::CreateV2Kek(fb_service); }) == HKDFGUARD_OK,
              "PreferTpm, TPM unusable: create falls back to the software KEK (event 1001)");
        auto kek = hkdfguard::OpenV2KekForWrap(fb_service);
        Check(kek->provider_type() == hkdfguard::kProviderTypeSoftware, "...which wrap then uses");

        hkdfguard::SetTestV2TpmUnusable(std::nullopt);
        hkdfguard::SetTestPolicyOverride(std::nullopt);
        Check(DeleteV2Kek(fb_service, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId), "fallback: test KEK removed");
    });
    hkdfguard::SetTestV2TpmUnusable(std::nullopt);
    hkdfguard::SetTestPolicyOverride(std::nullopt);
}

void UnelevatedChecks() {
    // ---- 7. Creating needs elevation ----
    // Whichever provider policy picks, creating fails without elevation and
    // leaves nothing: the TPM key file can't be written, and a machine key
    // can't be finalized.
    const int rc = hkdfguard_create_kek("hkdfguardwin.test.v2.unelevated");
    Check(rc == HKDFGUARD_ERR_KEK_ACCESS_DENIED || rc == HKDFGUARD_ERR_POLICY_INVALID,
          "unelevated: create_kek is refused (code " + std::to_string(rc) + ")");
    int exists = -1;
    Check(hkdfguard_kek_exists("hkdfguardwin.test.v2.unelevated", &exists) == HKDFGUARD_OK && exists == 0,
          "...and nothing was created");
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Guarded("offline checks", OfflineChecks);
    if (IsElevated()) {
        Guarded("elevated checks", ElevatedChecks);
    } else {
        Skip("version 2 KEKs through HkdfGuard.dll (needs elevation)");
        Guarded("unelevated checks", UnelevatedChecks);
    }
    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
