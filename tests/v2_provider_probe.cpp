// Hand-rolled probe program (no test framework), like test_v2_kek: checks the
// Windows key providers' behavior that payload version 2 relies on, directly
// through NCrypt and without HkdfGuard.dll, so it shows what a given TPM,
// provider or Windows build does before the library is relied on there
// (SecurityAssumptions.md section 17, "Standalone probes"). Throwaway keys
// only; every named key it makes is deleted. Exits 0 if every check passed,
// 1 otherwise; a section this machine can't run prints [SKIP], and behavior
// the library works around either way prints [INFO].
//
// Any account:
//   1. Software KSP, SP800_108_CTR_HMAC: a persisted, non-exportable key is
//      created, reopened, and reports its algorithm and export policy;
//      export is refused; its output is deterministic and survives
//      reopening. On an exportable throwaway key, NCryptKeyDerivation equals
//      HMAC-SHA-256 over the hand-built SP 800-108 block (src/sp800_108.h,
//      built here independently) for service names of 0 to 128 bytes, and
//      for the fingerprint's empty context.
//   2. Platform Crypto Provider, HMAC-SHA256, when it opens: a persisted key
//      with the SIGNATURE usage is created and reopened, and reports its
//      algorithm, that usage, hardware backing and no export; export is
//      refused; NCryptSignHash gives 32 bytes - deterministic, and changed by
//      its input's first and last byte - for inputs of 1 to 1,024 bytes, and
//      refuses 1,025; two keys differ, and the output is neither SHA-256 nor
//      an unkeyed HMAC of the input, nor the input; the output survives
//      reopening.
// Elevated:
//   3. Machine scope: both keys created as machine keys with an ACL like the
//      library's (SYSTEM and Administrators full control, Users read). A copy
//      of this program, run with this token restricted the way an unelevated
//      administrator's is (Administrators deny-only, privileges removed,
//      medium integrity), must open and use both - with the same output -
//      and be refused export, making them exportable, widening their DACL
//      and deleting them.
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <sddl.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

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

void Info(const std::string& what) {
    std::printf("[INFO] %s\n", what.c_str());
}

std::string Status(SECURITY_STATUS status) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08lX", static_cast<unsigned long>(status));
    return buf;
}

std::string ToHex(const Bytes& b) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (uint8_t v : b) {
        s += digits[v >> 4];
        s += digits[v & 15];
    }
    return s;
}

Bytes FromHex(const std::wstring& hex) {
    Bytes out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(std::wstring(hex, i, 2), nullptr, 16)));
    }
    return out;
}

bool IsElevated() {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    return GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) &&
           elevation.TokenIsElevated != 0;
}

class Provider {
public:
    ~Provider() {
        if (handle_ != 0) NCryptFreeObject(handle_);
    }
    SECURITY_STATUS Open(LPCWSTR name) { return NCryptOpenStorageProvider(&handle_, name, 0); }
    NCRYPT_PROV_HANDLE get() const { return handle_; }

private:
    NCRYPT_PROV_HANDLE handle_ = 0;
};

class Key {
public:
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() { reset(); }
    void reset() {
        if (handle_ != 0) NCryptFreeObject(handle_);
        handle_ = 0;
    }
    NCRYPT_KEY_HANDLE* put() {
        reset();
        return &handle_;
    }
    NCRYPT_KEY_HANDLE get() const { return handle_; }
    // NCryptDeleteKey frees the handle even when it fails.
    SECURITY_STATUS Delete(DWORD flags = 0) {
        const SECURITY_STATUS status = NCryptDeleteKey(handle_, flags);
        handle_ = 0;
        return status;
    }

private:
    NCRYPT_KEY_HANDLE handle_ = 0;
};

// ---- The SP 800-108 block, built by hand ----

constexpr char kWrapLabel[] = "hkdfguard-wrap-v1";
constexpr char kFingerprintLabel[] = "hkdfguard-kek-fingerprint-v1";
constexpr size_t kHeaderLen = 40;

// u16_le(len(service)) || service || a 40-byte header of `seed`, seed+1, ...
Bytes Context(size_t service_len, uint8_t seed = 0) {
    Bytes c = {static_cast<uint8_t>(service_len & 0xFF), static_cast<uint8_t>(service_len >> 8)};
    for (size_t i = 0; i < service_len; ++i) c.push_back(static_cast<uint8_t>('a' + i % 26));
    for (size_t i = 0; i < kHeaderLen; ++i) c.push_back(static_cast<uint8_t>(seed + i));
    return c;
}

// [1]_32 || Label || 0x00 || Context || [256]_32
Bytes Block(const char* label, const Bytes& context) {
    Bytes m = {0, 0, 0, 1};
    m.insert(m.end(), label, label + std::strlen(label));
    m.push_back(0);
    m.insert(m.end(), context.begin(), context.end());
    m.insert(m.end(), {0, 0, 1, 0});
    return m;
}

Bytes Hmac(const Bytes& key, const Bytes& message) {
    Bytes out(32);
    if (BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
                   const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), out.data(), 32) != 0) {
        out.clear();
    }
    return out;
}

Bytes Sha256(const Bytes& message) {
    Bytes out(32);
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(message.data()),
                   static_cast<ULONG>(message.size()), out.data(), 32) != 0) {
        out.clear();
    }
    return out;
}

// ---- The two operations ----

// The Software KSP's derivation: 32 bytes for `label` and `context` (none
// when empty, as the library passes the fingerprint's).
SECURITY_STATUS Derive(NCRYPT_KEY_HANDLE key, const char* label, const Bytes& context, Bytes& out,
                       DWORD flags = NCRYPT_SILENT_FLAG) {
    BCryptBuffer buffers[3] = {};
    ULONG count = 0;
    buffers[count++] = {static_cast<ULONG>(std::strlen(label)), KDF_LABEL, const_cast<char*>(label)};
    if (!context.empty()) {
        buffers[count++] = {static_cast<ULONG>(context.size()), KDF_CONTEXT, const_cast<uint8_t*>(context.data())};
    }
    buffers[count++] = {static_cast<ULONG>(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM,
                        const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM)};
    BCryptBufferDesc parameters = {BCRYPTBUFFER_VERSION, count, buffers};
    out.assign(32, 0);
    DWORD got = 0;
    const SECURITY_STATUS status = NCryptKeyDerivation(key, &parameters, out.data(), 32, &got, flags);
    if (status != ERROR_SUCCESS || got != 32) out.clear();
    return status;
}

// The PCP's HMAC: NCryptSignHash into a 32-byte buffer, as the library calls it.
SECURITY_STATUS Sign(NCRYPT_KEY_HANDLE key, const Bytes& message, Bytes& out, DWORD flags = NCRYPT_SILENT_FLAG) {
    out.assign(32, 0);
    DWORD got = 0;
    const SECURITY_STATUS status = NCryptSignHash(key, nullptr, const_cast<PBYTE>(message.data()),
                                                  static_cast<DWORD>(message.size()), out.data(), 32, &got, flags);
    if (status != ERROR_SUCCESS || got != 32) out.clear();
    return status;
}

std::wstring StringProperty(NCRYPT_HANDLE object, LPCWSTR property) {
    wchar_t value[64] = {};
    DWORD got = 0;
    if (NCryptGetProperty(object, property, reinterpret_cast<PBYTE>(value), sizeof(value) - sizeof(wchar_t), &got, 0) !=
        ERROR_SUCCESS) {
        return L"";
    }
    return value;
}

bool DwordProperty(NCRYPT_HANDLE object, LPCWSTR property, DWORD& value) {
    DWORD got = 0;
    return NCryptGetProperty(object, property, reinterpret_cast<PBYTE>(&value), sizeof(value), &got, 0) ==
               ERROR_SUCCESS &&
           got == sizeof(value);
}

constexpr DWORD kExportable = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                              NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG;

bool ExportRefused(NCRYPT_KEY_HANDLE key) {
    DWORD got = 0;
    return NCryptExportKey(key, 0, BCRYPT_KEY_DATA_BLOB, nullptr, nullptr, 0, &got, 0) != ERROR_SUCCESS;
}

// Creates a key of the version 2 shape on `provider`: the SP 800-108 key
// with a 256-bit length, or the HMAC key with the SIGNATURE usage; not
// exportable unless `exportable`; with `sddl` as its DACL when given, set
// before finalizing as the library's ApplyKeyAcl does.
SECURITY_STATUS CreateV2ShapedKey(NCRYPT_PROV_HANDLE provider, bool pcp, LPCWSTR name, DWORD flags, Key& key,
                                  bool exportable = false, LPCWSTR sddl = nullptr) {
    SECURITY_STATUS status =
        NCryptCreatePersistedKey(provider, key.put(), pcp ? NCRYPT_HMAC_SHA256_ALGORITHM : NCRYPT_SP800108_CTR_HMAC_ALGORITHM,
                                 name, 0, flags | NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) return status;
    if (pcp) {
        DWORD usage = NCRYPT_PCP_SIGNATURE_KEY;
        status = NCryptSetProperty(key.get(), NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&usage),
                                   sizeof(usage), 0);
    } else {
        DWORD length = 256;
        status = NCryptSetProperty(key.get(), NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&length), sizeof(length), 0);
    }
    if (status != ERROR_SUCCESS) return status;
    DWORD export_policy = exportable ? (NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) : 0;
    status = NCryptSetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                               sizeof(export_policy), 0);
    if (status != ERROR_SUCCESS) return status;
    if (sddl != nullptr) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        ULONG sd_len = 0;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, &sd_len)) {
            return static_cast<SECURITY_STATUS>(HRESULT_FROM_WIN32(GetLastError()));
        }
        status = NCryptSetProperty(key.get(), NCRYPT_SECURITY_DESCR_PROPERTY, static_cast<PBYTE>(sd), sd_len,
                                   DACL_SECURITY_INFORMATION);
        LocalFree(sd);
        if (status != ERROR_SUCCESS) return status;
    }
    return NCryptFinalizeKey(key.get(), NCRYPT_SILENT_FLAG);
}

// Deletes a leftover from an interrupted run, quietly.
void DeleteIfPresent(NCRYPT_PROV_HANDLE provider, LPCWSTR name, DWORD flags) {
    Key key;
    if (NCryptOpenKey(provider, key.put(), name, 0, flags | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        key.Delete();
    }
}

// ---- 1. Software KSP ----

void SoftwareKsp() {
    Provider provider;
    SECURITY_STATUS status = provider.Open(MS_KEY_STORAGE_PROVIDER);
    Check(status == ERROR_SUCCESS, "KSP: the Microsoft Software Key Storage Provider opens (" + Status(status) + ")");
    if (status != ERROR_SUCCESS) return;

    // A persisted, non-exportable key, as the software KEK is (user scope
    // here; machine scope is section 3).
    const wchar_t* name = L"HkdfGuardV2Probe_UserKdf";
    DeleteIfPresent(provider.get(), name, 0);
    {
        Key key;
        status = CreateV2ShapedKey(provider.get(), false, name, 0, key);
        Check(status == ERROR_SUCCESS, "KSP: a persisted, non-exportable SP800_108_CTR_HMAC key is created (" +
                                           Status(status) + ")");
        if (status != ERROR_SUCCESS) return;
    }
    Key key;
    status = NCryptOpenKey(provider.get(), key.put(), name, 0, NCRYPT_SILENT_FLAG);
    Check(status == ERROR_SUCCESS, "KSP: ...and reopened (" + Status(status) + ")");
    if (status != ERROR_SUCCESS) return;
    Check(StringProperty(key.get(), NCRYPT_ALGORITHM_PROPERTY) == NCRYPT_SP800108_CTR_HMAC_ALGORITHM,
          "KSP: it reports the algorithm SP800_108_CTR_HMAC");
    DWORD export_policy = kExportable;
    Check(DwordProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, export_policy) && (export_policy & kExportable) == 0,
          "KSP: it reports no export allowed");
    Check(ExportRefused(key.get()), "KSP: exporting it is refused");

    Bytes first, again, other;
    const SECURITY_STATUS derived = Derive(key.get(), kWrapLabel, Context(13), first);
    Derive(key.get(), kWrapLabel, Context(13), again);
    Derive(key.get(), kWrapLabel, Context(13, 1), other);
    Check(derived == ERROR_SUCCESS && first.size() == 32, "KSP: NCryptKeyDerivation gives 32 bytes (" + Status(derived) + ")");
    Check(!first.empty() && first == again, "KSP: ...deterministically");
    Check(!first.empty() && first != other, "KSP: ...and a different context gives a different output");
    Bytes silent_off;
    Derive(key.get(), kWrapLabel, Context(13), silent_off, 0);
    Check(!first.empty() && first == silent_off, "KSP: NCRYPT_SILENT_FLAG doesn't change the output");
    key.reset();
    status = NCryptOpenKey(provider.get(), key.put(), name, 0, NCRYPT_SILENT_FLAG);
    Bytes reopened;
    if (status == ERROR_SUCCESS) Derive(key.get(), kWrapLabel, Context(13), reopened);
    Check(!first.empty() && first == reopened, "KSP: the same output after reopening");
    status = key.Delete();
    Check(status == ERROR_SUCCESS, "KSP: the probe key is deleted (" + Status(status) + ")");

    // The known answer: an exportable throwaway key whose value can be
    // read, against HMAC-SHA-256 over the block built by hand.
    Key kat;
    status = CreateV2ShapedKey(provider.get(), false, nullptr, 0, kat, true);
    Bytes blob(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 64);
    DWORD got = 0;
    if (status == ERROR_SUCCESS) {
        status = NCryptExportKey(kat.get(), 0, BCRYPT_KEY_DATA_BLOB, nullptr, blob.data(), static_cast<DWORD>(blob.size()),
                                 &got, 0);
    }
    BCRYPT_KEY_DATA_BLOB_HEADER header{};
    if (status == ERROR_SUCCESS && got >= sizeof(header)) std::memcpy(&header, blob.data(), sizeof(header));
    const bool have_key = status == ERROR_SUCCESS && header.dwMagic == BCRYPT_KEY_DATA_BLOB_MAGIC &&
                          header.cbKeyData == 32 && got == sizeof(header) + 32;
    Check(have_key, "KSP: an exportable throwaway key of the same shape exports a 32-byte value (" + Status(status) + ")");
    if (!have_key) return;
    const Bytes secret(blob.begin() + sizeof(header), blob.begin() + sizeof(header) + 32);
    SecureZeroMemory(blob.data(), blob.size());

    int matched = 0;
    const size_t lengths[] = {0, 1, 13, 64, 127, 128};
    for (size_t len : lengths) {
        const Bytes context = Context(len, static_cast<uint8_t>(len));
        Bytes out;
        Derive(kat.get(), kWrapLabel, context, out);
        const Bytes want = Hmac(secret, Block(kWrapLabel, context));
        const bool ok = !out.empty() && out == want;
        matched += ok ? 1 : 0;
        if (!ok) Info("KSP: known answer differs for a " + std::to_string(len) + "-byte service name");
    }
    Check(matched == static_cast<int>(sizeof(lengths) / sizeof(lengths[0])),
          "KSP: the derivation equals HMAC-SHA-256 over the hand-built wrap block, service names of 0 to 128 bytes "
          "(inputs of 68 to 196 bytes)");
    Bytes fingerprint;
    Derive(kat.get(), kFingerprintLabel, {}, fingerprint);
    Check(!fingerprint.empty() && fingerprint == Hmac(secret, Block(kFingerprintLabel, {})),
          "KSP: ...and over the fingerprint's block, with no context");
}

// ---- 2. Platform Crypto Provider ----

void PlatformCryptoProvider() {
    Provider provider;
    SECURITY_STATUS status = provider.Open(MS_PLATFORM_CRYPTO_PROVIDER);
    if (status != ERROR_SUCCESS) {
        Skip("PCP: the Platform Crypto Provider can't be opened (" + Status(status) + "); no TPM checks run");
        return;
    }
    Info("PCP: HMAC-SHA256 listed as supported: " +
         std::string(NCryptIsAlgSupported(provider.get(), NCRYPT_HMAC_SHA256_ALGORITHM, 0) == ERROR_SUCCESS ? "yes" : "no"));

    // The SIGNATURE usage is what the library sets; whether the PCP also
    // takes a key without it is reported, not required.
    {
        Key bare;
        status = NCryptCreatePersistedKey(provider.get(), bare.put(), NCRYPT_HMAC_SHA256_ALGORITHM, nullptr, 0,
                                          NCRYPT_SILENT_FLAG);
        if (status == ERROR_SUCCESS) status = NCryptFinalizeKey(bare.get(), NCRYPT_SILENT_FLAG);
        Info("PCP: an HMAC key without the SIGNATURE usage finalizes with " + Status(status) +
             " (the library always sets the usage)");
    }

    const wchar_t* name = L"HkdfGuardV2Probe_UserHmac";
    DeleteIfPresent(provider.get(), name, 0);
    {
        Key key;
        status = CreateV2ShapedKey(provider.get(), true, name, 0, key);
        Check(status == ERROR_SUCCESS, "PCP: a persisted, non-exportable HMAC-SHA256 key with the SIGNATURE usage is "
                                       "created (" + Status(status) + ")");
        if (status != ERROR_SUCCESS) return;
    }
    // Properties from a fresh handle: the PCP reports stale values on the
    // creation handle (src/kek_store.cpp).
    Key key;
    status = NCryptOpenKey(provider.get(), key.put(), name, 0, NCRYPT_SILENT_FLAG);
    Check(status == ERROR_SUCCESS, "PCP: ...and reopened (" + Status(status) + ")");
    if (status != ERROR_SUCCESS) return;
    Check(StringProperty(key.get(), NCRYPT_ALGORITHM_PROPERTY) == NCRYPT_HMAC_SHA256_ALGORITHM,
          "PCP: it reports the algorithm HMAC-SHA256");
    DWORD usage = 0;
    Check(DwordProperty(key.get(), NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, usage) && (usage & NCRYPT_PCP_SIGNATURE_KEY) != 0,
          "PCP: it reports the SIGNATURE usage");
    DWORD impl = 0;
    const bool key_says = DwordProperty(key.get(), NCRYPT_IMPL_TYPE_PROPERTY, impl);
    if (!key_says) DwordProperty(provider.get(), NCRYPT_IMPL_TYPE_PROPERTY, impl);
    Check((impl & NCRYPT_IMPL_HARDWARE_FLAG) != 0,
          std::string("PCP: it is hardware backed (from the ") + (key_says ? "key" : "provider") + ")");
    DWORD export_policy = kExportable;
    Check(DwordProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, export_policy) && (export_policy & kExportable) == 0,
          "PCP: it reports no export allowed");
    Check(ExportRefused(key.get()), "PCP: exporting it is refused");

    // Inputs across the PCP's range; the library's are 68 to 196 bytes.
    const size_t lengths[] = {1, 20, 32, 33, 64, 68, 196, 512, 1024};
    int good = 0;
    for (size_t len : lengths) {
        Bytes message(len, 0x5a), out, again, first_changed, last_changed;
        const SECURITY_STATUS signed_status = Sign(key.get(), message, out);
        Sign(key.get(), message, again);
        Bytes m = message;
        m.front() ^= 1;
        Sign(key.get(), m, first_changed);
        m = message;
        m.back() ^= 1;
        Sign(key.get(), m, last_changed);
        const bool ok = signed_status == ERROR_SUCCESS && out.size() == 32 && out == again &&
                        !first_changed.empty() && out != first_changed && !last_changed.empty() && out != last_changed;
        good += ok ? 1 : 0;
        if (!ok) Info("PCP: a " + std::to_string(len) + "-byte input misbehaves (" + Status(signed_status) + ")");
    }
    Check(good == static_cast<int>(sizeof(lengths) / sizeof(lengths[0])),
          "PCP: NCryptSignHash gives 32 bytes, deterministic and changed by the first and last input byte, for "
          "inputs of 1 to 1,024 bytes");
    {
        Bytes out;
        status = Sign(key.get(), Bytes(1025, 0x5a), out);
        Check(status != ERROR_SUCCESS, "PCP: a 1,025-byte input is refused (" + Status(status) + ")");
    }

    // Keyed: another key differs, and the output is no unkeyed function.
    const Bytes message = Block(kWrapLabel, Context(13));
    Bytes out;
    Sign(key.get(), message, out);
    {
        Key second;
        status = CreateV2ShapedKey(provider.get(), true, nullptr, 0, second);
        Bytes other;
        if (status == ERROR_SUCCESS) Sign(second.get(), message, other);
        Check(!out.empty() && !other.empty() && out != other, "PCP: a second key gives a different output (" +
                                                                  Status(status) + ")");
    }
    Check(!out.empty() && out != Sha256(message) && out != Hmac({}, message) && out != Bytes(message.begin(), message.begin() + 32),
          "PCP: the output is neither SHA-256 nor an unkeyed HMAC of the input, nor the input");
    Bytes silent_off;
    Sign(key.get(), message, silent_off, 0);
    Check(!out.empty() && out == silent_off, "PCP: NCRYPT_SILENT_FLAG doesn't change the output");

    // A short output buffer: the library always passes 32 bytes, because on
    // an AMD firmware TPM the PCP reports success and 32 bytes here without
    // writing the result. Reported, not required.
    {
        uint8_t buffer[48];
        std::memset(buffer, 0xEE, sizeof buffer);
        DWORD got = 0;
        status = NCryptSignHash(key.get(), nullptr, const_cast<PBYTE>(message.data()), static_cast<DWORD>(message.size()),
                                buffer, 16, &got, NCRYPT_SILENT_FLAG);
        int past = 0;
        for (size_t i = 16; i < sizeof buffer; ++i) past += buffer[i] != 0xEE ? 1 : 0;
        const bool written = !out.empty() && std::memcmp(buffer, out.data(), 16) == 0;
        Info("PCP: a 16-byte output buffer gives " + Status(status) + ", reported length " + std::to_string(got) +
             ", first 16 bytes " + (written ? "written" : "not written") + ", " + std::to_string(past) +
             " bytes past the buffer changed");
    }

    key.reset();
    status = NCryptOpenKey(provider.get(), key.put(), name, 0, NCRYPT_SILENT_FLAG);
    Bytes reopened;
    if (status == ERROR_SUCCESS) Sign(key.get(), message, reopened);
    Check(!out.empty() && out == reopened, "PCP: the same output after reopening");
    // The PCP refuses NCRYPT_SILENT_FLAG on delete (NTE_BAD_FLAGS) on the
    // TPMs seen so far, which is why the library deletes without it.
    // Reported, not required.
    key.reset();
    status = NCryptOpenKey(provider.get(), key.put(), name, 0, NCRYPT_SILENT_FLAG);
    const SECURITY_STATUS silent = status == ERROR_SUCCESS ? key.Delete(NCRYPT_SILENT_FLAG) : status;
    Info("PCP: deleting with NCRYPT_SILENT_FLAG gives " + Status(silent));
    if (silent != ERROR_SUCCESS) {
        status = NCryptOpenKey(provider.get(), key.put(), name, 0, NCRYPT_SILENT_FLAG);
        if (status == ERROR_SUCCESS) status = key.Delete();
        Check(status == ERROR_SUCCESS, "PCP: the probe key is deleted (" + Status(status) + ")");
    }
}

// ---- 3. Machine scope ----

// The probe's machine keys, and their DACL: SYSTEM and Administrators full
// control, Users read (standing in for a key-use group), protected - the
// shape src/key_acl.cpp gives a KEK.
const wchar_t* const kMachineKdfName = L"HkdfGuardV2Probe_MachineKdf";
const wchar_t* const kMachineHmacName = L"HkdfGuardV2Probe_MachineHmac";
const wchar_t* const kMachineSddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)";
constexpr DWORD kMachine = NCRYPT_MACHINE_KEY_FLAG;

// The output both sides compare: the wrap block for a 13-byte service.
SECURITY_STATUS Compute(NCRYPT_KEY_HANDLE key, bool pcp, Bytes& out) {
    return pcp ? Sign(key, Block(kWrapLabel, Context(13)), out) : Derive(key, kWrapLabel, Context(13), out);
}

// Run as the restricted child: open each machine key, compute, compare
// with the output the elevated parent got, and try what a key-use account
// must not be able to do.
void UseMachineKey(bool pcp, const Bytes& expected) {
    const std::string who = std::string("machine, unelevated, ") + (pcp ? "PCP" : "KSP");
    Provider provider;
    SECURITY_STATUS status = provider.Open(pcp ? MS_PLATFORM_CRYPTO_PROVIDER : MS_KEY_STORAGE_PROVIDER);
    Key key;
    if (status == ERROR_SUCCESS) {
        status = NCryptOpenKey(provider.get(), key.put(), pcp ? kMachineHmacName : kMachineKdfName, 0,
                               kMachine | NCRYPT_SILENT_FLAG);
    }
    Check(status == ERROR_SUCCESS, who + ": the administrator's machine key opens (" + Status(status) + ")");
    if (status != ERROR_SUCCESS) return;
    Bytes out;
    status = Compute(key.get(), pcp, out);
    Check(!out.empty() && out == expected, who + ": it computes the administrator's output (" + Status(status) + ")");

    Check(ExportRefused(key.get()), who + ": exporting it is refused");
    DWORD wide = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    status = NCryptSetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&wide), sizeof(wide),
                               NCRYPT_PERSIST_FLAG);
    Check(status != ERROR_SUCCESS, who + ": making it exportable is refused (" + Status(status) + ")");
    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sd_len = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;WD)", SDDL_REVISION_1, &sd, &sd_len)) {
        status = NCryptSetProperty(key.get(), NCRYPT_SECURITY_DESCR_PROPERTY, static_cast<PBYTE>(sd), sd_len,
                                   DACL_SECURITY_INFORMATION);
        LocalFree(sd);
        Check(status != ERROR_SUCCESS, who + ": widening its DACL to Everyone is refused (" + Status(status) + ")");
    } else {
        Check(false, who + ": test setup: building the Everyone DACL");
    }
    status = key.Delete();
    Check(status != ERROR_SUCCESS, who + ": deleting it is refused (" + Status(status) + ")");
}

// This token, restricted as UAC restricts an administrator's unelevated one:
// Administrators deny-only, privileges removed, medium integrity.
HANDLE UnelevatedToken() {
    HANDLE self = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &self)) {
        return nullptr;
    }
    BYTE admins[SECURITY_MAX_SID_SIZE];
    DWORD admins_len = sizeof admins;
    BYTE medium[SECURITY_MAX_SID_SIZE];
    DWORD medium_len = sizeof medium;
    HANDLE restricted = nullptr;
    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &admins_len) &&
        CreateWellKnownSid(WinMediumLabelSid, nullptr, medium, &medium_len)) {
        SID_AND_ATTRIBUTES disable = {admins, 0};
        if (CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE, 1, &disable, 0, nullptr, 0, nullptr, &restricted)) {
            TOKEN_MANDATORY_LABEL label = {{medium, SE_GROUP_INTEGRITY}};
            if (!SetTokenInformation(restricted, TokenIntegrityLevel, &label, sizeof(label) + medium_len)) {
                CloseHandle(restricted);
                restricted = nullptr;
            }
        }
    }
    CloseHandle(self);
    return restricted;
}

// Runs this program as `--machine-use <ksp output> <pcp output or ->` under
// the unelevated token, its output on this console. Returns its exit code,
// or -1 if it couldn't be started.
int RunUnelevatedChild(const Bytes& ksp, const Bytes& pcp) {
    HANDLE token = UnelevatedToken();
    if (token == nullptr) return -1;
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const std::string args = ToHex(ksp) + " " + (pcp.empty() ? "-" : ToHex(pcp));
    std::wstring command = L"\"" + std::wstring(exe) + L"\" --machine-use " + std::wstring(args.begin(), args.end());

    HANDLE out = nullptr;
    HANDLE err = nullptr;
    DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE), GetCurrentProcess(), &out, 0, TRUE,
                    DUPLICATE_SAME_ACCESS);
    DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE), GetCurrentProcess(), &err, 0, TRUE,
                    DUPLICATE_SAME_ACCESS);
    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out;
    si.hStdError = err;
    PROCESS_INFORMATION pi{};
    const BOOL started =
        CreateProcessAsUserW(token, exe, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);
    int code = -1;
    if (started) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        code = static_cast<int>(exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        Info("machine: starting the unelevated copy failed, error " + std::to_string(GetLastError()));
    }
    if (out != nullptr) CloseHandle(out);
    if (err != nullptr) CloseHandle(err);
    CloseHandle(token);
    return code;
}

// Elevated: creates both machine keys, computes with each, has the
// unelevated copy use them, then deletes them.
void MachineScope() {
    Provider ksp;
    Provider pcp;
    const bool have_pcp = pcp.Open(MS_PLATFORM_CRYPTO_PROVIDER) == ERROR_SUCCESS;
    if (ksp.Open(MS_KEY_STORAGE_PROVIDER) != ERROR_SUCCESS) {
        Check(false, "machine: the Software KSP opens");
        return;
    }
    if (!have_pcp) Skip("machine, PCP: the Platform Crypto Provider can't be opened");

    Bytes ksp_out, pcp_out;
    DeleteIfPresent(ksp.get(), kMachineKdfName, kMachine);
    {
        Key key;
        SECURITY_STATUS status = CreateV2ShapedKey(ksp.get(), false, kMachineKdfName, kMachine, key, false, kMachineSddl);
        if (status == ERROR_SUCCESS) status = Compute(key.get(), false, ksp_out);
        Check(status == ERROR_SUCCESS && !ksp_out.empty(),
              "machine, KSP: the administrator creates a machine key with the library's DACL shape and uses it (" +
                  Status(status) + ")");
    }
    if (have_pcp) {
        DeleteIfPresent(pcp.get(), kMachineHmacName, kMachine);
        Key key;
        SECURITY_STATUS status = CreateV2ShapedKey(pcp.get(), true, kMachineHmacName, kMachine, key, false, kMachineSddl);
        if (status == ERROR_SUCCESS) {
            key.reset();
            status = NCryptOpenKey(pcp.get(), key.put(), kMachineHmacName, 0, kMachine | NCRYPT_SILENT_FLAG);
        }
        if (status == ERROR_SUCCESS) status = Compute(key.get(), true, pcp_out);
        Check(status == ERROR_SUCCESS && !pcp_out.empty(),
              "machine, PCP: the administrator creates a machine key with the library's DACL shape and uses it (" +
                  Status(status) + ")");
    }

    if (!ksp_out.empty()) {
        const int code = RunUnelevatedChild(ksp_out, pcp_out);
        Check(code == 0, "machine: the unelevated copy's checks all passed (exit " + std::to_string(code) + ")");
    }

    // Cleanup, elevated; a key the unelevated copy managed to delete is
    // already a failure there.
    {
        Key key;
        SECURITY_STATUS status = NCryptOpenKey(ksp.get(), key.put(), kMachineKdfName, 0, kMachine | NCRYPT_SILENT_FLAG);
        if (status == ERROR_SUCCESS) status = key.Delete();
        Check(status == ERROR_SUCCESS, "machine, KSP: the probe key is deleted (" + Status(status) + ")");
    }
    if (have_pcp) {
        Key key;
        SECURITY_STATUS status = NCryptOpenKey(pcp.get(), key.put(), kMachineHmacName, 0, kMachine | NCRYPT_SILENT_FLAG);
        if (status == ERROR_SUCCESS) status = key.Delete();
        Check(status == ERROR_SUCCESS, "machine, PCP: the probe key is deleted (" + Status(status) + ")");
    }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc == 4 && std::wcscmp(argv[1], L"--machine-use") == 0) {
        // The unelevated copy MachineScope starts; its exit code is its result.
        UseMachineKey(false, FromHex(argv[2]));
        if (std::wcscmp(argv[3], L"-") != 0) UseMachineKey(true, FromHex(argv[3]));
        return g_failures == 0 ? 0 : 1;
    }
    SoftwareKsp();
    PlatformCryptoProvider();
    if (IsElevated()) {
        MachineScope();
    } else {
        Skip("machine scope: creating machine keys needs elevation");
    }
    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
