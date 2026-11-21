#pragma once

// windows.h's min and max macros would break std::min and std::max below.
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Shared by the libFuzzer targets that attack HkdfGuard's C ABI
// (fuzz_unwrap_dek, fuzz_wrap_round_trip, fuzz_open_file, fuzz_string_bounds,
// fuzz_api_threads): the one-time setup, the input reader, the buffers a
// hostile caller presents, and the contract every call must keep. The
// counterpart of hkdfguard-native-linux's fuzz/fuzz_targets/common.rs, and
// the inputs decode the same shapes.
//
// The harnesses link the library's own sources (not HkdfGuard.dll), built
// with AddressSanitizer and HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE, so that:
//   - a read or write one byte outside any buffer here is a finding - every
//     buffer handed to the library is a heap allocation of exactly its
//     length, or ends against an inaccessible page (Guarded);
//   - policy is pinned without touching the registry: the Software KSP only,
//     the developer security model, no floor on setup calls;
//   - nothing is written to the event log (event_log_stub.cpp).
//
// A KEK can only be created elevated. Elevated (as in CI), setup creates a
// throwaway KEK per payload version and wraps a known DEK under each: "the
// genuine payload". Unelevated there is no KEK: every buffer, string and
// length attack still runs, and anything that needs the KEK must fail
// cleanly. kWorld.have_kek says which.

#include "fuzz_common.h"
#include "hkdfguard.h"
#include "kek_store.h"   // DeleteKek
#include "kek_v2.h"      // DeleteV2Kek
#include "policy.h"      // the test seams
#include "wire_format.h" // offsets and constants for the harness's own checks

#include <windows.h>
#include <aclapi.h> // SetNamedSecurityInfoW
#include <sddl.h>

#include <algorithm>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace fuzz {

// Reports a violated property with the values that show it, and aborts:
// libFuzzer records the input.
[[noreturn]] inline void Fail(const char* format, ...) {
    std::fprintf(stderr, "fuzz property violated: ");
    va_list args; // NOLINT(cppcoreguidelines-init-variables): va_start initializes it
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    std::fprintf(stderr, "\n");
    std::abort();
}

#define FUZZ_CHECK(condition, ...)              \
    do {                                        \
        if (!static_cast<bool>(condition)) {    \
            ::fuzz::Fail(__VA_ARGS__);          \
        }                                       \
    } while (0)

// ---- the input reader ----

// Reads the fuzzer's bytes as the fields a target's input is made of. Runs
// dry as zeros, so every input decodes to something.
struct In {
    const uint8_t* p;
    size_t n;

    uint8_t u8() {
        if (n == 0) return 0;
        --n;
        return *p++;
    }
    uint16_t u16() {
        const uint16_t lo = u8();
        return static_cast<uint16_t>(lo | (static_cast<uint16_t>(u8()) << 8));
    }
    int16_t i16() { return static_cast<int16_t>(u16()); }
    bool flag() { return (u8() & 1) != 0; }
    // A length-prefixed byte string: u16 length, then that many bytes (or
    // as many as are left).
    std::vector<uint8_t> blob() {
        const size_t len = std::min<size_t>(u16(), n);
        std::vector<uint8_t> out(p, p + len);
        p += len;
        n -= len;
        return out;
    }
};

// ---- exact buffers ----

// `n` bytes whose last byte is the last accessible byte before an
// inaccessible page: reading or writing byte n is an access violation, in
// any build and whoever does it. That matters here: the library zeroes with
// SecureZeroMemory and Windows (BCryptDecrypt, ReadFile) writes results
// straight into the caller's buffer - writes AddressSanitizer never sees.
// n may be 0: a valid pointer to no accessible bytes at all. Every buffer
// and string the harnesses hand the library is one of these.
class Exact {
public:
    Exact() : Exact(0, 0) {}
    Exact(size_t size, uint8_t fill) : n(size) {
        static const size_t page = [] {
            SYSTEM_INFO info{};
            GetSystemInfo(&info);
            return static_cast<size_t>(info.dwPageSize);
        }();
        const size_t data_len = std::max<size_t>(1, (size + page - 1) / page) * page;
        base_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, data_len + page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        DWORD old = 0;
        if (base_ == nullptr || VirtualProtect(base_ + data_len, page, PAGE_NOACCESS, &old) == 0) {
            std::fprintf(stderr, "harness: could not map a guarded buffer (error %lu)
", GetLastError());
            std::abort();
        }
        start_ = base_ + data_len - size;
        if (size != 0) std::memset(start_, fill, size);
    }
    explicit Exact(const std::vector<uint8_t>& bytes) : Exact(bytes.size(), 0) {
        if (n != 0) std::memcpy(start_, bytes.data(), n);
    }
    ~Exact() {
        if (base_ != nullptr) VirtualFree(base_, 0, MEM_RELEASE);
    }
    Exact(const Exact&) = delete;
    Exact& operator=(const Exact&) = delete;
    Exact(Exact&& other) noexcept : n(other.n), base_(other.base_), start_(other.start_) {
        other.base_ = nullptr;
        other.start_ = nullptr;
        other.n = 0;
    }
    Exact& operator=(Exact&& other) noexcept {
        if (this != &other) {
            if (base_ != nullptr) VirtualFree(base_, 0, MEM_RELEASE);
            n = other.n;
            base_ = other.base_;
            start_ = other.start_;
            other.base_ = nullptr;
            other.start_ = nullptr;
            other.n = 0;
        }
        return *this;
    }

    [[nodiscard]] uint8_t* data() const { return start_; }
    [[nodiscard]] const char* ptr() const { return reinterpret_cast<const char*>(start_); }
    [[nodiscard]] std::vector<uint8_t> copy() const { return {start_, start_ + n}; }

    size_t n = 0;

private:
    uint8_t* base_ = nullptr;
    uint8_t* start_ = nullptr;
};

// `text` as a C string whose terminator is the last accessible byte.
inline Exact CString(const std::string& text) {
    Exact e(text.size() + 1, 0);
    if (!text.empty()) std::memcpy(e.data(), text.data(), text.size());
    return e;
}

// A string exactly as given - terminated or not - ending against the
// inaccessible page: what a caller's string looks like when it ends at the
// end of a mapping, and what an unterminated one must be treated as.
using Guarded = Exact;

// ---- the world: policy, KEKs, the genuine payloads ----

inline constexpr int kVersions[] = {2, 1};

struct World {
    std::string service;       // the service whose KEKs setup creates
    std::string service_upper; // the same name in another case: the same service
    std::string other;         // a valid name no KEK was ever created for
    bool elevated = false;
    bool have_kek[3] = {};              // by payload version (1, 2)
    std::vector<uint8_t> genuine[3];    // by payload version: a real payload, or a well-formed stand-in
    uint8_t dek[HKDFGUARD_DEK_LEN] = {}; // the DEK the genuine payloads wrap
    std::wstring dir;                   // a private folder for key files (fuzz_open_file, fuzz_api_threads)
    std::wstring me;                    // this account's SID string
};

inline World& TheWorld() {
    static World world;
    return world;
}

inline bool Elevated() {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    return GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) &&
           elevation.TokenIsElevated != 0;
}

inline std::wstring CurrentUserSid() {
    DWORD size = 0;
    GetTokenInformation(GetCurrentProcessToken(), TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    wchar_t* text = nullptr;
    if (size == 0 || !GetTokenInformation(GetCurrentProcessToken(), TokenUser, buffer.data(), size, &size) ||
        !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) {
        Fail("harness: could not read this account's SID");
    }
    std::wstring sid(text);
    LocalFree(text);
    return sid;
}

inline std::wstring Widen(const std::string& ascii) { return {ascii.begin(), ascii.end()}; }

inline std::string Narrow(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), len, nullptr, nullptr);
    return out;
}

// Pins the payload version the library writes and accepts (ClassicalMode).
inline void UseVersion(int version) {
    hkdfguard::SetTestPayloadVersionOverride(version == 1 ? hkdfguard::PayloadVersionPolicy::Version1
                                                          : hkdfguard::PayloadVersionPolicy::Version2);
}

// A payload of `version` that parses but was wrapped under no KEK: what
// "the genuine payload" is when there is no KEK to make a real one.
inline std::vector<uint8_t> StandInPayload(int version) {
    std::vector<uint8_t> p(HKDFGUARD_WRAPPED_MAX_LEN);
    for (size_t i = 0; i < p.size(); ++i) p[i] = static_cast<uint8_t>(0x30 + i);
    p[hkdfguard::kVersionOffset] = static_cast<uint8_t>(version);
    p[hkdfguard::kProviderTypeOffset] = hkdfguard::kProviderTypeSoftware;
    p[hkdfguard::kReservedOffset] = 0;
    p[hkdfguard::kReservedOffset + 1] = 0;
    p[hkdfguard::kKeyIdOffset] = static_cast<uint8_t>(hkdfguard::kCurrentKeyId);
    p[hkdfguard::kKeyIdOffset + 1] = 0;
    p[hkdfguard::kKeyIdOffset + 2] = 0;
    p[hkdfguard::kKeyIdOffset + 3] = 0;
    return p;
}

inline void DeleteWorldKeks() {
    const World& w = TheWorld();
    for (const std::string& name : {w.service, w.other}) {
        try {
            hkdfguard::DeleteKek(Widen(name), hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId);
        } catch (...) {
            // best-effort: usually there is nothing to delete.
        }
        try {
            hkdfguard::DeleteV2Kek(Widen(name), hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId);
        } catch (...) {
            // best-effort: as above.
        }
    }
}

inline void RemoveWorldDir() {
    const World& w = TheWorld();
    if (w.dir.empty()) return;
    WIN32_FIND_DATAW found{};
    HANDLE find = FindFirstFileW((w.dir + L"\\*").c_str(), &found);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            DeleteFileW((w.dir + L"\\" + found.cFileName).c_str());
        } while (FindNextFileW(find, &found));
        FindClose(find);
    }
    RemoveDirectoryW(w.dir.c_str());
}

// Applies `sddl`'s DACL to `path`, protected from inheritance.
inline bool SetDacl(const std::wstring& path, const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return false;
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    const bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) &&
                    SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                          dacl, nullptr) == ERROR_SUCCESS;
    LocalFree(sd);
    return ok;
}

// Once per process. `tag` names the target: its KEKs and its folder are its
// own, so two targets can run side by side.
inline void Setup(const char* tag) {
    static bool done = false;
    if (done) return;
    done = true;

    World& w = TheWorld();
    w.service = std::string("hkdfguardwin.fuzz.") + tag;
    w.service_upper = w.service;
    for (char& c : w.service_upper) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    w.other = w.service + ".other";
    w.elevated = Elevated();
    w.me = CurrentUserSid();
    for (size_t i = 0; i < sizeof(w.dek); ++i) w.dek[i] = static_cast<uint8_t>(0x40 + i);

    // Policy, pinned in this process only (policy.h's test seams).
    hkdfguard::SetTestPolicyOverride(hkdfguard::KeyStoragePolicy::SoftwareOnly);
    hkdfguard::SetTestSecurityModelOverride(hkdfguard::SecurityModel::Developer);
    hkdfguard::SetTestKeyUseGroupsOverride(std::vector<std::wstring>{});
    hkdfguard::SetTestDeployerGroupsOverride(std::vector<std::wstring>{});
    hkdfguard::SetTestSetupMinDelayMsOverride(0UL);

    // A private folder for key files: under this account's own temp folder
    // (trusted in the developer model), spelled without 8.3 short names,
    // which hkdfguard_open_file refuses.
    wchar_t temp[MAX_PATH + 1] = {};
    wchar_t temp_long[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH + 1, temp);
    const DWORD long_len = GetLongPathNameW(temp, temp_long, MAX_PATH + 1);
    w.dir = std::wstring((long_len > 0 && long_len <= MAX_PATH) ? temp_long : temp) + L"hkdfguard-fuzz-" + Widen(tag) + L"-" +
            std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(w.dir.c_str(), nullptr);
    if (!SetDacl(w.dir, L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + w.me + L")")) {
        Fail("harness: could not protect %ls", w.dir.c_str());
    }

    if (w.elevated) DeleteWorldKeks(); // a crashed run's leftovers
    for (const int version : kVersions) {
        UseVersion(version);
        w.genuine[version] = StandInPayload(version);
        if (!w.elevated) continue;
        const int created = hkdfguard_create_kek(w.service.c_str());
        if (created != HKDFGUARD_OK) {
            // Version 2 needs a Software KSP with SP 800-108 keys; version 1
            // works wherever the library does.
            FUZZ_CHECK(version == 2, "harness: hkdfguard_create_kek (version %d) returned %d", version, created);
            std::fprintf(stderr, "fuzz setup: no version 2 KEK on this machine (create_kek returned %d)\n", created);
            continue;
        }
        std::vector<uint8_t> payload(HKDFGUARD_WRAPPED_MAX_LEN);
        int len = HKDFGUARD_WRAPPED_MAX_LEN;
        const int wrapped = hkdfguard_wrap_dek(w.service.c_str(), w.dek, HKDFGUARD_DEK_LEN, payload.data(), &len);
        FUZZ_CHECK(wrapped == HKDFGUARD_OK && len == HKDFGUARD_WRAPPED_MAX_LEN,
                   "harness: hkdfguard_wrap_dek (version %d) returned %d, length %d", version, wrapped, len);
        w.genuine[version] = payload;
        w.have_kek[version] = true;
    }
    std::fprintf(stderr, "fuzz setup: %s, version 1 KEK: %s, version 2 KEK: %s\n",
                 w.elevated ? "elevated" : "not elevated (no KEK: KEK-dependent paths must fail cleanly)",
                 w.have_kek[1] ? "yes" : "no", w.have_kek[2] ? "yes" : "no");

    std::atexit([] {
        if (TheWorld().elevated) DeleteWorldKeks();
        RemoveWorldDir();
    });
}

// The path (UTF-8) of a key file holding a genuine payload, in the world's
// private folder; written on first use.
inline const std::string& GenuineKeyFile() {
    static std::string utf8;
    if (!utf8.empty()) return utf8;
    const World& w = TheWorld();
    const std::wstring path = w.dir + L"\\genuine.bin";
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written = 0;
    const std::vector<uint8_t>& payload = w.genuine[2];
    const bool wrote = file != INVALID_HANDLE_VALUE &&
                       WriteFile(file, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) &&
                       written == payload.size();
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    FUZZ_CHECK(wrote, "harness: could not write %ls", path.c_str());
    utf8 = Narrow(path);
    return utf8;
}

// The first input byte of every target: which payload version this input
// runs under.
inline int PickVersion(In& in) {
    const int version = (in.u8() & 1) != 0 ? 1 : 2;
    UseVersion(version);
    return version;
}

// ---- the service argument ----

// The library's service-name rule, restated independently: 1 to 128 bytes
// of ASCII letters, digits and '.', not starting with '.', no "..".
inline bool ServiceNameIsValid(const std::string& name) {
    if (name.empty() || name.size() > 128) return false;
    for (const char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.';
        if (!ok) return false;
    }
    return name.front() != '.' && name.find("..") == std::string::npos;
}

inline std::string Lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// Every shape of service string a caller might pass.
struct Service {
    enum class Kind { Fuzz, Upper, Other, Raw, Null };
    Kind kind = Kind::Fuzz;
    std::vector<uint8_t> raw;

    static Service Read(In& in) {
        Service s;
        s.kind = static_cast<Kind>(in.u8() % 5);
        if (s.kind == Kind::Raw) s.raw = in.blob();
        return s;
    }
    // The string as C sees it (the first NUL ends it); nullopt is a NULL
    // pointer.
    [[nodiscard]] std::optional<std::string> text() const {
        const World& w = TheWorld();
        switch (kind) {
            case Kind::Fuzz: return w.service;
            case Kind::Upper: return w.service_upper;
            case Kind::Other: return w.other;
            case Kind::Raw: {
                const auto end = std::ranges::find(raw, uint8_t{0});
                return std::string(raw.begin(), end);
            }
            case Kind::Null: return std::nullopt;
        }
        return std::nullopt;
    }
    [[nodiscard]] bool valid() const {
        const auto t = text();
        return t.has_value() && ServiceNameIsValid(*t);
    }
    // Names the service the world's KEKs belong to, in any case.
    [[nodiscard]] bool is_fuzz() const {
        const auto t = text();
        return t.has_value() && Lower(*t) == TheWorld().service;
    }
};

// A Service's C string, alive for a call: an exact allocation, or NULL.
struct ServiceArg {
    Exact storage;
    const char* ptr = nullptr;
    explicit ServiceArg(const Service& s) {
        if (const auto t = s.text()) {
            storage = CString(*t);
            ptr = reinterpret_cast<const char*>(storage.data());
        }
    }
};

// ---- the output buffer ----

// How the caller's output buffer is presented: its declared capacity
// (negative included), and whether `out` or `out_len` is NULL.
struct Call {
    int cap = 0;
    bool out_null = false;
    bool out_len_null = false;

    static Call Read(In& in) {
        Call c;
        c.cap = in.i16();
        const uint8_t flags = in.u8();
        c.out_null = (flags & 1) != 0;
        c.out_len_null = (flags & 2) != 0;
        return c;
    }
    // Pointers valid, capacity non-negative: a call the contract promises an
    // answer to.
    [[nodiscard]] bool well_formed() const { return !out_null && !out_len_null && cap >= 0; }
};

inline constexpr uint8_t kFill = 0xAA;

struct Ret {
    int rc = 0;
    std::optional<int> out_len; // *out_len after the call, when out_len was not NULL
    std::vector<uint8_t> buf;   // the caller's buffer: max(cap, 0) bytes, kFill before the call

    [[nodiscard]] bool untouched() const {
        return std::ranges::all_of(buf, [](uint8_t b) { return b == kFill; });
    }
    [[nodiscard]] bool zeroed() const {
        return std::ranges::all_of(buf, [](uint8_t b) { return b == 0; });
    }
};

// Runs f(out, out_len) with the buffer `call` describes: an allocation of
// exactly the declared capacity, so a write past it is a finding.
template <typename F>
Ret WithBuffer(const Call& call, F&& f) {
    Exact buf(static_cast<size_t>(std::max(call.cap, 0)), kFill);
    int out_len = call.cap;
    Ret ret;
    ret.rc = std::forward<F>(f)(call.out_null ? nullptr : buf.data(), call.out_len_null ? nullptr : &out_len);
    if (!call.out_len_null) ret.out_len = out_len;
    ret.buf = buf.copy();
    return ret;
}

// What every call must satisfy whatever it returned. `zero_on_failure`: the
// function promises the caller's declared capacity is zeroed on any failure
// (unwrap, open_file), rather than left alone.
inline void CheckContract(const char* what, const Ret& ret, const Call& call, bool zero_on_failure) {
    FUZZ_CHECK(ret.rc != HKDFGUARD_ERR_INTERNAL_ERROR, "%s: INTERNAL_ERROR - an unexpected failure inside the library", what);
    FUZZ_CHECK(ret.rc <= 0, "%s: unknown positive status %d", what, ret.rc);
    if (call.out_len_null) {
        FUZZ_CHECK(ret.rc == HKDFGUARD_ERR_INVALID_ARGUMENT, "%s: out_len NULL returned %d", what, ret.rc);
        FUZZ_CHECK(ret.untouched(), "%s: out_len NULL, but the buffer was written (rc %d)", what, ret.rc);
    }
    if (ret.out_len.has_value() && ret.rc == HKDFGUARD_OK) {
        FUZZ_CHECK(*ret.out_len >= 0 && *ret.out_len <= std::max(call.cap, 0), "%s: OK but *out_len %d exceeds the capacity %d",
                   what, *ret.out_len, call.cap);
    }
    if (zero_on_failure && ret.rc != HKDFGUARD_OK && !call.out_len_null && !call.out_null) {
        FUZZ_CHECK(ret.zeroed(), "%s: failure (rc %d) left bytes in the caller's buffer", what, ret.rc);
    }
}

// The answer the argument checks every buffer-taking function shares must
// give, in the order hkdfguard.h documents, or nullopt when they all pass:
// out_len, the capacity's sign, the service, the size, then `out`.
// `out_before_size`: wrap and kek_fingerprint refuse a NULL `out` with a
// non-zero capacity before reporting the size; unwrap reports the size
// first.
inline std::optional<int> ArgumentVerdict(const Service& service, const Call& call, int needed, bool out_before_size) {
    if (call.out_len_null || call.cap < 0) return HKDFGUARD_ERR_INVALID_ARGUMENT;
    if (!service.valid()) return HKDFGUARD_ERR_INVALID_SERVICE_NAME;
    if (out_before_size && call.out_null && call.cap > 0) return HKDFGUARD_ERR_INVALID_ARGUMENT;
    if (call.cap < needed) return HKDFGUARD_ERR_BUFFER_TOO_SMALL;
    if (call.out_null) return HKDFGUARD_ERR_INVALID_ARGUMENT;
    return std::nullopt;
}

// hkdfguard_unwrap_dek with `payload` in an allocation of exactly its
// length.
inline Ret Unwrap(const Service& service, const std::vector<uint8_t>& payload, const Call& call) {
    const ServiceArg svc(service);
    const Exact wrapped(payload);
    return WithBuffer(call, [&](uint8_t* out, int* out_len) {
        return hkdfguard_unwrap_dek(svc.ptr, wrapped.data(), static_cast<int>(wrapped.n), out, out_len);
    });
}

// Whether `payload` passes the wire format's own checks, restated
// independently of src/wire_format.cpp: the length, a known version, zero
// reserved bytes, a known provider and the one key id.
inline bool PayloadParses(const std::vector<uint8_t>& p) {
    return p.size() == HKDFGUARD_WRAPPED_MAX_LEN && (p[0] == 1 || p[0] == 2) && (p[1] == 1 || p[1] == 2) && p[2] == 0 && p[3] == 0 &&
           p[4] == 1 && p[5] == 0 && p[6] == 0 && p[7] == 0;
}

// ---- edits to a genuine payload ----

// The genuine payload, arbitrary bytes, or the genuine payload with bytes
// flipped, cut short and extended.
inline std::vector<uint8_t> ReadPayload(In& in, int version) {
    const std::vector<uint8_t>& genuine = TheWorld().genuine[version];
    switch (in.u8() % 3) {
        case 0: return genuine;
        case 1: return in.blob();
        default: {
            std::vector<uint8_t> p = genuine;
            const size_t patches = in.u8() % 17;
            for (size_t i = 0; i < patches; ++i) {
                const size_t offset = in.u16() % p.size(); // offsets wrap round the payload
                p[offset] ^= in.u8();
            }
            if (in.flag()) p.resize(std::min<size_t>(in.u16(), p.size()));
            const std::vector<uint8_t> extend = in.blob();
            p.insert(p.end(), extend.begin(), extend.end());
            return p;
        }
    }
}

} // namespace fuzz
