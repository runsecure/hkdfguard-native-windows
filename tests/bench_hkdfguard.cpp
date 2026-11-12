// Performance benchmarks for HkdfGuard.dll and the internals behind it.
// Built only on request (cmake -DHKDFGUARD_BUILD_BENCHMARKS=ON); see
// tests/CMakeLists.txt. Not a pass/fail test: it prints latency statistics
// (min, median, p95, p99, mean, ops/s) per operation, and exits non-zero only
// if an operation under measurement *failed* - which is all the ctest smoke
// run (--quick) checks. Real numbers come from running it directly, from a
// Release build, on the machine being measured.
//
// Sections:
//   1. CPU only, never elevated: hash-to-curve, the point gate, the SP 800-108
//      framing and its HMAC, AES-GCM and the wire format, each through this
//      binary's own copy of src/ (built with the DLL's hardening flags).
//   2. hkdfguard_open_file, under the developer security model (elevated, it
//      sets SecurityModel 1 for the section; otherwise it runs only if the
//      machine is already in the developer model).
//   3. Through HkdfGuard.dll, elevated: for payload versions 1 and 2
//      (ClassicalMode 1 / 0) on the Software KSP and the TPM (KeyStoragePolicy
//      2 / 1), a throwaway KEK is created, then wrap, unwrap,
//      generate_and_wrap and kek_fingerprint are measured, single-threaded
//      and across threads. The KEKs are deleted afterwards.
//      hkdfguard_create_kek / hkdfguard_kek_exists are never timed: they are
//      held to a deliberate setup floor (SetupMinDelayMs), which this run sets
//      to 0 only so creating its KEKs doesn't take seconds.
//   3'. Not elevated, with --service NAME: the same measurements against an
//      already-provisioned KEK, under the machine's own policy, changing
//      nothing.
//
// Elevated, this changes machine-wide policy values under
// HKLM\Software\Policies\HkdfGuard while it runs (ClassicalMode,
// KeyStoragePolicy, SetupMinDelayMs, SecurityModel) and puts each back when
// done, as the tests do. Don't run it on a machine where an application is
// using HkdfGuard at the same time, and don't kill it mid-run (the values
// would be left set).
//
// Options:
//   --iterations N      timed operations per row on the Software KSP and in
//                       section 1 (default 2000 for section 1, 500 for KSP)
//   --tpm-iterations N  timed operations per row on the TPM (default 100)
//   --threads A,B,...   thread counts for the scaling rows (default 1,2,4,8)
//   --filter TEXT       only rows whose name contains TEXT
//   --csv PATH          also append every row to PATH as CSV
//   --service NAME      not elevated: measure this existing KEK
//   --quick             a few iterations of everything (the ctest smoke run)
#include "hkdfguard.h"
#include "aes_gcm.h"
#include "ecdh_hkdf.h"     // IsValidP256Point
#include "hash_to_curve.h" // PayloadEcdhPoint
#include "kek_store.h"     // DeleteKek - removes the version 1 KEKs this run creates
#include "kek_v2.h"        // DeleteV2Kek - ...and the version 2 ones
#include "sp800_108.h"     // WrapBlock
#include "wire_format.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock; // QueryPerformanceCounter on MSVC

struct Options {
    int iterations = 0;     // 0: per-section default
    int tpm_iterations = 100;
    std::vector<int> threads{1, 2, 4, 8};
    std::string filter;
    std::string csv;
    std::string service;
    bool quick = false;
};

Options g_opt;
FILE* g_csv = nullptr;
int g_failures = 0;
std::string g_machine; // CPU name, for the CSV

// Keeps the CPU-only bodies from being optimized away.
volatile uint8_t g_sink = 0;

// ---------------------------------------------------------------------------
// Statistics and reporting

struct Stats {
    double min_us = 0, median_us = 0, p95_us = 0, p99_us = 0, mean_us = 0, ops_per_sec = 0;
};

double Percentile(const std::vector<double>& sorted, double p) {
    if (sorted.empty()) return 0;
    const size_t index = static_cast<size_t>(p * static_cast<double>(sorted.size() - 1) + 0.5);
    return sorted[std::min(index, sorted.size() - 1)];
}

Stats Summarize(std::vector<double> latencies_us, double wall_seconds) {
    Stats s;
    if (latencies_us.empty()) return s;
    std::sort(latencies_us.begin(), latencies_us.end());
    double total = 0;
    for (double v : latencies_us) total += v;
    s.min_us = latencies_us.front();
    s.median_us = Percentile(latencies_us, 0.50);
    s.p95_us = Percentile(latencies_us, 0.95);
    s.p99_us = Percentile(latencies_us, 0.99);
    s.mean_us = total / static_cast<double>(latencies_us.size());
    s.ops_per_sec = wall_seconds > 0 ? static_cast<double>(latencies_us.size()) / wall_seconds : 0;
    return s;
}

void PrintHeaderRow() {
    std::printf("  %-48s %4s %7s %10s %10s %10s %10s %10s %10s\n", "operation", "thr", "iters", "min us", "median us",
                "p95 us", "p99 us", "mean us", "ops/s");
}

void Section(const char* title) {
    std::printf("\n== %s\n", title);
    PrintHeaderRow();
}

void Note(const std::string& text) { std::printf("  [note] %s\n", text.c_str()); }
void SkipRow(const std::string& text) { std::printf("  [skip] %s\n", text.c_str()); }

void Report(const std::string& name, int threads, int iterations, const Stats& s, bool ok) {
    if (!ok) {
        ++g_failures;
        std::printf("  %-48s %4d %7d  FAILED (an operation returned an error)\n", name.c_str(), threads, iterations);
    } else {
        std::printf("  %-48s %4d %7d %10.2f %10.2f %10.2f %10.2f %10.2f %10.0f\n", name.c_str(), threads, iterations,
                    s.min_us, s.median_us, s.p95_us, s.p99_us, s.mean_us, s.ops_per_sec);
    }
    if (g_csv != nullptr) {
        std::fprintf(g_csv, "\"%s\",\"%s\",%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.1f,%s\n", g_machine.c_str(), name.c_str(),
                     threads, iterations, s.min_us, s.median_us, s.p95_us, s.p99_us, s.mean_us, s.ops_per_sec,
                     ok ? "ok" : "failed");
        std::fflush(g_csv);
    }
}

bool Selected(const std::string& name) {
    return g_opt.filter.empty() || name.find(g_opt.filter) != std::string::npos;
}

int Warmup(int iterations) { return std::max(1, std::min(50, iterations / 10)); }

// Times `op` `iterations` times on this thread, after a short warm-up. `op`
// returns false on failure; the row is then reported FAILED.
void Bench(const std::string& name, int iterations, const std::function<bool()>& op) {
    if (!Selected(name)) return;
    bool ok = true;
    for (int i = 0, n = Warmup(iterations); i < n; ++i) ok = op() && ok;
    std::vector<double> latencies;
    latencies.reserve(static_cast<size_t>(iterations));
    const auto start = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        const auto t0 = Clock::now();
        ok = op() && ok;
        latencies.push_back(std::chrono::duration<double, std::micro>(Clock::now() - t0).count());
    }
    const double wall = std::chrono::duration<double>(Clock::now() - start).count();
    Report(name, 1, iterations, Summarize(std::move(latencies), wall), ok);
}

// `total` operations split across `threads` threads, all released together.
// `make_op` builds one thread's operation, so each thread owns its buffers.
// ops/s is total operations over the wall time from release to the last
// thread finishing - the aggregate throughput.
void BenchThreads(const std::string& name, int threads, int total,
                  const std::function<std::function<bool()>()>& make_op) {
    if (!Selected(name)) return;
    const int per_thread = std::max(1, total / threads);
    std::vector<std::vector<double>> latencies(static_cast<size_t>(threads));
    std::atomic<bool> ok{true};
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) {
        pool.emplace_back([&, t] {
            std::function<bool()> op = make_op();
            bool mine = true;
            for (int i = 0, n = Warmup(per_thread); i < n; ++i) mine = op() && mine;
            auto& lat = latencies[static_cast<size_t>(t)];
            lat.reserve(static_cast<size_t>(per_thread));
            ++ready;
            while (!go.load()) std::this_thread::yield();
            for (int i = 0; i < per_thread; ++i) {
                const auto t0 = Clock::now();
                mine = op() && mine;
                lat.push_back(std::chrono::duration<double, std::micro>(Clock::now() - t0).count());
            }
            if (!mine) ok = false;
        });
    }
    while (ready.load() < threads) std::this_thread::yield();
    const auto start = Clock::now();
    go = true;
    for (auto& th : pool) th.join();
    const double wall = std::chrono::duration<double>(Clock::now() - start).count();
    std::vector<double> all;
    for (auto& lat : latencies) all.insert(all.end(), lat.begin(), lat.end());
    Report(name, threads, per_thread * threads, Summarize(std::move(all), wall), ok.load());
}

// ---------------------------------------------------------------------------
// Environment

bool IsElevated() {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    return GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) &&
           elevation.TokenIsElevated != 0;
}

std::string Narrow(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

std::string RegString(HKEY root, const wchar_t* path, const wchar_t* name) {
    wchar_t buf[512] = {};
    DWORD size = sizeof(buf) - sizeof(wchar_t);
    if (RegGetValueW(root, path, name, RRF_RT_REG_SZ, nullptr, buf, &size) != ERROR_SUCCESS) return {};
    std::string s = Narrow(buf);
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

// A policy value as found, or "absent".
std::string PolicyDword(const wchar_t* name) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\Policies\\HkdfGuard", name, RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
                     nullptr, &value, &size) != ERROR_SUCCESS) {
        return "absent";
    }
    return std::to_string(value);
}

// The Platform Crypto Provider's platform string - TPM version, vendor and
// firmware - so TPM rows can be told apart across machines. Empty if there
// is no usable TPM provider.
std::string TpmPlatform() {
    NCRYPT_PROV_HANDLE provider = 0;
    if (NCryptOpenStorageProvider(&provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS) return {};
    wchar_t buf[256] = {};
    DWORD size = 0;
    std::string out;
    if (NCryptGetProperty(provider, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, reinterpret_cast<PBYTE>(buf), sizeof(buf) - sizeof(wchar_t),
                          &size, 0) == ERROR_SUCCESS) {
        out = Narrow(buf);
    } else {
        out = "present (platform type unavailable)";
    }
    NCryptFreeObject(provider);
    return out;
}

void PrintEnvironment(bool elevated) {
    g_machine = RegString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");
    const std::string os = RegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName") +
                           " build " +
                           RegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    const std::string tpm = TpmPlatform();
    std::printf("HkdfGuard benchmarks\n");
    std::printf("  cpu:      %s (%u logical processors)\n", g_machine.c_str(), std::thread::hardware_concurrency());
    std::printf("  os:       %s\n", os.c_str());
    std::printf("  tpm:      %s\n", tpm.empty() ? "none" : tpm.c_str());
    std::printf("  elevated: %s\n", elevated ? "yes" : "no");
    std::printf("  policy:   ClassicalMode=%s KeyStoragePolicy=%s SecurityModel=%s AuditUnwrapSuccess=%s SetupMinDelayMs=%s\n",
                PolicyDword(L"ClassicalMode").c_str(), PolicyDword(L"KeyStoragePolicy").c_str(),
                PolicyDword(L"SecurityModel").c_str(), PolicyDword(L"AuditUnwrapSuccess").c_str(),
                PolicyDword(L"SetupMinDelayMs").c_str());
#ifndef NDEBUG
    std::printf("  WARNING:  this is a Debug build; its numbers say little about a Release build's.\n");
#endif
    if (PolicyDword(L"AuditUnwrapSuccess") != "absent" && PolicyDword(L"AuditUnwrapSuccess") != "0") {
        std::printf("  note:     AuditUnwrapSuccess is on, so every unwrap below includes writing an event log entry.\n");
    }
}

// Sets a REG_DWORD under HKLM\Software\Policies\HkdfGuard for as long as the
// object lives, then puts back whatever was there - as the tests' helper of
// the same name. Needs elevation; active() says whether it took.
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

void Random(uint8_t* out, size_t len) {
    BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

// A structurally valid version 2 payload, for the parser and open_file -
// neither of which unwraps, so no KEK is involved.
std::vector<uint8_t> SyntheticPayload() {
    uint8_t salt[hkdfguard::kSaltLen], nonce[hkdfguard::kNonceLen], ct[hkdfguard::kCiphertextLen],
        tag[hkdfguard::kTagLen], fp[hkdfguard::kFingerprintLen];
    Random(salt, sizeof(salt));
    Random(nonce, sizeof(nonce));
    Random(ct, sizeof(ct));
    Random(tag, sizeof(tag));
    Random(fp, sizeof(fp));
    std::vector<uint8_t> out(hkdfguard::kTotalLen);
    hkdfguard::SerializeWrappedDek(hkdfguard::kFormatVersion2, hkdfguard::kProviderTypeSoftware, hkdfguard::kCurrentKeyId,
                                   salt, nonce, ct, tag, fp, out.data());
    return out;
}

// Wraps an internal call that reports failure by throwing.
bool NoThrow(const std::function<void()>& f) {
    try {
        f();
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// 1. CPU only

void CpuSection() {
    Section("1. CPU only (this binary's copy of src/, no KEK)");
    const int n = g_opt.quick ? 5 : (g_opt.iterations > 0 ? g_opt.iterations : 2000);

    uint8_t salt[hkdfguard::kSaltLen];
    Random(salt, sizeof(salt));
    uint8_t point[hkdfguard::kPublicPointLen] = {};
    Bench("hash-to-curve P-256 (PayloadEcdhPoint)", n, [&] {
        return NoThrow([&] {
            salt[0]++;
            hkdfguard::PayloadEcdhPoint(salt, point);
            g_sink = static_cast<uint8_t>(g_sink ^ point[0]);
        });
    });
    hkdfguard::PayloadEcdhPoint(salt, point);
    Bench("P-256 point validation (IsValidP256Point)", n, [&] {
        const bool valid = hkdfguard::IsValidP256Point(point);
        g_sink = static_cast<uint8_t>(g_sink ^ static_cast<uint8_t>(valid));
        return valid;
    });

    uint8_t header[hkdfguard::kHeaderLen];
    hkdfguard::SerializeWrappedDekHeader(hkdfguard::kFormatVersion2, hkdfguard::kProviderTypeSoftware,
                                         hkdfguard::kCurrentKeyId, salt, header);
    const std::string service = "hkdfguardwin.bench.cpu";
    Bench("SP 800-108 wrap block (WrapBlock)", n, [&] {
        return NoThrow([&] {
            std::vector<uint8_t> block = hkdfguard::WrapBlock(1, service, header, sizeof(header));
            g_sink = static_cast<uint8_t>(g_sink ^ block[0]);
        });
    });
    uint8_t hmac_key[32];
    Random(hmac_key, sizeof(hmac_key));
    const std::vector<uint8_t> block = hkdfguard::WrapBlock(1, service, header, sizeof(header));
    Bench("SP 800-108 block + HMAC-SHA-256 (bcrypt)", n, [&] {
        uint8_t mac[32];
        const bool ok = BCRYPT_SUCCESS(BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, hmac_key, sizeof(hmac_key),
                                                  const_cast<PUCHAR>(block.data()), static_cast<ULONG>(block.size()),
                                                  mac, sizeof(mac)));
        g_sink = static_cast<uint8_t>(g_sink ^ mac[0]);
        return ok;
    });

    uint8_t key[32], dek[hkdfguard::kCiphertextLen], aad[hkdfguard::kAuthenticatedLen];
    Random(key, sizeof(key));
    Random(dek, sizeof(dek));
    Random(aad, sizeof(aad));
    uint8_t nonce[hkdfguard::kNonceLen], ct[hkdfguard::kCiphertextLen], tag[hkdfguard::kTagLen], back[sizeof(dek)];
    Bench("AES-256-GCM encrypt, 32-byte DEK", n, [&] {
        return NoThrow([&] {
            hkdfguard::AesGcmEncrypt(key, dek, sizeof(dek), aad, sizeof(aad), nonce, ct, tag);
            g_sink = static_cast<uint8_t>(g_sink ^ tag[0]);
        });
    });
    hkdfguard::AesGcmEncrypt(key, dek, sizeof(dek), aad, sizeof(aad), nonce, ct, tag);
    Bench("AES-256-GCM decrypt, 32-byte DEK", n, [&] {
        return NoThrow([&] {
            hkdfguard::AesGcmDecrypt(key, nonce, ct, sizeof(ct), aad, sizeof(aad), tag, back);
            g_sink = static_cast<uint8_t>(g_sink ^ back[0]);
        });
    });

    const std::vector<uint8_t> payload = SyntheticPayload();
    Bench("wire format parse (ParseWrappedDek)", n, [&] {
        return NoThrow([&] {
            const hkdfguard::ParsedWrappedDek parsed =
                hkdfguard::ParseWrappedDek(payload.data(), static_cast<int32_t>(payload.size()));
            g_sink = static_cast<uint8_t>(g_sink ^ parsed.version);
        });
    });
}

// ---------------------------------------------------------------------------
// 2. hkdfguard_open_file

void OpenFileSection(bool elevated) {
    Section("2. hkdfguard_open_file (developer security model)");
    const std::string name = "open_file, 132-byte key file";
    if (!Selected(name)) return;

    // Elevated, the developer model is set for this section only; otherwise
    // the machine must already be in it - under production this account's
    // own file is (correctly) untrusted, and there is nothing to measure.
    std::unique_ptr<ScopedMachinePolicyDword> developer;
    if (elevated) developer = std::make_unique<ScopedMachinePolicyDword>(L"SecurityModel", 1);
    int model = -1, may_write = 0;
    if (hkdfguard_security_model(&model, &may_write) != HKDFGUARD_OK || model != HKDFGUARD_SECURITY_MODEL_DEVELOPER ||
        may_write != 1) {
        SkipRow(name + ": not in the developer security model, and not elevated to set it");
        return;
    }

    // %TEMP% may be an 8.3 short name, which open_file refuses; expand it.
    wchar_t temp[MAX_PATH + 1] = {}, temp_long[MAX_PATH + 1] = {};
    GetTempPathW(MAX_PATH + 1, temp);
    const DWORD long_len = GetLongPathNameW(temp, temp_long, MAX_PATH + 1);
    const std::wstring dir = std::wstring((long_len > 0 && long_len <= MAX_PATH) ? temp_long : temp) + L"hkdfguard-bench-" +
                             std::to_wstring(GetCurrentProcessId());
    const std::wstring path = dir + L"\\bench.key";
    CreateDirectoryW(dir.c_str(), nullptr);
    const std::vector<uint8_t> payload = SyntheticPayload();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD written = 0;
    const bool wrote = file != INVALID_HANDLE_VALUE &&
                       WriteFile(file, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) &&
                       written == payload.size();
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);

    if (wrote) {
        const std::string utf8 = Narrow(path);
        const int n = g_opt.quick ? 5 : (g_opt.iterations > 0 ? g_opt.iterations : 500);
        Bench(name, n, [&] {
            uint8_t out[HKDFGUARD_WRAPPED_MAX_LEN];
            int len = sizeof(out);
            return hkdfguard_open_file(utf8.c_str(), out, &len) == HKDFGUARD_OK;
        });
    } else {
        SkipRow(name + ": could not write the key file under %TEMP%");
    }
    DeleteFileW(path.c_str());
    RemoveDirectoryW(dir.c_str());
}

// ---------------------------------------------------------------------------
// 3. Through HkdfGuard.dll, with a KEK

// Measures the public hot path against `service`'s existing KEK. `label`
// prefixes every row name, e.g. "v2 software".
void DllRows(const char* service, const std::string& label, int iterations) {
    uint8_t dek[HKDFGUARD_DEK_LEN];
    Random(dek, sizeof(dek));
    uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
    int wrapped_len = sizeof(wrapped);
    const int first = hkdfguard_wrap_dek(service, dek, HKDFGUARD_DEK_LEN, wrapped, &wrapped_len);
    if (first != HKDFGUARD_OK) {
        ++g_failures;
        std::printf("  [fail] %s: the first wrap returned %d; nothing measured\n", label.c_str(), first);
        return;
    }

    Bench(label + " wrap_dek", iterations, [&] {
        uint8_t out[HKDFGUARD_WRAPPED_MAX_LEN];
        int len = sizeof(out);
        return hkdfguard_wrap_dek(service, dek, HKDFGUARD_DEK_LEN, out, &len) == HKDFGUARD_OK;
    });
    Bench(label + " unwrap_dek", iterations, [&] {
        uint8_t out[HKDFGUARD_DEK_LEN];
        int len = sizeof(out);
        return hkdfguard_unwrap_dek(service, wrapped, wrapped_len, out, &len) == HKDFGUARD_OK &&
               std::memcmp(out, dek, sizeof(dek)) == 0;
    });
    Bench(label + " generate_and_wrap_dek", iterations, [&] {
        uint8_t out[HKDFGUARD_WRAPPED_MAX_LEN];
        int len = sizeof(out);
        return hkdfguard_generate_and_wrap_dek(service, out, &len) == HKDFGUARD_OK;
    });
    Bench(label + " kek_fingerprint", iterations, [&] {
        uint8_t out[HKDFGUARD_KEK_FINGERPRINT_LEN];
        int len = sizeof(out);
        return hkdfguard_kek_fingerprint(service, out, &len) == HKDFGUARD_OK;
    });

    // Thread scaling: the same total work spread over more threads. Flat
    // ops/s means the provider serializes the calls.
    const std::vector<uint8_t> wrapped_copy(wrapped, wrapped + wrapped_len);
    for (int threads : g_opt.threads) {
        BenchThreads(label + " wrap_dek (threads)", threads, iterations, [&] {
            return std::function<bool()>([service, dek_copy = std::vector<uint8_t>(dek, dek + sizeof(dek))] {
                uint8_t out[HKDFGUARD_WRAPPED_MAX_LEN];
                int len = sizeof(out);
                return hkdfguard_wrap_dek(service, dek_copy.data(), HKDFGUARD_DEK_LEN, out, &len) == HKDFGUARD_OK;
            });
        });
    }
    for (int threads : g_opt.threads) {
        BenchThreads(label + " unwrap_dek (threads)", threads, iterations, [&] {
            return std::function<bool()>([service, &wrapped_copy] {
                uint8_t out[HKDFGUARD_DEK_LEN];
                int len = sizeof(out);
                return hkdfguard_unwrap_dek(service, wrapped_copy.data(), static_cast<int>(wrapped_copy.size()), out,
                                            &len) == HKDFGUARD_OK;
            });
        });
    }
}

// Deletes this run's KEK for `service` on `provider_type`, whichever payload
// version it is; absent is fine.
void DeleteBenchKek(const std::wstring& service, int version, uint8_t provider_type) {
    try {
        if (version == 1) {
            hkdfguard::DeleteKek(service, provider_type, hkdfguard::kCurrentKeyId);
        } else {
            hkdfguard::DeleteV2Kek(service, provider_type, hkdfguard::kCurrentKeyId);
        }
    } catch (...) {
    }
}

struct KekConfig {
    int version;          // payload version: 1 (ClassicalMode 1) or 2 (ClassicalMode 0)
    uint8_t provider;     // kProviderTypeSoftware or kProviderTypeTpm
    const char* label;    // row prefix
    const char* service;  // throwaway service name
};

void ElevatedDllSection() {
    // Setup calls are held to SetupMinDelayMs (one second by default); they
    // aren't measured, so the floor is lifted only to keep KEK creation quick.
    ScopedMachinePolicyDword no_floor(L"SetupMinDelayMs", 0);
    const bool has_tpm = !TpmPlatform().empty();
    const KekConfig configs[] = {
        {1, hkdfguard::kProviderTypeSoftware, "v1 software", "hkdfguardwin.bench.v1.software"},
        {2, hkdfguard::kProviderTypeSoftware, "v2 software", "hkdfguardwin.bench.v2.software"},
        {1, hkdfguard::kProviderTypeTpm, "v1 tpm", "hkdfguardwin.bench.v1.tpm"},
        {2, hkdfguard::kProviderTypeTpm, "v2 tpm", "hkdfguardwin.bench.v2.tpm"},
    };
    for (const KekConfig& c : configs) {
        const bool tpm = c.provider == hkdfguard::kProviderTypeTpm;
        char title[128];
        std::snprintf(title, sizeof(title), "3. HkdfGuard.dll, payload version %d, %s KEK", c.version,
                      tpm ? "TPM (Platform Crypto Provider)" : "Software KSP");
        Section(title);
        // Don't create a KEK that no row selected by --filter would use.
        bool any = false;
        for (const char* op : {" wrap_dek", " unwrap_dek", " generate_and_wrap_dek", " kek_fingerprint",
                               " wrap_dek (threads)", " unwrap_dek (threads)"}) {
            any = any || Selected(std::string(c.label) + op);
        }
        if (!any) continue;
        if (tpm && !has_tpm) {
            SkipRow(std::string(c.label) + ": no TPM (Platform Crypto Provider) on this machine");
            continue;
        }
        const std::wstring service_w = Widen(c.service);
        ScopedMachinePolicyDword classical(L"ClassicalMode", c.version == 1 ? 1 : 0);
        ScopedMachinePolicyDword storage(L"KeyStoragePolicy", tpm ? 1 : 2); // RequireTpm / SoftwareOnly
        if (!classical.active() || !storage.active()) {
            ++g_failures;
            SkipRow(std::string(c.label) + ": could not set ClassicalMode / KeyStoragePolicy");
            continue;
        }
        DeleteBenchKek(service_w, c.version, c.provider); // a leftover from an interrupted run
        const int rc = hkdfguard_create_kek(c.service);
        if (rc != HKDFGUARD_OK) {
            // The TPM may lack what a version needs (version 2: HMAC keys).
            if (tpm) {
                SkipRow(std::string(c.label) + ": hkdfguard_create_kek returned " + std::to_string(rc));
            } else {
                ++g_failures;
                std::printf("  [fail] %s: hkdfguard_create_kek returned %d\n", c.label, rc);
            }
            continue;
        }
        const int n = g_opt.quick ? 5 : (tpm ? g_opt.tpm_iterations : (g_opt.iterations > 0 ? g_opt.iterations : 500));
        DllRows(c.service, c.label, n);
        DeleteBenchKek(service_w, c.version, c.provider);
    }
}

void ExistingKekSection() {
    Section(("3. HkdfGuard.dll, existing KEK \"" + g_opt.service + "\" under this machine's policy").c_str());
    const int n = g_opt.quick ? 5 : (g_opt.iterations > 0 ? g_opt.iterations : 200);
    Note("KeyStoragePolicy and ClassicalMode are whatever the machine has; see the policy line above.");
    DllRows(g_opt.service.c_str(), "existing", n);
}

// ---------------------------------------------------------------------------

bool ParseInt(const char* s, int& out) {
    char* end = nullptr;
    const long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0' || v <= 0 || v > 10'000'000) return false;
    out = static_cast<int>(v);
    return true;
}

bool ParseArgs(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
        const char* value = nullptr;
        if (arg == "--quick") {
            g_opt.quick = true;
        } else if (arg == "--iterations" && (value = next()) != nullptr) {
            if (!ParseInt(value, g_opt.iterations)) return false;
        } else if (arg == "--tpm-iterations" && (value = next()) != nullptr) {
            if (!ParseInt(value, g_opt.tpm_iterations)) return false;
        } else if (arg == "--threads" && (value = next()) != nullptr) {
            g_opt.threads.clear();
            std::string list = value;
            size_t start = 0;
            while (start <= list.size()) {
                const size_t comma = std::min(list.find(',', start), list.size());
                int t = 0;
                if (!ParseInt(list.substr(start, comma - start).c_str(), t) || t > 256) return false;
                g_opt.threads.push_back(t);
                start = comma + 1;
            }
        } else if (arg == "--filter" && (value = next()) != nullptr) {
            g_opt.filter = value;
        } else if (arg == "--csv" && (value = next()) != nullptr) {
            g_opt.csv = value;
        } else if (arg == "--service" && (value = next()) != nullptr) {
            g_opt.service = value;
        } else {
            return false;
        }
    }
    if (g_opt.quick) g_opt.threads = {1, 2};
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (!ParseArgs(argc, argv)) {
        std::fprintf(stderr,
                     "usage: bench_hkdfguard [--quick] [--iterations N] [--tpm-iterations N] [--threads 1,2,4,8]\n"
                     "                       [--filter TEXT] [--csv PATH] [--service NAME]\n");
        return 2;
    }
    const bool elevated = IsElevated();
    PrintEnvironment(elevated);

    if (!g_opt.csv.empty()) {
        const bool fresh = GetFileAttributesW(Widen(g_opt.csv).c_str()) == INVALID_FILE_ATTRIBUTES;
        if (fopen_s(&g_csv, g_opt.csv.c_str(), "a") != 0 || g_csv == nullptr) {
            std::fprintf(stderr, "cannot open %s for writing\n", g_opt.csv.c_str());
            return 2;
        }
        if (fresh) {
            std::fprintf(g_csv, "machine,operation,threads,iterations,min_us,median_us,p95_us,p99_us,mean_us,ops_per_sec,status\n");
        }
    }

    CpuSection();
    OpenFileSection(elevated);
    if (!g_opt.service.empty()) {
        ExistingKekSection();
    } else if (elevated) {
        ElevatedDllSection();
    } else {
        Section("3. HkdfGuard.dll");
        SkipRow("not elevated: run elevated to measure throwaway KEKs, or pass --service NAME for an existing one");
    }

    if (g_csv != nullptr) std::fclose(g_csv);
    std::printf("\n%s\n", g_failures == 0 ? "done" : "done, with failures (see FAILED / [fail] above)");
    return g_failures == 0 ? 0 : 1;
}
