// This file is the boundary between the public C ABI (hkdfguard.h) and this
// project's internal C++ implementation. Everything here has one job:
// validate arguments, orchestrate the internal helpers in the right order,
// and translate C++ exceptions into the plain integer status codes the ABI
// promises - nothing crypto-specific happens directly in this file.
#include "../include/hkdfguard.h"

#include "aes_gcm.h"
#include "ecdh_hkdf.h"
#include "errors.h"
#include "event_log.h"
#include "policy.h" // LoadAuditUnwrapSuccess
#include "process_hardening.h" // HardenProcess - hkdfguard_harden_process's implementation
#include "kek_store.h"
#include "key_file.h" // ReadWrappedKeyFile - hkdfguard_open_file's implementation
#include "secure_buffer.h"
#include "wire_format.h"

// windows.h: MultiByteToWideChar, CP_UTF8, MB_ERR_INVALID_CHARS (used by
// ServiceToWide below). bcrypt.h: BCryptGenRandom (used by WrapDekCore for
// each payload's salt, and by hkdfguard_generate_and_wrap_dek to source the
// new DEK's randomness). cstring: strnlen, memcpy. string: std::wstring.
#include <windows.h>
#include <bcrypt.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>

// `using namespace hkdfguard;` brings every name declared inside `namespace
// hkdfguard { ... }` (SecureBuffer, ResolvedKek, HkdfGuardError, the
// kSaltLen/kNonceLen/... constants, AesGcmEncrypt, and so on) into
// scope here without needing the `hkdfguard::` prefix on each one. This is
// a deliberate, narrow use of the directive: it's placed in a .cpp file
// (never in a header, where it would leak into every file that includes
// that header) and this file is small enough that the risk of an
// accidental name collision is low.
using namespace hkdfguard;

// Anonymous namespace: ValidateAndConvertService below is only used inside
// this file (see aes_gcm.cpp's OpenAesKey for the fuller explanation of
// what this construct does).
namespace {
    constexpr size_t kMaxServiceLen = 128; // bytes, excluding the null terminator

    // Serializes every setup call (hkdfguard_create_kek,
    // hkdfguard_kek_exists) so that, with the floor in GatedSetup, their
    // combined rate is capped at one per LoadSetupMinDelayMs() however many
    // threads call in.
    std::mutex g_setup_gate;

    // How many setup calls this process has made. They're meant to happen
    // once per application startup, so a count well beyond that is the
    // signature of a caller looping on them.
    std::atomic<unsigned long> g_setup_calls{0};

    // Setup-call count past which event 2007 is logged (once). Generous
    // enough for a multi-service application's genuine startup, small
    // enough that a hot loop trips it within seconds. Same as Linux.
    constexpr unsigned long kSetupCallsWarnAt = 10;

    // Runs `f` - the provider-touching part of a setup call - serialized
    // against every other setup call, and doesn't return (or let `f`'s
    // exception out) until at least LoadSetupMinDelayMs() has passed since
    // it was entered, whatever `f` did and however fast. Callers validate
    // their arguments first, so a bad pointer or service name still fails
    // at once; only calls that would reach a provider pay the floor. The
    // Linux build's gated_setup, step for step.
    //
    // Why: create_kek and kek_exists each open a fresh key storage provider
    // handle (and on the TPM, a PCP session), so a buggy or hot-looping
    // caller could otherwise drive the TPM as fast as it can call. The
    // floor is about load, not secrecy: hkdfguard_wrap_dek, the hot path,
    // is not slowed, and answers KEK_NOT_FOUND at once for a service with
    // no KEK.
    template <typename F>
    void GatedSetup(F &&f) {
        std::lock_guard<std::mutex> serialized(g_setup_gate);
        const auto entered = std::chrono::steady_clock::now();
        const unsigned long floor_ms = LoadSetupMinDelayMs();

        // Waits out the rest of the floor on every way out of this
        // function, a throw from `f` included.
        struct Floor {
            std::chrono::steady_clock::time_point until;
            ~Floor() {
                for (auto now = std::chrono::steady_clock::now(); now < until;
                     now = std::chrono::steady_clock::now()) {
                    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(until - now).count();
                    Sleep(static_cast<DWORD>(remaining > 0 ? remaining : 1));
                }
            }
        } floor{entered + std::chrono::milliseconds(floor_ms)};

        const unsigned long count = g_setup_calls.fetch_add(1, std::memory_order_relaxed) + 1;
        if (count == kSetupCallsWarnAt + 1) {
            LogSetupCallsExceeded(kSetupCallsWarnAt, floor_ms);
        }

        f();
    }

    // Validates that the incoming servicename is alphanumeric or period(dot)
    bool IsValidServiceChar(char c) noexcept {
        return
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '.';
    }

    // Lowercases a single ASCII byte; anything else (digits, '.') is
    // returned unchanged. Written by hand, rather than via <cctype>'s
    // tolower, to avoid that function's locale-dependent behavior - this
    // codebase's service-name charset is pure ASCII by construction (see
    // IsValidServiceChar), so a fixed 'A'-'Z' range is all this ever needs
    // to handle.
    char ToLowerServiceChar(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    // Validates `service` (null/length/charset - see IsValidServiceChar) and
    // returns a lowercase-normalized copy of it as a narrow ASCII string.
    // Normalizing case here, at the one place every public entry point's
    // `service` argument passes through, means two callers who differ only
    // in case (e.g. "MyApp" and "myapp") are treated as the exact same
    // service everywhere downstream: the same persisted KEK name (see
    // ServiceToWide/kek_store.cpp's KeyName) and the same HKDF info bytes
    // (see WrapDekCore/hkdfguard_unwrap_dek below) - not just a
    // case-insensitive KEK lookup with a case-sensitive key derivation
    // underneath it, which would make wrap/unwrap fail whenever the two
    // calls' casing didn't match exactly.
    //
    // Throws HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME) if `service` is null,
    // empty, too long, contains a character outside the allowed charset,
    // starts with '.', or contains "..".
    std::string NormalizeService(const char *service) {
        if (service == nullptr) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME, "service is null");
        }
        // strnlen behaves like the familiar strlen (walk forward until a '\0'
        // byte, return how many bytes were seen) but stops early and returns
        // `kMaxServiceLen + 1` if no '\0' turns up within that many bytes
        // first - this bounds how far into `service` we ever read, in case the
        // caller passed a pointer to a buffer that isn't actually
        // null-terminated within any reasonable length (a defensive measure
        // against a misbehaving caller, since this is a boundary the ABI has no
        // other way to validate: `service` is just a raw pointer with no length
        // parameter alongside it, by design, since it's meant to be an ordinary
        // C string).
        size_t len = strnlen(service, kMaxServiceLen + 1);
        if (len == 0 || len > kMaxServiceLen) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME, "service is empty or too long");
        }

        std::string normalized(service, len);
        for (char &c : normalized) {
            if (!IsValidServiceChar(c)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_INVALID_SERVICE_NAME,
                    "service contains invalid characters");
            }
            c = ToLowerServiceChar(c);
        }

        // Dot rules, the same as the Linux library's: a service name may not
        // start with '.' and may not contain two consecutive dots. Nothing on
        // Windows uses the name as a path today, but holding one rule on every
        // platform means a service name valid on one is valid on all, and it
        // keeps names from ever spelling ".", "..", a hidden-file name, or an
        // empty label between dots. A single trailing '.' is allowed, as on
        // Linux.
        if (normalized.front() == '.' || normalized.find("..") != std::string::npos) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_INVALID_SERVICE_NAME,
                "service may not start with '.' or contain \"..\"");
        }
        return normalized;
    }

    // Converts an already-NormalizeService()-validated ASCII string into the
    // wide string used as part of the persisted KEK's name. Every byte in
    // `normalized` is, by construction, ASCII alphanumeric or '.', so this
    // conversion cannot actually fail today - MB_ERR_INVALID_CHARS and the
    // resulting HKDFGUARD_ERR_INVALID_SERVICE_NAME are kept anyway as defense in
    // depth, in case NormalizeService's contract ever changes without this
    // call site being updated to match.
    std::wstring ServiceToWide(const std::string &normalized) {
        // Converting UTF-8 to UTF-16 (the std::wstring every NCrypt
        // key-name parameter ultimately needs) is, like several other
        // Windows APIs already seen in this project, a two-call "ask for
        // the size, then convert for real" operation.
        int wide_len = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, normalized.c_str(), static_cast<int>(normalized.size()), nullptr, 0);
        if (wide_len <= 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME, "service is not valid UTF-8");
        }
        // `std::wstring wide(static_cast<size_t>(wide_len), L'\0')`
        // constructs a wide string of exactly `wide_len` characters, every
        // one initially L'\0' - i.e. pre-allocates the right amount of
        // storage for MultiByteToWideChar's second call to write its real
        // output into via `wide.data()`.
        std::wstring wide(static_cast<size_t>(wide_len), L'\0');
        MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, normalized.c_str(), static_cast<int>(normalized.size()), wide.data(),
            wide_len);
        return wide;
    }

    // Records a failed call in the event log (see event_log.h for which codes
    // produce an event) and hands `code` straight back, so every ABI entry
    // point can write `return Audit(op, service, code);` on its failure
    // paths without the logging ever changing what the caller receives.
    // The service is logged in its normalized form; a service argument that
    // doesn't even validate is logged as "(invalid service name)" rather
    // than echoed, so nothing but the restricted charset reaches the log.
    int32_t Audit(AuditOp op, const char *service, int32_t code) noexcept {
        std::string loggable;
        try {
            loggable = NormalizeService(service);
        } catch (...) {
            loggable.clear();
        }
        LogOperationFailure(op, loggable, code);
        return code;
    }

    // Convenience wrapper for callers (hkdfguard_kek_exists, hkdfguard_create_kek)
    // that only need the normalized wide key-name form, not the normalized
    // narrow form WrapDekCore/hkdfguard_unwrap_dek also need for HKDF's info.
    std::wstring ValidateAndConvertService(const char *service) {
        return ServiceToWide(NormalizeService(service));
    }

    // The actual wrap orchestration shared by hkdfguard_wrap_dek (wraps a
    // caller-supplied DEK) and hkdfguard_generate_and_wrap_dek (wraps a freshly
    // generated one) - factored out here so this crypto sequence exists in
    // exactly one place rather than being duplicated between the two ABI entry
    // points below. Callers are responsible for catching whatever this throws;
    // it does not itself touch the ABI's integer-status-code convention.
    // `op` only labels the success audit event (Wrap vs GenerateAndWrap).
    int32_t WrapDekCore(
        AuditOp op, const char *service, const uint8_t *dek, int32_t dek_len, uint8_t *out, int32_t *out_len) {
        // Argument checks in the Linux build's order, so the same mistake
        // gets the same code on both. `out` is checked later: it may be
        // NULL for a size probe.
        if (dek == nullptr || out_len == nullptr) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT;
        }
        if (dek_len != HKDFGUARD_DEK_LEN) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT;
        }
        // `*out_len` dereferences the pointer to read the caller-supplied
        // buffer capacity (the "in" half of this in/out parameter - see
        // hkdfguard.h's note on this pattern).
        const int32_t capacity = *out_len;
        if (capacity < 0) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT; // a negative capacity makes no sense
        }

        std::string normalized_service = NormalizeService(service);

        // Buffer checks, before any provider work: a size probe (NULL `out`,
        // capacity 0) or a buffer that could never hold the result costs no
        // TPM round trip. The required size is reported back through
        // *out_len, so a caller can allocate exactly that and retry (the
        // CLI's WrapDek does).
        if (out == nullptr && capacity > 0) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT; // a declared capacity with nowhere to write
        }
        if (capacity < HKDFGUARD_WRAPPED_MAX_LEN) {
            *out_len = HKDFGUARD_WRAPPED_MAX_LEN;
            return HKDFGUARD_ERR_BUFFER_TOO_SMALL;
        }

        std::wstring service_name = ServiceToWide(normalized_service);

        // Opens this service's machine-wide persistent KEK, preferring the
        // TPM/vTPM-backed Platform Crypto Provider and falling back to the
        // Software Key Storage Provider automatically. Never creates one -
        // hkdfguard_create_kek must have already provisioned it (see
        // kek_store.h/.cpp) - so this fails with HKDFGUARD_ERR_PROVIDER_ERROR if
        // the service has no KEK yet.
        ResolvedKek kek = OpenKekForWrap(service_name);

        // Fingerprint of the KEK this payload is being wrapped under: stamped
        // into the payload and bound into the key and the AAD below, so unwrap can both
        // check it explicitly (before any ECDH) and authenticate it (see
        // wire_format.h's layout comment).
        uint8_t fingerprint[kFingerprintLen];
        ComputeKekFingerprint(kek.key.get(), fingerprint);

        // A fresh random salt for this payload: it selects the point H(salt)
        // the KEK's private key is combined with, and is HKDF's salt, so
        // every payload gets its own Z and its own wrapping key. Generated
        // before the AAD, because the salt is part of the header the AAD
        // authenticates.
        uint8_t salt[kSaltLen];
        NTSTATUS salt_status = BCryptGenRandom(nullptr, salt, static_cast<ULONG>(kSaltLen), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(salt_status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenRandom(salt) failed");
        }

        // The authenticated bytes = header || KEK fingerprint (see
        // wire_format.h): the AES-GCM AAD, and with the normalized service
        // name, HKDF's info. The header is built here exactly as
        // SerializeWrappedDek will write it below - both go through
        // SerializeWrappedDekHeader - so the version, provider type and KeyId
        // the payload carries are the ones bound into the key and the tag.
        // None of it is secret; unwrap rebuilds it from the received bytes.
        uint8_t header[kHeaderLen];
        SerializeWrappedDekHeader(kek.provider_type, kek.key_id, salt, header);
        std::vector<uint8_t> authenticated = BuildWrappedDekAuthenticated(header, fingerprint);
        // `nonce`/`ciphertext`/`tag` are declared here, *outside* the nested
        // block below, because they're needed again afterward (by
        // SerializeWrappedDek) - none of the three is secret (they're all meant
        // to become part of the public wrapped payload), so there's no reason
        // to scope them any more tightly than that.
        uint8_t nonce[kNonceLen];
        uint8_t ciphertext[kCiphertextLen];
        uint8_t tag[kTagLen];
        {
            // `wrapping_key` - the actual AES-256 key material derived for this
            // one wrap call - is deliberately declared inside this nested
            // `{ ... }` block rather than alongside the buffers above, and used
            // for nothing outside of it. That means its destructor
            // (SecureBuffer's SecureZeroMemory wipe - see secure_buffer.h)
            // fires the instant this block ends, i.e. immediately after
            // AesGcmEncrypt's done with it, rather than only at the end of the
            // whole function (which would otherwise leave it sitting around,
            // unused but unwiped, for the length of SerializeWrappedDek and the
            // `return` below). This is the same "shrink the scope to shrink
            // the lifetime" technique used for `prk` inside ecdh_hkdf.cpp's
            // HkdfSha512.
            SecureBuffer<32> wrapping_key;
            // ECDH(KEK private key, H(salt)) + HKDF-SHA512 - the same
            // derivation unwrap runs. Wrapping uses the KEK's *private* key
            // (inside the TPM for a TPM-backed KEK), which is what makes a
            // payload impossible to forge from the public key alone.
            // HKDF's info binds the case-normalized `normalized_service`
            // bytes (not the caller's original-case `service`, and not the
            // wide NCrypt-key-name form `service_name` above): the key is
            // tied to the exact (case-insensitive) service it was wrapped
            // for. Using the normalized form - the same one ServiceToWide
            // derived `service_name` from - is what makes wrap/unwrap
            // genuinely case-insensitive end to end: with the raw `service`
            // bytes, two calls differing only in case would resolve to the
            // same KEK but derive different keys, and unwrap would fail.
            DeriveWrappingKey(kek.provider.get(), kek.key.get(), normalized_service, authenticated, wrapping_key);

            // AES-256-GCM directly from the caller's dek pointer - no
            // intermediate plaintext staging buffer. The AAD is the
            // authenticated bytes: the fingerprint binds the ciphertext to
            // the specific KEK, and the header the routing fields (provider
            // type, KeyId) and the version, so neither the service (through
            // the key) nor the routing nor the format can be swapped
            // undetected.
            AesGcmEncrypt(
                wrapping_key.data(), dek, static_cast<unsigned long>(dek_len),
                authenticated.data(), static_cast<unsigned long>(authenticated.size()),
                nonce, ciphertext, tag);
        } // <- wrapping_key's destructor (zeroing it) runs here, right now.

        // Assemble the final 132-byte payload directly into the caller's
        // buffer, and report how many bytes were written back through the
        // out-parameter.
        SerializeWrappedDek(kek.provider_type, kek.key_id, salt, nonce, ciphertext, tag, fingerprint, out);
        *out_len = static_cast<int32_t>(kTotalLen);

        // Audit: who wrapped, for which service, under which KEK, and a hash
        // of the exact payload produced (public bytes only - see event_log.h).
        LogDekOperation(op, normalized_service, kek.provider_type, fingerprint, out, kTotalLen);
        return HKDFGUARD_OK;
    }

} // namespace

// `extern "C"` here (repeated at each function, rather than wrapping all of
// them in one block) matches how hkdfguard.h declared them, and is required
// for the same reason explained there: it gives each of these functions the
// plain, unmangled name (e.g. "hkdfguard_wrap_dek") that other languages'
// FFI layers look up by exact string. HKDFGUARD_API expands to
// __declspec(dllexport) here specifically because CMakeLists.txt defines
// HKDFGUARD_EXPORTS only while compiling this DLL's own sources (see
// hkdfguard.h's comment on that macro).
extern "C" HKDFGUARD_API int hkdfguard_wrap_dek(
    const char *service,
    const uint8_t *dek, int dek_len,
    uint8_t *out, int *out_len) {
    // The entire body lives inside one `try` block: this is what makes it
    // possible for every internal helper WrapDekCore calls
    // (NormalizeService, ServiceToWide, OpenKekForWrap,
    // DeriveWrappingKeyForWrap, AesGcmEncrypt, ...) to simply `throw
    // HkdfGuardError(...)` the moment something goes wrong, instead of
    // every one of them returning a code that this function would
    // otherwise have to check after every single call. Two `catch` clauses
    // below turn whatever came out of the `try` block back into a plain
    // `int32_t` for the ABI - which is the one and only place in this
    // whole codebase a C++ exception is allowed to stop, per the "no
    // exception crosses the ABI" requirement.
    try {
        return WrapDekCore(AuditOp::Wrap, service, dek, dek_len, out, out_len);
    } catch (const HkdfGuardError &e) {
        // The expected/"normal" failure path: one of our own helpers threw
        // a specific, meaningful status code - recorded in the event log if
        // it's one worth auditing, then handed straight back to the caller.
        return Audit(AuditOp::Wrap, service, e.code());
    } catch (...) {
        // `catch (...)` is C++'s "catch absolutely anything" handler - it
        // matches even exception types this code has never heard of (a
        // standard library exception like std::bad_alloc from a failed
        // heap allocation, for instance). This is the final safety net that
        // makes the ABI's "no exception ever crosses this boundary"
        // guarantee unconditionally true, not just true for the specific
        // exception type this project happens to throw itself.
        return Audit(AuditOp::Wrap, service, HKDFGUARD_ERR_INTERNAL_ERROR);
    }
}

extern "C" HKDFGUARD_API int hkdfguard_kek_exists(
    const char *service,
    int *out_exists) {
    if (out_exists == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }

    try {
        std::wstring service_name =
                ValidateAndConvertService(service);

        // Slow on purpose - see GatedSetup. "Exists" and "doesn't exist"
        // take the same time.
        GatedSetup([&] { *out_exists = KekExists(service_name) ? 1 : 0; });

        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::KekExists, service, e.code());
    } catch (...) {
        return Audit(AuditOp::KekExists, service, HKDFGUARD_ERR_INTERNAL_ERROR);
    }
}

extern "C" HKDFGUARD_API int hkdfguard_kek_fingerprint(
    const char *service,
    uint8_t *out, int *out_len) {
    // The same argument order as hkdfguard_wrap_dek: out_len, capacity, the
    // service name, then the buffer - so a size probe touches no provider.
    if (out_len == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }
    const int32_t capacity = *out_len;
    if (capacity < 0) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }

    try {
        std::string normalized_service = NormalizeService(service);
        if (out == nullptr && capacity > 0) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT; // a declared capacity with nowhere to write
        }
        if (capacity < static_cast<int32_t>(kFingerprintLen)) {
            *out_len = static_cast<int32_t>(kFingerprintLen);
            return HKDFGUARD_ERR_BUFFER_TOO_SMALL;
        }

        // Exactly the KEK a wrap would use, verified the same way - so the
        // value printed after provisioning is the one stamped into every
        // payload. Not gated: like wrap, it only opens an existing key.
        ResolvedKek kek = OpenKekForWrap(ServiceToWide(normalized_service));
        ComputeKekFingerprint(kek.key.get(), out);
        *out_len = static_cast<int32_t>(kFingerprintLen);
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::KekFingerprint, service, e.code());
    } catch (...) {
        return Audit(AuditOp::KekFingerprint, service, HKDFGUARD_ERR_INTERNAL_ERROR);
    }
}

extern "C" HKDFGUARD_API int hkdfguard_create_kek(
    const char *service) {
    try {
        std::wstring service_name =
                ValidateAndConvertService(service);

        // Who may use the resulting KEK comes from machine policy (see
        // hkdfguard.h and policy.h's LoadKeyUseGroupsPolicy), read and
        // validated inside CreateKek - nothing about access is caller-chosen.
        // Slow on purpose - see GatedSetup.
        GatedSetup([&] { CreateKek(service_name); });

        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::CreateKek, service, e.code());
    } catch (...) {
        return Audit(AuditOp::CreateKek, service, HKDFGUARD_ERR_INTERNAL_ERROR);
    }
}

extern "C" HKDFGUARD_API int hkdfguard_generate_and_wrap_dek(
    const char *service,
    uint8_t *out, int *out_len) {
    try {
        // `dek` is a SecureBuffer, not a plain stack array: it's zeroed by
        // its own destructor the instant this function returns (any exit
        // path, including an exception unwinding through WrapDekCore),
        // exactly like `wrapping_key` inside WrapDekCore itself. This is
        // the one and only place the freshly generated plaintext DEK
        // exists at all - it's never returned to the caller (see
        // hkdfguard.h's comment on this function) and never staged
        // anywhere else.
        SecureBuffer<HKDFGUARD_DEK_LEN> dek;

        // BCRYPT_USE_SYSTEM_PREFERRED_RNG: the OS's CSPRNG, the same
        // source AesGcmEncrypt uses for nonces (see aes_gcm.cpp) - not a
        // plain PRNG.
        NTSTATUS status = BCryptGenRandom(
            nullptr, dek.data(), static_cast<ULONG>(HKDFGUARD_DEK_LEN), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            return Audit(AuditOp::GenerateAndWrap, service, HKDFGUARD_ERR_CRYPTO_ERROR);
        }

        return WrapDekCore(AuditOp::GenerateAndWrap, service, dek.data(), HKDFGUARD_DEK_LEN, out, out_len);
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::GenerateAndWrap, service, e.code());
    } catch (...) {
        return Audit(AuditOp::GenerateAndWrap, service, HKDFGUARD_ERR_INTERNAL_ERROR);
    }
}

extern "C" HKDFGUARD_API int hkdfguard_unwrap_dek(
    const char *service,
    const uint8_t *wrapped, int wrapped_len,
    uint8_t *out, int *out_len) {
    // out_len must be checked before anything else - every other line in
    // this function (including the `fail` helper defined just below) needs
    // to be able to dereference it safely.
    if (out_len == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }

    // Captured once, up front, before any chance of `*out_len` being
    // overwritten - `capacity` is what the caller originally promised about
    // the size of `out`, and it's what `fail` below uses to know how many
    // bytes it's safe to zero.
    const int32_t capacity = *out_len;
    // A *lambda expression*: an anonymous, inline function value. `[&]`
    // is the "capture clause" - it says this lambda may refer to any local
    // variable from the enclosing function (here, `out` and `capacity`) *by
    // reference*, i.e. it sees their live values at the moment it's called,
    // not a snapshot taken when the lambda was created. `(int32_t code)` is
    // its parameter list, and the body is the same as an ordinary function.
    // `fail` is then called, below, from several different places as a
    // single shared "on any failure, do this, then return that code" helper
    // - avoiding repeating the zero-then-return logic at every one of those
    // call sites.
    auto fail = [&](int32_t code) {
        // On any failure path, wipe whatever the caller declared as the
        // buffer's capacity, since AES-GCM decryption can write
        // unauthenticated plaintext into `out` even when it ultimately
        // fails (e.g. a tag mismatch) - no stale plaintext may remain.
        if (out != nullptr && capacity > 0) {
            SecureZero(out, static_cast<size_t>(capacity));
        }
        return code;
    };

    try {
        // The Linux build's order: arguments, then the service name, then
        // the buffer - so the same mistake gets the same code on both.
        if (wrapped == nullptr) {
            return fail(HKDFGUARD_ERR_INVALID_ARGUMENT);
        }
        if (wrapped_len < 0 || capacity < 0) {
            return fail(HKDFGUARD_ERR_INVALID_ARGUMENT);
        }

        std::string normalized_service = NormalizeService(service);

        // The DEK is always HKDFGUARD_DEK_LEN bytes, so whether it fits is
        // known before the payload is even parsed. Checked before `out`, so
        // a size probe (NULL `out`, capacity 0) gets the required size.
        if (capacity < HKDFGUARD_DEK_LEN) {
            *out_len = HKDFGUARD_DEK_LEN;
            return fail(HKDFGUARD_ERR_BUFFER_TOO_SMALL);
        }
        if (out == nullptr) {
            return fail(HKDFGUARD_ERR_INVALID_ARGUMENT); // a declared capacity with nowhere to write
        }

        std::wstring service_name = ServiceToWide(normalized_service);

        // Validates the payload's shape/version and hands back pointers
        // into `wrapped` for each field (see wire_format.h/.cpp) - throws
        // HKDFGUARD_ERR_PAYLOAD_MALFORMED on anything that doesn't look like a
        // genuine WrappedDekV1 payload.
        ParsedWrappedDek parsed = ParseWrappedDek(wrapped, wrapped_len);

        // Open (never create) the KEK the payload's routing fields select.
        ResolvedKek kek = OpenKekForUnwrap(service_name, parsed.provider_type, parsed.key_id);

        // Is that actually the KEK this payload was wrapped under? Compared
        // before any ECDH so a payload for a different/rotated KEK fails
        // fast and precisely (HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH), costing no TPM
        // operation, rather than surfacing later as an authentication
        // failure that looks identical to tampering. Not constant-time, and
        // needn't be: both sides of the comparison are hashes of public
        // keys. This is a check on the key the routing fields chose, never a
        // search for a key that matches - see wire_format.h.
        uint8_t expected_fingerprint[kFingerprintLen];
        ComputeKekFingerprint(kek.key.get(), expected_fingerprint);
        if (std::memcmp(expected_fingerprint, parsed.fingerprint, kFingerprintLen) != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH, "payload was not wrapped under this KEK");
        }

        // Same authenticated bytes as WrapDekCore: the header exactly as
        // received || the payload's (now verified) fingerprint. Taken from
        // the received bytes, not re-serialized from the parsed fields, so
        // the key and the tag check cover what was actually presented - and
        // copied once, here, so the salt DeriveWrappingKey reads from them
        // is the salt the AAD covers.
        std::vector<uint8_t> authenticated = BuildWrappedDekAuthenticated(parsed.header, parsed.fingerprint);

        {
            // Same reasoning as the wrap side above: `wrapping_key` is
            // scoped to only the two statements that need it, so it's
            // wiped the moment this block ends - immediately after
            // AesGcmDecrypt is done with it - rather than lingering,
            // unused, until the function returns.
            SecureBuffer<32> wrapping_key;
            // ECDH(KEK private key, H(salt)) (may execute inside a
            // TPM/vTPM) + HKDF-SHA512 -> the same 32-byte wrapping key
            // derived at wrap time, from the payload's salt.
            DeriveWrappingKey(kek.provider.get(), kek.key.get(), normalized_service, authenticated, wrapping_key);

            // Decrypt directly into the caller's buffer - no intermediate
            // plaintext staging buffer. The AAD must match what
            // AesGcmEncrypt used at wrap time, and the key the service
            // (see WrapDekCore's comment on why the normalized service form,
            // not the caller's original-case `service`, is what's used).
            AesGcmDecrypt(
                wrapping_key.data(), parsed.nonce, parsed.ciphertext,
                static_cast<unsigned long>(kCiphertextLen),
                authenticated.data(), static_cast<unsigned long>(authenticated.size()),
                parsed.tag, out);
        } // <- wrapping_key's destructor (zeroing it) runs here, right now.

        // Success: `out` now holds the recovered plaintext DEK (its one
        // and only copy - this function never staged it anywhere else),
        // and the caller is told exactly how many bytes that is.
        *out_len = HKDFGUARD_DEK_LEN;

        // Audit: who unwrapped, for which service, under which KEK, and a hash
        // of the exact payload presented - matching the hash its wrap event
        // recorded. Hashes the caller's (public) payload buffer, never `out`.
        // Unless an administrator has turned this one event off via the
        // AuditUnwrapSuccess policy value (see policy.h) - e.g. for a caller
        // that legitimately unwraps often. Unwrap *failures* are logged
        // regardless, in the catch blocks below.
        if (LoadAuditUnwrapSuccess()) {
            LogDekOperation(
                AuditOp::Unwrap, normalized_service, parsed.provider_type, parsed.fingerprint,
                wrapped, static_cast<size_t>(wrapped_len));
        }
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        // Note this correctly covers the auth-failure case too:
        // AesGcmDecrypt throws HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED) on
        // a tag mismatch, which unwinds out through the nested block above
        // (wiping wrapping_key via its destructor along the way, same as
        // any other exit) and is caught right here, where `fail(e.code())`
        // then zeroes `out` before this function returns - satisfying "no
        // stale plaintext may remain" even though some unauthenticated
        // bytes may have been written into `out` by BCryptDecrypt before it
        // detected the mismatch (see aes_gcm.cpp's comment on that).
        // `fail` (zeroing) runs first, logging second - the buffer is never
        // left holding unauthenticated bytes while the event is written.
        return Audit(AuditOp::Unwrap, service, fail(e.code()));
    } catch (...) {
        return Audit(AuditOp::Unwrap, service, fail(HKDFGUARD_ERR_INTERNAL_ERROR));
    }
}

extern "C" HKDFGUARD_API int hkdfguard_open_file(
    const char *path,
    uint8_t *out, int *out_len) {
    if (out_len == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }

    // Same shape as hkdfguard_unwrap_dek: remember the caller's capacity,
    // and on any failure zero that much of `out`, so a rejected file never
    // leaves partial or malformed bytes behind. *out_len is left as the
    // caller set it, as wrap and unwrap do; only BUFFER_TOO_SMALL (the
    // required size) and success (the bytes read) write to it.
    const int32_t capacity = *out_len;
    auto fail = [&](int32_t code) {
        if (out != nullptr && capacity > 0) {
            SecureZero(out, static_cast<size_t>(capacity));
        }
        return code;
    };

    // Mostly not audited: the event log records failures against a
    // service's KEK, and a file read involves neither. The one exception is
    // a file that looks like an unwrapped DEK (HKDFGUARD_ERR_FILE_PLAINTEXT_KEY) - a possible key
    // exposure an administrator needs to hear about, logged below.
    try {
        // The Linux build's order: capacity, then the path (null, empty,
        // too long or not UTF-8), then the buffer - all before anything is
        // opened, so a size probe (NULL `out`, capacity 0) touches no file.
        if (capacity < 0) {
            return fail(HKDFGUARD_ERR_INVALID_ARGUMENT);
        }
        if (path == nullptr) {
            return fail(HKDFGUARD_ERR_INVALID_ARGUMENT);
        }
        KeyFilePathToWide(path); // throws HKDFGUARD_ERR_INVALID_ARGUMENT
        if (capacity < HKDFGUARD_WRAPPED_MAX_LEN) {
            *out_len = HKDFGUARD_WRAPPED_MAX_LEN;
            return fail(HKDFGUARD_ERR_BUFFER_TOO_SMALL);
        }
        if (out == nullptr) {
            return fail(HKDFGUARD_ERR_INVALID_ARGUMENT); // a declared capacity with nowhere to write
        }

        ReadWrappedKeyFile(path, out);
        *out_len = HKDFGUARD_WRAPPED_MAX_LEN;
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        // Zero first, log second, as hkdfguard_unwrap_dek does.
        const int32_t code = fail(e.code());
        if (code == HKDFGUARD_ERR_FILE_PLAINTEXT_KEY) {
            std::wstring loggable;
            try {
                loggable = KeyFilePathToWide(path); // already succeeded once to get this far
            } catch (...) {
                loggable = L"(unprintable path)";
            }
            LogPlaintextKeyFile(loggable);
        }
        return code;
    } catch (...) {
        return fail(HKDFGUARD_ERR_INTERNAL_ERROR);
    }
}

extern "C" HKDFGUARD_API int hkdfguard_harden_process(void) {
    return hkdfguard_harden_process_with_flags(0);
}

extern "C" HKDFGUARD_API int hkdfguard_harden_process_with_flags(unsigned int flags) {
    // Every HKDFGUARD_HARDEN_* flag this build knows. Any other bit is
    // refused before anything is changed, so a flag added later is never
    // silently ignored by an older DLL - as on Linux.
    constexpr unsigned int kKnownFlags = HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE;
    if ((flags & ~kKnownFlags) != 0) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }
    // Not audited: no service is involved. Anything that escapes
    // HardenProcess - even an allocation failure while building a DACL -
    // still means the process was left less hardened than asked, so every
    // failure maps to the one documented code.
    try {
        HardenProcess((flags & HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) != 0);
        return HKDFGUARD_OK;
    } catch (...) {
        return HKDFGUARD_ERR_PROCESS_HARDENING_FAILED;
    }
}
