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
#include "kek_store.h"
#include "secure_buffer.h"
#include "wire_format.h"

// windows.h: MultiByteToWideChar, CP_UTF8, MB_ERR_INVALID_CHARS (used by
// ServiceToWide below). bcrypt.h: BCryptGenRandom (used by
// hkdfguard_generate_and_wrap_dek below to source the new DEK's
// randomness). cstring: strnlen, memcpy. string: std::wstring.
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <string>

// `using namespace hkdfguard;` brings every name declared inside `namespace
// hkdfguard { ... }` (SecureBuffer, ResolvedKek, HkdfGuardError, the
// kEphemeralPubLen/kNonceLen/... constants, AesGcmEncrypt, and so on) into
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
    // ServiceToWide/kek_store.cpp's KeyName) and the same AES-GCM AAD bytes
    // (see WrapDekCore/hkdfguard_unwrap_dek below) - not just a
    // case-insensitive KEK lookup with case-sensitive AAD underneath it,
    // which would make wrap/unwrap fail whenever the two calls' casing
    // didn't match exactly.
    //
    // Throws HkdfGuardError if `service` is null, empty, too long, or
    // contains a character outside the allowed charset.
    std::string NormalizeService(const char *service) {
        if (service == nullptr) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARG, "service is null");
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
            throw HkdfGuardError(HKDFGUARD_ERR_SERVICE_NAME_INVALID, "service is empty or too long");
        }

        std::string normalized(service, len);
        for (char &c : normalized) {
            if (!IsValidServiceChar(c)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_SERVICE_NAME_INVALID,
                    "service contains invalid characters");
            }
            c = ToLowerServiceChar(c);
        }
        return normalized;
    }

    // Converts an already-NormalizeService()-validated ASCII string into the
    // wide string used as part of the persisted KEK's name. Every byte in
    // `normalized` is, by construction, ASCII alphanumeric or '.', so this
    // conversion cannot actually fail today - MB_ERR_INVALID_CHARS and the
    // resulting HKDFGUARD_ERR_INVALID_ARG are kept anyway as defense in
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
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARG, "service is not valid UTF-8");
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
    // narrow form WrapDekCore/hkdfguard_unwrap_dek also need for AAD.
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
        // Basic null-pointer validation before touching any of the pointers.
        // `dek_len`/`out_len` themselves are validated next.
        if (dek == nullptr || out == nullptr || out_len == nullptr) {
            return HKDFGUARD_ERR_INVALID_ARG;
        }
        if (dek_len != HKDFGUARD_DEK_LEN) {
            return HKDFGUARD_ERR_INVALID_ARG;
        }
        // `*out_len` dereferences the pointer to read the caller-supplied
        // buffer capacity (the "in" half of this in/out parameter - see
        // hkdfguard.h's note on this pattern). Checked before doing any real
        // work, so a too-small buffer fails fast.
        if (*out_len < HKDFGUARD_WRAPPED_LEN) {
            return HKDFGUARD_ERR_BUFFER_TOO_SMALL;
        }

        std::string normalized_service = NormalizeService(service);
        std::wstring service_name = ServiceToWide(normalized_service);

        // Opens this service's machine-wide persistent KEK, preferring the
        // TPM/vTPM-backed Platform Crypto Provider and falling back to the
        // Software Key Storage Provider automatically. Never creates one -
        // hkdfguard_create_kek must have already provisioned it (see
        // kek_store.h/.cpp) - so this fails with HKDFGUARD_ERR_PROVIDER if
        // the service has no KEK yet.
        ResolvedKek kek = OpenKekForWrap(service_name);

        // Fingerprint of the KEK this payload is being wrapped under: stamped
        // into the payload and bound into the AAD below, so unwrap can both
        // check it explicitly (before any ECDH) and authenticate it (see
        // wire_format.h's layout comment).
        uint8_t fingerprint[kFingerprintLen];
        ComputeKekFingerprint(kek.key.get(), fingerprint);

        // AAD = normalized service name || KEK fingerprint. None of it is
        // secret; it just has to be reproduced byte-for-byte on unwrap.
        std::vector<uint8_t> aad(normalized_service.begin(), normalized_service.end());
        aad.insert(aad.end(), fingerprint, fingerprint + kFingerprintLen);

        // Ephemeral ECDH + HKDF-SHA512 -> 32-byte AES wrapping key. Only the
        // KEK's public key is needed here, so this never touches the TPM.
        uint8_t ephemeral_pub[kEphemeralPubLen];
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
            DeriveWrappingKeyForWrap(kek.key.get(), ephemeral_pub, wrapping_key);

            // AES-256-GCM directly from the caller's dek pointer - no
            // intermediate plaintext staging buffer. The AAD's service
            // component is the case-normalized `normalized_service` bytes
            // (not the caller's original-case `service`, and not the wide
            // NCrypt-key-name form `service_name` above): it binds this
            // ciphertext to the exact (case-insensitive) service it was
            // wrapped for. Using the normalized form - the same one
            // ServiceToWide derived `service_name` from - is what makes
            // wrap/unwrap genuinely case-insensitive end to end: if the raw
            // `service` bytes were used instead, two calls that differ only
            // in case would resolve to the same KEK but produce/expect
            // different AAD, and unwrap would fail authentication. The
            // fingerprint component binds the ciphertext to the specific
            // KEK, so neither the service nor the routing can be swapped
            // undetected.
            AesGcmEncrypt(
                wrapping_key.data(), dek, static_cast<unsigned long>(dek_len),
                aad.data(), static_cast<unsigned long>(aad.size()),
                nonce, ciphertext, tag);
        } // <- wrapping_key's destructor (zeroing it) runs here, right now.

        // Assemble the final 164-byte payload directly into the caller's
        // buffer, and report how many bytes were written back through the
        // out-parameter.
        SerializeWrappedDek(kek.provider_type, kek.key_id, ephemeral_pub, nonce, ciphertext, tag, fingerprint, out);
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
extern "C" HKDFGUARD_API int32_t hkdfguard_wrap_dek(
    const char *service,
    const uint8_t *dek, int32_t dek_len,
    uint8_t *out, int32_t *out_len) {
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
        return Audit(AuditOp::Wrap, service, HKDFGUARD_ERR_INTERNAL);
    }
}

extern "C" HKDFGUARD_API int32_t hkdfguard_kek_exists(
    const char *service,
    int32_t *out_exists) {
    if (out_exists == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARG;
    }

    try {
        std::wstring service_name =
                ValidateAndConvertService(service);

        *out_exists = KekExists(service_name) ? 1 : 0;

        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::KekExists, service, e.code());
    } catch (...) {
        return Audit(AuditOp::KekExists, service, HKDFGUARD_ERR_INTERNAL);
    }
}

extern "C" HKDFGUARD_API int32_t hkdfguard_create_kek(
    const char *service) {
    try {
        std::wstring service_name =
                ValidateAndConvertService(service);

        // Who may use the resulting KEK comes from machine policy (see
        // hkdfguard.h and policy.h's LoadKeyUseGroupsPolicy), read and
        // validated inside CreateKek - nothing about access is caller-chosen.
        CreateKek(service_name);

        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::CreateKek, service, e.code());
    } catch (...) {
        return Audit(AuditOp::CreateKek, service, HKDFGUARD_ERR_INTERNAL);
    }
}

extern "C" HKDFGUARD_API int32_t hkdfguard_generate_and_wrap_dek(
    const char *service,
    uint8_t *out, int32_t *out_len) {
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
            return Audit(AuditOp::GenerateAndWrap, service, HKDFGUARD_ERR_CRYPTO);
        }

        return WrapDekCore(AuditOp::GenerateAndWrap, service, dek.data(), HKDFGUARD_DEK_LEN, out, out_len);
    } catch (const HkdfGuardError &e) {
        return Audit(AuditOp::GenerateAndWrap, service, e.code());
    } catch (...) {
        return Audit(AuditOp::GenerateAndWrap, service, HKDFGUARD_ERR_INTERNAL);
    }
}

extern "C" HKDFGUARD_API int32_t hkdfguard_unwrap_dek(
    const char *service,
    const uint8_t *wrapped, int32_t wrapped_len,
    uint8_t *out, int32_t *out_len) {
    // out_len must be checked before anything else - every other line in
    // this function (including the `fail` helper defined just below) needs
    // to be able to dereference it safely.
    if (out_len == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARG;
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
        if (out == nullptr || wrapped == nullptr) {
            return fail(HKDFGUARD_ERR_INVALID_ARG);
        }
        if (capacity < HKDFGUARD_DEK_LEN) {
            return fail(HKDFGUARD_ERR_BUFFER_TOO_SMALL);
        }

        std::string normalized_service = NormalizeService(service);
        std::wstring service_name = ServiceToWide(normalized_service);

        // Validates the payload's shape/version and hands back pointers
        // into `wrapped` for each field (see wire_format.h/.cpp) - throws
        // HKDFGUARD_ERR_MALFORMED on anything that doesn't look like a
        // genuine WrappedDekV1 payload.
        ParsedWrappedDek parsed = ParseWrappedDek(wrapped, wrapped_len);

        // Open (never create) the KEK the payload's routing fields select.
        ResolvedKek kek = OpenKekForUnwrap(service_name, parsed.provider_type, parsed.key_id);

        // Is that actually the KEK this payload was wrapped under? Compared
        // before any ECDH so a payload for a different/rotated KEK fails
        // fast and precisely (HKDFGUARD_ERR_KEK_MISMATCH), costing no TPM
        // operation, rather than surfacing later as an authentication
        // failure that looks identical to tampering. Not constant-time, and
        // needn't be: both sides of the comparison are hashes of public
        // keys. This is a check on the key the routing fields chose, never a
        // search for a key that matches - see wire_format.h.
        uint8_t expected_fingerprint[kFingerprintLen];
        ComputeKekFingerprint(kek.key.get(), expected_fingerprint);
        if (std::memcmp(expected_fingerprint, parsed.fingerprint, kFingerprintLen) != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_KEK_MISMATCH, "payload was not wrapped under this KEK");
        }

        // Same AAD construction as WrapDekCore: normalized service name ||
        // the payload's (now verified) fingerprint.
        std::vector<uint8_t> aad(normalized_service.begin(), normalized_service.end());
        aad.insert(aad.end(), parsed.fingerprint, parsed.fingerprint + kFingerprintLen);

        {
            // Same reasoning as the wrap side above: `wrapping_key` is
            // scoped to only the two statements that need it, so it's
            // wiped the moment this block ends - immediately after
            // AesGcmDecrypt is done with it - rather than lingering,
            // unused, until the function returns.
            SecureBuffer<32> wrapping_key;
            // ECDH against the KEK's private key (may execute inside a
            // TPM/vTPM) + HKDF-SHA512 -> the same 32-byte wrapping key
            // derived at wrap time.
            DeriveWrappingKeyForUnwrap(kek.provider.get(), kek.key.get(), parsed.ephemeral_pub, wrapping_key);

            // Decrypt directly into the caller's buffer - no intermediate
            // plaintext staging buffer. AAD must match what AesGcmEncrypt
            // used at wrap time (see WrapDekCore's comment on why the
            // normalized service form, not the caller's original-case
            // `service`, is what's used).
            AesGcmDecrypt(
                wrapping_key.data(), parsed.nonce, parsed.ciphertext,
                static_cast<unsigned long>(kCiphertextLen),
                aad.data(), static_cast<unsigned long>(aad.size()),
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
        // AesGcmDecrypt throws HkdfGuardError(HKDFGUARD_ERR_AUTH_FAILED) on
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
        return Audit(AuditOp::Unwrap, service, fail(HKDFGUARD_ERR_INTERNAL));
    }
}
