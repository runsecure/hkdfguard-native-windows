// The boundary between the public C ABI (hkdfguard.h) and the internal C++
// implementation: validates arguments, calls the internal helpers in the
// required order, and translates exceptions into the ABI's integer status
// codes. No cryptography is implemented directly here.
#include "../include/hkdfguard.h"

#include "aes_gcm.h"
#include "ecdh_hkdf.h"
#include "errors.h"
#include "event_log.h"
#include "policy.h" // LoadAuditUnwrapSuccess, LoadPayloadVersionPolicy, SecurityModel
#include "process_hardening.h" // HardenProcess - hkdfguard_harden_process's implementation
#include "kek_store.h" // the version 1 KEK
#include "kek_v2.h"    // the version 2 KEK
#include "key_file.h" // ReadWrappedKeyFile - hkdfguard_open_file's implementation
#include "secure_buffer.h"
#include "wire_format.h"

// bcrypt.h: BCryptGenRandom for each payload's salt and for
// hkdfguard_generate_and_wrap_dek's new DEK.
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h> // ConvertStringSidToSidA - hkdfguard_key_file_principal_trusted
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

using namespace hkdfguard;

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
    // enough that a hot loop trips it within seconds.
    constexpr unsigned long kSetupCallsWarnAt = 10;

    // Runs `f` - the provider-touching part of a setup call - serialized
    // against every other setup call, and doesn't return (or let `f`'s
    // exception out) until at least LoadSetupMinDelayMs() has passed since
    // it was entered, whatever `f` did and however fast. Callers validate
    // their arguments first, so a bad pointer or service name still fails
    // at once; only calls that would reach a provider pay the floor.
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

        const unsigned long count = g_setup_calls.fetch_add(1) + 1;
        if (count == kSetupCallsWarnAt + 1) {
            LogSetupCallsExceeded(kSetupCallsWarnAt, floor_ms);
        }

        f();
    }

    // Allowed service-name characters: ASCII letters, digits and '.'.
    bool IsValidServiceChar(char c) noexcept {
        return
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '.';
    }

    // Lowercases an ASCII letter; anything else is returned unchanged.
    // Avoids <cctype>'s tolower because it is locale-dependent; the
    // service-name charset is pure ASCII (see IsValidServiceChar).
    char ToLowerServiceChar(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    // Validates `service` (null/length/charset - see IsValidServiceChar) and
    // returns a lowercase-normalized copy of it as a narrow ASCII string.
    // Every entry point's `service` passes through here, so names differing
    // only in case (e.g. "MyApp" and "myapp") are the same service
    // everywhere downstream: the same persisted KEK name (see
    // ServiceToWide/kek_store.cpp's KeyName) and the same HKDF info bytes
    // (see WrapDekCore/hkdfguard_unwrap_dek). Normalizing only the KEK
    // lookup would make unwrap fail whenever the casing differed.
    //
    // Throws HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME) if `service` is null,
    // empty, too long, contains a character outside the allowed charset,
    // starts with '.', or contains "..".
    std::string NormalizeService(const char *service) {
        if (service == nullptr) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME, "service is null");
        }
        // Bounded read: `service` is a plain C string with no length
        // parameter, so never read more than kMaxServiceLen + 1 bytes of a
        // buffer that may not be null-terminated.
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

        // Dot rules: a service name may not start with '.' or contain two
        // consecutive dots; a single trailing '.' is allowed. Nothing on
        // Windows uses the name as a path, but the rules are shared across
        // platforms so a name valid on one is valid on all, and they keep
        // names from spelling ".", "..", a hidden-file name, or an empty
        // label between dots.
        if (normalized.front() == '.' || normalized.find("..") != std::string::npos) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_INVALID_SERVICE_NAME,
                "service may not start with '.' or contain \"..\"");
        }
        return normalized;
    }

    // Converts an already-NormalizeService()-validated ASCII string into the
    // wide string used as part of the persisted KEK's name. Every byte in
    // `normalized` is ASCII alphanumeric or '.', so this conversion cannot
    // fail; MB_ERR_INVALID_CHARS and HKDFGUARD_ERR_INVALID_SERVICE_NAME are
    // defense in depth should NormalizeService's contract change.
    std::wstring ServiceToWide(const std::string &normalized) {
        // UTF-8 -> UTF-16 for NCrypt key names: one call for the size, one
        // to convert.
        int wide_len = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, normalized.c_str(), static_cast<int>(normalized.size()), nullptr, 0);
        if (wide_len <= 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_INVALID_SERVICE_NAME, "service is not valid UTF-8");
        }
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

    // The one payload version this host writes and accepts, from the
    // ClassicalMode policy (policy.h), read on every call; an invalid value
    // fails closed. Every KEK operation below takes its path from this, and
    // nothing else: there is no fallback from one version to the other.
    uint8_t RequirePayloadVersion() {
        switch (LoadPayloadVersionPolicy()) {
            case PayloadVersionPolicy::Version2:
                return kFormatVersion2;
            case PayloadVersionPolicy::Version1:
                return kFormatVersion1;
            default:
                throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid ClassicalMode policy");
        }
    }

    // The wrap sequence shared by hkdfguard_wrap_dek (caller-supplied DEK)
    // and hkdfguard_generate_and_wrap_dek (freshly generated DEK). Returns
    // argument/buffer status codes directly and throws HkdfGuardError for
    // everything else; callers catch. `op` only labels the success audit
    // event (Wrap vs GenerateAndWrap).
    int32_t WrapDekCore(
        AuditOp op, const char *service, const uint8_t *dek, int32_t dek_len, uint8_t *out, int32_t *out_len) {
        // Argument checks follow the Linux build's order, so the same mistake
        // gets the same code on both. `out` is checked later: it may be NULL
        // for a size probe.
        if (dek == nullptr || out_len == nullptr) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT;
        }
        if (dek_len != HKDFGUARD_DEK_LEN) {
            return HKDFGUARD_ERR_INVALID_ARGUMENT;
        }
        // In: the caller's buffer capacity (see hkdfguard.h's in/out note).
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

        // The payload version this host writes (ClassicalMode), and with it
        // which KEK: version 2's (kek_v2.h) or version 1's (kek_store.h).
        // Either is opened per KeyStoragePolicy, the TPM preferred, and never
        // created - hkdfguard_create_kek must have already provisioned it -
        // so this fails with HKDFGUARD_ERR_KEK_NOT_FOUND if the service has
        // no KEK of this version yet.
        const uint8_t version = RequirePayloadVersion();
        std::optional<ResolvedKek> v1_kek;
        std::unique_ptr<V2Kek> v2_kek;
        uint8_t provider_type = 0;
        uint32_t key_id = 0;

        // Fingerprint of the KEK this payload is being wrapped under: stamped
        // into the payload and bound into the key and the AAD below, so unwrap can both
        // check it explicitly (before any key derivation) and authenticate it (see
        // wire_format.h's layout comment).
        uint8_t fingerprint[kFingerprintLen];
        if (version == kFormatVersion2) {
            v2_kek = OpenV2KekForWrap(service_name);
            v2_kek->Fingerprint(fingerprint);
            provider_type = v2_kek->provider_type();
            key_id = v2_kek->key_id();
        } else {
            v1_kek.emplace(OpenKekForWrap(service_name));
            ComputeKekFingerprint(v1_kek->key.get(), fingerprint);
            provider_type = v1_kek->provider_type;
            key_id = v1_kek->key_id;
        }

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
        SerializeWrappedDekHeader(version, provider_type, key_id, salt, header);
        std::vector<uint8_t> authenticated = BuildWrappedDekAuthenticated(header, fingerprint);
        // Public parts of the payload, needed after the key's scope ends.
        uint8_t nonce[kNonceLen];
        uint8_t ciphertext[kCiphertextLen];
        uint8_t tag[kTagLen];
        {
            // Scoped to this block so the wrapping key is wiped (SecureBuffer,
            // see secure_buffer.h) as soon as AesGcmEncrypt is done with it.
            SecureBuffer<32> wrapping_key;
            // The same derivation unwrap runs, and in both versions one that
            // needs the KEK itself (inside the TPM for a TPM-backed KEK), so
            // nobody without access to it can forge a payload:
            //   version 2: PRF(KEK, the SP 800-108 block over the service
            //     name and the header) - sp800_108.h;
            //   version 1: ECDH(KEK private key, H(salt)) + HKDF-SHA512 -
            //     ecdh_hkdf.h.
            // Both bind `normalized_service` (not the caller's original-case
            // `service`), so the key is tied to the case-insensitive service
            // name and wrap/unwrap agree regardless of casing (see
            // NormalizeService).
            if (version == kFormatVersion2) {
                v2_kek->WrappingKey(normalized_service, header, wrapping_key);
            } else {
                DeriveWrappingKey(v1_kek->provider.get(), v1_kek->key.get(), normalized_service, authenticated,
                                  wrapping_key);
            }

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
        } // wrapping_key is zeroed here.

        // Assemble the 132-byte payload directly into the caller's buffer.
        SerializeWrappedDek(version, provider_type, key_id, salt, nonce, ciphertext, tag, fingerprint, out);
        *out_len = static_cast<int32_t>(kTotalLen);

        // Audit: who wrapped, for which service, in which version, under
        // which KEK, and a hash of the exact payload produced (public bytes
        // only - see event_log.h).
        LogDekOperation(op, normalized_service, provider_type, version, fingerprint, out, kTotalLen);
        return HKDFGUARD_OK;
    }

} // namespace

// Exported entry points. HKDFGUARD_API is __declspec(dllexport) here because
// CMakeLists.txt defines HKDFGUARD_EXPORTS only for this DLL's sources (see
// hkdfguard.h). Each one catches every exception and returns a status code:
// no C++ exception crosses the ABI.
extern "C" HKDFGUARD_API int hkdfguard_wrap_dek(
    const char *service,
    const uint8_t *dek, int dek_len,
    uint8_t *out, int *out_len) {
    try {
        return WrapDekCore(AuditOp::Wrap, service, dek, dek_len, out, out_len);
    } catch (const HkdfGuardError &e) {
        // A specific status code from an internal helper: audited if it's
        // one worth logging, then returned to the caller.
        return Audit(AuditOp::Wrap, service, e.code());
    } catch (...) {
        // Anything else (e.g. std::bad_alloc) is INTERNAL_ERROR.
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
        GatedSetup([&] {
            const bool exists = RequirePayloadVersion() == kFormatVersion2 ? V2KekExists(service_name)
                                                                           : KekExists(service_name);
            *out_exists = exists ? 1 : 0;
        });

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
        if (RequirePayloadVersion() == kFormatVersion2) {
            OpenV2KekForWrap(ServiceToWide(normalized_service))->Fingerprint(out);
        } else {
            ResolvedKek kek = OpenKekForWrap(ServiceToWide(normalized_service));
            ComputeKekFingerprint(kek.key.get(), out);
        }
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
        // The KEK provisioned is the one for this host's payload version.
        // Slow on purpose - see GatedSetup.
        GatedSetup([&] {
            if (RequirePayloadVersion() == kFormatVersion2) {
                CreateV2Kek(service_name);
            } else {
                CreateKek(service_name);
            }
        });

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
        // The only copy of the generated plaintext DEK: never returned to
        // the caller (see hkdfguard.h) and zeroed on every exit path,
        // including an exception from WrapDekCore.
        SecureBuffer<HKDFGUARD_DEK_LEN> dek;

        // The OS CSPRNG, the same source AesGcmEncrypt uses for nonces
        // (see aes_gcm.cpp).
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
    // Checked first: everything below, including `fail`, reads *out_len.
    if (out_len == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }

    // The caller's declared size of `out`, captured before *out_len can be
    // overwritten; `fail` zeroes exactly this many bytes.
    const int32_t capacity = *out_len;
    // On any failure, zero the caller's whole declared buffer and return
    // `code`: AES-GCM decryption can write unauthenticated plaintext into
    // `out` before detecting a tag mismatch, and no stale plaintext may
    // remain.
    auto fail = [&](int32_t code) {
        if (out != nullptr && capacity > 0) {
            SecureZero(out, static_cast<size_t>(capacity));
        }
        return code;
    };

    try {
        // Check order matches the Linux build (arguments, service name,
        // buffer), so the same mistake gets the same code on both.
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
        // genuine payload of either version.
        ParsedWrappedDek parsed = ParseWrappedDek(wrapped, wrapped_len);

        // The one version this host accepts (ClassicalMode), checked before
        // any key is opened: a payload of the other version is refused
        // outright, never tried. The version byte is also bound into each
        // version's key derivation and AAD, so rewriting it gains nothing.
        const uint8_t version = RequirePayloadVersion();
        if (parsed.version != version) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED,
                                 "payload version is not the one this host's ClassicalMode policy uses");
        }

        // Open (never create) the KEK the payload's routing fields select,
        // of this version.
        std::optional<ResolvedKek> v1_kek;
        std::unique_ptr<V2Kek> v2_kek;
        if (version == kFormatVersion2) {
            v2_kek = OpenV2KekForUnwrap(service_name, parsed.provider_type, parsed.key_id);
        } else {
            v1_kek.emplace(OpenKekForUnwrap(service_name, parsed.provider_type, parsed.key_id));
        }

        // Is that actually the KEK this payload was wrapped under? Compared
        // before deriving the wrapping key so a payload for a different or
        // rotated KEK fails precisely (HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH),
        // rather than surfacing later as an authentication failure that
        // looks identical to tampering. (Version 1 spends no TPM operation on
        // it; version 2's fingerprint is itself a PRF output, computed in the
        // same TPM session as the wrapping key.) Not constant-time, and
        // needn't be: both fingerprints are public. This is a check on the
        // key the routing fields chose, never a search for a key that
        // matches - see wire_format.h.
        uint8_t expected_fingerprint[kFingerprintLen];
        if (version == kFormatVersion2) {
            v2_kek->Fingerprint(expected_fingerprint);
        } else {
            ComputeKekFingerprint(v1_kek->key.get(), expected_fingerprint);
        }
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
            // Scoped so the key is wiped as soon as AesGcmDecrypt is done.
            SecureBuffer<32> wrapping_key;
            // The same 32-byte wrapping key derived at wrap time, from the
            // header as received: version 2's PRF over the SP 800-108
            // block, or version 1's ECDH(KEK private key, H(salt)) +
            // HKDF-SHA512 - either possibly inside a TPM/vTPM.
            if (version == kFormatVersion2) {
                v2_kek->WrappingKey(normalized_service, parsed.header, wrapping_key);
            } else {
                DeriveWrappingKey(v1_kek->provider.get(), v1_kek->key.get(), normalized_service, authenticated,
                                  wrapping_key);
            }

            // Decrypt directly into the caller's buffer - no intermediate
            // plaintext staging buffer. The AAD must match what
            // AesGcmEncrypt used at wrap time, and the key binds the
            // normalized service name, as in WrapDekCore.
            AesGcmDecrypt(
                wrapping_key.data(), parsed.nonce, parsed.ciphertext,
                static_cast<unsigned long>(kCiphertextLen),
                authenticated.data(), static_cast<unsigned long>(authenticated.size()),
                parsed.tag, out);
        } // wrapping_key is zeroed here.

        // `out` holds the only copy of the recovered plaintext DEK.
        *out_len = HKDFGUARD_DEK_LEN;

        // Audit: who unwrapped, for which service, under which KEK, and a hash
        // of the exact payload presented - matching the hash its wrap event
        // recorded. Hashes the caller's (public) payload buffer, never `out`.
        // An administrator can turn this one event off via the
        // AuditUnwrapSuccess policy value (see policy.h), e.g. for a caller
        // that legitimately unwraps often. Unwrap *failures* are logged
        // regardless, in the catch blocks below.
        if (LoadAuditUnwrapSuccess()) {
            LogDekOperation(
                AuditOp::Unwrap, normalized_service, parsed.provider_type, parsed.version, parsed.fingerprint,
                wrapped, static_cast<size_t>(wrapped_len));
        }
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        // Includes a tag mismatch (PAYLOAD_AUTH_FAILED from AesGcmDecrypt),
        // after which `out` may hold unauthenticated bytes written by
        // BCryptDecrypt (see aes_gcm.cpp). `fail` zeroes them first, then
        // the event is logged, so the buffer never holds them while the
        // event is written.
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
        // Check order matches the Linux build: capacity, then the path (null, empty,
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

extern "C" HKDFGUARD_API int hkdfguard_security_model(
    int *out_model,
    int *out_may_write_key_files) {
    if (out_model == nullptr || out_may_write_key_files == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }
    // Not audited: it reads policy and changes nothing.
    try {
        bool may_write = false;
        const SecurityModel model = CallerMayWriteKeyFiles(may_write);
        *out_model = model == SecurityModel::Developer ? HKDFGUARD_SECURITY_MODEL_DEVELOPER
                                                       : HKDFGUARD_SECURITY_MODEL_PRODUCTION;
        *out_may_write_key_files = may_write ? 1 : 0;
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError &e) {
        return e.code();
    } catch (...) {
        return HKDFGUARD_ERR_INTERNAL_ERROR;
    }
}

extern "C" HKDFGUARD_API int hkdfguard_key_file_principal_trusted(
    const char *sid,
    int *out_trusted) {
    if (sid == nullptr || out_trusted == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }
    PSID parsed = nullptr;
    if (strnlen(sid, 256) >= 256 || !ConvertStringSidToSidA(sid, &parsed)) {
        return HKDFGUARD_ERR_INVALID_ARGUMENT;
    }
    // Not audited: it reads policy and changes nothing.
    int32_t rc = HKDFGUARD_OK;
    try {
        *out_trusted = IsTrustedKeyFilePrincipal(parsed) ? 1 : 0;
    } catch (const HkdfGuardError &e) {
        rc = e.code();
    } catch (...) {
        rc = HKDFGUARD_ERR_INTERNAL_ERROR;
    }
    LocalFree(parsed);
    return rc;
}

extern "C" HKDFGUARD_API int hkdfguard_harden_process(void) {
    return hkdfguard_harden_process_with_flags(0);
}

extern "C" HKDFGUARD_API int hkdfguard_harden_process_with_flags(unsigned int flags) {
    // Every HKDFGUARD_HARDEN_* flag this build knows. Any other bit is
    // refused before anything is changed, so a flag this DLL doesn't know
    // is never silently ignored.
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
