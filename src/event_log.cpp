#include "event_log.h"

#include "../include/hkdfguard.h"
#include "wire_format.h" // kProviderTypeTpm / kProviderTypeSoftware

#include <windows.h>
#include <bcrypt.h> // BCryptHash - payload fingerprint for the wrap/unwrap events

#include <atomic>
#include <string>
#include <vector>

// What is logged, and why:
//
//   1000 Information  A KEK was created. Creation is rare and
//                     consequential (it fixes who can ever use the key),
//                     so every one is recorded with who did it.
//   1001 Warning      A KEK was created on the software provider because
//                     PreferTpm's TPM attempt failed - the key exists, but
//                     without the hardware protection the policy preferred.
//   1002 Information  A DEK was wrapped (hkdfguard_wrap_dek or
//                     hkdfguard_generate_and_wrap_dek).
//   1003 Information  A DEK was unwrapped.
//                     Both record the KEK fingerprint and a SHA-256 of the
//                     wrapped payload, so each unwrap can be matched to the
//                     wrap that produced it - which also makes a substituted
//                     older payload visible, since deployment rollback is
//                     deliberately allowed by the format itself.
//   1005 Warning      hkdfguard_open_file trusted a key file under the
//                     developer security model, once per process - the
//                     caller's own files are accepted, which a production
//                     machine must not do.
//   1004 Warning      A KEK was retired (deleted) by hkdfguard.exe retire.
//                     Written by the CLI, not this file - the library has no
//                     delete - but its message lives in this DLL's table.
//   2000 Warning      KEK_ACCESS_DENIED on any call: someone tried to use (or
//                     create) a KEK they aren't authorized for, or tried
//                     to provision without elevation.
//   2002 Error        KEK_INVALID: an existing KEK under a service's
//                     name has an ACL this library would never create -
//                     possibly pre-planted or widened. Worth investigating.
//   2003 Warning      PAYLOAD_AUTH_FAILED / KEK_FINGERPRINT_MISMATCH /
//                     PAYLOAD_MALFORMED / PAYLOAD_UNSUPPORTED on unwrap:
//                     the payload was tampered with, truncated, wrapped
//                     for a different service, under a different KEK, or
//                     in a format version this build does not know.
//   2004 Error        POLICY_INVALID / WIN_GROUP_INVALID: the machine policy in
//                     the registry is misconfigured, so calls fail closed.
//   2005 Error        PROVIDER_ERROR / CRYPTO_ERROR / INTERNAL_ERROR: the
//                     key storage provider or crypto layer itself failed.
//
// Not logged: INVALID_ARGUMENT / BUFFER_TOO_SMALL /
// INVALID_SERVICE_NAME (caller programming errors), and KEK_NOT_FOUND
// (the normal "provision first" state). Nothing secret is ever logged -
// only the service name, provider, operation, error code, calling user
// and calling process.
//
// The event's user field is the caller's identity - the thread token if
// the thread is impersonating (a service acting for a client), otherwise
// the process token - so Event Viewer's "User" column says who acted.
//
// Any local user can write to the Application log, so an unprivileged
// process can add noise under this source name; these events are an audit
// aid, not tamper-proof evidence.

namespace hkdfguard {
    namespace {
        constexpr wchar_t kEventSource[] = L"hkdfguard-native-windows";

        // Must match src/event_messages.mc.
        constexpr DWORD kEvtKekCreated = 1000;
        constexpr DWORD kEvtKekCreatedSoftwareFallback = 1001;
        constexpr DWORD kEvtDekWrapped = 1002;
        constexpr DWORD kEvtDekUnwrapped = 1003;
        constexpr DWORD kEvtDeveloperMode = 1005;
        constexpr DWORD kEvtAccessDenied = 2000;
        constexpr DWORD kEvtKekAclInvalid = 2002;
        constexpr DWORD kEvtIntegrityFailure = 2003;
        constexpr DWORD kEvtPolicyInvalid = 2004;
        constexpr DWORD kEvtOperationFailed = 2005;
        constexpr DWORD kEvtPlaintextKeyFile = 2006;
        constexpr DWORD kEvtSetupCallsExceeded = 2007;

        const wchar_t *CodeName(int32_t code) noexcept {
            switch (code) {
                case HKDFGUARD_OK: return L"HKDFGUARD_OK";
                case HKDFGUARD_ERR_INVALID_ARGUMENT: return L"HKDFGUARD_ERR_INVALID_ARGUMENT";
                case HKDFGUARD_ERR_BUFFER_TOO_SMALL: return L"HKDFGUARD_ERR_BUFFER_TOO_SMALL";
                case HKDFGUARD_ERR_PROVIDER_UNAVAILABLE: return L"HKDFGUARD_ERR_PROVIDER_UNAVAILABLE";
                case HKDFGUARD_ERR_PROVIDER_ERROR: return L"HKDFGUARD_ERR_PROVIDER_ERROR";
                case HKDFGUARD_ERR_CRYPTO_ERROR: return L"HKDFGUARD_ERR_CRYPTO_ERROR";
                case HKDFGUARD_ERR_INTERNAL_ERROR: return L"HKDFGUARD_ERR_INTERNAL_ERROR";
                case HKDFGUARD_ERR_INVALID_SERVICE_NAME: return L"HKDFGUARD_ERR_INVALID_SERVICE_NAME";
                case HKDFGUARD_ERR_POLICY_INVALID: return L"HKDFGUARD_ERR_POLICY_INVALID";
                case HKDFGUARD_ERR_PAYLOAD_MALFORMED: return L"HKDFGUARD_ERR_PAYLOAD_MALFORMED";
                case HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED: return L"HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED";
                case HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED: return L"HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED";
                case HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH: return L"HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH";
                case HKDFGUARD_ERR_KEK_NOT_FOUND: return L"HKDFGUARD_ERR_KEK_NOT_FOUND";
                case HKDFGUARD_ERR_KEK_ACCESS_DENIED: return L"HKDFGUARD_ERR_KEK_ACCESS_DENIED";
                case HKDFGUARD_ERR_KEK_INVALID: return L"HKDFGUARD_ERR_KEK_INVALID";
                case HKDFGUARD_ERR_PROCESS_HARDENING_FAILED: return L"HKDFGUARD_ERR_PROCESS_HARDENING_FAILED";
                case HKDFGUARD_ERR_FILE_NOT_FOUND: return L"HKDFGUARD_ERR_FILE_NOT_FOUND";
                case HKDFGUARD_ERR_FILE_ACCESS_DENIED: return L"HKDFGUARD_ERR_FILE_ACCESS_DENIED";
                case HKDFGUARD_ERR_FILE_IO: return L"HKDFGUARD_ERR_FILE_IO";
                case HKDFGUARD_ERR_FILE_TOO_SHORT: return L"HKDFGUARD_ERR_FILE_TOO_SHORT";
                case HKDFGUARD_ERR_FILE_TOO_LONG: return L"HKDFGUARD_ERR_FILE_TOO_LONG";
                case HKDFGUARD_ERR_FILE_PLAINTEXT_KEY: return L"HKDFGUARD_ERR_FILE_PLAINTEXT_KEY";
                case HKDFGUARD_ERR_FILE_MALFORMED: return L"HKDFGUARD_ERR_FILE_MALFORMED";
                case HKDFGUARD_ERR_FILE_UNTRUSTED: return L"HKDFGUARD_ERR_FILE_UNTRUSTED";
                case HKDFGUARD_ERR_WIN_GROUP_INVALID: return L"HKDFGUARD_ERR_WIN_GROUP_INVALID";
                default: return L"(unknown code)";
            }
        }

        const wchar_t *OpName(AuditOp op) noexcept {
            switch (op) {
                case AuditOp::KekExists: return L"hkdfguard_kek_exists";
                case AuditOp::KekFingerprint: return L"hkdfguard_kek_fingerprint";
                case AuditOp::CreateKek: return L"hkdfguard_create_kek";
                case AuditOp::Wrap: return L"hkdfguard_wrap_dek";
                case AuditOp::GenerateAndWrap: return L"hkdfguard_generate_and_wrap_dek";
                case AuditOp::Unwrap: return L"hkdfguard_unwrap_dek";
            }
            return L"(unknown operation)";
        }

        const wchar_t *ProviderLabel(uint8_t providerType) noexcept {
            switch (providerType) {
                case kProviderTypeTpm: return L"Microsoft Platform Crypto Provider (TPM, provider_type 1)";
                case kProviderTypeSoftware: return L"Microsoft Software Key Storage Provider (provider_type 2)";
                default: return L"(unknown provider)";
            }
        }

        // The service names reaching here are already restricted to ASCII
        // letters, digits and '.', so a byte-for-byte widen is exact - and
        // there is no way to smuggle formatting or newlines into an event.
        std::wstring Widen(const std::string &s) {
            return std::wstring(s.begin(), s.end());
        }

        std::wstring Hex(const uint8_t *bytes, size_t len) {
            static const wchar_t kDigits[] = L"0123456789abcdef";
            std::wstring out;
            out.reserve(len * 2);
            for (size_t i = 0; i < len; ++i) {
                out.push_back(kDigits[bytes[i] >> 4]);
                out.push_back(kDigits[bytes[i] & 0x0F]);
            }
            return out;
        }

        // SHA-256 of a public buffer (the wrapped payload), hex-encoded, or a
        // placeholder if hashing fails - the event is still worth writing.
        std::wstring Sha256Hex(const uint8_t *data, size_t len) {
            uint8_t digest[32] = {};
            NTSTATUS status = BCryptHash(
                BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
                const_cast<PUCHAR>(data), static_cast<ULONG>(len), digest, sizeof(digest));
            if (!BCRYPT_SUCCESS(status)) {
                return L"(unavailable)";
            }
            return Hex(digest, sizeof(digest));
        }

        // The acting user's SID: the thread's impersonation token if there is
        // one, otherwise the process token. Empty on any failure (the event is
        // then written without a user, rather than not at all).
        std::vector<BYTE> CallerSid() {
            HANDLE token = nullptr;
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) &&
                !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
                return {};
            }
            DWORD size = 0;
            GetTokenInformation(token, TokenUser, nullptr, 0, &size);
            std::vector<BYTE> buffer(size);
            std::vector<BYTE> sid;
            if (size != 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
                PSID user = reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid;
                DWORD length = GetLengthSid(user);
                sid.resize(length);
                if (!CopySid(length, sid.data(), user)) {
                    sid.clear();
                }
            }
            CloseHandle(token);
            return sid;
        }

        std::wstring ProcessDescription() {
            std::wstring path(MAX_PATH, L'\0');
            for (int attempt = 0; attempt < 4; ++attempt) {
                DWORD written = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
                if (written == 0) {
                    path = L"(unknown)";
                    break;
                }
                if (written < path.size()) {
                    path.resize(written);
                    break;
                }
                path.assign(path.size() * 2, L'\0');
            }
            return path + L" (PID " + std::to_wstring(GetCurrentProcessId()) + L")";
        }

        void Write(WORD type, DWORD eventId, const std::wstring &text) noexcept {
            try {
                HANDLE source = RegisterEventSourceW(nullptr, kEventSource);
                if (source == nullptr) {
                    return;
                }
                std::wstring full = text + L" Process: " + ProcessDescription() + L".";
                LPCWSTR strings[1] = {full.c_str()};
                std::vector<BYTE> sid = CallerSid();
                ReportEventW(
                    source, type, 0, eventId, sid.empty() ? nullptr : sid.data(),
                    1, 0, strings, nullptr);
                DeregisterEventSource(source);
            } catch (...) {
                // Logging must never affect the operation being logged.
            }
        }
    } // namespace

    void LogKekCreated(const std::wstring &service, uint8_t providerType, int32_t tpmFallbackCode) noexcept {
        try {
            if (tpmFallbackCode == HKDFGUARD_OK) {
                Write(EVENTLOG_INFORMATION_TYPE, kEvtKekCreated,
                      L"KEK created for service '" + service + L"' on " + ProviderLabel(providerType) + L".");
            } else {
                Write(EVENTLOG_WARNING_TYPE, kEvtKekCreatedSoftwareFallback,
                      L"KEK created for service '" + service + L"' on " + ProviderLabel(providerType) +
                      L" because the KeyStoragePolicy is PreferTpm and the TPM attempt failed with " +
                      CodeName(tpmFallbackCode) + L" (" + std::to_wstring(tpmFallbackCode) +
                      L"). This KEK is not hardware-protected.");
            }
        } catch (...) {
        }
    }

    void LogDekOperation(
        AuditOp op,
        const std::string &service,
        uint8_t providerType,
        const uint8_t *kekFingerprint,
        const uint8_t *payload,
        size_t payloadLen) noexcept {
        try {
            const bool unwrap = (op == AuditOp::Unwrap);
            std::wstring text =
                    std::wstring(OpName(op)) + L" succeeded: DEK " + (unwrap ? L"unwrapped" : L"wrapped") +
                    L" for service '" + Widen(service) + L"' using the KEK on " + ProviderLabel(providerType) +
                    L". KEK fingerprint (SHA-256 of public key): " + Hex(kekFingerprint, kFingerprintLen) +
                    L". Wrapped payload SHA-256: " + Sha256Hex(payload, payloadLen) + L".";
            Write(EVENTLOG_INFORMATION_TYPE, unwrap ? kEvtDekUnwrapped : kEvtDekWrapped, text);
        } catch (...) {
        }
    }

    void LogOperationFailure(AuditOp op, const std::string &service, int32_t code) noexcept {
        try {
            DWORD eventId = 0;
            WORD type = EVENTLOG_ERROR_TYPE;
            const wchar_t *meaning = L"";

            switch (code) {
                case HKDFGUARD_ERR_KEK_ACCESS_DENIED:
                    eventId = kEvtAccessDenied;
                    type = EVENTLOG_WARNING_TYPE;
                    meaning = op == AuditOp::CreateKek
                                  ? L"the caller is not authorized to open this KEK, or tried to create a new KEK "
                                    L"without an elevated process"
                                  : L"the caller is not authorized to use this KEK";
                    break;
                case HKDFGUARD_ERR_KEK_INVALID:
                    eventId = kEvtKekAclInvalid;
                    meaning = L"a KEK already exists under this service name, but its ACL is missing, lacks "
                              L"SYSTEM/Administrators, or grants an over-broad principal - it may have been "
                              L"pre-planted or widened; it was left untouched";
                    break;
                case HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED:
                case HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH:
                case HKDFGUARD_ERR_PAYLOAD_MALFORMED:
                case HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED:
                    if (op != AuditOp::Unwrap) {
                        return;
                    }
                    eventId = kEvtIntegrityFailure;
                    type = EVENTLOG_WARNING_TYPE;
                    meaning = code == HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED
                                  ? L"the payload failed authentication: tampered with, or presented for the "
                                    L"wrong service"
                                  : code == HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH
                                        ? L"the payload was not wrapped under this service's current KEK"
                                        : code == HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED
                                              ? L"the payload's format version is not one this build "
                                                L"understands (corrupted, tampered with, or from a newer version)"
                                              : L"the payload is not a valid wrapped DEK (truncated, corrupted, "
                                                L"or tampered with)";
                    break;
                case HKDFGUARD_ERR_POLICY_INVALID:
                case HKDFGUARD_ERR_WIN_GROUP_INVALID:
                    eventId = kEvtPolicyInvalid;
                    meaning = code == HKDFGUARD_ERR_POLICY_INVALID
                                  ? L"HKLM\\Software\\Policies\\HkdfGuard\\KeyStoragePolicy is present but not a "
                                    L"valid REG_DWORD 0, 1 or 2; every call fails closed until it is fixed"
                                  : L"an entry in HKLM\\Software\\Policies\\HkdfGuard\\KeyUseGroups is "
                                    L"unresolvable, not a group, over-broad, or not host-local";
                    break;
                case HKDFGUARD_ERR_PROVIDER_UNAVAILABLE:
                case HKDFGUARD_ERR_PROVIDER_ERROR:
                case HKDFGUARD_ERR_CRYPTO_ERROR:
                case HKDFGUARD_ERR_INTERNAL_ERROR:
                    eventId = kEvtOperationFailed;
                    meaning = L"the key storage provider or a cryptographic operation failed";
                    break;
                default:
                    // Caller mistakes and "not provisioned yet" - not logged.
                    return;
            }

            std::wstring serviceText = service.empty() ? L"(invalid service name)" : L"'" + Widen(service) + L"'";
            Write(type, eventId,
                  std::wstring(OpName(op)) + L" failed for service " + serviceText + L": " + CodeName(code) +
                  L" (" + std::to_wstring(code) + L") - " + meaning + L".");
        } catch (...) {
        }
    }

    void LogPlaintextKeyFile(const std::wstring &path) noexcept {
        try {
            // An error, like 2002: not a failed operation but a finding that
            // needs an administrator's attention.
            Write(EVENTLOG_ERROR_TYPE, kEvtPlaintextKeyFile,
                  L"hkdfguard_open_file refused '" + path + L"': " + CodeName(HKDFGUARD_ERR_FILE_PLAINTEXT_KEY) +
                  L" (" + std::to_wstring(HKDFGUARD_ERR_FILE_PLAINTEXT_KEY) + L") - the file holds what looks "
                  L"like an unwrapped DEK (" + std::to_wstring(HKDFGUARD_DEK_LEN) +
                  L" raw bytes, or its hex or base64), so it may be a plaintext key written to disk by "
                  L"mistake. None of its contents were returned. Treat that key as exposed: find out how the "
                  L"file was written, remove it, and re-mint the DEK.");
        } catch (...) {
        }
    }

    void LogDeveloperModeKeyFile() noexcept {
        static std::atomic<bool> logged{false};
        if (logged.exchange(true)) {
            return;
        }
        try {
            Write(EVENTLOG_WARNING_TYPE, kEvtDeveloperMode,
                  L"hkdfguard_open_file is running under the developer security model "
                  L"(HKLM\\Software\\Policies\\HkdfGuard\\SecurityModel = 1): key files owned by the calling "
                  L"account are trusted, so an application that can write files could persist a key file its own "
                  L"service accepts. Remove the value (or set it to 0) on any production machine. Logged once per "
                  L"process.");
        } catch (...) {
        }
    }

    void LogSetupCallsExceeded(unsigned long calls, unsigned long floor_ms) noexcept {
        try {
            Write(EVENTLOG_WARNING_TYPE, kEvtSetupCallsExceeded,
                  L"This process has made more than " + std::to_wstring(calls) +
                  L" hkdfguard_create_kek / hkdfguard_kek_exists calls. These are meant to run once per "
                  L"application startup; each costs a fresh key storage provider connection plus at least " +
                  std::to_wstring(floor_ms) +
                  L" ms, and they run one at a time. A caller is probably calling them per request or in a "
                  L"loop: call them once at startup, then use hkdfguard_wrap_dek / hkdfguard_unwrap_dek.");
        } catch (...) {
        }
    }
} // namespace hkdfguard
