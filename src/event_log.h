#pragma once

// Audit events written to the Windows Application event log under the
// source "hkdfguard-native-windows" - see event_log.cpp for exactly what is
// and isn't logged, and src/event_messages.mc for the event IDs.
//
// Every function here is noexcept and best-effort: a failure to log (no
// rights to the log, event log service stopped, out of memory) is silently
// ignored and can never change the outcome of the operation being logged.
// No key material, DEK, or payload byte is ever passed to these functions.

#include <cstdint>
#include <string>

namespace hkdfguard {

    enum class AuditOp {
        KekExists,
        KekFingerprint,
        CreateKek,
        Wrap,
        GenerateAndWrap,
        Unwrap,
    };

    // A KEK was newly created (not merely found already present).
    // `tpmFallbackCode` is HKDFGUARD_OK for an ordinary creation, or the
    // TPM attempt's HKDFGUARD_ERR_* code when PreferTpm fell back to the
    // software provider - logged as a warning, since the KEK then lacks the
    // hardware protection the policy preferred.
    void LogKekCreated(const std::wstring &service, uint8_t providerType, int32_t tpmFallbackCode) noexcept;

    // A wrap (op Wrap or GenerateAndWrap) or unwrap (op Unwrap) succeeded.
    // Records which KEK was used (its public-key fingerprint) and which
    // payload (SHA-256 of the 132 wrapped bytes) - both public values that
    // reveal nothing about the DEK - so an unwrap can be matched back to the
    // wrap that produced it, and a substituted older payload is visible.
    // `payload` is the wrapped output (wrap) or input (unwrap); it is only
    // hashed, never logged.
    void LogDekOperation(
        AuditOp op,
        const std::string &service,
        uint8_t providerType,
        const uint8_t *kekFingerprint,
        const uint8_t *payload,
        size_t payloadLen) noexcept;

    // An ABI call failed with `code`. Only security- or operations-relevant
    // codes produce an event; caller mistakes (bad arguments, buffer too
    // small, malformed service name) and "not provisioned yet" do not.
    // `service` is the normalized service name, or empty if it was invalid.
    void LogOperationFailure(AuditOp op, const std::string &service, int32_t code) noexcept;

    // hkdfguard_open_file refused `path` because it holds what looks like an
    // unwrapped DEK - 32 raw bytes, or its hex or base64
    // (HKDFGUARD_ERR_FILE_PLAINTEXT_KEY): possibly a plaintext key on disk.
    // The only event that call writes - its other failures concern no KEK
    // and are reported to the caller alone. The path is logged so an
    // administrator can find the file; none of its contents are logged.
    void LogPlaintextKeyFile(const std::wstring &path) noexcept;

    // This process has just made its (`calls` + 1)th setup call
    // (hkdfguard_create_kek / hkdfguard_kek_exists), each held to at least
    // `floor_ms`: the signature of a caller looping on them. Logged once
    // per process, a warning - the counterpart of the Linux build's
    // log::warn at the same point.
    void LogSetupCallsExceeded(unsigned long calls, unsigned long floor_ms) noexcept;

} // namespace hkdfguard
