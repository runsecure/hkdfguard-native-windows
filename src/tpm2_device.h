#pragma once

#include "errors.h"        // HkdfGuardError
#include "secure_buffer.h" // SecureBuffer<N>
#include "tpm2_marshal.h"
#include "tpm2_session.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

// The TPM itself, for the version 2 TPM provider
// (docs/adr/0001-post-quantum-payload-version-2.md, section 3): raw TPM 2.0
// commands sent through TBS (tbs.dll), built and checked by tpm2_marshal.h
// and tpm2_session.h. Each Tpm owns one TBS context; objects and sessions
// loaded through it are visible only to it, and TBS flushes whatever is left
// when the context closes.
//
// Only the operations the provider needs are here. Every one that can carry
// a secret - TPM2_HMAC's output, the wrapping key - goes through an
// encrypted, salted session; the others need no confidentiality and use a
// password session with the empty password, or none.
namespace hkdfguard::tpm2 {
    // TBS's TPM_E_COMMAND_BLOCKED: TBS refused the command for this caller
    // (its block list, or Group Policy). Returned as a response code.
    constexpr uint32_t kRcCommandBlocked = 0x80280400;

    // A TPM or TBS failure, carrying the TPM response code or TBS result
    // that caused it, so the provider can tell, say, a blocked command from
    // a broken TPM. code() is HKDFGUARD_ERR_PROVIDER_UNAVAILABLE when no TPM
    // 2.0 could be reached through TBS at all, and
    // HKDFGUARD_ERR_PROVIDER_ERROR otherwise.
    class TpmError : public HkdfGuardError {
    public:
        TpmError(int code, uint32_t tpm_code, const char *what) : HkdfGuardError(code, what), tpm_code_(tpm_code) {}
        uint32_t tpm_code() const { return tpm_code_; }

    private:
        uint32_t tpm_code_;
    };

    // Sends one complete command and returns the complete response. Tests
    // wrap the TBS transport to tamper with responses.
    using Transport = std::function<Bytes(const Bytes &command)>;

    // A transport over a new TBS context for a TPM 2.0, closed when the last
    // copy of the transport is destroyed. Throws TpmError with
    // HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, carrying the TBS result, if there
    // is no TPM 2.0 or TBS is unavailable. A TBS failure to submit a command
    // is a TpmError with HKDFGUARD_ERR_PROVIDER_ERROR.
    Transport OpenTbsTransport();

    class Tpm {
    public:
        // Over a new TBS context (OpenTbsTransport).
        Tpm();
        explicit Tpm(Transport transport);

        Tpm(const Tpm &) = delete;
        Tpm &operator=(const Tpm &) = delete;

        // TPM2_ReadPublic. The public area is returned as received; the
        // Name is checked against ComputeName of it, so the two can't
        // disagree.
        ReadPublicResult ReadPublic(uint32_t handle);
        // TPM2_GetCapability: every persistent handle (0x81xxxxxx).
        std::vector<uint32_t> PersistentHandles();
        // TPM2_GetCapability: one fixed TPM property, e.g. kPtInputBuffer.
        // Throws TpmError if the TPM doesn't report it.
        uint32_t Property(uint32_t property);

        // TPM2_StartAuthSession: a session salted to `tpm_key`, whose public
        // area the caller has read (and pinned). The session is the caller's
        // to close: see ScopedSession.
        std::unique_ptr<Session> StartSaltedSession(uint32_t tpm_key, const PublicArea &tpm_key_public);

        // TPM2_Create under `parent`, which has an empty authValue, from
        // `public_template`. Nothing is loaded or made persistent.
        CreateResult Create(uint32_t parent, const Bytes &public_template);
        // TPM2_Load under `parent`: blobs exactly as Create returned them.
        // The returned Name is checked against the public blob's.
        LoadResult Load(uint32_t parent, const Bytes &private_blob, const Bytes &public_blob);
        // TPM2_LoadExternal of a public and sensitive area into `hierarchy`.
        LoadResult LoadExternal(const Bytes &sensitive, const Bytes &public_area, uint32_t hierarchy);
        // One-shot TPM2_HMAC of `data` with `key` (Name `key_name`, empty
        // authValue) under `session`, both ways encrypted; the 32-byte result
        // is decrypted straight into `out`. With `continue_session` false the
        // TPM closes the session afterwards.
        void Hmac(Session &session, uint32_t key, const Bytes &key_name, const Bytes &data,
                  SecureBuffer<kSha256Len> &out, bool continue_session);
        // TPM2_FlushContext.
        void FlushContext(uint32_t handle);

    private:
        // Sends `command` and splits the response; a non-zero response code
        // becomes a TpmError.
        Response Execute(const Bytes &command, size_t handle_count, size_t auth_count);
        // Flushes `handle`, ignoring a failure, on a path that is about to
        // throw a more specific error.
        void FlushQuietly(uint32_t handle) noexcept;

        Transport transport_;
    };

    // Flushes a loaded object when it goes out of scope, unless released.
    // A failed flush is ignored: TBS flushes it anyway when the context
    // closes.
    class ScopedTpmObject {
    public:
        ScopedTpmObject(Tpm &tpm, uint32_t handle) : tpm_(tpm), handle_(handle) {}
        ScopedTpmObject(const ScopedTpmObject &) = delete;
        ScopedTpmObject &operator=(const ScopedTpmObject &) = delete;
        ~ScopedTpmObject();

        uint32_t get() const { return handle_; }

    private:
        Tpm &tpm_;
        uint32_t handle_;
    };

    // Owns a Session and flushes it at the end of scope if the TPM still
    // holds it (see Session::open).
    class ScopedSession {
    public:
        ScopedSession(Tpm &tpm, std::unique_ptr<Session> session) : tpm_(tpm), session_(std::move(session)) {}
        ScopedSession(const ScopedSession &) = delete;
        ScopedSession &operator=(const ScopedSession &) = delete;
        ~ScopedSession();

        Session &operator*() const { return *session_; }
        Session *operator->() const { return session_.get(); }

    private:
        Tpm &tpm_;
        std::unique_ptr<Session> session_;
    };
} // namespace hkdfguard::tpm2
