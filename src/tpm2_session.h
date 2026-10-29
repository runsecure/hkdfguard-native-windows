#pragma once

#include "secure_buffer.h" // SecureBuffer<N>
#include "tpm2_marshal.h"  // Bytes, PublicArea, Response, AuthCommand
#include <cstddef>
#include <cstdint>
#include <vector>

// The cryptography of a TPM 2.0 salted HMAC session with parameter
// encryption, as the version 2 TPM provider uses it
// (docs/adr/0001-post-quantum-payload-version-2.md, section 3): the key
// derivation functions, AES-128-CFB, object Names, the session salt, and a
// Session that authorizes commands, verifies responses and encrypts and
// decrypts the first parameter each way. Like tpm2_marshal.h, nothing here
// talks to a TPM, so all of it is tested without one; tpm2_device.h sends
// what it builds.
//
// Only what the provider needs is supported: SHA-256 as every hash (the
// session's, KDFa's and the storage root key's nameAlg), AES-128-CFB as the
// session's parameter cipher, an unbound session, and entities with an
// empty authValue. References are to the TPM 2.0 Library specification,
// Part 1 (architecture).
//
// Secrets - the salt, the session key, the CFB keys and every decrypted
// response parameter - live in SecureBuffers, wiped when they go out of
// scope. Failures of the cryptography itself are
// HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR); a response that fails its
// HMAC, or anything else unexpected from the TPM, is
// HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR).
namespace hkdfguard::tpm2 {
    constexpr size_t kSha256Len = 32;
    constexpr size_t kNonceLen = 32;   // nonceCaller, and so nonceTPM
    constexpr size_t kAesBlockLen = 16;
    constexpr size_t kSessionKeyBits = 128; // AES-128-CFB parameter encryption

    // SHA-256 and HMAC-SHA-256 (BCrypt).
    void Sha256(const uint8_t *data, size_t len, uint8_t out[kSha256Len]);
    void HmacSha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[kSha256Len]);

    // KDFa (Part 1, 11.4.10.2) with HMAC-SHA-256: `out_len` bytes of
    //   HMAC(key, [i]_32 || label || 0x00 || context_u || context_v || [out_len * 8]_32)
    // for i = 1, 2, ..., truncated. `label` is a C string; its terminating
    // NUL is the 0x00.
    void KdfaSha256(
        const uint8_t *key, size_t key_len,
        const char *label,
        const Bytes &context_u, const Bytes &context_v,
        uint8_t *out, size_t out_len);

    // KDFe (Part 1, 11.4.10.3) with SHA-256: `out_len` bytes of
    //   SHA-256([i]_32 || z || label || 0x00 || party_u || party_v)
    // for i = 1, 2, ..., truncated. Used only to derive the salt from an
    // ECDH shared secret, for an ECC storage root key.
    void KdfeSha256(
        const uint8_t *z, size_t z_len,
        const char *label,
        const Bytes &party_u, const Bytes &party_v,
        uint8_t *out, size_t out_len);

    // AES-128 in CFB mode with full-block (128-bit) feedback, as the TPM
    // uses for parameter encryption (Part 1, 11.4.6.3): `len` bytes from
    // `in` to `out` (which may be the same buffer). A partial final block
    // needs no padding: only as much keystream as the data is used.
    void Aes128Cfb(
        const uint8_t key[16], const uint8_t iv[kAesBlockLen],
        const uint8_t *in, uint8_t *out, size_t len,
        bool encrypt);

    // An object's Name: its nameAlg followed by the nameAlg digest of its
    // marshaled public area (Part 1, 16). Throws
    // HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR) unless the nameAlg is
    // SHA-256.
    Bytes ComputeName(const Bytes &public_area);

    // A new random salt for a session salted to `tpm_key` (the storage root
    // key), and that salt encrypted to it as TPM2_StartAuthSession takes it
    // (Part 1, annex B.10.3 for RSA, C.6.1 for ECC):
    //   RSA: RSA-OAEP(SHA-256, label "SECRET\0") of the salt;
    //   ECC (P-256): an ephemeral key's point; the salt is
    //        KDFe(Z, "SECRET", ephemeral x, tpm_key x).
    // `tpm_key` must have SHA-256 as its nameAlg (the salt is that size).
    // Any other key is HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR).
    void MakeSessionSalt(const PublicArea &tpm_key, SecureBuffer<kSha256Len> &salt, Bytes &encrypted_salt);

    // One salted, unbound HMAC session with SHA-256 and AES-128-CFB, from
    // TPM2_StartAuthSession's result. It authorizes one entity at a time
    // with an empty authValue, encrypts the first command parameter and has
    // the TPM encrypt the first response parameter, and checks every
    // response's HMAC before anything in it is used.
    //
    // Use: Authorize builds a command; the caller sends it; Verify checks the
    // response and rolls the nonces; DecryptResponseParameter then recovers
    // the first response parameter. Not copyable: the session key exists
    // once.
    class Session {
    public:
        // sessionKey = KDFa(salt, "ATH", nonceTPM, nonceCaller, 256) - the
        // unbound form, the bind key's authValue being empty (Part 1, 19.6.8).
        // `nonce_caller` is the one sent with TPM2_StartAuthSession.
        Session(uint32_t handle, const SecureBuffer<kSha256Len> &salt, const Bytes &nonce_tpm, const Bytes &nonce_caller);

        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;

        uint32_t handle() const { return handle_; }
        // False once a command sent without continueSession has completed:
        // the TPM closed the session itself, so it needs no
        // TPM2_FlushContext. While true, whoever holds the session flushes it.
        bool open() const { return open_; }
        // False after a failed command or a response that didn't verify:
        // the session may still exist in the TPM, but this object refuses to
        // authorize anything more with it.
        bool usable() const { return usable_; }

        // The complete command: `command_code` with `handles`, authorized by
        // this session for handles[0] (whose Name is `entity_name`), with
        // `parameters` - whose first field must be a TPM2B - its data
        // encrypted with a fresh nonceCaller. cpHash covers the parameters as
        // sent, encrypted (Part 1, 18.7). With `continue_session` false the
        // TPM ends the session after this command.
        Bytes Authorize(
            uint32_t command_code,
            const std::vector<uint32_t> &handles,
            const std::vector<Bytes> &handle_names,
            const Bytes &parameters,
            bool continue_session);

        // Checks the response to the command Authorize built last: a
        // success response with exactly one authorization entry, whose HMAC
        // over rpHash = SHA-256(responseCode || commandCode || parameters),
        // the new nonceTPM, the nonceCaller and the attributes verifies.
        // Then rolls nonceTPM forward. A failed check throws
        // HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR). An error response (a
        // non-zero response code, which carries no authorization) doesn't
        // throw - the code is the caller's to report - but, like a failed
        // check, leaves the session unusable.
        void Verify(const Response &response);

        // Marks the session unusable when the response to the last command
        // couldn't even be parsed, so Verify never saw it.
        void Abandon();

        // Decrypts the data of the first response parameter (a TPM2B's
        // bytes, as the TPM encrypted them) of the response Verify accepted
        // last, into `out` (`len` bytes). The key and IV are
        // KDFa(sessionKey, "CFB", nonceTPM, nonceCaller, 256): the TPM's new
        // nonce first, for a response.
        void DecryptResponseParameter(const Bytes &encrypted, uint8_t *out, size_t len) const;

    private:
        uint32_t handle_;
        bool open_ = true;
        bool usable_ = true;
        bool awaiting_response_ = false;
        bool verified_ = false;
        uint32_t command_code_ = 0;
        uint8_t attributes_ = 0;
        SecureBuffer<kSha256Len> session_key_;
        Bytes nonce_tpm_;
        Bytes nonce_caller_;
    };
} // namespace hkdfguard::tpm2
