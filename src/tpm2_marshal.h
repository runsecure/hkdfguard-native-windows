#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint32_t
#include <utility> // std::pair (ParseCapabilityProperties's result)
#include <vector>

// TPM 2.0 command marshaling and response parsing for the version 2 TPM
// provider (docs/adr/0001-post-quantum-payload-version-2.md, section 3): the
// exact byte layouts of the commands it sends through TBS, and strict
// parsers for what comes back. Nothing here talks to a TPM, holds a handle
// or does any cryptography, so all of it can be tested and fuzzed without
// one.
//
// Only the commands and structures the provider uses are covered: ReadPublic,
// GetCapability, StartAuthSession, Create, Load, LoadExternal, HMAC and
// FlushContext, and the public areas of RSA, ECC and keyed-hash objects.
// Layouts follow the TPM 2.0 Library specification, Part 2 (structures) and
// Part 3 (commands). Every integer is big-endian on the wire.
//
// The parsers treat every response as untrusted: each length is bounded by
// both the bytes actually present and a fixed maximum for its field, and
// each structure must be consumed exactly - a trailing byte is as malformed
// as a missing one. Anything else throws
// HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR), the same code as any other
// failure of the key's provider.
namespace hkdfguard::tpm2 {
    using Bytes = std::vector<uint8_t>;

    // ---- Constants (Part 2) ----

    // TPM_ST: command and response tags.
    constexpr uint16_t kStNoSessions = 0x8001;
    constexpr uint16_t kStSessions = 0x8002;
    constexpr uint16_t kStCreation = 0x8021; // TPMT_TK_CREATION's tag

    // TPM_CC: command codes.
    constexpr uint32_t kCcCreate = 0x00000153;
    constexpr uint32_t kCcHmac = 0x00000155;
    constexpr uint32_t kCcLoad = 0x00000157;
    constexpr uint32_t kCcFlushContext = 0x00000165;
    constexpr uint32_t kCcLoadExternal = 0x00000167;
    constexpr uint32_t kCcReadPublic = 0x00000173;
    constexpr uint32_t kCcStartAuthSession = 0x00000176;
    constexpr uint32_t kCcGetCapability = 0x0000017A;

    // TPM_RH / TPM_RS: permanent handles.
    constexpr uint32_t kRhNull = 0x40000007;
    constexpr uint32_t kRsPassword = 0x40000009;

    // TPM_ALG_ID.
    constexpr uint16_t kAlgRsa = 0x0001;
    constexpr uint16_t kAlgHmac = 0x0005;
    constexpr uint16_t kAlgAes = 0x0006;
    constexpr uint16_t kAlgKeyedHash = 0x0008;
    constexpr uint16_t kAlgXor = 0x000A;
    constexpr uint16_t kAlgSha256 = 0x000B;
    constexpr uint16_t kAlgNull = 0x0010;
    constexpr uint16_t kAlgRsaes = 0x0015;
    constexpr uint16_t kAlgEcdaa = 0x001A;
    constexpr uint16_t kAlgEcc = 0x0023;
    constexpr uint16_t kAlgCfb = 0x0043;

    // TPM_SE: session types.
    constexpr uint8_t kSeHmac = 0x00;

    // TPM_CAP and TPM_PT.
    constexpr uint32_t kCapHandles = 0x00000001;
    constexpr uint32_t kCapTpmProperties = 0x00000006;
    constexpr uint32_t kPtInputBuffer = 0x0000010D;

    // TPMA_OBJECT bits.
    constexpr uint32_t kObjFixedTpm = 1u << 1;
    constexpr uint32_t kObjFixedParent = 1u << 4;
    constexpr uint32_t kObjSensitiveDataOrigin = 1u << 5;
    constexpr uint32_t kObjUserWithAuth = 1u << 6;
    constexpr uint32_t kObjNoDa = 1u << 10;
    constexpr uint32_t kObjRestricted = 1u << 16;
    constexpr uint32_t kObjDecrypt = 1u << 17;
    constexpr uint32_t kObjSign = 1u << 18;

    // TPMA_SESSION bits.
    constexpr uint8_t kSessionContinue = 0x01;
    constexpr uint8_t kSessionDecrypt = 0x20;
    constexpr uint8_t kSessionEncrypt = 0x40;

    // ---- Size limits ----
    //
    // Upper bounds on each variable-length field the parsers accept. They are
    // the largest sizes the structures can legitimately have for the
    // algorithms this provider handles (SHA-512 at most for digests, RSA-4096
    // and P-521 at most for keys), so a genuine TPM never exceeds them; a
    // response that does is malformed.
    constexpr size_t kMaxDigest = 64;                   // TPM2B_DIGEST, nonces, HMACs
    constexpr size_t kMaxName = 2 + kMaxDigest;         // TPM2B_NAME: nameAlg || digest
    constexpr size_t kMaxRsaModulus = 512;              // RSA-4096
    constexpr size_t kMaxEccCoordinate = 66;            // P-521
    constexpr size_t kMaxBuffer = 1024;                 // TPM2B_MAX_BUFFER (data to TPM2_HMAC)
    constexpr size_t kMaxStructure = 1024;              // public areas, private blobs, creation data
    constexpr size_t kMaxResponse = 4096;               // the TBS result buffer
    constexpr size_t kMaxCapabilityCount = 128;         // entries in one GetCapability response
    constexpr size_t kResponseHeaderLen = 10;           // tag, size, responseCode

    // ---- Encoding ----

    // Appends big-endian integers and TPM2B (u16 size || bytes) fields to a
    // byte vector. A TPM2B longer than 0xFFFF bytes can't be encoded and is
    // HKDFGUARD_ERR_INTERNAL_ERROR: every caller passes bounded data.
    class Writer {
    public:
        void U8(uint8_t v);
        void U16(uint16_t v);
        void U32(uint32_t v);
        void Raw(const uint8_t *p, size_t n);
        void Raw(const Bytes &b) { Raw(b.data(), b.size()); }
        void Tpm2b(const uint8_t *p, size_t n);
        void Tpm2b(const Bytes &b) { Tpm2b(b.data(), b.size()); }

        const Bytes &bytes() const { return out_; }
        Bytes take() { return std::move(out_); }

    private:
        Bytes out_;
    };

    // One entry of a command's authorization area (TPMS_AUTH_COMMAND).
    struct AuthCommand {
        uint32_t session_handle = kRsPassword;
        Bytes nonce;              // empty for a password session
        uint8_t attributes = kSessionContinue;
        Bytes hmac;               // the password itself for a password session
    };

    // A password session with an empty password: how the provider
    // authorizes objects with an empty authValue (the storage root key, and
    // its own keys) when no parameter encryption is needed.
    AuthCommand PasswordSession();

    // A whole command: header (tag, size, code), handles, then - only when
    // `auths` is non-empty, which also makes the tag TPM_ST_SESSIONS - the
    // authorization area's size and entries, then the parameters.
    Bytes BuildCommand(
        uint32_t command_code,
        const std::vector<uint32_t> &handles,
        const std::vector<AuthCommand> &auths,
        const Bytes &parameters);

    // Commands with no authorization: complete command bytes.
    Bytes ReadPublicCommand(uint32_t object_handle);
    Bytes GetCapabilityCommand(uint32_t capability, uint32_t property, uint32_t count);
    Bytes FlushContextCommand(uint32_t handle);
    // An HMAC session (TPM_SE_HMAC), salted to `tpm_key` with
    // `encrypted_salt` (empty for unsalted), unbound when `bind` is
    // TPM_RH_NULL, with AES-`sym_key_bits`-CFB parameter encryption and
    // `auth_hash` as its hash.
    Bytes StartAuthSessionCommand(
        uint32_t tpm_key,
        uint32_t bind,
        const Bytes &nonce_caller,
        const Bytes &encrypted_salt,
        uint16_t sym_key_bits,
        uint16_t auth_hash);
    // Loads an object with its sensitive part into `hierarchy` (the NULL
    // hierarchy for the known-answer test). `sensitive` is a marshaled
    // TPMT_SENSITIVE and `public_area` a TPMT_PUBLIC; both get their TPM2B
    // size here.
    Bytes LoadExternalCommand(const Bytes &sensitive, const Bytes &public_area, uint32_t hierarchy);

    // Parameter areas for commands sent with authorization, kept separate
    // from BuildCommand so the session code can hash (and encrypt the first
    // parameter of) exactly what is sent.
    //
    // TPM2_Create: an empty TPM2B_SENSITIVE_CREATE (no authValue, no data -
    // the TPM generates the key), `public_area` as the template, no
    // outsideInfo and no PCR selection.
    Bytes CreateParameters(const Bytes &public_area);
    // TPM2_Load: `private_blob` and `public_blob` exactly as TPM2_Create
    // returned them, each including its TPM2B size.
    Bytes LoadParameters(const Bytes &private_blob, const Bytes &public_blob);
    // TPM2_HMAC: `data` (at most kMaxBuffer bytes) and the hash algorithm.
    Bytes HmacParameters(const Bytes &data, uint16_t hash_alg);

    // Object templates.
    //
    // TPMT_PUBLIC of a keyed-hash object with `hash_alg` as both its nameAlg
    // and its HMAC scheme's hash, an empty authPolicy and `unique` as its
    // unique field.
    Bytes KeyedHashPublicArea(uint32_t attributes, uint16_t hash_alg, const Bytes &unique);
    // TPMT_SENSITIVE of a keyed-hash object: empty authValue, `seed` as its
    // seedValue and `key` as its sensitive data. Only for the known-answer
    // test's fixed, public key; never for a real KEK, which the TPM
    // generates and never reveals.
    Bytes KeyedHashSensitive(const Bytes &seed, const Bytes &key);

    // ---- Parsing ----

    // Reads big-endian fields from a byte range, throwing
    // HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR) on any read past its end
    // or over a field's maximum.
    class Reader {
    public:
        Reader(const uint8_t *p, size_t n) : p_(p), n_(n) {}
        explicit Reader(const Bytes &b) : Reader(b.data(), b.size()) {}

        uint8_t U8();
        uint16_t U16();
        uint32_t U32();
        Bytes Raw(size_t n);
        // A TPM2B: a u16 size of at most `max`, then that many bytes.
        Bytes Tpm2b(size_t max);
        // The same TPM2B returned with its size prefix, as a blob to hand
        // back to the TPM unchanged (TPM2_Create's outputs, for TPM2_Load).
        Bytes Tpm2bWithSize(size_t max);

        size_t remaining() const { return n_ - pos_; }
        size_t position() const { return pos_; }
        // Throws unless every byte has been read.
        void ExpectEnd() const;

    private:
        const uint8_t *Take(size_t n);

        const uint8_t *p_;
        size_t n_;
        size_t pos_ = 0;
    };

    // One entry of a response's authorization area (TPMS_AUTH_RESPONSE).
    struct AuthResponse {
        Bytes nonce;
        uint8_t attributes = 0;
        Bytes hmac;
    };

    // A response split into its parts. For a TPM_ST_SESSIONS response,
    // `parameters` is exactly the parameterSize bytes - what the session
    // code hashes for rpHash - and `auths` the authorization entries after
    // them.
    struct Response {
        uint16_t tag = 0;
        uint32_t response_code = 0;
        std::vector<uint32_t> handles;
        Bytes parameters;
        std::vector<AuthResponse> auths;
    };

    // Splits a complete response. The header's size must equal `n` (between
    // kResponseHeaderLen and kMaxResponse). A non-zero response code ends the
    // parse: an error response must be the bare 10-byte header with
    // TPM_ST_NO_SESSIONS, and `response_code` is the caller's to act on.
    // Otherwise `handle_count` handles follow - the number the command
    // returns - then for TPM_ST_SESSIONS the parameterSize, parameters and
    // exactly `auth_count` authorization entries (one per session the
    // command used), and for TPM_ST_NO_SESSIONS the rest as parameters.
    Response ParseResponse(const uint8_t *p, size_t n, size_t handle_count, size_t auth_count);
    inline Response ParseResponse(const Bytes &b, size_t handle_count, size_t auth_count) {
        return ParseResponse(b.data(), b.size(), handle_count, auth_count);
    }

    // A parsed TPMT_PUBLIC, for the object types the provider meets.
    struct PublicArea {
        uint16_t type = 0;
        uint16_t name_alg = 0;
        uint32_t attributes = 0;
        Bytes auth_policy;
        // TPMT_SYM_DEF_OBJECT, for RSA and ECC (the storage root key's
        // inner wrapping): kAlgNull, or an algorithm with key bits and mode.
        uint16_t symmetric_alg = kAlgNull;
        uint16_t symmetric_key_bits = 0;
        uint16_t symmetric_mode = 0;
        // The scheme (RSA, ECC or keyed-hash) and its hash, kAlgNull if none.
        uint16_t scheme = kAlgNull;
        uint16_t scheme_hash = kAlgNull;
        // RSA.
        uint16_t rsa_key_bits = 0;
        uint32_t rsa_exponent = 0; // 0 means the default, 65537
        Bytes rsa_modulus;
        // ECC.
        uint16_t ecc_curve = 0;
        uint16_t ecc_kdf = kAlgNull;
        Bytes ecc_x;
        Bytes ecc_y;
        // Keyed-hash: its unique field (a digest).
        Bytes keyed_hash_unique;
    };

    // Parses one TPMT_PUBLIC that fills `area` exactly. An object type other
    // than RSA, ECC or keyed-hash is malformed here.
    PublicArea ParsePublicArea(const Bytes &area);

    // TPM2_ReadPublic: the public area as received (kept raw, since its
    // digest is the Name), its Name and its qualified Name.
    struct ReadPublicResult {
        Bytes public_area;
        Bytes name;
        Bytes qualified_name;
    };
    ReadPublicResult ParseReadPublic(const Response &response);

    // TPM2_GetCapability(TPM_CAP_HANDLES): the handles, and whether the TPM
    // has more beyond them.
    std::vector<uint32_t> ParseCapabilityHandles(const Response &response, bool &more_data);
    // TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES): (property, value) pairs.
    std::vector<std::pair<uint32_t, uint32_t>> ParseCapabilityProperties(const Response &response, bool &more_data);

    // TPM2_StartAuthSession: the session handle and nonceTPM.
    struct StartAuthSessionResult {
        uint32_t session_handle = 0;
        Bytes nonce_tpm;
    };
    StartAuthSessionResult ParseStartAuthSession(const Response &response);

    // TPM2_Create: the new object's private and public blobs, each with its
    // TPM2B size, ready for TPM2_Load and for the key file. The creation
    // data, hash and ticket that follow are checked for shape and dropped.
    struct CreateResult {
        Bytes private_blob;
        Bytes public_blob;
    };
    CreateResult ParseCreate(const Response &response);

    // TPM2_Load and TPM2_LoadExternal: the loaded object's handle and Name.
    struct LoadResult {
        uint32_t object_handle = 0;
        Bytes name;
    };
    LoadResult ParseLoad(const Response &response);

    // TPM2_HMAC: the outHMAC digest, exactly as it arrived - still encrypted
    // if the session encrypted the response.
    Bytes ParseHmac(const Response &response);
} // namespace hkdfguard::tpm2
