#include "tpm2_marshal.h"
#include "errors.h"

namespace hkdfguard::tpm2 {
    namespace {
        [[noreturn]] void Malformed(const char *what) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, what);
        }

        // Parsers of a command's result are only called on a success
        // response; anything else is a bug in the caller, not in the TPM.
        void RequireSuccess(const Response &response) {
            if (response.response_code != 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "parsing the result of a failed TPM command");
            }
        }

        void RequireHandles(const Response &response, size_t count) {
            if (response.handles.size() != count) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM response parsed with the wrong handle count");
            }
        }

        // TPMT_SYM_DEF_OBJECT: an algorithm, then - unless it is
        // TPM_ALG_NULL - its key bits and mode.
        void ReadSymmetric(Reader &r, PublicArea &area) {
            area.symmetric_alg = r.U16();
            if (area.symmetric_alg != kAlgNull) {
                area.symmetric_key_bits = r.U16();
                area.symmetric_mode = r.U16();
            }
        }

        // The (property, value) or handle count of a GetCapability response,
        // after moreData and the capability it echoes.
        uint32_t ReadCapabilityHeader(Reader &r, uint32_t capability, bool &more_data) {
            const uint8_t more = r.U8();
            if (more > 1) {
                Malformed("TPM capability moreData is not a boolean");
            }
            more_data = more == 1;
            if (r.U32() != capability) {
                Malformed("TPM returned a different capability than asked for");
            }
            const uint32_t count = r.U32();
            if (count > kMaxCapabilityCount) {
                Malformed("TPM capability list too long");
            }
            return count;
        }
    } // namespace

    // ---- Writer ----

    void Writer::U8(uint8_t v) {
        out_.push_back(v);
    }

    void Writer::U16(uint16_t v) {
        U8(static_cast<uint8_t>(v >> 8));
        U8(static_cast<uint8_t>(v));
    }

    void Writer::U32(uint32_t v) {
        U16(static_cast<uint16_t>(v >> 16));
        U16(static_cast<uint16_t>(v));
    }

    void Writer::Raw(const uint8_t *p, size_t n) {
        if (n != 0) {
            out_.insert(out_.end(), p, p + n);
        }
    }

    void Writer::Tpm2b(const uint8_t *p, size_t n) {
        if (n > 0xFFFF) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM2B field too long to encode");
        }
        U16(static_cast<uint16_t>(n));
        Raw(p, n);
    }

    // ---- Commands ----

    AuthCommand PasswordSession() {
        return AuthCommand{};
    }

    Bytes BuildCommand(
        uint32_t command_code,
        const std::vector<uint32_t> &handles,
        const std::vector<AuthCommand> &auths,
        const Bytes &parameters) {
        Writer w;
        w.U16(auths.empty() ? kStNoSessions : kStSessions);
        w.U32(0); // commandSize, patched below
        w.U32(command_code);
        for (uint32_t h : handles) {
            w.U32(h);
        }
        if (!auths.empty()) {
            Writer area;
            for (const AuthCommand &a : auths) {
                area.U32(a.session_handle);
                area.Tpm2b(a.nonce);
                area.U8(a.attributes);
                area.Tpm2b(a.hmac);
            }
            w.U32(static_cast<uint32_t>(area.bytes().size()));
            w.Raw(area.bytes());
        }
        w.Raw(parameters);

        Bytes out = w.take();
        if (out.size() > kMaxResponse) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM command too long");
        }
        const uint32_t size = static_cast<uint32_t>(out.size());
        out[2] = static_cast<uint8_t>(size >> 24);
        out[3] = static_cast<uint8_t>(size >> 16);
        out[4] = static_cast<uint8_t>(size >> 8);
        out[5] = static_cast<uint8_t>(size);
        return out;
    }

    Bytes ReadPublicCommand(uint32_t object_handle) {
        return BuildCommand(kCcReadPublic, {object_handle}, {}, {});
    }

    Bytes GetCapabilityCommand(uint32_t capability, uint32_t property, uint32_t count) {
        Writer p;
        p.U32(capability);
        p.U32(property);
        p.U32(count);
        return BuildCommand(kCcGetCapability, {}, {}, p.bytes());
    }

    Bytes FlushContextCommand(uint32_t handle) {
        // flushHandle is a parameter, not a handle-area entry (Part 3).
        Writer p;
        p.U32(handle);
        return BuildCommand(kCcFlushContext, {}, {}, p.bytes());
    }

    Bytes StartAuthSessionCommand(
        uint32_t tpm_key,
        uint32_t bind,
        const Bytes &nonce_caller,
        const Bytes &encrypted_salt,
        uint16_t sym_key_bits,
        uint16_t auth_hash) {
        Writer p;
        p.Tpm2b(nonce_caller);
        p.Tpm2b(encrypted_salt);
        p.U8(kSeHmac);
        p.U16(kAlgAes); // TPMT_SYM_DEF: algorithm, key bits, mode
        p.U16(sym_key_bits);
        p.U16(kAlgCfb);
        p.U16(auth_hash);
        return BuildCommand(kCcStartAuthSession, {tpm_key, bind}, {}, p.bytes());
    }

    Bytes LoadExternalCommand(const Bytes &sensitive, const Bytes &public_area, uint32_t hierarchy) {
        Writer p;
        p.Tpm2b(sensitive);
        p.Tpm2b(public_area);
        p.U32(hierarchy);
        return BuildCommand(kCcLoadExternal, {}, {}, p.bytes());
    }

    Bytes CreateParameters(const Bytes &public_area) {
        Writer sensitive; // TPMS_SENSITIVE_CREATE
        sensitive.U16(0); // userAuth: empty
        sensitive.U16(0); // data: empty, so the TPM generates the key
        Writer p;
        p.Tpm2b(sensitive.bytes());
        p.Tpm2b(public_area);
        p.U16(0); // outsideInfo: empty
        p.U32(0); // creationPCR: TPML_PCR_SELECTION with no entries
        return p.take();
    }

    Bytes LoadParameters(const Bytes &private_blob, const Bytes &public_blob) {
        // Each blob is a whole TPM2B, size included, exactly as ParseCreate
        // returned it; one whose size prefix disagrees with its length is a
        // caller bug (a corrupt key file is caught when it is read).
        for (const Bytes *b : {&private_blob, &public_blob}) {
            if (b->size() < 2 || static_cast<size_t>(((*b)[0] << 8) | (*b)[1]) != b->size() - 2) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM key blob is not one TPM2B");
            }
        }
        Writer p;
        p.Raw(private_blob);
        p.Raw(public_blob);
        return p.take();
    }

    Bytes HmacParameters(const Bytes &data, uint16_t hash_alg) {
        if (data.size() > kMaxBuffer) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM2_HMAC input too long");
        }
        Writer p;
        p.Tpm2b(data);
        p.U16(hash_alg);
        return p.take();
    }

    Bytes KeyedHashPublicArea(uint32_t attributes, uint16_t hash_alg, const Bytes &unique) {
        Writer w;
        w.U16(kAlgKeyedHash);
        w.U16(hash_alg);   // nameAlg
        w.U32(attributes);
        w.U16(0);          // authPolicy: empty
        w.U16(kAlgHmac);   // TPMT_KEYEDHASH_SCHEME: HMAC ...
        w.U16(hash_alg);   // ... with this hash
        w.Tpm2b(unique);
        return w.take();
    }

    Bytes KeyedHashSensitive(const Bytes &seed, const Bytes &key) {
        Writer w;
        w.U16(kAlgKeyedHash);
        w.U16(0); // authValue: empty
        w.Tpm2b(seed);
        w.Tpm2b(key);
        return w.take();
    }

    // ---- Reader ----

    const uint8_t *Reader::Take(size_t n) {
        if (n > n_ - pos_) {
            Malformed("TPM response truncated");
        }
        const uint8_t *at = p_ + pos_;
        pos_ += n;
        return at;
    }

    uint8_t Reader::U8() {
        return *Take(1);
    }

    uint16_t Reader::U16() {
        const uint8_t *b = Take(2);
        return static_cast<uint16_t>((b[0] << 8) | b[1]);
    }

    uint32_t Reader::U32() {
        const uint8_t *b = Take(4);
        return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
               (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
    }

    Bytes Reader::Raw(size_t n) {
        const uint8_t *b = Take(n);
        return Bytes(b, b + n);
    }

    Bytes Reader::Tpm2b(size_t max) {
        const uint16_t size = U16();
        if (size > max) {
            Malformed("TPM2B field larger than its maximum");
        }
        return Raw(size);
    }

    Bytes Reader::Tpm2bWithSize(size_t max) {
        const size_t start = pos_;
        Tpm2b(max);
        return Bytes(p_ + start, p_ + pos_);
    }

    void Reader::ExpectEnd() const {
        if (pos_ != n_) {
            Malformed("TPM response has trailing bytes");
        }
    }

    // ---- Responses ----

    Response ParseResponse(const uint8_t *p, size_t n, size_t handle_count, size_t auth_count) {
        if (p == nullptr || n < kResponseHeaderLen || n > kMaxResponse) {
            Malformed("TPM response has an impossible length");
        }
        Reader r(p, n);
        Response response;
        response.tag = r.U16();
        const uint32_t size = r.U32();
        response.response_code = r.U32();
        if (size != n) {
            Malformed("TPM response size field disagrees with its length");
        }
        if (response.tag != kStNoSessions && response.tag != kStSessions) {
            Malformed("TPM response has an unknown tag");
        }

        // An error response is the header alone (Part 1, 18.4).
        if (response.response_code != 0) {
            if (response.tag != kStNoSessions || n != kResponseHeaderLen) {
                Malformed("TPM error response is not a bare header");
            }
            return response;
        }

        // A command sent with sessions answers with them, and one sent
        // without, without.
        if ((response.tag == kStSessions) != (auth_count != 0)) {
            Malformed("TPM response tag disagrees with the command's sessions");
        }
        for (size_t i = 0; i < handle_count; ++i) {
            response.handles.push_back(r.U32());
        }
        if (response.tag == kStNoSessions) {
            response.parameters = r.Raw(r.remaining());
            return response;
        }

        const uint32_t parameter_size = r.U32();
        if (parameter_size > r.remaining()) {
            Malformed("TPM response parameterSize exceeds the response");
        }
        response.parameters = r.Raw(parameter_size);
        for (size_t i = 0; i < auth_count; ++i) {
            AuthResponse a;
            a.nonce = r.Tpm2b(kMaxDigest);
            a.attributes = r.U8();
            a.hmac = r.Tpm2b(kMaxDigest);
            response.auths.push_back(std::move(a));
        }
        r.ExpectEnd();
        return response;
    }

    PublicArea ParsePublicArea(const Bytes &bytes) {
        if (bytes.size() > kMaxStructure) {
            Malformed("TPM public area too long");
        }
        Reader r(bytes);
        PublicArea area;
        area.type = r.U16();
        area.name_alg = r.U16();
        area.attributes = r.U32();
        area.auth_policy = r.Tpm2b(kMaxDigest);
        switch (area.type) {
            case kAlgRsa:
                ReadSymmetric(r, area);
                // TPMT_RSA_SCHEME: every scheme but RSAES (and NULL) has a hash.
                area.scheme = r.U16();
                if (area.scheme != kAlgNull && area.scheme != kAlgRsaes) {
                    area.scheme_hash = r.U16();
                }
                area.rsa_key_bits = r.U16();
                area.rsa_exponent = r.U32();
                area.rsa_modulus = r.Tpm2b(kMaxRsaModulus);
                break;
            case kAlgEcc:
                ReadSymmetric(r, area);
                // TPMT_ECC_SCHEME: a hash, plus a count for ECDAA.
                area.scheme = r.U16();
                if (area.scheme != kAlgNull) {
                    area.scheme_hash = r.U16();
                    if (area.scheme == kAlgEcdaa) {
                        r.U16();
                    }
                }
                area.ecc_curve = r.U16();
                // TPMT_KDF_SCHEME: a hash unless NULL.
                area.ecc_kdf = r.U16();
                if (area.ecc_kdf != kAlgNull) {
                    r.U16();
                }
                area.ecc_x = r.Tpm2b(kMaxEccCoordinate);
                area.ecc_y = r.Tpm2b(kMaxEccCoordinate);
                break;
            case kAlgKeyedHash:
                // TPMT_KEYEDHASH_SCHEME: HMAC has a hash, XOR a hash and a
                // KDF, NULL nothing.
                area.scheme = r.U16();
                if (area.scheme == kAlgHmac) {
                    area.scheme_hash = r.U16();
                } else if (area.scheme == kAlgXor) {
                    area.scheme_hash = r.U16();
                    r.U16();
                } else if (area.scheme != kAlgNull) {
                    Malformed("TPM keyed-hash object has an unknown scheme");
                }
                area.keyed_hash_unique = r.Tpm2b(kMaxDigest);
                break;
            default:
                Malformed("TPM public area of an unsupported object type");
        }
        r.ExpectEnd();
        return area;
    }

    ReadPublicResult ParseReadPublic(const Response &response) {
        RequireSuccess(response);
        RequireHandles(response, 0);
        Reader r(response.parameters);
        ReadPublicResult result;
        result.public_area = r.Tpm2b(kMaxStructure);
        result.name = r.Tpm2b(kMaxName);
        result.qualified_name = r.Tpm2b(kMaxName);
        r.ExpectEnd();
        ParsePublicArea(result.public_area); // must itself be well formed
        return result;
    }

    std::vector<uint32_t> ParseCapabilityHandles(const Response &response, bool &more_data) {
        RequireSuccess(response);
        RequireHandles(response, 0);
        Reader r(response.parameters);
        const uint32_t count = ReadCapabilityHeader(r, kCapHandles, more_data);
        std::vector<uint32_t> handles;
        for (uint32_t i = 0; i < count; ++i) {
            handles.push_back(r.U32());
        }
        r.ExpectEnd();
        return handles;
    }

    std::vector<std::pair<uint32_t, uint32_t>> ParseCapabilityProperties(const Response &response, bool &more_data) {
        RequireSuccess(response);
        RequireHandles(response, 0);
        Reader r(response.parameters);
        const uint32_t count = ReadCapabilityHeader(r, kCapTpmProperties, more_data);
        std::vector<std::pair<uint32_t, uint32_t>> properties;
        for (uint32_t i = 0; i < count; ++i) {
            const uint32_t property = r.U32();
            properties.emplace_back(property, r.U32());
        }
        r.ExpectEnd();
        return properties;
    }

    StartAuthSessionResult ParseStartAuthSession(const Response &response) {
        RequireSuccess(response);
        RequireHandles(response, 1);
        Reader r(response.parameters);
        StartAuthSessionResult result;
        result.session_handle = response.handles[0];
        result.nonce_tpm = r.Tpm2b(kMaxDigest);
        r.ExpectEnd();
        // nonceTPM is the size of nonceCaller, which is at least 16 bytes
        // (Part 3, TPM2_StartAuthSession).
        if (result.nonce_tpm.size() < 16) {
            Malformed("TPM session nonce too short");
        }
        return result;
    }

    CreateResult ParseCreate(const Response &response) {
        RequireSuccess(response);
        RequireHandles(response, 0);
        Reader r(response.parameters);
        CreateResult result;
        result.private_blob = r.Tpm2bWithSize(kMaxStructure);
        result.public_blob = r.Tpm2bWithSize(kMaxStructure);
        r.Tpm2b(kMaxStructure); // creationData
        r.Tpm2b(kMaxDigest);    // creationHash
        if (r.U16() != kStCreation) {   // TPMT_TK_CREATION: tag ...
            Malformed("TPM creation ticket has the wrong tag");
        }
        r.U32();                // ... hierarchy ...
        r.Tpm2b(kMaxDigest);    // ... digest
        r.ExpectEnd();
        ParsePublicArea(Bytes(result.public_blob.begin() + 2, result.public_blob.end()));
        return result;
    }

    LoadResult ParseLoad(const Response &response) {
        RequireSuccess(response);
        RequireHandles(response, 1);
        Reader r(response.parameters);
        LoadResult result;
        result.object_handle = response.handles[0];
        result.name = r.Tpm2b(kMaxName);
        r.ExpectEnd();
        return result;
    }

    Bytes ParseHmac(const Response &response) {
        RequireSuccess(response);
        RequireHandles(response, 0);
        Reader r(response.parameters);
        Bytes out = r.Tpm2b(kMaxDigest);
        r.ExpectEnd();
        return out;
    }
} // namespace hkdfguard::tpm2
