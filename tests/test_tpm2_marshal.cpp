// Hand-rolled test program (no test framework), like test_roundtrip: checks
// src/tpm2_marshal.cpp's TPM 2.0 command encodings and response parsers.
// Needs no TPM and no elevation - nothing here talks to a TPM. Exits 0 if
// every check passed, 1 otherwise.
//
//   1. Golden commands: each builder's bytes equal the encoding the TBS probe
//      sent to a real TPM, which accepted it (see kGoldenCommands).
//   2. Encoding limits: oversized inputs are refused, not truncated.
//   3. Responses: well-formed responses of every command parse to the right
//      fields; each class of malformation is rejected.
//   4. Mutation sweep: every truncation, every extension by one byte, every
//      single-bit flip and a seeded run of random edits of each well-formed
//      response either parses or fails with HKDFGUARD_ERR_PROVIDER_ERROR -
//      never another error, never a crash or an out-of-bounds read.
#include "tpm2_marshal.h"
#include "errors.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <random>
#include <string>
#include <vector>

using hkdfguard::HkdfGuardError;
using namespace hkdfguard::tpm2;

namespace {

int g_failures = 0;

void Check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("[PASS] %s\n", what.c_str());
    } else {
        std::printf("[FAIL] %s\n", what.c_str());
        ++g_failures;
    }
}

Bytes FromHex(const char* hex) {
    Bytes out;
    for (size_t i = 0; hex[i] != '\0' && hex[i + 1] != '\0'; i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(std::string(hex + i, 2), nullptr, 16)));
    }
    return out;
}

std::string ToHex(const Bytes& b) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (uint8_t c : b) {
        s += digits[c >> 4];
        s += digits[c & 15];
    }
    return s;
}

// The HKDFGUARD_ERR_* code `f` throws, HKDFGUARD_OK if it returns, or a
// sentinel for any other exception.
constexpr int kOtherException = 1;
int CodeOf(const std::function<void()>& f) {
    try {
        f();
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError& e) {
        return e.code();
    } catch (...) {
        return kOtherException;
    }
}

void SetSize(Bytes& response) {
    const uint32_t n = static_cast<uint32_t>(response.size());
    if (response.size() >= 6) {
        response[2] = static_cast<uint8_t>(n >> 24);
        response[3] = static_cast<uint8_t>(n >> 16);
        response[4] = static_cast<uint8_t>(n >> 8);
        response[5] = static_cast<uint8_t>(n);
    }
}

// A success response: header, handles, then for sessions the
// parameterSize, parameters and authorization area.
Bytes SuccessResponse(const std::vector<uint32_t>& handles, const Bytes& parameters, const Bytes& auth_area) {
    Writer w;
    w.U16(auth_area.empty() ? kStNoSessions : kStSessions);
    w.U32(0);
    w.U32(0); // TPM_RC_SUCCESS
    for (uint32_t h : handles) w.U32(h);
    if (!auth_area.empty()) w.U32(static_cast<uint32_t>(parameters.size()));
    w.Raw(parameters);
    w.Raw(auth_area);
    Bytes out = w.take();
    SetSize(out);
    return out;
}

// One TPMS_AUTH_RESPONSE: a 32-byte nonce, attributes, a 32-byte HMAC.
Bytes AuthArea(uint8_t attributes) {
    Writer w;
    w.Tpm2b(Bytes(32, 0x5A));
    w.U8(attributes);
    w.Tpm2b(Bytes(32, 0xA5));
    return w.take();
}

// An RSA-2048 storage-key public area, shaped like Windows' storage root key.
Bytes RsaStoragePublic() {
    Writer w;
    w.U16(kAlgRsa);
    w.U16(kAlgSha256);
    w.U32(0x00030472);
    w.U16(0);                                    // authPolicy
    w.U16(kAlgAes); w.U16(128); w.U16(kAlgCfb);  // symmetric
    w.U16(kAlgNull);                             // scheme
    w.U16(2048);
    w.U32(0);                                    // exponent: default
    Bytes modulus(256);
    for (size_t i = 0; i < modulus.size(); ++i) modulus[i] = static_cast<uint8_t>(i);
    w.Tpm2b(modulus);
    return w.take();
}

// An ECC P-256 storage-key public area.
Bytes EccStoragePublic() {
    Writer w;
    w.U16(kAlgEcc);
    w.U16(kAlgSha256);
    w.U32(0x00030472);
    w.U16(0);
    w.U16(kAlgAes); w.U16(128); w.U16(kAlgCfb);
    w.U16(kAlgNull);   // scheme
    w.U16(0x0003);     // TPM_ECC_NIST_P256
    w.U16(kAlgNull);   // kdf
    w.Tpm2b(Bytes(32, 0x11));
    w.Tpm2b(Bytes(32, 0x22));
    return w.take();
}

Bytes Name(uint8_t fill) {
    Bytes n = {0x00, 0x0B};
    n.insert(n.end(), 32, fill);
    return n;
}

struct ResponseCase {
    std::string name;
    Bytes response;
    size_t handle_count;
    size_t auth_count;
    std::function<void(const Response&)> parse;
};

std::vector<ResponseCase> WellFormedResponses() {
    std::vector<ResponseCase> cases;

    {
        Writer p;
        p.Tpm2b(RsaStoragePublic());
        p.Tpm2b(Name(0x01));
        p.Tpm2b(Name(0x02));
        cases.push_back({"ReadPublic (RSA)", SuccessResponse({}, p.bytes(), {}), 0, 0,
                         [](const Response& r) { ParseReadPublic(r); }});
    }
    {
        Writer p;
        p.Tpm2b(EccStoragePublic());
        p.Tpm2b(Name(0x03));
        p.Tpm2b(Name(0x04));
        cases.push_back({"ReadPublic (ECC)", SuccessResponse({}, p.bytes(), {}), 0, 0,
                         [](const Response& r) { ParseReadPublic(r); }});
    }
    {
        Writer p;
        p.U8(0);
        p.U32(kCapHandles);
        p.U32(3);
        p.U32(0x81000001); p.U32(0x81000002); p.U32(0x81010001);
        cases.push_back({"GetCapability (handles)", SuccessResponse({}, p.bytes(), {}), 0, 0,
                         [](const Response& r) { bool more = false; ParseCapabilityHandles(r, more); }});
    }
    {
        Writer p;
        p.U8(1);
        p.U32(kCapTpmProperties);
        p.U32(1);
        p.U32(kPtInputBuffer); p.U32(1024);
        cases.push_back({"GetCapability (properties)", SuccessResponse({}, p.bytes(), {}), 0, 0,
                         [](const Response& r) { bool more = false; ParseCapabilityProperties(r, more); }});
    }
    {
        Writer p;
        p.Tpm2b(Bytes(32, 0x77));
        cases.push_back({"StartAuthSession", SuccessResponse({0x02000000}, p.bytes(), {}), 1, 0,
                         [](const Response& r) { ParseStartAuthSession(r); }});
    }
    {
        Writer p;
        p.Tpm2b(Bytes(126, 0x61));                                            // outPrivate
        p.Tpm2b(KeyedHashPublicArea(0x00040472, kAlgSha256, Bytes(32, 0x62))); // outPublic
        p.Tpm2b(Bytes(60, 0x63));                                             // creationData
        p.Tpm2b(Bytes(32, 0x64));                                             // creationHash
        p.U16(kStCreation); p.U32(0x40000001); p.Tpm2b(Bytes(32, 0x65));      // creationTicket
        cases.push_back({"Create", SuccessResponse({}, p.bytes(), AuthArea(kSessionContinue)), 0, 1,
                         [](const Response& r) { ParseCreate(r); }});
    }
    {
        Writer p;
        p.Tpm2b(Name(0x05));
        cases.push_back({"Load", SuccessResponse({0x80000001}, p.bytes(), AuthArea(kSessionContinue)), 1, 1,
                         [](const Response& r) { ParseLoad(r); }});
    }
    {
        Writer p;
        p.Tpm2b(Name(0x06));
        cases.push_back({"LoadExternal", SuccessResponse({0x80000002}, p.bytes(), {}), 1, 0,
                         [](const Response& r) { ParseLoad(r); }});
    }
    {
        Writer p;
        p.Tpm2b(Bytes(32, 0x66));
        cases.push_back({"HMAC", SuccessResponse({}, p.bytes(), AuthArea(kSessionEncrypt | kSessionContinue)), 0, 1,
                         [](const Response& r) { ParseHmac(r); }});
    }
    {
        Writer p; // FlushContext: no parameters at all
        cases.push_back({"FlushContext", SuccessResponse({}, p.bytes(), {}), 0, 0, [](const Response& r) {
                             if (!r.parameters.empty()) throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "unexpected parameters");
                         }});
    }
    return cases;
}

// As the provider will use the parsers: split the response, act on a
// non-zero response code as the TPM's error (an acceptable outcome here),
// and parse the command's result only on success.
int ParseCode(const ResponseCase& c, const Bytes& response) {
    return CodeOf([&] {
        const Response r = ParseResponse(response, c.handle_count, c.auth_count);
        if (r.response_code == 0) c.parse(r);
    });
}

} // namespace

int main() {
    // ---- 1. Golden commands ----
    //
    // Printed by gen_vectors.cpp, which runs tbs_probe.cpp's encoding code
    // unchanged with fixed inputs. The probe sent these layouts to an AMD
    // firmware TPM, elevated and as a standard account, and every command
    // succeeded (docs/adr/0001-post-quantum-payload-version-2.md, Evidence).
    {
        Bytes load_private = {0x00, 0x04, 0x01, 0x02, 0x03, 0x04};
        Bytes load_public = {0x00, 0x03, 0xaa, 0xbb, 0xcc};
        Bytes kat_key(32);
        for (int i = 0; i < 32; ++i) kat_key[i] = static_cast<uint8_t>(0xA0 + i);
        const std::vector<AuthCommand> pw = {PasswordSession()};

        struct Golden {
            const char* name;
            const char* hex;
            Bytes built;
        };
        const Golden golden[] = {
            {"ReadPublic(0x81000001)", "80010000000e0000017381000001", ReadPublicCommand(0x81000001)},
            {"GetCapability(handles, 0x81000000, 64)", "8001000000160000017a000000018100000000000040",
             GetCapabilityCommand(kCapHandles, 0x81000000, 64)},
            {"GetCapability(properties, INPUT_BUFFER, 1)", "8001000000160000017a000000060000010d00000001",
             GetCapabilityCommand(kCapTpmProperties, kPtInputBuffer, 1)},
            {"FlushContext(0x80000002)", "80010000000e0000016580000002", FlushContextCommand(0x80000002)},
            {"Create(0x81000001, HMAC-SHA256 key)",
             "800200000039000001538100000100000009400000090000010000000400000000001000"
             "08000b0004047200000005000b0000000000000000",
             BuildCommand(kCcCreate, {0x81000001}, pw,
                          CreateParameters(KeyedHashPublicArea(
                              kObjFixedTpm | kObjFixedParent | kObjSensitiveDataOrigin | kObjUserWithAuth | kObjNoDa | kObjSign,
                              kAlgSha256, {})))},
            {"Load(0x81000001, priv, pub)",
             "8002000000260000015781000001000000094000000900000100000004010203040003aa"
             "bbcc",
             BuildCommand(kCcLoad, {0x81000001}, pw, LoadParameters(load_private, load_public))},
            {"HMAC(0x80000001, \"abc\", SHA-256)",
             "8002000000220000015580000001000000094000000900000100000003616263000b",
             BuildCommand(kCcHmac, {0x80000001}, pw, HmacParameters({'a', 'b', 'c'}, kAlgSha256))},
            {"LoadExternal(known HMAC key, NULL hierarchy)",
             "80010000008a000001670048000800000020111111111111111111111111111111111111"
             "11111111111111111111111111110020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
             "b4b5b6b7b8b9babbbcbdbebf00300008000b0004044000000005000b0020333333333333"
             "333333333333333333333333333333333333333333333333333340000007",
             LoadExternalCommand(KeyedHashSensitive(Bytes(32, 0x11), kat_key),
                                 KeyedHashPublicArea(kObjUserWithAuth | kObjNoDa | kObjSign, kAlgSha256, Bytes(32, 0x33)),
                                 kRhNull)},
            {"StartAuthSession(0x81000001, NULL, salted, AES-128-CFB, SHA-256)",
             "800100000043000001768100000140000007002044444444444444444444444444444444"
             "4444444444444444444444444444444400045555555500000600800043000b",
             StartAuthSessionCommand(0x81000001, kRhNull, Bytes(32, 0x44), Bytes(4, 0x55), 128, kAlgSha256)},
        };
        for (const Golden& g : golden) {
            const bool same = g.built == FromHex(g.hex);
            Check(same, std::string("golden command: ") + g.name);
            if (!same) std::printf("    built %s\n", ToHex(g.built).c_str());
        }
    }

    // ---- 2. Encoding limits ----
    {
        Check(CodeOf([] { HmacParameters(Bytes(kMaxBuffer), kAlgSha256); }) == HKDFGUARD_OK,
              "HMAC input of exactly kMaxBuffer (1024) bytes is encoded");
        Check(CodeOf([] { HmacParameters(Bytes(kMaxBuffer + 1), kAlgSha256); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "HMAC input over kMaxBuffer is refused, not truncated");
        Check(CodeOf([] { Writer w; w.Tpm2b(Bytes(0x10000)); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a TPM2B over 0xFFFF bytes is refused");
        Check(CodeOf([] { LoadParameters({0x00, 0x05, 0x01}, {0x00, 0x00}); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "LoadParameters refuses a blob whose TPM2B size disagrees with its length");
        Check(CodeOf([] { LoadParameters({}, {0x00, 0x00}); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "LoadParameters refuses an empty blob");
        Check(CodeOf([] { BuildCommand(kCcHmac, {}, {}, Bytes(kMaxResponse)); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a command longer than the TBS buffer is refused");
    }

    // ---- 3. Responses ----
    {
        // Every well-formed case parses.
        for (const ResponseCase& c : WellFormedResponses()) {
            Check(ParseCode(c, c.response) == HKDFGUARD_OK, "well-formed response parses: " + c.name);
        }

        // Error responses: the bare header, and nothing else.
        const Bytes error = FromHex("80010000000a0000018b");
        Response r = ParseResponse(error, 1, 1);
        Check(r.response_code == 0x18B && r.handles.empty() && r.parameters.empty(),
              "an error response yields its code and nothing else, whatever the command returns on success");
        Check(CodeOf([&] { ParseLoad(r); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "parsing a failed command's result is a caller bug (INTERNAL_ERROR)");
        Bytes error_long = error;
        error_long.push_back(0);
        SetSize(error_long);
        Check(CodeOf([&] { ParseResponse(error_long, 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "an error response with a body is malformed");
        Check(CodeOf([] { ParseResponse(FromHex("80020000000a0000018b"), 0, 1); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "an error response tagged TPM_ST_SESSIONS is malformed");

        // Header checks.
        Check(CodeOf([] { ParseResponse(FromHex("800100000009000000"), 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "a response shorter than its header is malformed");
        Check(CodeOf([] { ParseResponse(FromHex("80010000000b00000000"), 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "a size field that disagrees with the length is malformed");
        Check(CodeOf([] { ParseResponse(FromHex("80030000000a00000000"), 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "an unknown tag is malformed");
        Bytes huge(kMaxResponse + 1, 0);
        huge[0] = 0x80; huge[1] = 0x01;
        SetSize(huge);
        Check(CodeOf([&] { ParseResponse(huge, 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "a response longer than the TBS buffer is malformed");
        Check(CodeOf([] { ParseResponse(nullptr, 10, 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "a null response is malformed");

        // Field values.
        {
            Writer p;
            p.Tpm2b(RsaStoragePublic());
            p.Tpm2b(Name(0x01));
            p.Tpm2b(Name(0x02));
            ReadPublicResult rp = ParseReadPublic(ParseResponse(SuccessResponse({}, p.bytes(), {}), 0, 0));
            PublicArea a = ParsePublicArea(rp.public_area);
            Check(a.type == kAlgRsa && a.name_alg == kAlgSha256 && a.attributes == 0x00030472 &&
                      a.symmetric_alg == kAlgAes && a.symmetric_key_bits == 128 && a.symmetric_mode == kAlgCfb &&
                      a.scheme == kAlgNull && a.rsa_key_bits == 2048 && a.rsa_exponent == 0 &&
                      a.rsa_modulus.size() == 256 && a.rsa_modulus[255] == 0xFF,
                  "ReadPublic: the RSA storage key's fields");
            Check(rp.name == Name(0x01) && rp.qualified_name == Name(0x02), "ReadPublic: Name and qualified Name");
            Check(rp.public_area == RsaStoragePublic(), "ReadPublic: the public area is kept byte for byte");
        }
        {
            PublicArea a = ParsePublicArea(EccStoragePublic());
            Check(a.type == kAlgEcc && a.ecc_curve == 0x0003 && a.ecc_kdf == kAlgNull && a.ecc_x == Bytes(32, 0x11) &&
                      a.ecc_y == Bytes(32, 0x22),
                  "ParsePublicArea: an ECC P-256 storage key's fields");
            PublicArea k = ParsePublicArea(KeyedHashPublicArea(0x00040472, kAlgSha256, Bytes(32, 0x62)));
            Check(k.type == kAlgKeyedHash && k.name_alg == kAlgSha256 && k.attributes == 0x00040472 &&
                      k.scheme == kAlgHmac && k.scheme_hash == kAlgSha256 && k.keyed_hash_unique == Bytes(32, 0x62),
                  "ParsePublicArea: KeyedHashPublicArea round-trips");
            Bytes symcipher = KeyedHashPublicArea(0, kAlgSha256, {});
            symcipher[0] = 0x00; symcipher[1] = 0x25; // TPM_ALG_SYMCIPHER
            Check(CodeOf([&] { ParsePublicArea(symcipher); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "ParsePublicArea refuses an object type it doesn't handle");
            Bytes odd_scheme = KeyedHashPublicArea(0, kAlgSha256, {});
            odd_scheme[10] = 0x00; odd_scheme[11] = 0x14; // scheme TPM_ALG_RSASSA on a keyed-hash object
            Check(CodeOf([&] { ParsePublicArea(odd_scheme); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "ParsePublicArea refuses an unknown keyed-hash scheme");
            Bytes trailing = EccStoragePublic();
            trailing.push_back(0);
            Check(CodeOf([&] { ParsePublicArea(trailing); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "ParsePublicArea refuses a trailing byte");
            Writer big;
            big.U16(kAlgRsa); big.U16(kAlgSha256); big.U32(0); big.U16(0);
            big.U16(kAlgNull); big.U16(kAlgNull); big.U16(8192); big.U32(0);
            big.Tpm2b(Bytes(kMaxRsaModulus + 1));
            Check(CodeOf([&] { ParsePublicArea(big.bytes()); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "ParsePublicArea refuses a modulus over kMaxRsaModulus");
        }
        {
            bool more = true;
            Writer p;
            p.U8(0); p.U32(kCapHandles); p.U32(2); p.U32(0x81000001); p.U32(0x81000009);
            std::vector<uint32_t> h = ParseCapabilityHandles(ParseResponse(SuccessResponse({}, p.bytes(), {}), 0, 0), more);
            Check(h == std::vector<uint32_t>{0x81000001, 0x81000009} && !more, "GetCapability: handles and moreData");
            Writer q;
            q.U8(2); q.U32(kCapHandles); q.U32(0);
            Check(CodeOf([&] { ParseCapabilityHandles(ParseResponse(SuccessResponse({}, q.bytes(), {}), 0, 0), more); }) ==
                      HKDFGUARD_ERR_PROVIDER_ERROR,
                  "GetCapability: a moreData that isn't 0 or 1 is malformed");
            Writer s;
            s.U8(0); s.U32(kCapTpmProperties); s.U32(0);
            Check(CodeOf([&] { ParseCapabilityHandles(ParseResponse(SuccessResponse({}, s.bytes(), {}), 0, 0), more); }) ==
                      HKDFGUARD_ERR_PROVIDER_ERROR,
                  "GetCapability: a different capability than asked for is malformed");
            Writer t;
            t.U8(0); t.U32(kCapHandles); t.U32(static_cast<uint32_t>(kMaxCapabilityCount + 1));
            for (size_t i = 0; i <= kMaxCapabilityCount; ++i) t.U32(0x81000000);
            Check(CodeOf([&] { ParseCapabilityHandles(ParseResponse(SuccessResponse({}, t.bytes(), {}), 0, 0), more); }) ==
                      HKDFGUARD_ERR_PROVIDER_ERROR,
                  "GetCapability: more than kMaxCapabilityCount entries is malformed");
            Writer u;
            u.U8(0); u.U32(kCapTpmProperties); u.U32(1); u.U32(kPtInputBuffer); u.U32(1024);
            auto props = ParseCapabilityProperties(ParseResponse(SuccessResponse({}, u.bytes(), {}), 0, 0), more);
            Check(props.size() == 1 && props[0].first == kPtInputBuffer && props[0].second == 1024,
                  "GetCapability: a TPM property and its value");
        }
        {
            Writer p;
            p.Tpm2b(Bytes(32, 0x77));
            StartAuthSessionResult s = ParseStartAuthSession(ParseResponse(SuccessResponse({0x02000000}, p.bytes(), {}), 1, 0));
            Check(s.session_handle == 0x02000000 && s.nonce_tpm == Bytes(32, 0x77), "StartAuthSession: handle and nonceTPM");
            Writer q;
            q.Tpm2b(Bytes(15, 0x77));
            Check(CodeOf([&] { ParseStartAuthSession(ParseResponse(SuccessResponse({0x02000000}, q.bytes(), {}), 1, 0)); }) ==
                      HKDFGUARD_ERR_PROVIDER_ERROR,
                  "StartAuthSession: a nonceTPM under 16 bytes is malformed");
        }
        {
            Writer p;
            Bytes pub = KeyedHashPublicArea(0x00040472, kAlgSha256, Bytes(32, 0x62));
            p.Tpm2b(Bytes(126, 0x61));
            p.Tpm2b(pub);
            p.Tpm2b(Bytes(60, 0x63));
            p.Tpm2b(Bytes(32, 0x64));
            p.U16(kStCreation); p.U32(0x40000001); p.Tpm2b(Bytes(32, 0x65));
            Response r2 = ParseResponse(SuccessResponse({}, p.bytes(), AuthArea(kSessionContinue)), 0, 1);
            CreateResult c = ParseCreate(r2);
            Writer priv; priv.Tpm2b(Bytes(126, 0x61));
            Writer pubb; pubb.Tpm2b(pub);
            Check(c.private_blob == priv.bytes() && c.public_blob == pubb.bytes(),
                  "Create: the private and public blobs, each with its TPM2B size");
            Check(r2.auths.size() == 1 && r2.auths[0].nonce == Bytes(32, 0x5A) && r2.auths[0].attributes == kSessionContinue &&
                      r2.auths[0].hmac == Bytes(32, 0xA5),
                  "Create: the session's response authorization");
            Check(CodeOf([&] { LoadParameters(c.private_blob, c.public_blob); }) == HKDFGUARD_OK,
                  "Create's blobs are accepted by LoadParameters unchanged");

            Bytes bad_ticket = p.bytes();
            bad_ticket[bad_ticket.size() - 32 - 2 - 4 - 1] ^= 0x01; // the ticket tag's low byte
            Check(CodeOf([&] { ParseCreate(ParseResponse(SuccessResponse({}, bad_ticket, AuthArea(0)), 0, 1)); }) ==
                      HKDFGUARD_ERR_PROVIDER_ERROR,
                  "Create: a creation ticket with the wrong tag is malformed");
        }
        {
            Writer p;
            p.Tpm2b(Bytes(32, 0x66));
            const Bytes auth = AuthArea(kSessionEncrypt);
            Response r3 = ParseResponse(SuccessResponse({}, p.bytes(), auth), 0, 1);
            Check(ParseHmac(r3) == Bytes(32, 0x66), "HMAC: outHMAC");
            Check(r3.parameters == p.bytes(), "HMAC: the parameter area is exactly parameterSize bytes (what rpHash covers)");
            Check(CodeOf([&] { ParseResponse(SuccessResponse({}, p.bytes(), auth), 0, 0); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "a TPM_ST_SESSIONS response to a command sent without sessions is malformed");
            Check(CodeOf([&] { ParseResponse(SuccessResponse({}, p.bytes(), {}), 0, 1); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "a TPM_ST_NO_SESSIONS response to a command sent with a session is malformed");
            Bytes two_auths = auth;
            two_auths.insert(two_auths.end(), auth.begin(), auth.end());
            Check(CodeOf([&] { ParseResponse(SuccessResponse({}, p.bytes(), two_auths), 0, 1); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "more authorization entries than sessions is malformed");
            Bytes big_param = SuccessResponse({}, p.bytes(), auth);
            big_param[13] = 0xFF; // parameterSize past the end of the response
            Check(CodeOf([&] { ParseResponse(big_param, 0, 1); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "a parameterSize past the end of the response is malformed");
        }
        {
            Writer p;
            p.Tpm2b(Bytes(kMaxName + 1, 0x01));
            Check(CodeOf([&] { ParseLoad(ParseResponse(SuccessResponse({0x80000001}, p.bytes(), {}), 1, 0)); }) ==
                      HKDFGUARD_ERR_PROVIDER_ERROR,
                  "Load: a Name over kMaxName is malformed");
        }
    }

    // ---- 4. Mutation sweep ----
    {
        std::mt19937 rng(0x48474B44); // fixed seed: reproducible
        for (const ResponseCase& c : WellFormedResponses()) {
            const Bytes& good = c.response;
            int bad_outcomes = 0;
            int parsed_truncation = 0;

            // Every truncation, with the size field kept consistent so the
            // parse reaches the structures inside (a mismatched size would be
            // caught by the header alone).
            for (size_t len = 0; len < good.size(); ++len) {
                Bytes t(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(len));
                SetSize(t);
                const int code = ParseCode(c, t);
                if (code == HKDFGUARD_OK) ++parsed_truncation;
                else if (code != HKDFGUARD_ERR_PROVIDER_ERROR) ++bad_outcomes;
            }
            // Every response is fully length-determined, so no strict prefix
            // of a well-formed one parses.
            Check(parsed_truncation == 0, c.name + ": no truncation parses");

            Bytes extended = good;
            extended.push_back(0x00);
            SetSize(extended);
            Check(ParseCode(c, extended) == HKDFGUARD_ERR_PROVIDER_ERROR, c.name + ": one trailing byte is malformed");

            // Every single-bit flip, the size field left as flipped.
            for (size_t i = 0; i < good.size(); ++i) {
                for (int bit = 0; bit < 8; ++bit) {
                    Bytes m = good;
                    m[i] ^= static_cast<uint8_t>(1u << bit);
                    const int code = ParseCode(c, m);
                    if (code != HKDFGUARD_OK && code != HKDFGUARD_ERR_PROVIDER_ERROR) ++bad_outcomes;
                }
            }

            // Seeded random edits: overwrite, insert or delete a few bytes,
            // usually re-fixing the size field.
            for (int iteration = 0; iteration < 20000; ++iteration) {
                Bytes m = good;
                const int edits = 1 + static_cast<int>(rng() % 4);
                for (int e = 0; e < edits && !m.empty(); ++e) {
                    const size_t at = rng() % m.size();
                    switch (rng() % 3) {
                        case 0: m[at] = static_cast<uint8_t>(rng()); break;
                        case 1: m.insert(m.begin() + static_cast<std::ptrdiff_t>(at), static_cast<uint8_t>(rng())); break;
                        default: m.erase(m.begin() + static_cast<std::ptrdiff_t>(at)); break;
                    }
                }
                if (rng() % 4 != 0) SetSize(m);
                const int code = ParseCode(c, m);
                if (code != HKDFGUARD_OK && code != HKDFGUARD_ERR_PROVIDER_ERROR) ++bad_outcomes;
            }
            Check(bad_outcomes == 0, c.name + ": every mutation parses or fails with PROVIDER_ERROR only");
        }
    }

    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
