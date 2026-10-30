// Hand-rolled test program (no test framework), like test_roundtrip: checks
// src/tpm2_session.cpp (the session cryptography) and src/tpm2_device.cpp
// (raw TPM 2.0 commands through TBS). Exits 0 if every check passed, 1
// otherwise.
//
// Offline, on any machine:
//   1. Primitives against independent references: AES-128-CFB against
//      NIST SP 800-38A F.3.13 and BCrypt; KDFa, KDFe and ComputeName
//      against values computed with Python's hmac and hashlib.
//   2. Session salts round-trip through keys generated here: the RSA-OAEP
//      salt decrypts with the private key, and the ECC salt is reproduced
//      from the private key's side of the ECDH.
//   3. Session misuse is refused.
// Live, when TBS reaches a TPM 2.0 (no elevation needed; skipped otherwise):
//   4. The storage root keys: listed, read, and their Names recomputed.
//   5. A known-answer test end to end: a known HMAC key loaded with
//      TPM2_LoadExternal, TPM2_HMAC through a session salted to each
//      storage root key, with both parameters encrypted, equals BCrypt's
//      HMAC-SHA-256 - so the TPM accepted this side's salt, session key,
//      cpHash and command encryption, and this side decrypted the response.
//   6. A key made with TPM2_Create and loaded with TPM2_Load gives
//      repeatable, input-dependent output through the session.
//   7. Tampered responses and TPM errors: a flipped bit anywhere in a
//      session response is refused, and a TPM error surfaces its code.
#include "tpm2_device.h"
#include "tpm2_session.h"
#include "errors.h"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

using hkdfguard::HkdfGuardError;
using hkdfguard::SecureBuffer;
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

void Skip(const std::string& what) {
    std::printf("[SKIP] %s\n", what.c_str());
}

Bytes FromHex(const char* hex) {
    Bytes out;
    for (size_t i = 0; hex[i] != '\0' && hex[i + 1] != '\0'; i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(std::string(hex + i, 2), nullptr, 16)));
    }
    return out;
}

std::string ToHex(const uint8_t* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += digits[p[i] >> 4];
        s += digits[p[i] & 15];
    }
    return s;
}
std::string ToHex(const Bytes& b) { return ToHex(b.data(), b.size()); }

std::string Hex32(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08X", static_cast<unsigned>(v));
    return buf;
}

// Runs one section; an exception that escapes it is a failure of that
// section, reported with its code (and the TPM's), not an abort of the run.
void Guarded(const std::string& section, const std::function<void()>& body) {
    try {
        body();
    } catch (const TpmError& e) {
        Check(false, section + ": TpmError, code " + std::to_string(e.code()) + ", TPM/TBS code " + Hex32(e.tpm_code()) +
                         ": " + e.what());
    } catch (const HkdfGuardError& e) {
        Check(false, section + ": HkdfGuardError, code " + std::to_string(e.code()) + ": " + e.what());
    } catch (const std::exception& e) {
        Check(false, section + ": exception: " + e.what());
    }
}

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

// The known-answer test's fixed key, and the longest PRF input of the ADR's
// construction (196 bytes).
Bytes KatKey() {
    Bytes k(32);
    for (int i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(0xA0 + i);
    return k;
}

Bytes KatInput(uint8_t fill) {
    Bytes b(196, fill);
    for (size_t i = 0; i < 4; ++i) b[i] = static_cast<uint8_t>(i == 3 ? 1 : 0);
    return b;
}

Bytes BcryptHmac(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
               const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), out.data(), 32);
    return out;
}

// LoadExternal's public area for `key` must carry unique = SHA-256(seed ||
// key), which the TPM checks.
LoadResult LoadKatKey(Tpm& tpm, const Bytes& key) {
    const Bytes seed(32, 0x5E);
    Bytes seeded = seed;
    seeded.insert(seeded.end(), key.begin(), key.end());
    Bytes unique(32);
    Sha256(seeded.data(), seeded.size(), unique.data());
    return tpm.LoadExternal(KeyedHashSensitive(seed, key),
                            KeyedHashPublicArea(kObjUserWithAuth | kObjNoDa | kObjSign, kAlgSha256, unique), kRhNull);
}

void OfflineChecks() {
    // ---- 1. Primitives ----
    {
        const Bytes key = FromHex("2b7e151628aed2a6abf7158809cf4f3c");
        const Bytes iv = FromHex("000102030405060708090a0b0c0d0e0f");
        const Bytes plain = FromHex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        const Bytes cipher = FromHex(
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
        Bytes out(plain.size());
        Aes128Cfb(key.data(), iv.data(), plain.data(), out.data(), plain.size(), true);
        Check(out == cipher, "AES-128-CFB encryption matches NIST SP 800-38A F.3.13");
        Aes128Cfb(key.data(), iv.data(), cipher.data(), out.data(), cipher.size(), false);
        Check(out == plain, "AES-128-CFB decryption matches NIST SP 800-38A F.3.14");
        bool prefixes = true;
        for (size_t len : {1u, 15u, 16u, 17u, 33u, 63u}) {
            Bytes part(len);
            Aes128Cfb(key.data(), iv.data(), plain.data(), part.data(), len, true);
            prefixes = prefixes && std::memcmp(part.data(), cipher.data(), len) == 0;
            Bytes back(len);
            Aes128Cfb(key.data(), iv.data(), part.data(), back.data(), len, false);
            prefixes = prefixes && std::memcmp(back.data(), plain.data(), len) == 0;
        }
        Check(prefixes, "AES-128-CFB of a partial final block: the matching prefix, and it decrypts");
        Bytes in_place = plain;
        Aes128Cfb(key.data(), iv.data(), in_place.data(), in_place.data(), in_place.size(), true);
        Aes128Cfb(key.data(), iv.data(), in_place.data(), in_place.data(), in_place.size(), false);
        Check(in_place == plain, "AES-128-CFB works in place, both ways");

        // BCrypt's own CFB with 16-byte feedback, as a second reference.
        BCRYPT_KEY_HANDLE k = nullptr;
        BCryptGenerateSymmetricKey(BCRYPT_AES_CFB_ALG_HANDLE, &k, nullptr, 0, const_cast<PUCHAR>(key.data()), 16, 0);
        DWORD block = 16;
        BCryptSetProperty(k, BCRYPT_MESSAGE_BLOCK_LENGTH, reinterpret_cast<PUCHAR>(&block), sizeof(block), 0);
        Bytes long_plain(160);
        for (size_t i = 0; i < long_plain.size(); ++i) long_plain[i] = static_cast<uint8_t>(i * 31 + 7);
        Bytes ref(long_plain.size()), mine(long_plain.size());
        Bytes iv_copy = iv;
        ULONG got = 0;
        BCryptEncrypt(k, long_plain.data(), static_cast<ULONG>(long_plain.size()), nullptr, iv_copy.data(), 16, ref.data(),
                      static_cast<ULONG>(ref.size()), &got, 0);
        BCryptDestroyKey(k);
        Aes128Cfb(key.data(), iv.data(), long_plain.data(), mine.data(), mine.size(), true);
        Check(got == ref.size() && mine == ref, "AES-128-CFB matches BCrypt CFB-128 over 160 bytes");
    }
    {
        const Bytes key = [] { Bytes k(32); for (int i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(i); return k; }();
        const Bytes u(32, 0x11), v(32, 0x22);
        uint8_t out[48];
        KdfaSha256(key.data(), key.size(), "ATH", u, v, out, 32);
        Check(ToHex(out, 32) == "a8679444f320a6d0a02c03cac153c458f28758eca056594e887fcefdc2d7e95b",
              "KDFa(\"ATH\", 256 bits) matches the Python reference");
        KdfaSha256(key.data(), key.size(), "CFB", u, v, out, 32);
        Check(ToHex(out, 32) == "8912c1219a825fa7bb0f4fc87f4fbdf597093e9f3a2732b916de4a9dfdd4a3ae",
              "KDFa(\"CFB\", 256 bits) matches the Python reference");
        KdfaSha256(key.data(), key.size(), "XYZ", u, v, out, 48);
        Check(ToHex(out, 48) ==
                  "6e40f1a535e8571967fe82e40e7c42141fe469a2f9774b398d8eac13466316ef241af21ddf2bc5b159ae5470d00f7333",
              "KDFa over two blocks (384 bits) matches the Python reference");
        KdfaSha256(key.data(), key.size(), "CFB", {}, {}, out, 16);
        Check(ToHex(out, 16) == "3cc2ace820efbd89ee9b337ce6a9b300", "KDFa with empty contexts (128 bits) matches the Python reference");

        Bytes z(32);
        for (int i = 0; i < 32; ++i) z[i] = static_cast<uint8_t>(100 + i);
        KdfeSha256(z.data(), z.size(), "SECRET", u, v, out, 32);
        Check(ToHex(out, 32) == "13d40e359d1be91e2b8fb87e42b45e0e6de49098437b4937058caa0a1ddc65b1",
              "KDFe(\"SECRET\", 256 bits) matches the Python reference");
        KdfeSha256(z.data(), z.size(), "SECRET", u, v, out, 40);
        Check(ToHex(out, 40) == "13d40e359d1be91e2b8fb87e42b45e0e6de49098437b4937058caa0a1ddc65b172c4d9cca8cf5680",
              "KDFe over two blocks (320 bits) matches the Python reference");

        const Bytes area = KeyedHashPublicArea(kObjUserWithAuth | kObjNoDa | kObjSign, kAlgSha256, Bytes(32, 0x33));
        Check(ToHex(ComputeName(area)) == "000bfe3915a412cda544822e1dbca600fb0b93e5a62bcb48d1f4461294066a67d936",
              "ComputeName matches the Python reference");
        Bytes sha1_area = area;
        sha1_area[3] = 0x04; // nameAlg TPM_ALG_SHA1
        Check(CodeOf([&] { ComputeName(sha1_area); }) == HKDFGUARD_ERR_PROVIDER_ERROR, "ComputeName refuses a nameAlg other than SHA-256");
    }

    // ---- 2. Session salts ----
    {
        BCRYPT_KEY_HANDLE rsa = nullptr;
        BCryptGenerateKeyPair(BCRYPT_RSA_ALG_HANDLE, &rsa, 2048, 0);
        BCryptFinalizeKeyPair(rsa, 0);
        Bytes blob(1024);
        ULONG got = 0;
        BCryptExportKey(rsa, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), static_cast<ULONG>(blob.size()), &got, 0);
        const auto* header = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
        PublicArea key;
        key.type = kAlgRsa;
        key.name_alg = kAlgSha256;
        const uint8_t* exp = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        key.rsa_exponent = 0; // 65537, as the TPM writes it
        Check(header->cbPublicExp == 3 && exp[0] == 1 && exp[1] == 0 && exp[2] == 1, "test setup: an RSA-2048 key with exponent 65537");
        key.rsa_modulus.assign(exp + header->cbPublicExp, exp + header->cbPublicExp + header->cbModulus);
        SecureBuffer<kSha256Len> salt;
        Bytes encrypted;
        MakeSessionSalt(key, salt, encrypted);
        static const char kLabel[] = "SECRET";
        BCRYPT_OAEP_PADDING_INFO oaep{BCRYPT_SHA256_ALGORITHM, reinterpret_cast<PUCHAR>(const_cast<char*>(kLabel)), sizeof(kLabel)};
        uint8_t decrypted[256] = {};
        const NTSTATUS st = BCryptDecrypt(rsa, encrypted.data(), static_cast<ULONG>(encrypted.size()), &oaep, nullptr, 0,
                                          decrypted, sizeof(decrypted), &got, BCRYPT_PAD_OAEP);
        Check(encrypted.size() == 256 && st == 0 && got == 32 && std::memcmp(decrypted, salt.data(), 32) == 0,
              "RSA salt: OAEP(SHA-256, \"SECRET\\0\") decrypts to the salt with the private key");
        BCryptDestroyKey(rsa);

        BCRYPT_KEY_HANDLE ecc = nullptr;
        BCryptGenerateKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, &ecc, 256, 0);
        BCryptFinalizeKeyPair(ecc, 0);
        Bytes eblob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
        BCryptExportKey(ecc, nullptr, BCRYPT_ECCPUBLIC_BLOB, eblob.data(), static_cast<ULONG>(eblob.size()), &got, 0);
        PublicArea ekey;
        ekey.type = kAlgEcc;
        ekey.name_alg = kAlgSha256;
        ekey.ecc_curve = 0x0003;
        ekey.ecc_x.assign(eblob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), eblob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32);
        ekey.ecc_y.assign(eblob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, eblob.end());
        SecureBuffer<kSha256Len> esalt;
        Bytes point;
        MakeSessionSalt(ekey, esalt, point);
        // The private side: ECDH(private key, ephemeral point), then KDFe.
        Reader r(point);
        const Bytes ex = r.Tpm2b(32), ey = r.Tpm2b(32);
        r.ExpectEnd();
        Bytes pblob(sizeof(BCRYPT_ECCKEY_BLOB));
        auto* ph = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pblob.data());
        ph->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        ph->cbKey = 32;
        pblob.insert(pblob.end(), ex.begin(), ex.end());
        pblob.insert(pblob.end(), ey.begin(), ey.end());
        BCRYPT_KEY_HANDLE eph = nullptr;
        BCRYPT_SECRET_HANDLE secret = nullptr;
        BCryptImportKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, nullptr, BCRYPT_ECCPUBLIC_BLOB, &eph, pblob.data(),
                            static_cast<ULONG>(pblob.size()), 0);
        BCryptSecretAgreement(ecc, eph, &secret, 0);
        uint8_t z[32];
        BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, z, 32, &got, 0);
        std::reverse(z, z + 32);
        uint8_t expect[32];
        KdfeSha256(z, 32, "SECRET", ex, ekey.ecc_x, expect, 32);
        Check(ex.size() == 32 && ey.size() == 32 && std::memcmp(expect, esalt.data(), 32) == 0,
              "ECC salt: the private key's side of the ECDH reproduces the salt");
        BCryptDestroySecret(secret);
        BCryptDestroyKey(eph);
        BCryptDestroyKey(ecc);

        PublicArea sha1 = key;
        sha1.name_alg = 0x0004;
        Check(CodeOf([&] { SecureBuffer<32> s; Bytes e; MakeSessionSalt(sha1, s, e); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "a salt key whose nameAlg isn't SHA-256 is refused");
        PublicArea p384 = ekey;
        p384.ecc_curve = 0x0004;
        Check(CodeOf([&] { SecureBuffer<32> s; Bytes e; MakeSessionSalt(p384, s, e); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "an ECC salt key on a curve other than P-256 is refused");
        PublicArea bad_point = ekey;
        bad_point.ecc_y[31] ^= 0x01;
        Check(CodeOf([&] { SecureBuffer<32> s; Bytes e; MakeSessionSalt(bad_point, s, e); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "an ECC salt key whose point is off the curve is refused");
    }

    // ---- 3. Session misuse ----
    {
        SecureBuffer<kSha256Len> salt;
        const Bytes nonce(kNonceLen, 0x01);
        Check(CodeOf([&] { Session s(0x02000000, salt, Bytes(16, 0x01), nonce); }) == HKDFGUARD_ERR_PROVIDER_ERROR,
              "a session whose nonceTPM isn't 32 bytes is refused");
        Session s(0x02000000, salt, nonce, nonce);
        const Bytes params = HmacParameters(Bytes(4, 0x09), kAlgSha256);
        Check(CodeOf([&] { s.Verify(Response{}); }) == HKDFGUARD_ERR_INTERNAL_ERROR, "Verify before any command is refused");
        Check(CodeOf([&] { s.DecryptResponseParameter(Bytes(32), Bytes(32).data(), 32); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "DecryptResponseParameter before a verified response is refused");
        Check(CodeOf([&] { s.Authorize(kCcHmac, {0x80000001}, {}, params, true); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a command without a Name for its handle is refused");
        Check(CodeOf([&] { s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, Bytes{0x00, 0x09, 0x01}, true); }) ==
                  HKDFGUARD_ERR_INTERNAL_ERROR,
              "a command whose first parameter isn't a TPM2B is refused");
        Bytes first = s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, params, true);
        Check(first.size() > params.size(), "a command is authorized");
        Check(CodeOf([&] { s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, params, true); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a second command before the first's response is refused");
        // A response whose HMAC is wrong.
        Response forged;
        forged.tag = kStSessions;
        forged.parameters = Bytes{0x00, 0x20};
        forged.parameters.insert(forged.parameters.end(), 32, 0x00);
        forged.auths.push_back(AuthResponse{Bytes(kNonceLen, 0x02), static_cast<uint8_t>(kSessionEncrypt | kSessionContinue), Bytes(32, 0x03)});
        Check(CodeOf([&] { s.Verify(forged); }) == HKDFGUARD_ERR_PROVIDER_ERROR, "a response with a wrong HMAC is refused");
        Check(!s.usable() && CodeOf([&] { s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, params, true); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "after a refused response the session authorizes nothing more");
        Check(s.open(), "...but is still open, so its owner flushes it");
    }

    // ---- 3a. Whether the session survives is the TPM's answer ----
    // A response this side's own session key verifies - built here, since
    // the key comes from values the test chooses (the salt and both initial
    // nonces) - whose continueSession bit differs from the request's. The
    // TPM's verified bit must decide open().
    {
        SecureBuffer<kSha256Len> salt;
        const Bytes initial(kNonceLen, 0x01);
        Bytes session_key(kSha256Len);
        KdfaSha256(salt.data(), salt.size(), "ATH", initial, initial, session_key.data(), session_key.size());
        const Bytes params = HmacParameters(Bytes(4, 0x09), kAlgSha256);

        // A verified response to the command just authorized, with
        // `attributes` as the TPM's session attributes.
        auto verified_response = [&](const Bytes& command, uint8_t attributes) {
            // The command's nonceCaller: after the 10-byte header, the one
            // handle, authorizationSize, the session handle and nonce's size.
            const Bytes nonce_caller(command.begin() + 24, command.begin() + 24 + kNonceLen);
            Response r;
            r.tag = kStSessions;
            r.parameters = Bytes{0x00, 0x20};
            r.parameters.insert(r.parameters.end(), 32, 0x00);
            const Bytes nonce_tpm(kNonceLen, 0x07);
            Bytes rp_input = {0, 0, 0, 0}; // responseCode
            rp_input.insert(rp_input.end(), {0x00, 0x00, 0x01, 0x55}); // TPM_CC_HMAC
            rp_input.insert(rp_input.end(), r.parameters.begin(), r.parameters.end());
            uint8_t rp_hash[kSha256Len];
            Sha256(rp_input.data(), rp_input.size(), rp_hash);
            Bytes hmac_input(rp_hash, rp_hash + kSha256Len);
            hmac_input.insert(hmac_input.end(), nonce_tpm.begin(), nonce_tpm.end());
            hmac_input.insert(hmac_input.end(), nonce_caller.begin(), nonce_caller.end());
            hmac_input.push_back(attributes);
            Bytes hmac(kSha256Len);
            HmacSha256(session_key.data(), session_key.size(), hmac_input.data(), hmac_input.size(), hmac.data());
            r.auths.push_back(AuthResponse{nonce_tpm, attributes, hmac});
            return r;
        };

        {
            Session s(0x02000000, salt, initial, initial);
            const Bytes command = s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, params, true);
            const Response r = verified_response(command, kSessionEncrypt);
            Check(CodeOf([&] { s.Verify(r); }) == HKDFGUARD_OK && !s.open(),
                  "continueSession asked for but the TPM's verified response clears it: the session is closed, so "
                  "nothing flushes its handle");
        }
        {
            Session s(0x02000000, salt, initial, initial);
            const Bytes command = s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, params, false);
            const Response r = verified_response(command, static_cast<uint8_t>(kSessionEncrypt | kSessionContinue));
            Check(CodeOf([&] { s.Verify(r); }) == HKDFGUARD_OK && s.open(),
                  "continueSession not asked for but the TPM's verified response keeps it: the session stays open, "
                  "so its owner flushes it");
        }
        {
            Session s(0x02000000, salt, initial, initial);
            const Bytes command = s.Authorize(kCcHmac, {0x80000001}, {Bytes(34)}, params, true);
            Response r = verified_response(command, static_cast<uint8_t>(kSessionEncrypt | kSessionContinue));
            r.auths[0].attributes = kSessionEncrypt; // flipped after the HMAC was computed
            Check(CodeOf([&] { s.Verify(r); }) == HKDFGUARD_ERR_PROVIDER_ERROR && s.open(),
                  "a continueSession bit changed in transit fails the response HMAC, and the session is kept open");
        }
    }
}

void LiveChecks() {
    Transport tbs;
    try {
        tbs = OpenTbsTransport();
    } catch (const TpmError& e) {
        Skip("live TPM checks: no TPM 2.0 through TBS (TBS result 0x" + ToHex(Bytes{
            static_cast<uint8_t>(e.tpm_code() >> 24), static_cast<uint8_t>(e.tpm_code() >> 16),
            static_cast<uint8_t>(e.tpm_code() >> 8), static_cast<uint8_t>(e.tpm_code())}) + ")");
        return;
    }
    Tpm tpm(tbs);

    // ---- 4. Storage root keys ----
    std::vector<std::pair<uint32_t, PublicArea>> srks;
    Guarded("4. storage root keys", [&] {
        const std::vector<uint32_t> handles = tpm.PersistentHandles();
        Check(!handles.empty(), "persistent handles listed (" + std::to_string(handles.size()) + ")");
        for (uint32_t h : {0x81000001u, 0x81000009u}) {
            bool present = false;
            for (uint32_t x : handles) present = present || x == h;
            if (!present) {
                Skip("storage key " + ToHex(Bytes{0x81, 0x00, 0x00, static_cast<uint8_t>(h)}) + " is not present");
                continue;
            }
            Guarded("4. ReadPublic " + Hex32(h), [&] {
                ReadPublicResult rp = tpm.ReadPublic(h); // throws if the Name doesn't match
                PublicArea area = ParsePublicArea(rp.public_area);
                const bool storage = (area.attributes & kObjRestricted) && (area.attributes & kObjDecrypt);
                Check(storage && area.name_alg == kAlgSha256,
                      Hex32(h) + ": a SHA-256 restricted-decrypt " + (area.type == kAlgRsa ? "RSA" : "ECC") +
                          " key, Name " + ToHex(rp.name) + " recomputed");
                if (storage) srks.emplace_back(h, area);
            });
        }
        Check(tpm.Property(kPtInputBuffer) >= 196, "TPM_PT_INPUT_BUFFER covers the 196-byte PRF input");
    });

    // ---- 5. Known-answer test through each salted, encrypted session ----
    const Bytes kat_key = KatKey();
    for (const auto& [srk_handle, srk_public] : srks) {
        const uint32_t srk = srk_handle;
        const PublicArea& area = srk_public;
        const std::string label = std::string(area.type == kAlgRsa ? "RSA" : "ECC") + "-salted session: ";
        Guarded("5. " + label + "known-answer test", [&] {
        LoadResult loaded = LoadKatKey(tpm, kat_key);
        ScopedTpmObject key(tpm, loaded.object_handle);
        ScopedSession session(tpm, tpm.StartSaltedSession(srk, area));
        bool all = true;
        for (int round = 0; round < 3; ++round) {
            const Bytes input = KatInput(static_cast<uint8_t>(0x40 + round));
            SecureBuffer<kSha256Len> out;
            tpm.Hmac(*session, key.get(), loaded.name, input, out, round < 2);
            all = all && std::memcmp(out.data(), BcryptHmac(kat_key, input).data(), 32) == 0;
        }
        Check(all, label + "TPM2_HMAC of a known key equals BCrypt HMAC-SHA-256, three rounds, nonces rolled");
        Check(!session->open(), label + "the last round, without continueSession, closed the session");
        });
    }
    if (srks.empty()) {
        Skip("known-answer test: no storage root key");
        return;
    }
    const uint32_t srk = srks[0].first;
    const PublicArea& srk_area = srks[0].second;

    // ---- 6. A created key ----
    Guarded("6. a created key", [&] {
        const Bytes templ = KeyedHashPublicArea(
            kObjFixedTpm | kObjFixedParent | kObjSensitiveDataOrigin | kObjUserWithAuth | kObjNoDa | kObjSign, kAlgSha256, {});
        CreateResult created = tpm.Create(srk, templ);
        Check(created.public_blob.size() > 2 && created.private_blob.size() > 2, "TPM2_Create of an HMAC-SHA-256 key");
        LoadResult loaded = tpm.Load(srk, created.private_blob, created.public_blob);
        ScopedTpmObject key(tpm, loaded.object_handle);
        ScopedSession session(tpm, tpm.StartSaltedSession(srk, srk_area));
        SecureBuffer<kSha256Len> a, b, c;
        tpm.Hmac(*session, key.get(), loaded.name, KatInput(0x01), a, true);
        tpm.Hmac(*session, key.get(), loaded.name, KatInput(0x01), b, true);
        tpm.Hmac(*session, key.get(), loaded.name, KatInput(0x02), c, true);
        Check(std::memcmp(a.data(), b.data(), 32) == 0 && std::memcmp(a.data(), c.data(), 32) != 0,
              "a created key's HMAC through the session: repeatable, and different for a different input");
        Check(std::memcmp(a.data(), BcryptHmac(kat_key, KatInput(0x01)).data(), 32) != 0,
              "...and it isn't the known-answer key's (the TPM generated its own)");
        Check(session->open(), "the session stays open while continueSession is set; ScopedSession flushes it");
    });

    // ---- 7. Tampering and TPM errors ----
    Guarded("7. tampering and TPM errors", [&] {
        // Whether a command is TPM2_HMAC (its code is bytes 6..9).
        auto is_hmac = [](const Bytes& command) {
            return command.size() >= 10 && command[6] == 0 && command[7] == 0 && command[8] == 0x01 && command[9] == 0x55;
        };
        // Flip one bit at a chosen offset of the next HMAC response.
        long flip_at = -1;
        Tpm tampering([&](const Bytes& command) {
            Bytes response = tbs(command);
            if (is_hmac(command) && flip_at >= 0 && static_cast<size_t>(flip_at) < response.size()) {
                response[static_cast<size_t>(flip_at)] ^= 0x01;
            }
            return response;
        });
        LoadResult loaded = LoadKatKey(tampering, kat_key);
        ScopedTpmObject key(tampering, loaded.object_handle);

        // A clean HMAC response, to learn its length. Only the HMAC's: the
        // session's flush at the end of scope has a response too.
        size_t response_len = 0;
        {
            Tpm measuring([&](const Bytes& command) {
                Bytes r = tbs(command);
                if (is_hmac(command)) response_len = r.size();
                return r;
            });
            ScopedSession session(measuring, measuring.StartSaltedSession(srk, srk_area));
            SecureBuffer<kSha256Len> out;
            measuring.Hmac(*session, key.get(), loaded.name, KatInput(0x07), out, true);
        }
        Check(response_len == 10 + 4 + 34 + 34 + 1 + 34, "an encrypted TPM2_HMAC response is 117 bytes");

        // Every byte after the header: the parameterSize, the encrypted
        // outHMAC, the new nonceTPM, the attributes, the response HMAC.
        int refused = 0, tried = 0;
        for (size_t at = 10; at < response_len; ++at) {
            flip_at = static_cast<long>(at);
            ScopedSession session(tampering, tampering.StartSaltedSession(srk, srk_area));
            SecureBuffer<kSha256Len> out;
            ++tried;
            if (CodeOf([&] { tampering.Hmac(*session, key.get(), loaded.name, KatInput(0x07), out, true); }) ==
                HKDFGUARD_ERR_PROVIDER_ERROR && !session->usable()) {
                ++refused;
            }
        }
        flip_at = -1;
        Check(tried > 0 && refused == tried, "a flipped bit in any of the " + std::to_string(tried) +
                                    " bytes after an HMAC response's header is refused, leaving the session unusable");

        // A TPM error: the response code comes through.
        ScopedSession session(tpm, tpm.StartSaltedSession(srk, srk_area));
        SecureBuffer<kSha256Len> out;
        uint32_t code = 0;
        try {
            tpm.Hmac(*session, 0x80FFFFFF, loaded.name, KatInput(0x07), out, true);
        } catch (const TpmError& e) {
            code = e.tpm_code();
        }
        Check(code != 0 && !session->usable(), "TPM2_HMAC with no such key: a TpmError with the TPM's code (0x" +
                                                   ToHex(Bytes{static_cast<uint8_t>(code >> 24), static_cast<uint8_t>(code >> 16),
                                                               static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code)}) +
                                                   "), and the session unusable");

        CreateResult created = tpm.Create(srk, KeyedHashPublicArea(
            kObjFixedTpm | kObjFixedParent | kObjSensitiveDataOrigin | kObjUserWithAuth | kObjNoDa | kObjSign, kAlgSha256, {}));
        Bytes corrupt = created.private_blob;
        corrupt[corrupt.size() / 2] ^= 0x01;
        uint32_t load_code = 0;
        try {
            tpm.Load(srk, corrupt, created.public_blob);
        } catch (const TpmError& e) {
            load_code = e.tpm_code();
        }
        Check(load_code != 0, "TPM2_Load of a corrupted private blob: the TPM refuses it (integrity check)");

        Bytes wrong_unique_public = KeyedHashPublicArea(kObjUserWithAuth | kObjNoDa | kObjSign, kAlgSha256, Bytes(32, 0x00));
        uint32_t ext_code = 0;
        try {
            tpm.LoadExternal(KeyedHashSensitive(Bytes(32, 0x5E), kat_key), wrong_unique_public, kRhNull);
        } catch (const TpmError& e) {
            ext_code = e.tpm_code();
        }
        Check(ext_code != 0, "TPM2_LoadExternal with a unique that doesn't bind the key: the TPM refuses it");
    });
}

} // namespace

int main() {
    // Unbuffered, so the output up to any failure survives a crash.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Guarded("offline checks", OfflineChecks);
    Guarded("live checks", LiveChecks);
    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
