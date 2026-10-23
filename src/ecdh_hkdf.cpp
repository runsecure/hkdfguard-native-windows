#include "ecdh_hkdf.h"
#include "errors.h"
#include "hash_to_curve.h" // PayloadEcdhPoint - H(salt)
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <cstring> // memcpy
#include <vector>

#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif

// Design note: the wrapping key is derived from Z = ECDH(KEK private key,
// H(salt)), where H(salt) is the payload's salt hashed to a P-256 point
// (hash_to_curve.h) - the construction this project's Linux implementation
// uses. Wrap and unwrap run the *same* code (DeriveWrappingKey below) with
// the same salt, so they derive the same key by construction, and both
// need the KEK's private key: knowing only the KEK's public key no longer
// lets anyone build a payload that unwraps (it did under the earlier
// ephemeral-key/ECIES construction this replaced before the first release).
//
// The ECDH runs as NCryptSecretAgreement on the KEK's own provider - inside
// the TPM for a Platform Crypto Provider KEK - and the shared secret is
// taken out raw via BCRYPT_KDF_RAW_SECRET ("TRUNCATE"), then fed to the
// single, self-contained HKDF-SHA512 (RFC 5869) implementation below.
// NCryptDeriveKey has no HKDF of its own. BCRYPT_KDF_RAW_SECRET returns the
// shared point's X coordinate little-endian; it is reversed to the
// conventional big-endian form before HKDF, which is what the Linux
// implementation (RustCrypto's raw_secret_bytes) feeds HKDF too.

namespace hkdfguard {
    // Anonymous namespace = internal linkage = "private to this file"; see
    // aes_gcm.cpp's comment on the same construct for the full explanation.
    namespace {
        // Fixed prefix of the HKDF "info" parameter, for *domain separation*:
        // it ties the derived wrapping key to this exact protocol, so the
        // derivation can never collide with some unrelated use of the same
        // ECDH inputs. The same string as the Linux build's HKDF_INFO_PREFIX;
        // its "v1" is the wrap protocol's version, matching the payload's
        // version byte. Cryptographic input: changing it changes every
        // wrapping key, and the golden-payload test (tests/test_roundtrip.cpp
        // section 29) fails.
        constexpr char kHkdfInfoPrefix[] = "hkdfguard-wrap-v1:";
        constexpr size_t kSharedSecretLen = 32; // P-256 ECDH shared secret (X-coordinate)

        // HKDF info = prefix || u16le(len(service)) || service ||
        // authenticated (header || KEK fingerprint) - the Linux build's
        // derive_wrapping_key, byte for byte. The length prefix keeps the
        // concatenation unambiguous. Not secret - all of it is public - so a
        // plain vector rather than a SecureBuffer.
        std::vector<uint8_t> BuildHkdfInfo(const std::string &service, const std::vector<uint8_t> &authenticated) {
            constexpr size_t prefix_len = sizeof(kHkdfInfoPrefix) - 1; // exclude NUL
            if (service.size() > 0xFFFF) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "service name too long for the HKDF info");
            }
            std::vector<uint8_t> info;
            info.reserve(prefix_len + 2 + service.size() + authenticated.size());
            info.insert(info.end(), kHkdfInfoPrefix, kHkdfInfoPrefix + prefix_len);
            info.push_back(static_cast<uint8_t>(service.size() & 0xFF));
            info.push_back(static_cast<uint8_t>((service.size() >> 8) & 0xFF));
            info.insert(info.end(), service.begin(), service.end());
            info.insert(info.end(), authenticated.begin(), authenticated.end());
            return info;
        }

        // Exports the public part of an ECDH P-256 key held by NCrypt (exporting the
        // public key is always permitted, independent of the key's export policy)
        // as raw X||Y bytes.
        void ExportNCryptEccPublicKey(NCRYPT_KEY_HANDLE key, uint8_t out[kPublicPointLen]) {
            // Windows' "ask for the size first, then ask again with a big-enough
            // buffer" pattern, used throughout Win32/CNG: the first call passes a
            // null output pointer and 0 length, and the API responds by writing the
            // *required* size into `cb` (via the `&cb` out-parameter) instead of
            // actually exporting anything.
            DWORD cb = 0;
            SECURITY_STATUS status = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &cb, 0);
            // SECURITY_STATUS is NCrypt's equivalent of BCrypt's NTSTATUS -
            // ERROR_SUCCESS (0) means success, anything else is a specific failure
            // code. `sizeof(BCRYPT_ECCKEY_BLOB)` is the fixed-size header every ECC
            // key blob starts with (see below); if the reported size isn't even
            // big enough to hold that header, something is already wrong.
            if (status != ERROR_SUCCESS || cb <= sizeof(BCRYPT_ECCKEY_BLOB)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "NCryptExportKey (size query) failed");
            }

            // Second call: now that we know the required size, allocate a
            // right-sized buffer and ask NCrypt to actually fill it in.
            std::vector<uint8_t> blob(cb);
            status = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), cb, &cb, 0);
            if (status != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "NCryptExportKey failed");
            }

            // A BCRYPT_ECCPUBLIC_BLOB is a small fixed header (BCRYPT_ECCKEY_BLOB:
            // a magic number identifying the curve, plus the key size in bytes)
            // immediately followed by the raw X and Y coordinates back-to-back.
            // `reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data())` treats the
            // first bytes of the buffer *as if* they were a BCRYPT_ECCKEY_BLOB
            // struct laid directly over that memory - this only works because CNG
            // guarantees that's exactly the byte layout it wrote there.
            const auto *header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB *>(blob.data());
            // Sanity-check this is really a P-256 ECDH key (the P-256 magic, not
            // the generic magic another 256-bit curve would export with, and
            // 32-byte coordinates) with enough bytes - as actually written by
            // the second call, `cb` - for the header plus both coordinates (64
            // total, == kPublicPointLen) before trusting the memory layout any
            // further. kek_store.cpp's VerifyCurve applies the same rule when
            // the KEK is opened.
            if (header->dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || header->cbKey != 32 ||
                cb < sizeof(BCRYPT_ECCKEY_BLOB) + kPublicPointLen) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "unexpected ECC public key blob format");
            }
            // Copy just the X||Y coordinate bytes (skipping the header) out into
            // the caller's fixed 64-byte buffer.
            memcpy(out, blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), kPublicPointLen);
        }


        // Imports raw P-256 public key bytes (X||Y) as a software BCrypt key -
        // used only as a point validator (see IsValidP256Point).
        ScopedBCryptKey ImportBCryptEccPublicKey(BCRYPT_ALG_HANDLE ecdh_alg, const uint8_t pub[kPublicPointLen]) {
            // Build a BCRYPT_ECCPUBLIC_BLOB (header + X||Y bytes) in memory so
            // BCryptImportKeyPair can parse it back into a real key object.
            std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + kPublicPointLen);
            auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(blob.data());
            header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC; // identifies "ECDH, P-256, public key"
            header->cbKey = 32; // each coordinate is 32 bytes
            memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), pub, kPublicPointLen);

            ScopedBCryptKey key;
            NTSTATUS status = BCryptImportKeyPair(
                ecdh_alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, key.put(),
                blob.data(), static_cast<ULONG>(blob.size()), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptImportKeyPair failed");
            }
            return key;
        }

        // Extracts the *raw* ECDH shared secret (no KDF applied) from a
        // secret-agreement handle produced by NCryptSecretAgreement.
        // BCRYPT_KDF_RAW_SECRET (the string "TRUNCATE") means "don't derive
        // anything, hand back the shared secret itself" - little-endian X.
        // dwFlags must be 0: NCryptDeriveKey accepts only
        // KDF_USE_SECRET_AS_HMAC_KEY_FLAG, and fails every KDF with
        // NTE_INVALID_PARAMETER if passed NCRYPT_SILENT_FLAG.
        void ExtractRawSecretFromNCrypt(NCRYPT_SECRET_HANDLE secret, SecureBuffer<kSharedSecretLen> &out) {
            DWORD result_len = 0;
            SECURITY_STATUS status = NCryptDeriveKey(
                secret, BCRYPT_KDF_RAW_SECRET, nullptr,
                out.data(), static_cast<DWORD>(out.size()), &result_len, 0);
            if (status != ERROR_SUCCESS || result_len != out.size()) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "NCryptDeriveKey(raw secret) failed");
            }
        }

        // Computes HMAC-SHA512(key, data) -> a 64-byte output. `key`/`key_len` may
        // be null/0 (used for the HKDF-Extract step with an empty salt).
        //
        // `uint8_t out[64]` here is, like the array parameters seen in other
        // headers, really just a `uint8_t*` - the literal "64" is documentation,
        // not an enforced size (see wire_format.h's note on this same notation).
        void HmacSha512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[64]) {
            // Opens CNG's SHA-512 implementation, but with the
            // BCRYPT_ALG_HANDLE_HMAC_FLAG flag - this is what makes it compute
            // *keyed* HMAC-SHA512 rather than plain unkeyed SHA-512.
            ScopedBCryptAlg alg;
            NTSTATUS status = BCryptOpenAlgorithmProvider(
                alg.put(), BCRYPT_SHA512_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "open HMAC-SHA512 provider failed");
            }

            // CNG hash/HMAC operations need a caller-supplied scratch buffer
            // ("hash object") to hold their internal working state, whose required
            // size varies by algorithm/provider - so, another instance of Windows'
            // "ask for the size, then allocate that much" pattern: BCryptGetProperty
            // here queries BCRYPT_OBJECT_LENGTH, the size CNG needs for that
            // scratch buffer, writing it into `hash_object_len`.
            DWORD hash_object_len = 0, cb_result = 0;
            status = BCryptGetProperty(
                alg.get(), BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&hash_object_len), sizeof(hash_object_len), &cb_result, 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "query HMAC object length failed");
            }

            // Allocate that scratch buffer, and create the actual hash/HMAC object.
            // Passing `key`/`key_len` here (CNG's `pbSecret`/`cbSecret` parameters)
            // is what seeds this as an *HMAC* keyed with `key`, rather than a plain
            // hash - when `key` is null/key_len is 0 (the HKDF-Extract call below),
            // this becomes HMAC with an empty key, per RFC 5869's "no salt
            // provided" default (see the comment on HkdfSha512 below for why that's
            // equivalent).
            std::vector<uint8_t> hash_object(hash_object_len);
            // CNG keeps the HMAC's state - derived from `key`, which is the ECDH
            // secret or the PRK - in this buffer. The guard wipes it on every
            // way out of this function, a failed CNG call's exception included.
            // Declared after the vector it wipes and before `hash`, so it runs
            // after BCryptDestroyHash has released the object and before the
            // vector frees the memory.
            ScopedSecureZero wipe_hash_object(hash_object.data(), hash_object.size());
            ScopedBCryptHash hash;
            status = BCryptCreateHash(
                alg.get(), hash.put(), hash_object.data(), hash_object_len,
                const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptCreateHash(HMAC) failed");
            }

            // Feeds `data` into the hash/HMAC's running state. CNG's hashing API is
            // split into Create -> HashData (possibly called more than once, to
            // feed data in chunks) -> FinishHash; this project always has all its
            // input available at once, so HashData is only ever called the one
            // time here.
            status = BCryptHashData(hash.get(), const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptHashData failed");
            }

            // Finalizes the computation and writes the 64-byte HMAC-SHA512 result
            // into `out`.
            status = BCryptFinishHash(hash.get(), out, 64, 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptFinishHash failed");
            }
            // On return - or on any throw above - `hash` is destroyed, then
            // `wipe_hash_object` zeroes CNG's scratch buffer, then the vector
            // and `alg` are released, in reverse order of declaration.
        }

        // HKDF-SHA512 (RFC 5869), specialized for a 32-byte output: since the
        // requested OKM length (32) is less than the hash length (64),
        // HKDF-Expand needs exactly one round, T(1) = HMAC-SHA512(PRK, info ||
        // 0x01), truncated to its first 32 bytes. `salt` is HKDF-Extract's
        // salt - here, the payload's salt.
        void HkdfSha512(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                        const std::vector<uint8_t> &info, SecureBuffer<32> &okm_out) {
            std::vector<uint8_t> t1_input(info.size() + 1);
            memcpy(t1_input.data(), info.data(), info.size());
            t1_input[info.size()] = 0x01;

            // `prk` and `t1` - the HKDF-Extract output and the full HKDF-Expand
            // output, both key material derived from the ECDH shared secret -
            // are scoped to exactly the statements that need them, so their
            // destructors (SecureZeroMemory, see secure_buffer.h) wipe them the
            // instant this block ends.
            {
                // HKDF-Extract: PRK = HMAC-SHA512(salt, IKM).
                SecureBuffer<64> prk;
                HmacSha512(salt, salt_len, ikm, ikm_len, prk.data());
                // HKDF-Expand's one round, truncated to 32 bytes.
                SecureBuffer<64> t1;
                HmacSha512(prk.data(), prk.size(), t1_input.data(), t1_input.size(), t1.data());
                memcpy(okm_out.data(), t1.data(), okm_out.size());
            } // <- prk's and t1's destructors (zeroing them) run here, right now.

            // Public bytes plus a counter: wiped only as defense in depth.
            SecureZero(t1_input.data(), t1_input.size());
        }
    } // namespace

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    namespace {
        // See SetTestEcdhProviderFault in ecdh_hkdf.h. Off by default, so a
        // test binary that never sets it behaves exactly like the DLL.
        bool g_testEcdhProviderFault = false;
    }

    void SetTestEcdhProviderFault(bool failOpen) {
        g_testEcdhProviderFault = failOpen;
    }
#endif

    bool IsValidP256Point(const uint8_t pub[kPublicPointLen]) {
        ScopedBCryptAlg ecdh_alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(ecdh_alg.put(), BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testEcdhProviderFault) {
            // As if the open had failed. The real handle (if any) is
            // released by ecdh_alg's destructor as usual.
            status = static_cast<NTSTATUS>(0xC0000225L); // STATUS_NOT_FOUND
        }
#endif
        if (!BCRYPT_SUCCESS(status)) {
            // Infrastructure failure (can't even open the software provider),
            // not a verdict on the point.
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "open ECDH provider failed");
        }
        try {
            // The import itself is the validation: the software provider
            // rejects any X||Y that isn't a point on P-256 (see
            // SecurityAssumptions.md for the fuzzing that established this).
            // The key object is discarded - only the verdict is wanted.
            ImportBCryptEccPublicKey(ecdh_alg.get(), pub);
            return true;
        } catch (const HkdfGuardError &) {
            return false;
        }
    }
    void ComputeKekFingerprint(NCRYPT_KEY_HANDLE kek_key, uint8_t out[kFingerprintLen]) {
        uint8_t kek_pub[kPublicPointLen];
        ExportNCryptEccPublicKey(kek_key, kek_pub);

        // Plain (unkeyed) SHA-256 via CNG - the same Create/HashData/Finish
        // sequence HmacSha512 above uses, minus the HMAC flag and key.
        ScopedBCryptAlg alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "open SHA-256 provider failed");
        }

        DWORD hash_object_len = 0, cb_result = 0;
        status = BCryptGetProperty(
            alg.get(), BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_object_len), sizeof(hash_object_len), &cb_result, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "query SHA-256 object length failed");
        }

        std::vector<uint8_t> hash_object(hash_object_len);
        ScopedBCryptHash hash;
        status = BCryptCreateHash(alg.get(), hash.put(), hash_object.data(), hash_object_len, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptCreateHash(SHA-256) failed");
        }

        status = BCryptHashData(hash.get(), kek_pub, static_cast<ULONG>(kPublicPointLen), 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptHashData(SHA-256) failed");
        }

        status = BCryptFinishHash(hash.get(), out, static_cast<ULONG>(kFingerprintLen), 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptFinishHash(SHA-256) failed");
        }
        // Nothing here is secret (a public key and its public hash), so no
        // zeroing is needed beyond the RAII handles closing themselves.
    }

    void DeriveWrappingKey(
        NCRYPT_PROV_HANDLE provider,
        NCRYPT_KEY_HANDLE kek_key,
        const std::string &service,
        const std::vector<uint8_t> &authenticated,
        SecureBuffer<32> &wrapping_key_out) {
        if (authenticated.size() != kAuthenticatedLen) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "authenticated bytes have the wrong length");
        }
        // The salt is the header's, read from `authenticated` - the caller's
        // own copy, built once from the payload - so the point, HKDF's salt
        // and HKDF's info are all derived from the same bytes, whatever
        // another thread does to the caller's payload buffer meanwhile.
        const uint8_t *salt_copy = authenticated.data() + kSaltOffset;

        // H(salt): a P-256 point nobody knows the discrete log of. It is
        // computed here, not taken from the payload, so no attacker-chosen
        // point ever reaches the KEK. It is still checked through the
        // fuzzed BCrypt import before any KSP sees it: a point that failed
        // would mean a bug in hash_to_curve.cpp, and fails closed.
        uint8_t point[kPublicPointLen];
        PayloadEcdhPoint(salt_copy, point);
        if (!IsValidP256Point(point)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "hash-to-curve produced a point not on P-256");
        }

        // Import H(salt) on the KEK's own provider, to pair with the KEK's
        // private key. NCRYPT_SILENT_FLAG on both calls: a key with a
        // UI-requiring protection policy must fail, not prompt or block,
        // inside a non-interactive service.
        std::vector<uint8_t> point_blob(sizeof(BCRYPT_ECCKEY_BLOB) + kPublicPointLen);
        auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(point_blob.data());
        header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        header->cbKey = 32;
        memcpy(point_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), point, kPublicPointLen);

        ScopedNCryptKey point_key;
        SECURITY_STATUS status = NCryptImportKey(
            provider, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, point_key.put(),
            point_blob.data(), static_cast<DWORD>(point_blob.size()), NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "NCryptImportKey(H(salt)) failed");
        }

        // Z = ECDH(KEK private key, H(salt)) - the step that runs inside the
        // TPM for a Platform Crypto Provider KEK. This is a use of the KEK's
        // private key, so it needs the same permission as unwrap: an account
        // the KEK's ACL doesn't admit is refused when it opens the key.
        ScopedNCryptSecret secret;
        status = NCryptSecretAgreement(kek_key, point_key.get(), secret.put(), NCRYPT_SILENT_FLAG);
        point_key.reset();
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "NCryptSecretAgreement failed");
        }

        // Raw Z, little-endian from CNG, reversed into big-endian X.
        SecureBuffer<kSharedSecretLen> z_little_endian;
        ExtractRawSecretFromNCrypt(secret.get(), z_little_endian);
        secret.reset(); // shared secret is highly sensitive; destroy immediately once extracted
        SecureBuffer<kSharedSecretLen> z;
        for (size_t i = 0; i < kSharedSecretLen; ++i) {
            z.data()[i] = z_little_endian.data()[kSharedSecretLen - 1 - i];
        }

        // HKDF-SHA512(salt = the payload's salt, IKM = Z, info = prefix ||
        // service || authenticated) -> the 32-byte AES-256-GCM wrapping key,
        // written straight into the caller's buffer.
        std::vector<uint8_t> info = BuildHkdfInfo(service, authenticated);
        HkdfSha512(salt_copy, kSaltLen, z.data(), z.size(), info, wrapping_key_out);
        // `z` and `z_little_endian` are wiped by their destructors as this
        // function returns.
    }
} // namespace hkdfguard