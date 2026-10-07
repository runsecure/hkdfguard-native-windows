#include "ecdh_hkdf.h"
#include "errors.h"
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <cstring> // memcpy
#include <vector>

#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif

// Design note: wrap-side (BCryptSecretAgreement, software ephemeral key) and
// unwrap-side (NCryptSecretAgreement, possibly TPM-backed KEK) derivation
// MUST produce bit-identical wrapping keys from identical inputs, or every
// unwrap would fail authentication. Rather than rely on two separately
// implemented "black box" HKDF code paths inside BCrypt and NCrypt (whose
// KDF-identifier support differs - NCryptDeriveKey, verified against the
// installed Windows SDK headers, has no HKDF algorithm ID at all), both
// sides extract the *raw* ECDH shared secret via the well-documented
// BCRYPT_KDF_RAW_SECRET ("TRUNCATE") identifier - supported by both
// BCryptDeriveKey and NCryptDeriveKey, since they take the same secret
// handle shape and the same pwszKDF string - and then run a single,
// self-contained HKDF-SHA512 (RFC 5869) implementation, written once below
// and used identically by both paths.

namespace hkdfguard {
    // Anonymous namespace = internal linkage = "private to this file"; see
    // aes_gcm.cpp's comment on the same construct for the full explanation.
    namespace {
        // Fixed context string mixed into the HKDF "info" parameter (see
        // BuildHkdfInfo below) purely for *domain separation*: it makes the derived
        // wrapping key depend on "this exact protocol, version 1" and not just on
        // the raw numbers involved, so this derivation can never accidentally
        // collide with some unrelated use of the same ECDH keys/HKDF elsewhere.
        // `constexpr char kHkdfContext[] = "..."` declares a compile-time-constant
        // C-style character array; `sizeof(kHkdfContext) - 1` (used below) is the
        // standard idiom for "the string's length, not counting the automatic
        // trailing '\0' the compiler appends to every string literal."
        constexpr char kHkdfContext[] = "HkdfGuardWin-DEK-Wrap-v1";
        constexpr size_t kSharedSecretLen = 32; // P-256 ECDH shared secret (X-coordinate)

        // Builds the HKDF "info" byte string that binds the derived wrapping key to
        // both parties' public keys, by concatenating: the fixed context string,
        // the ephemeral public key, and the KEK's public key. Because this is
        // recomputed identically on both the wrap side and the unwrap side from the
        // same two public keys, both sides feed HKDF the exact same info bytes -
        // one of the two ingredients (along with the raw shared secret) that must
        // match exactly for wrap and unwrap to derive the same wrapping key.
        //
        // Returned as a `std::vector<uint8_t>` (a dynamically-sized, heap-allocated
        // array, as opposed to a fixed-size C array or this project's own
        // SecureBuffer) because none of these three inputs are secret - they're all
        // public keys and a public string - so there's no need for the
        // zero-on-destruction behavior SecureBuffer provides, and a vector's
        // runtime-computed size is simpler here than juggling a fixed-size buffer.
        std::vector<uint8_t> BuildHkdfInfo(
            const uint8_t ephemeral_pub[kEphemeralPubLen],
            const uint8_t kek_pub[kEphemeralPubLen]) {
            constexpr size_t context_len = sizeof(kHkdfContext) - 1; // exclude NUL
            // Pre-size the vector to hold exactly all three pieces concatenated, so
            // the memcpy calls below never need to grow/reallocate it.
            std::vector<uint8_t> info(context_len + kEphemeralPubLen + kEphemeralPubLen);
            // `info.data()` gives a raw pointer to the vector's first byte; `p` is
            // then advanced by pointer arithmetic after each memcpy so the next
            // copy lands immediately after the previous one, building up the
            // concatenation piece by piece.
            uint8_t *p = info.data();
            memcpy(p, kHkdfContext, context_len);
            p += context_len;
            memcpy(p, ephemeral_pub, kEphemeralPubLen);
            p += kEphemeralPubLen;
            memcpy(p, kek_pub, kEphemeralPubLen);
            return info;
        }

        // Exports the public part of an ECDH P-256 key held by NCrypt (exporting the
        // public key is always permitted, independent of the key's export policy)
        // as raw X||Y bytes.
        void ExportNCryptEccPublicKey(NCRYPT_KEY_HANDLE key, uint8_t out[kEphemeralPubLen]) {
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
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "NCryptExportKey (size query) failed");
            }

            // Second call: now that we know the required size, allocate a
            // right-sized buffer and ask NCrypt to actually fill it in.
            std::vector<uint8_t> blob(cb);
            status = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), cb, &cb, 0);
            if (status != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "NCryptExportKey failed");
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
            // total, == kEphemeralPubLen) before trusting the memory layout any
            // further. kek_store.cpp's VerifyCurve applies the same rule when
            // the KEK is opened.
            if (header->dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || header->cbKey != 32 ||
                cb < sizeof(BCRYPT_ECCKEY_BLOB) + kEphemeralPubLen) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "unexpected ECC public key blob format");
            }
            // Copy just the X||Y coordinate bytes (skipping the header) out into
            // the caller's fixed 64-byte buffer.
            memcpy(out, blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), kEphemeralPubLen);
        }

        // Imports raw P-256 public key bytes (X||Y) as a software BCrypt key, for
        // use in the wrap-side (ephemeral, software-only) ECDH computation.
        ScopedBCryptKey ImportBCryptEccPublicKey(BCRYPT_ALG_HANDLE ecdh_alg, const uint8_t pub[kEphemeralPubLen]) {
            // The reverse of ExportNCryptEccPublicKey above: build a
            // BCRYPT_ECCPUBLIC_BLOB (header + X||Y bytes) in memory so
            // BCryptImportKeyPair can parse it back into a real key object.
            std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + kEphemeralPubLen);
            // `reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data())` (non-const this
            // time) lets us write through `header` directly into the start of the
            // vector's storage, filling in the struct's two fields in place.
            auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(blob.data());
            header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC; // identifies "ECDH, P-256, public key"
            header->cbKey = 32; // each coordinate is 32 bytes
            // Copy the actual X||Y bytes in immediately after the header.
            memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), pub, kEphemeralPubLen);

            ScopedBCryptKey key;
            NTSTATUS status = BCryptImportKeyPair(
                ecdh_alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, key.put(),
                blob.data(), static_cast<ULONG>(blob.size()), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptImportKeyPair failed");
            }
            return key;
        }

        // Extracts the *raw* ECDH shared secret (no KDF applied) from a
        // software-computed BCrypt secret-agreement handle. BCRYPT_KDF_RAW_SECRET
        // (the string "TRUNCATE") is a special pwszKDF value that means "don't
        // actually derive anything, just hand back the shared secret bytes
        // themselves" - it's what lets this codebase apply its own, single,
        // hand-written HKDF implementation identically on both the BCrypt and
        // NCrypt sides (see the file-level Design note above).
        void ExtractRawSecretFromBCrypt(BCRYPT_SECRET_HANDLE secret, SecureBuffer<kSharedSecretLen> &out) {
            ULONG result_len = 0;
            NTSTATUS status = BCryptDeriveKey(
                secret, BCRYPT_KDF_RAW_SECRET, nullptr,
                out.data(), static_cast<ULONG>(out.size()), &result_len, 0);
            if (!BCRYPT_SUCCESS(status) || result_len != out.size()) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptDeriveKey(raw secret) failed");
            }
        }

        // Same idea as ExtractRawSecretFromBCrypt above, but for a secret-agreement
        // handle produced by NCryptSecretAgreement instead (the TPM/vTPM-capable
        // path) - the NCrypt equivalent function, NCryptDeriveKey, happens to accept
        // the exact same BCRYPT_KDF_RAW_SECRET string as its own pwszKDF parameter.
        void ExtractRawSecretFromNCrypt(NCRYPT_SECRET_HANDLE secret, SecureBuffer<kSharedSecretLen> &out) {
            DWORD result_len = 0;
            SECURITY_STATUS status = NCryptDeriveKey(
                secret, BCRYPT_KDF_RAW_SECRET, nullptr,
                out.data(), static_cast<DWORD>(out.size()), &result_len, 0);
            if (status != ERROR_SUCCESS || result_len != out.size()) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "NCryptDeriveKey(raw secret) failed");
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
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "open HMAC-SHA512 provider failed");
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
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "query HMAC object length failed");
            }

            // Allocate that scratch buffer, and create the actual hash/HMAC object.
            // Passing `key`/`key_len` here (CNG's `pbSecret`/`cbSecret` parameters)
            // is what seeds this as an *HMAC* keyed with `key`, rather than a plain
            // hash - when `key` is null/key_len is 0 (the HKDF-Extract call below),
            // this becomes HMAC with an empty key, per RFC 5869's "no salt
            // provided" default (see the comment on HkdfSha512 below for why that's
            // equivalent).
            std::vector<uint8_t> hash_object(hash_object_len);
            ScopedBCryptHash hash;
            status = BCryptCreateHash(
                alg.get(), hash.put(), hash_object.data(), hash_object_len,
                const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptCreateHash(HMAC) failed");
            }

            // Feeds `data` into the hash/HMAC's running state. CNG's hashing API is
            // split into Create -> HashData (possibly called more than once, to
            // feed data in chunks) -> FinishHash; this project always has all its
            // input available at once, so HashData is only ever called the one
            // time here.
            status = BCryptHashData(hash.get(), const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptHashData failed");
            }

            // Finalizes the computation and writes the 64-byte HMAC-SHA512 result
            // into `out`.
            status = BCryptFinishHash(hash.get(), out, 64, 0);
            // The scratch buffer CNG used internally (which, depending on the key
            // this HMAC was computed with, may retain sensitive intermediate state)
            // is wiped immediately after FinishHash, *before* even checking
            // whether that call succeeded - so it's zeroed unconditionally on every
            // path out of this function, success or failure alike.
            SecureZero(hash_object.data(), hash_object.size());
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptFinishHash failed");
            }
            // `alg` and `hash` (both RAII handles) are closed automatically here as
            // the function returns.
        }

        // HKDF-SHA512 (RFC 5869), specialized for a 32-byte output: since the
        // requested OKM length (32) is less than the hash length (64), HKDF-Expand
        // still needs exactly one round (T(1) = HMAC-SHA512(PRK, info || 0x01)),
        // per RFC 5869's Expand step - it's just that this T(1) is now truncated to
        // the first 32 bytes rather than used in full, since 32 < HashLen. The
        // empty-salt HKDF-Extract step (HMAC-SHA512 with a zero-length key) is
        // equivalent to RFC 5869's "no salt" default (HashLen zero bytes), because
        // HMAC zero-pads any key shorter than the block size to the same all-zero
        // 128-byte block either way.
        void HkdfSha512(const uint8_t *ikm, size_t ikm_len, const std::vector<uint8_t> &info,
                        SecureBuffer<32> &okm_out) {
            // The HKDF-Expand input, `info || 0x01` (the info bytes followed by a
            // single counter byte, per RFC 5869's definition of T(1)), doesn't
            // depend on the PRK at all, so it's fine to build it before computing
            // the PRK - which is done here so the nested block below can be as
            // small and single-purpose as possible.
            std::vector<uint8_t> t1_input(info.size() + 1);
            memcpy(t1_input.data(), info.data(), info.size());
            t1_input[info.size()] = 0x01;

            // This inner `{ ... }` is an ordinary, otherwise-unremarkable C++
            // block - but introducing one here on purpose (rather than just
            // declaring `prk`/`t1` alongside `t1_input` above) is itself a
            // deliberate security measure: `prk` and `t1` (the HKDF-Extract output
            // and the full, untruncated HKDF-Expand output - both sensitive key
            // material derived from the ECDH shared secret) are scoped to *exactly*
            // the statements that need them. Their destructors - which wipe them
            // via SecureZeroMemory, see SecureBuffer in secure_buffer.h - therefore
            // run the instant this block ends, immediately after their last use,
            // rather than only at the end of the whole HkdfSha512 function (which
            // would leave them sitting in memory, unused but unwiped, through the
            // SecureZero(t1_input...) call below).
            {
                // HKDF-Extract: PRK = HMAC-SHA512(salt, IKM). Passing `nullptr, 0`
                // as the key here means "no salt" - see the empty-salt equivalence
                // explained in this function's doc comment above.
                SecureBuffer<64> prk;
                HmacSha512(nullptr, 0, ikm, ikm_len, prk.data());
                // HKDF-Expand's one and only round: T(1) = HMAC-SHA512(PRK, info ||
                // 0x01). Unlike the SHA-256 version of this function, T(1) (64
                // bytes) is now larger than the 32-byte output this function
                // promises, so it's computed into its own buffer first...
                SecureBuffer<64> t1;
                HmacSha512(prk.data(), prk.size(), t1_input.data(), t1_input.size(), t1.data());
                // ...and then truncated to the first 32 bytes, per RFC 5869's
                // HKDF-Expand definition (OKM = T(1) truncated to L octets, when
                // L <= HashLen).
                memcpy(okm_out.data(), t1.data(), okm_out.size());
            } // <- prk's and t1's destructors (zeroing them) run here, right now.

            // `t1_input` only ever held public information (the info bytes) plus a
            // single non-secret counter byte, so this wipe is just defense in
            // depth, not a secrecy requirement the way `prk`'s and `t1`'s were.
            SecureZero(t1_input.data(), t1_input.size());
        }
    } // namespace

    void ValidateEphemeralPublicKey(const uint8_t pub[kEphemeralPubLen]) {
        ScopedBCryptAlg ecdh_alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(ecdh_alg.put(), BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            // Infrastructure failure (can't even open the software provider),
            // not a verdict on the point - reported as CRYPTO, not MALFORMED,
            // so a caller can't mistake it for "the payload is bad."
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "open ECDH provider failed");
        }
        try {
            // The import itself is the validation: the software provider
            // rejects any X||Y that isn't a point on P-256 (see
            // SecurityAssumptions.md for the fuzzing that established this).
            // The resulting key object is discarded immediately - only the
            // accept/reject verdict is wanted here.
            ImportBCryptEccPublicKey(ecdh_alg.get(), pub);
        } catch (const HkdfGuardError &) {
            throw HkdfGuardError(HKDFGUARD_ERR_MALFORMED, "ephemeral public key is not a valid P-256 point");
        }
    }

    void ComputeKekFingerprint(NCRYPT_KEY_HANDLE kek_key, uint8_t out[kFingerprintLen]) {
        uint8_t kek_pub[kEphemeralPubLen];
        ExportNCryptEccPublicKey(kek_key, kek_pub);

        // Plain (unkeyed) SHA-256 via CNG - the same Create/HashData/Finish
        // sequence HmacSha512 above uses, minus the HMAC flag and key.
        ScopedBCryptAlg alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "open SHA-256 provider failed");
        }

        DWORD hash_object_len = 0, cb_result = 0;
        status = BCryptGetProperty(
            alg.get(), BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_object_len), sizeof(hash_object_len), &cb_result, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "query SHA-256 object length failed");
        }

        std::vector<uint8_t> hash_object(hash_object_len);
        ScopedBCryptHash hash;
        status = BCryptCreateHash(alg.get(), hash.put(), hash_object.data(), hash_object_len, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptCreateHash(SHA-256) failed");
        }

        status = BCryptHashData(hash.get(), kek_pub, static_cast<ULONG>(kEphemeralPubLen), 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptHashData(SHA-256) failed");
        }

        status = BCryptFinishHash(hash.get(), out, static_cast<ULONG>(kFingerprintLen), 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptFinishHash(SHA-256) failed");
        }
        // Nothing here is secret (a public key and its public hash), so no
        // zeroing is needed beyond the RAII handles closing themselves.
    }

    void DeriveWrappingKeyForWrap(
        NCRYPT_KEY_HANDLE kek_key,
        uint8_t ephemeral_pub_out[kEphemeralPubLen],
        SecureBuffer<32> &wrapping_key_out) {
        // Step 1: get the KEK's *public* key bytes. Note `kek_key` itself is
        // never used for anything else in this function - the private key
        // (possibly locked inside a TPM) is not needed at all on the wrap side,
        // only its public counterpart, which any key is always allowed to
        // export.
        uint8_t kek_pub[kEphemeralPubLen];
        ExportNCryptEccPublicKey(kek_key, kek_pub);

        // Step 2: generate a brand-new, one-time-use ("ephemeral") P-256 key
        // pair entirely in software via plain BCrypt (as opposed to NCrypt) -
        // there's no reason to involve the TPM for a key that's thrown away the
        // moment this function returns.
        ScopedBCryptAlg ecdh_alg;
        NTSTATUS status = BCryptOpenAlgorithmProvider(ecdh_alg.put(), BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "open ECDH provider failed");
        }

        // BCryptGenerateKeyPair creates the key pair "in progress" (some
        // algorithms allow tweaking properties before it's finalized);
        // BCryptFinalizeKeyPair below locks it in as ready to use. `256` is the
        // key length in bits, matching P-256.
        ScopedBCryptKey ephemeral_key;
        status = BCryptGenerateKeyPair(ecdh_alg.get(), ephemeral_key.put(), 256, 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "generate ephemeral key pair failed");
        }
        status = BCryptFinalizeKeyPair(ephemeral_key.get(), 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "finalize ephemeral key pair failed");
        }

        // Export the ephemeral key's *public* half (X||Y bytes) so it can be
        // written into the wrapped payload later - this is what lets the
        // unwrap side later reconstruct the same shared secret using the KEK's
        // private key. Same "query size, then fetch" two-call pattern seen
        // earlier in ExportNCryptEccPublicKey, but via the BCrypt (not NCrypt)
        // export function, since `ephemeral_key` is a BCrypt key object.
        DWORD cb = 0;
        status = BCryptExportKey(ephemeral_key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &cb, 0);
        if (!BCRYPT_SUCCESS(status) || cb <= sizeof(BCRYPT_ECCKEY_BLOB)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptExportKey (size query) failed");
        }
        std::vector<uint8_t> ephemeral_blob(cb);
        status = BCryptExportKey(ephemeral_key.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, ephemeral_blob.data(), cb, &cb,
                                 0);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptExportKey failed");
        }
        // Skip past the blob's header to copy out just the X||Y coordinate
        // bytes into the caller's output parameter.
        memcpy(ephemeral_pub_out, ephemeral_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), kEphemeralPubLen);

        // Step 3: bring the KEK's public key (fetched in step 1) into the
        // BCrypt world too, as a BCrypt key object, so it can be used together
        // with the software ephemeral key below.
        ScopedBCryptKey kek_pub_key = ImportBCryptEccPublicKey(ecdh_alg.get(), kek_pub);

        // Step 4: the actual Diffie-Hellman computation - combines our
        // ephemeral *private* key with the KEK's *public* key to produce a
        // shared secret only someone holding the KEK's private key could ever
        // also compute (from the ephemeral *public* key, which travels along in
        // the wrapped payload).
        ScopedBCryptSecret secret;
        status = BCryptSecretAgreement(ephemeral_key.get(), kek_pub_key.get(), secret.put(), 0);
        // The ephemeral *private* key was only ever needed for the line
        // immediately above; explicitly resetting it here (rather than waiting
        // for the function to return and its destructor to fire naturally)
        // closes/destroys it as early as possible, per this project's "minimize
        // secret lifetime" policy - it's dead the instant the agreement is
        // computed, so it's disposed of the instant the agreement is computed.
        ephemeral_key.reset();
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptSecretAgreement failed");
        }

        // Step 5: pull the raw shared-secret bytes out of the opaque
        // BCRYPT_SECRET_HANDLE (see ExtractRawSecretFromBCrypt's comment for
        // why "raw", not KDF-processed, bytes are requested here).
        SecureBuffer<kSharedSecretLen> raw_secret;
        ExtractRawSecretFromBCrypt(secret.get(), raw_secret);
        secret.reset(); // shared secret is highly sensitive; destroy immediately once extracted

        // Step 6: HKDF-SHA512 over the raw shared secret, with the info string
        // binding it to both public keys (see BuildHkdfInfo above), writes the
        // final 32-byte wrapping key straight into the caller's
        // `wrapping_key_out` - this function never holds a second copy of the
        // final wrapping key itself.
        std::vector<uint8_t> info = BuildHkdfInfo(ephemeral_pub_out, kek_pub);
        HkdfSha512(raw_secret.data(), raw_secret.size(), info, wrapping_key_out);
        // `raw_secret` (a SecureBuffer) is wiped automatically the instant this
        // function returns, immediately after the line above - its only use in
        // this whole function - since C++ runs a local variable's destructor
        // at the end of its enclosing scope, and this is the last statement in
        // that scope.
    }

    void DeriveWrappingKeyForUnwrap(
        NCRYPT_PROV_HANDLE provider,
        NCRYPT_KEY_HANDLE kek_key,
        const uint8_t ephemeral_pub[kEphemeralPubLen],
        SecureBuffer<32> &wrapping_key_out) {
        // `ephemeral_pub` points directly into the caller's wrapped-payload
        // buffer (see hkdfguard.cpp's ParsedWrappedDek - it aliases the
        // original `wrapped` pointer, nothing is copied yet at this point),
        // which - unlike a buffer this function owns - could in principle be
        // mutated by another thread in the same host process between one
        // read of it and the next. Copied into a local, fixed array exactly
        // once, right here, before anything else touches it: every
        // subsequent use in this function (the validation below, the blob
        // built for NCryptImportKey, and the HKDF info string) reads *this*
        // copy, never the caller's buffer again. Without this,
        // ValidateEphemeralPublicKey could validate one set of bytes while
        // NCryptImportKey/NCryptSecretAgreement below are handed a different,
        // never-validated set read moments later - reopening the exact
        // invalid-curve attack surface that validation exists to close,
        // through a check-then-use race rather than a missing check.
        uint8_t ephemeral_pub_copy[kEphemeralPubLen];
        memcpy(ephemeral_pub_copy, ephemeral_pub, kEphemeralPubLen);

        // `ephemeral_pub_copy` is the one input to this whole function that
        // an attacker controls outright (it's read straight out of the
        // wrapped payload), and it's about to be combined with the
        // long-term KEK *private* key in NCryptSecretAgreement below -
        // exactly the setup for an invalid-curve / small-subgroup attack if
        // an off-curve point were ever accepted. Reject it here, through the
        // software provider whose point validation this project has
        // actually fuzzed, before it reaches NCryptImportKey on whichever
        // KSP the payload's ProviderType byte selected - so the TPM path is
        // protected by the same verified check as the software path, rather
        // than each KSP's own untested import validation.
        ValidateEphemeralPublicKey(ephemeral_pub_copy);

        // Fetch the KEK's public key too, only so it can be mixed into the
        // HKDF info string identically to how the wrap side computed it
        // (the private key is what actually gets used for the ECDH step
        // below).
        uint8_t kek_pub[kEphemeralPubLen];
        ExportNCryptEccPublicKey(kek_key, kek_pub);

        // Rebuild a BCRYPT_ECCPUBLIC_BLOB (header + X||Y) from the
        // now-validated local copy - same layout ImportBCryptEccPublicKey
        // builds, but this one needs to become an *NCrypt* key (via
        // NCryptImportKey just below) rather than a BCrypt one, since it has
        // to be paired with the NCrypt-managed KEK private key for the
        // agreement call that follows.
        std::vector<uint8_t> ephemeral_blob(sizeof(BCRYPT_ECCKEY_BLOB) + kEphemeralPubLen);
        auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(ephemeral_blob.data());
        header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        header->cbKey = 32;
        memcpy(ephemeral_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), ephemeral_pub_copy, kEphemeralPubLen);

        // NCRYPT_SILENT_FLAG on both calls below: without it, a pre-planted
        // key or import target with a UI-requiring protection policy could
        // make either call display a credential/consent prompt - or block
        // indefinitely waiting for one - inside what is typically a
        // non-interactive service process. With it, such a case fails with
        // an error instead. Confirmed accepted (not NTE_BAD_FLAGS) by both
        // NCryptImportKey and NCryptSecretAgreement empirically.
        ScopedNCryptKey ephemeral_ncrypt_key;
        SECURITY_STATUS status = NCryptImportKey(
            provider, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, ephemeral_ncrypt_key.put(),
            ephemeral_blob.data(), static_cast<DWORD>(ephemeral_blob.size()), NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "NCryptImportKey(ephemeral public) failed");
        }

        ScopedNCryptSecret secret;
        // This is the one step that may execute inside a TPM/vTPM, since
        // kek_key's private part may be non-exportable hardware-backed key
        // material.
        status = NCryptSecretAgreement(kek_key, ephemeral_ncrypt_key.get(), secret.put(), NCRYPT_SILENT_FLAG);
        // The imported ephemeral *public* key isn't secret itself, but it's no
        // longer needed either way once the agreement has been computed, so
        // it's released promptly rather than left open until function return.
        ephemeral_ncrypt_key.reset();
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "NCryptSecretAgreement failed");
        }

        SecureBuffer<kSharedSecretLen> raw_secret;
        ExtractRawSecretFromNCrypt(secret.get(), raw_secret);
        secret.reset(); // shared secret is highly sensitive; destroy immediately once extracted

        // Identical HKDF construction to the wrap side, with
        // `ephemeral_pub_copy` and `kek_pub` swapped in the same argument
        // order BuildHkdfInfo used on the wrap side (ephemeral first, then
        // KEK) - this is what makes the two sides' `info` bytes
        // byte-for-byte identical, which combined with the
        // byte-for-byte-identical raw shared secret is what guarantees both
        // sides derive the exact same wrapping key. Using the local copy
        // here too (not the caller's `ephemeral_pub` pointer) keeps this
        // consistent with the point that was actually validated and used
        // for the ECDH step above, rather than risking a third, independent
        // read of the live payload buffer.
        std::vector<uint8_t> info = BuildHkdfInfo(ephemeral_pub_copy, kek_pub);
        HkdfSha512(raw_secret.data(), raw_secret.size(), info, wrapping_key_out);
        // As on the wrap side, `raw_secret` is wiped automatically here as the
        // function returns, immediately after its only use above.
    }
} // namespace hkdfguard
