#include "tpm2_session.h"
#include "errors.h"
#include "handle_traits.h" // ScopedBCryptKey, ScopedBCryptSecret

#include <bcrypt.h>
#include <algorithm> // std::min, std::reverse
#include <cstring>   // memcpy, strlen

namespace hkdfguard::tpm2 {
    namespace {
        [[noreturn]] void CryptoFailure(const char *what) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, what);
        }

        [[noreturn]] void BadTpmData(const char *what) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, what);
        }

        void AppendU32(Bytes &b, uint32_t v) {
            b.push_back(static_cast<uint8_t>(v >> 24));
            b.push_back(static_cast<uint8_t>(v >> 16));
            b.push_back(static_cast<uint8_t>(v >> 8));
            b.push_back(static_cast<uint8_t>(v));
        }

        void AppendLabel(Bytes &b, const char *label) {
            b.insert(b.end(), label, label + std::strlen(label));
            b.push_back(0x00);
        }

        void Append(Bytes &b, const Bytes &x) {
            b.insert(b.end(), x.begin(), x.end());
        }

        void Random(uint8_t *out, size_t len) {
            if (BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
                CryptoFailure("BCryptGenRandom failed");
            }
        }

        // Compares two equal-length MACs without an early exit.
        bool ConstantTimeEqual(const uint8_t *a, const uint8_t *b, size_t len) {
            uint8_t diff = 0;
            for (size_t i = 0; i < len; ++i) {
                diff |= static_cast<uint8_t>(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        // The CFB key and IV for one parameter: KDFa(sessionKey, "CFB",
        // nonceNewer, nonceOlder, 256), the first 16 bytes the key and the
        // rest the IV (Part 1, 21.4).
        void CfbKeyAndIv(const SecureBuffer<kSha256Len> &session_key, const Bytes &newer, const Bytes &older,
                         SecureBuffer<kSessionKeyBits / 8 + kAesBlockLen> &key_and_iv) {
            KdfaSha256(session_key.data(), session_key.size(), "CFB", newer, older, key_and_iv.data(), key_and_iv.size());
        }
    } // namespace

    void Sha256(const uint8_t *data, size_t len, uint8_t out[kSha256Len]) {
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(data), static_cast<ULONG>(len), out,
                       kSha256Len) != 0) {
            CryptoFailure("SHA-256 failed");
        }
    }

    void HmacSha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[kSha256Len]) {
        if (BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, const_cast<PUCHAR>(key), static_cast<ULONG>(key_len),
                       const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), out, kSha256Len) != 0) {
            CryptoFailure("HMAC-SHA-256 failed");
        }
    }

    void KdfaSha256(
        const uint8_t *key, size_t key_len,
        const char *label,
        const Bytes &context_u, const Bytes &context_v,
        uint8_t *out, size_t out_len) {
        // Everything hashed is public; only the key and the output are secret.
        const uint32_t bits = static_cast<uint32_t>(out_len * 8);
        size_t done = 0;
        for (uint32_t i = 1; done < out_len; ++i) {
            Bytes input;
            AppendU32(input, i);
            AppendLabel(input, label);
            Append(input, context_u);
            Append(input, context_v);
            AppendU32(input, bits);
            SecureBuffer<kSha256Len> block;
            HmacSha256(key, key_len, input.data(), input.size(), block.data());
            const size_t n = (std::min)(kSha256Len, out_len - done);
            std::memcpy(out + done, block.data(), n);
            done += n;
        }
    }

    void KdfeSha256(
        const uint8_t *z, size_t z_len,
        const char *label,
        const Bytes &party_u, const Bytes &party_v,
        uint8_t *out, size_t out_len) {
        size_t done = 0;
        for (uint32_t i = 1; done < out_len; ++i) {
            // The input holds Z, the shared secret: wiped as it goes.
            Bytes input;
            AppendU32(input, i);
            input.insert(input.end(), z, z + z_len);
            AppendLabel(input, label);
            Append(input, party_u);
            Append(input, party_v);
            ScopedSecureZero wipe_input(input.data(), input.size());
            SecureBuffer<kSha256Len> block;
            Sha256(input.data(), input.size(), block.data());
            const size_t n = (std::min)(kSha256Len, out_len - done);
            std::memcpy(out + done, block.data(), n);
            done += n;
        }
    }

    void Aes128Cfb(
        const uint8_t key[16], const uint8_t iv[kAesBlockLen],
        const uint8_t *in, uint8_t *out, size_t len,
        bool encrypt) {
        ScopedBCryptKey aes;
        if (BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, aes.put(), nullptr, 0, const_cast<PUCHAR>(key), 16, 0) != 0) {
            CryptoFailure("AES key setup failed");
        }
        // The feedback register: the IV, then each ciphertext block.
        SecureBuffer<kAesBlockLen> reg;
        std::memcpy(reg.data(), iv, kAesBlockLen);
        for (size_t off = 0; off < len; off += kAesBlockLen) {
            SecureBuffer<kAesBlockLen> keystream;
            ULONG got = 0;
            if (BCryptEncrypt(aes.get(), reg.data(), kAesBlockLen, nullptr, nullptr, 0, keystream.data(), kAesBlockLen,
                              &got, 0) != 0 || got != kAesBlockLen) {
                CryptoFailure("AES block encryption failed");
            }
            const size_t n = (std::min)(kAesBlockLen, len - off);
            // Keep this block's ciphertext before `out` may overwrite `in`.
            uint8_t cipher[kAesBlockLen] = {};
            if (!encrypt) {
                std::memcpy(cipher, in + off, n);
            }
            for (size_t i = 0; i < n; ++i) {
                out[off + i] = static_cast<uint8_t>(in[off + i] ^ keystream.data()[i]);
            }
            if (encrypt) {
                std::memcpy(cipher, out + off, n);
            }
            if (n == kAesBlockLen) {
                std::memcpy(reg.data(), cipher, kAesBlockLen);
            }
        }
    }

    Bytes ComputeName(const Bytes &public_area) {
        // TPMT_PUBLIC starts with the object type; the nameAlg is the next
        // field, bytes 2..3.
        if (public_area.size() < 4 || public_area[2] != 0x00 || public_area[3] != kAlgSha256) {
            BadTpmData("object's nameAlg is not SHA-256");
        }
        Bytes name = {0x00, static_cast<uint8_t>(kAlgSha256)};
        name.resize(2 + kSha256Len);
        Sha256(public_area.data(), public_area.size(), name.data() + 2);
        return name;
    }

    void MakeSessionSalt(const PublicArea &tpm_key, SecureBuffer<kSha256Len> &salt, Bytes &encrypted_salt) {
        if (tpm_key.name_alg != kAlgSha256) {
            BadTpmData("session salt key's nameAlg is not SHA-256");
        }

        if (tpm_key.type == kAlgRsa) {
            if (tpm_key.rsa_modulus.empty()) {
                BadTpmData("session salt key has no RSA modulus");
            }
            Random(salt.data(), salt.size());
            // BCRYPT_RSAKEY_BLOB, then the exponent and the modulus,
            // big-endian. An exponent of 0 in a TPM public area means 65537.
            const uint32_t e = tpm_key.rsa_exponent == 0 ? 65537u : tpm_key.rsa_exponent;
            Bytes exponent;
            for (int shift = 24; shift >= 0; shift -= 8) {
                if (!exponent.empty() || (e >> shift) != 0) {
                    exponent.push_back(static_cast<uint8_t>(e >> shift));
                }
            }
            Bytes blob(sizeof(BCRYPT_RSAKEY_BLOB));
            auto *header = reinterpret_cast<BCRYPT_RSAKEY_BLOB *>(blob.data());
            header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
            header->BitLength = static_cast<ULONG>(tpm_key.rsa_modulus.size() * 8);
            header->cbPublicExp = static_cast<ULONG>(exponent.size());
            header->cbModulus = static_cast<ULONG>(tpm_key.rsa_modulus.size());
            Append(blob, exponent);
            Append(blob, tpm_key.rsa_modulus);
            ScopedBCryptKey rsa;
            if (BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, nullptr, BCRYPT_RSAPUBLIC_BLOB, rsa.put(), blob.data(),
                                    static_cast<ULONG>(blob.size()), 0) != 0) {
                BadTpmData("session salt key's RSA public key does not import");
            }
            // OAEP with SHA-256 (the key's nameAlg) and the label "SECRET",
            // its terminating NUL included (Part 1, annex B.10.3).
            static const char kLabel[] = "SECRET";
            BCRYPT_OAEP_PADDING_INFO oaep{BCRYPT_SHA256_ALGORITHM, reinterpret_cast<PUCHAR>(const_cast<char *>(kLabel)),
                                          static_cast<ULONG>(sizeof(kLabel))};
            encrypted_salt.assign(tpm_key.rsa_modulus.size(), 0);
            ULONG got = 0;
            if (BCryptEncrypt(rsa.get(), salt.data(), static_cast<ULONG>(salt.size()), &oaep, nullptr, 0,
                              encrypted_salt.data(), static_cast<ULONG>(encrypted_salt.size()), &got, BCRYPT_PAD_OAEP) != 0) {
                CryptoFailure("RSA-OAEP encryption of the session salt failed");
            }
            encrypted_salt.resize(got);
            return;
        }

        if (tpm_key.type == kAlgEcc) {
            constexpr uint16_t kEccNistP256 = 0x0003;
            constexpr size_t kCoord = 32;
            if (tpm_key.ecc_curve != kEccNistP256 || tpm_key.ecc_x.empty() || tpm_key.ecc_x.size() > kCoord ||
                tpm_key.ecc_y.empty() || tpm_key.ecc_y.size() > kCoord) {
                BadTpmData("session salt key is not a P-256 key");
            }
            // The key's point, left-padded to 32 bytes per coordinate.
            Bytes point_blob(sizeof(BCRYPT_ECCKEY_BLOB));
            auto *header = reinterpret_cast<BCRYPT_ECCKEY_BLOB *>(point_blob.data());
            header->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
            header->cbKey = kCoord;
            point_blob.insert(point_blob.end(), kCoord - tpm_key.ecc_x.size(), 0);
            Append(point_blob, tpm_key.ecc_x);
            point_blob.insert(point_blob.end(), kCoord - tpm_key.ecc_y.size(), 0);
            Append(point_blob, tpm_key.ecc_y);
            ScopedBCryptKey tpm_point;
            if (BCryptImportKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, nullptr, BCRYPT_ECCPUBLIC_BLOB, tpm_point.put(),
                                    point_blob.data(), static_cast<ULONG>(point_blob.size()), 0) != 0) {
                BadTpmData("session salt key's point is not on P-256");
            }

            ScopedBCryptKey ephemeral;
            if (BCryptGenerateKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, ephemeral.put(), 256, 0) != 0 ||
                BCryptFinalizeKeyPair(ephemeral.get(), 0) != 0) {
                CryptoFailure("ephemeral P-256 key generation failed");
            }
            Bytes ephemeral_blob(sizeof(BCRYPT_ECCKEY_BLOB) + 2 * kCoord);
            ULONG got = 0;
            if (BCryptExportKey(ephemeral.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, ephemeral_blob.data(),
                                static_cast<ULONG>(ephemeral_blob.size()), &got, 0) != 0 || got != ephemeral_blob.size()) {
                CryptoFailure("ephemeral P-256 key export failed");
            }
            const Bytes ephemeral_x(ephemeral_blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB),
                                    ephemeral_blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + kCoord);
            const Bytes ephemeral_y(ephemeral_blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + kCoord, ephemeral_blob.end());

            ScopedBCryptSecret agreement;
            if (BCryptSecretAgreement(ephemeral.get(), tpm_point.get(), agreement.put(), 0) != 0) {
                CryptoFailure("ECDH with the session salt key failed");
            }
            SecureBuffer<kCoord> z;
            if (BCryptDeriveKey(agreement.get(), BCRYPT_KDF_RAW_SECRET, nullptr, z.data(), kCoord, &got, 0) != 0 ||
                got != kCoord) {
                CryptoFailure("ECDH raw secret extraction failed");
            }
            std::reverse(z.data(), z.data() + kCoord); // CNG returns x little-endian
            // salt = KDFe(Z, "SECRET", QeU.x, QsV.x), the key's x as it
            // appears in its public area (Part 1, annex C.6.1).
            KdfeSha256(z.data(), kCoord, "SECRET", ephemeral_x, tpm_key.ecc_x, salt.data(), salt.size());
            Writer point; // TPMS_ECC_POINT
            point.Tpm2b(ephemeral_x);
            point.Tpm2b(ephemeral_y);
            encrypted_salt = point.take();
            return;
        }

        BadTpmData("session salt key is neither RSA nor ECC");
    }

    Session::Session(uint32_t handle, const SecureBuffer<kSha256Len> &salt, const Bytes &nonce_tpm, const Bytes &nonce_caller)
        : handle_(handle), nonce_tpm_(nonce_tpm), nonce_caller_(nonce_caller) {
        if (nonce_tpm.size() != kNonceLen || nonce_caller.size() != kNonceLen) {
            BadTpmData("session nonce of the wrong size");
        }
        KdfaSha256(salt.data(), salt.size(), "ATH", nonce_tpm_, nonce_caller_, session_key_.data(), session_key_.size());
    }

    Bytes Session::Authorize(
        uint32_t command_code,
        const std::vector<uint32_t> &handles,
        const std::vector<Bytes> &handle_names,
        const Bytes &parameters,
        bool continue_session) {
        if (!open_ || !usable_ || awaiting_response_) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM session used out of order");
        }
        if (handles.empty() || handle_names.size() != handles.size()) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM session command needs a Name per handle");
        }
        // The first parameter must be a TPM2B: its data is what is
        // encrypted.
        if (parameters.size() < 2 || static_cast<size_t>((parameters[0] << 8) | parameters[1]) > parameters.size() - 2) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM session command's first parameter is not a TPM2B");
        }
        const size_t first_len = static_cast<size_t>((parameters[0] << 8) | parameters[1]);

        nonce_caller_.assign(kNonceLen, 0);
        Random(nonce_caller_.data(), kNonceLen);
        attributes_ = static_cast<uint8_t>(kSessionDecrypt | kSessionEncrypt | (continue_session ? kSessionContinue : 0));

        // Command parameter encryption: nonceCaller is the newer nonce.
        Bytes sent = parameters;
        {
            SecureBuffer<kSessionKeyBits / 8 + kAesBlockLen> key_and_iv;
            CfbKeyAndIv(session_key_, nonce_caller_, nonce_tpm_, key_and_iv);
            Aes128Cfb(key_and_iv.data(), key_and_iv.data() + 16, sent.data() + 2, sent.data() + 2, first_len, true);
        }

        // cpHash = SHA-256(commandCode || Names || parameters as sent).
        Bytes cp_input;
        AppendU32(cp_input, command_code);
        for (const Bytes &name : handle_names) {
            Append(cp_input, name);
        }
        Append(cp_input, sent);
        uint8_t cp_hash[kSha256Len];
        Sha256(cp_input.data(), cp_input.size(), cp_hash);

        // HMAC(sessionKey || authValue, cpHash || nonceCaller || nonceTPM ||
        // attributes); authValue is empty, and the session is both the
        // authorizing and the encrypting one, so no extra nonces (Part 1, 19.6.5).
        Bytes hmac_input(cp_hash, cp_hash + kSha256Len);
        Append(hmac_input, nonce_caller_);
        Append(hmac_input, nonce_tpm_);
        hmac_input.push_back(attributes_);
        AuthCommand auth;
        auth.session_handle = handle_;
        auth.nonce = nonce_caller_;
        auth.attributes = attributes_;
        auth.hmac.resize(kSha256Len);
        HmacSha256(session_key_.data(), session_key_.size(), hmac_input.data(), hmac_input.size(), auth.hmac.data());

        Bytes command = BuildCommand(command_code, handles, {auth}, sent);
        command_code_ = command_code;
        awaiting_response_ = true;
        return command;
    }

    void Session::Verify(const Response &response) {
        if (!awaiting_response_) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM session response without a command");
        }
        awaiting_response_ = false;
        verified_ = false;
        // A failed command leaves the session as it was in the TPM (no nonce
        // rolls), but this object is not used again: the caller flushes it.
        if (response.response_code != 0) {
            usable_ = false;
            return;
        }
        if (response.tag != kStSessions || response.auths.size() != 1) {
            usable_ = false;
            BadTpmData("TPM response lacks the session's authorization");
        }
        const AuthResponse &auth = response.auths[0];
        if (auth.nonce.size() != kNonceLen || auth.hmac.size() != kSha256Len || (auth.attributes & kSessionEncrypt) == 0) {
            usable_ = false;
            BadTpmData("TPM response authorization has the wrong shape");
        }

        // rpHash = SHA-256(responseCode || commandCode || parameters).
        Bytes rp_input;
        AppendU32(rp_input, 0);
        AppendU32(rp_input, command_code_);
        Append(rp_input, response.parameters);
        uint8_t rp_hash[kSha256Len];
        Sha256(rp_input.data(), rp_input.size(), rp_hash);

        // HMAC(sessionKey, rpHash || nonceTPM || nonceCaller || attributes):
        // the TPM's new nonce is the newer one.
        Bytes hmac_input(rp_hash, rp_hash + kSha256Len);
        Append(hmac_input, auth.nonce);
        Append(hmac_input, nonce_caller_);
        hmac_input.push_back(auth.attributes);
        uint8_t expected[kSha256Len];
        HmacSha256(session_key_.data(), session_key_.size(), hmac_input.data(), hmac_input.size(), expected);
        if (!ConstantTimeEqual(expected, auth.hmac.data(), kSha256Len)) {
            usable_ = false;
            BadTpmData("TPM response HMAC does not verify");
        }

        nonce_tpm_ = auth.nonce;
        verified_ = true;
        if ((attributes_ & kSessionContinue) == 0) {
            open_ = false; // the TPM has closed it
        }
    }

    void Session::Abandon() {
        awaiting_response_ = false;
        verified_ = false;
        usable_ = false;
    }

    void Session::DecryptResponseParameter(const Bytes &encrypted, uint8_t *out, size_t len) const {
        if (!verified_ || encrypted.size() != len) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM response parameter decrypted out of order");
        }
        // Response parameter encryption: nonceTPM is the newer nonce.
        SecureBuffer<kSessionKeyBits / 8 + kAesBlockLen> key_and_iv;
        CfbKeyAndIv(session_key_, nonce_tpm_, nonce_caller_, key_and_iv);
        Aes128Cfb(key_and_iv.data(), key_and_iv.data() + 16, encrypted.data(), out, len, false);
    }
} // namespace hkdfguard::tpm2
