#include "kek_v2.h"
#include "aes_cmac.h"
#include "errors.h"
#include "event_log.h"     // LogKekCreated, LogVersion2Unavailable
#include "handle_traits.h" // ScopedNCryptProv, ScopedNCryptKey
#include "key_acl.h"       // ApplyKeyAcl, ValidateKeyUseGroups, VerifyExistingKeyAcl, VerifyKeyAcl
#include "policy.h"        // LoadEffectivePolicy, LoadKeyUseGroupsPolicy, LoadDeployerGroupsPolicy
#include "sp800_108.h"
#include "tpm2_device.h"

#include <windows.h>
#include <ncrypt.h>

#include <atomic>
#include <cstdio>  // snprintf
#include <cstring> // memcpy, memcmp

namespace hkdfguard {
    namespace {
        // Windows' storage root key, the parent of every version 2 TPM KEK.
        constexpr uint32_t kStorageRootKey = 0x81000001;

        // The known-answer test: the Linux library's own vector
        // (hkdfguard-native-linux, src/crypto.rs, known_answer) - a KEK of 32
        // bytes of 0x2a, whose fingerprint (HMAC-SHA-256 over the
        // fingerprint block) is this.
        constexpr uint8_t kKatKeyByte = 0x2a;
        constexpr uint8_t kKatFingerprint[kFingerprintLen] = {
            0x59, 0xaa, 0x2a, 0xc5, 0x50, 0xf7, 0xc4, 0x0e, 0xa3, 0xd5, 0x2b, 0x6c, 0x56, 0x72, 0x0f, 0xa8,
            0xc6, 0x2b, 0x4c, 0x2e, 0x78, 0xbe, 0x0e, 0xf6, 0x4b, 0x77, 0xdc, 0x40, 0xeb, 0x01, 0x14, 0x5b};

        // Once a test passes in this process it isn't repeated; a failure
        // is retried on the next call, so a TPM that was briefly busy isn't
        // written off for the life of the process.
        std::atomic<bool> g_tpm_known_answer_passed{false};
        std::atomic<bool> g_cmac_known_answer_passed{false};

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        std::optional<TpmKeyStore> g_test_tpm_store;
        std::optional<std::string> g_test_tpm_unusable;
#endif

        // The TPM can't be used for version 2 at all, for `reason`. The one
        // failure PreferTpm answers by falling back to the software KSP, as
        // version 1's TpmUnusableError is - and never while a TPM key file
        // exists. Its code is HKDFGUARD_ERR_PROVIDER_UNAVAILABLE.
        class V2TpmUnusable : public HkdfGuardError {
        public:
            explicit V2TpmUnusable(const std::string &reason)
                : HkdfGuardError(HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, "the TPM can't be used for version 2"),
                  reason_(reason) {}
            const std::string &reason() const { return reason_; }

        private:
            std::string reason_;
        };

        std::string Hex32(uint32_t v) {
            char buf[16];
            std::snprintf(buf, sizeof buf, "0x%08X", static_cast<unsigned>(v));
            return buf;
        }

        // A TpmError while proving the TPM usable becomes V2TpmUnusable; a
        // blocked command is named as such, since its fix (Group Policy) is
        // specific.
        [[noreturn]] void Unusable(const std::string &step, const tpm2::TpmError &e) {
            if (e.tpm_code() == tpm2::kRcCommandBlocked) {
                throw V2TpmUnusable(step + ": TBS blocks a TPM command this needs (TPM_E_COMMAND_BLOCKED); check the "
                                           "Group Policy list of blocked TPM commands");
            }
            throw V2TpmUnusable(step + " failed (TPM/TBS code " + Hex32(e.tpm_code()) + ")");
        }

        // The ASCII form of a normalized service name (letters, digits and
        // '.', as hkdfguard.cpp's NormalizeService guarantees).
        std::string Narrow(const std::wstring &service) {
            std::string out;
            for (wchar_t c : service) {
                if (c > 0x7F) {
                    throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "service name is not normalized");
                }
                out += static_cast<char>(c);
            }
            return out;
        }

        TpmKeyStore Store() {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
            if (g_test_tpm_store) {
                return *g_test_tpm_store;
            }
#endif
            return DefaultTpmKeyStore();
        }

        std::vector<std::wstring> AclGroups() {
            // As version 1's CreateKek: KeyUseGroups and DeployerGroups
            // together, vetted before anything is created.
            std::vector<std::wstring> groups = LoadKeyUseGroupsPolicy();
            for (std::wstring &deployer : LoadDeployerGroupsPolicy()) {
                groups.push_back(std::move(deployer));
            }
            ValidateKeyUseGroups(groups);
            return groups;
        }

        KeyStoragePolicy RequirePolicy() {
            const KeyStoragePolicy policy = LoadEffectivePolicy();
            if (policy == KeyStoragePolicy::Invalid) {
                throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
            }
            return policy;
        }

        // ---- The TPM ----

        // A TBS connection, the storage root key's public area, and proof
        // (the known-answer test) that the TPM's HMAC is HMAC-SHA-256.
        struct UsableTpm {
            std::unique_ptr<tpm2::Tpm> tpm;
            tpm2::PublicArea srk;
            Bytes srk_name;
        };

        void RunTpmKnownAnswerTest(tpm2::Tpm &tpm, const tpm2::PublicArea &srk) {
            if (g_tpm_known_answer_passed.load()) {
                return;
            }
            // The Linux vector's KEK, loaded as an external object in the
            // NULL hierarchy: unique = SHA-256(seed || key), which the TPM
            // checks.
            const Bytes key(32, kKatKeyByte);
            const Bytes seed(32, 0x5E);
            Bytes seeded = seed;
            seeded.insert(seeded.end(), key.begin(), key.end());
            Bytes unique(32);
            tpm2::Sha256(seeded.data(), seeded.size(), unique.data());
            SecureBuffer<32> out;
            try {
                const tpm2::LoadResult loaded = tpm.LoadExternal(
                    tpm2::KeyedHashSensitive(seed, key),
                    tpm2::KeyedHashPublicArea(tpm2::kObjUserWithAuth | tpm2::kObjNoDa | tpm2::kObjSign, tpm2::kAlgSha256, unique),
                    tpm2::kRhNull);
                tpm2::ScopedTpmObject kat_key(tpm, loaded.object_handle);
                tpm2::ScopedSession session(tpm, tpm.StartSaltedSession(kStorageRootKey, srk));
                tpm.Hmac(*session, kat_key.get(), loaded.name, FingerprintBlock(1), out, false);
            } catch (const tpm2::TpmError &e) {
                Unusable("the TPM's HMAC-SHA-256 known-answer test", e);
            }
            if (std::memcmp(out.data(), kKatFingerprint, kFingerprintLen) != 0) {
                throw V2TpmUnusable("the TPM's HMAC-SHA-256 failed its known-answer test");
            }
            g_tpm_known_answer_passed.store(true);
        }

        UsableTpm OpenUsableTpm() {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
            if (g_test_tpm_unusable) {
                throw V2TpmUnusable(*g_test_tpm_unusable);
            }
#endif
            UsableTpm usable;
            try {
                usable.tpm = std::make_unique<tpm2::Tpm>();
            } catch (const tpm2::TpmError &e) {
                throw V2TpmUnusable("no TPM 2.0 is reachable through TBS (TBS result " + Hex32(e.tpm_code()) + ")");
            }
            try {
                tpm2::ReadPublicResult srk = usable.tpm->ReadPublic(kStorageRootKey);
                usable.srk = tpm2::ParsePublicArea(srk.public_area);
                usable.srk_name = std::move(srk.name);
            } catch (const tpm2::TpmError &e) {
                Unusable("reading the storage root key (0x81000001)", e);
            }
            if (const auto problem = StorageRootKeyProblem(usable.srk)) {
                throw V2TpmUnusable("the key at 0x81000001 is not a storage root key this library can use: " + *problem);
            }
            RunTpmKnownAnswerTest(*usable.tpm, usable.srk);
            return usable;
        }

        // A version 2 TPM KEK, loaded under the storage root key it was
        // created under. The session is started on first use and serves
        // every PRF call of the operation (the fingerprint, then the
        // wrapping key), then is flushed with the key.
        class TpmV2Kek : public V2Kek {
        public:
            TpmV2Kek(UsableTpm usable, TpmKeyFile file)
                : V2Kek(kProviderTypeTpm, kCurrentKeyId), tpm_(std::move(usable.tpm)), srk_(std::move(usable.srk)),
                  file_(std::move(file)) {
                // The key file pins the storage root key it was made under.
                if (file_.parent_handle != kStorageRootKey || file_.parent_name != usable.srk_name) {
                    throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID,
                                         "the storage root key has changed since this KEK was created");
                }
                const tpm2::LoadResult loaded = tpm_->Load(file_.parent_handle, file_.private_blob, file_.public_blob);
                key_ = std::make_unique<tpm2::ScopedTpmObject>(*tpm_, loaded.object_handle);
                key_name_ = loaded.name;
            }

            void Fingerprint(uint8_t out[kFingerprintLen]) override {
                SecureBuffer<32> value;
                Prf(FingerprintBlock(1), value);
                std::memcpy(out, value.data(), kFingerprintLen);
            }

            void WrappingKey(const std::string &service, const uint8_t header[kHeaderLen], SecureBuffer<32> &out) override {
                Prf(WrapBlock(1, service, header, kHeaderLen), out);
            }

        private:
            void Prf(const Bytes &block, SecureBuffer<32> &out) {
                if (!session_ || !(*session_)->usable()) {
                    session_.reset();
                    session_ = std::make_unique<tpm2::ScopedSession>(*tpm_, tpm_->StartSaltedSession(file_.parent_handle, srk_));
                }
                tpm_->Hmac(**session_, key_->get(), key_name_, block, out, true);
            }

            // Destroyed in reverse: the session, then the key, then TBS.
            std::unique_ptr<tpm2::Tpm> tpm_;
            tpm2::PublicArea srk_;
            TpmKeyFile file_;
            std::unique_ptr<tpm2::ScopedTpmObject> key_;
            Bytes key_name_;
            std::unique_ptr<tpm2::ScopedSession> session_;
        };

        std::unique_ptr<V2Kek> OpenTpmKek(const std::wstring &service) {
            // The key file first: it says whether a TPM KEK exists at all,
            // whatever state the TPM is in.
            TpmKeyFile file = ReadTpmKeyFile(Store(), TpmKeyFileName(service, kCurrentKeyId), Narrow(service));
            return std::make_unique<TpmV2Kek>(OpenUsableTpm(), std::move(file));
        }

        // Creates the TPM KEK if its key file doesn't exist; verifies it if
        // it does. Returns whether it created one.
        bool CreateTpmKek(const std::wstring &service, const std::vector<std::wstring> &groups) {
            const TpmKeyStore store = Store();
            const std::wstring file_name = TpmKeyFileName(service, kCurrentKeyId);
            // An existing KEK - found now, or created concurrently below -
            // must still work and must grant every group the current
            // policy names, as version 1's existing KEK must (VerifyKeyAcl).
            const auto verify_existing = [&] {
                OpenTpmKek(service)->Fingerprint(std::vector<uint8_t>(kFingerprintLen).data());
                VerifyTpmKeyFileGrants(store, file_name, groups);
            };
            if (TpmKeyFileExists(store, file_name, Narrow(service))) {
                verify_existing();
                return false;
            }

            UsableTpm usable = OpenUsableTpm();
            tpm2::CreateResult created;
            try {
                created = usable.tpm->Create(kStorageRootKey, TpmKekTemplate());
            } catch (const tpm2::TpmError &e) {
                Unusable("creating the KEK under the storage root key", e);
            }
            TpmKeyFile file;
            file.service = Narrow(service);
            file.parent_handle = kStorageRootKey;
            file.parent_name = usable.srk_name;
            file.public_blob = std::move(created.public_blob);
            file.private_blob = std::move(created.private_blob);

            if (!WriteTpmKeyFile(store, file_name, file, groups)) {
                // Created concurrently by another provisioning run: that
                // file is the KEK, and is verified like any existing one.
                verify_existing();
                return false;
            }
            // Used once through the full open path before it counts; a KEK
            // that can't be is removed, not left for a later wrap to find.
            try {
                uint8_t fingerprint[kFingerprintLen];
                OpenTpmKek(service)->Fingerprint(fingerprint);
                VerifyTpmKeyFileGrants(store, file_name, groups);
            } catch (...) {
                DeleteTpmKeyFile(store, file_name);
                throw;
            }
            return true;
        }

        // ---- The software KSP ----

        // As version 1's ThrowForNCryptFailure, for the software KSP.
        [[noreturn]] void ThrowForNCryptFailure(SECURITY_STATUS status, const char *message) {
            if (status == NTE_BAD_KEYSET) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_NOT_FOUND, "no version 2 software KEK is provisioned for this service");
            }
            if (status == NTE_PERM || status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_ACCESS_DENIED, "access to the version 2 software KEK was denied");
            }
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, message);
        }

        void OpenProvider(ScopedNCryptProv &provider) {
            if (NCryptOpenStorageProvider(provider.put(), MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "NCryptOpenStorageProvider failed");
            }
        }

        // NCRYPT_MACHINE_KEY_FLAG: a machine key, as version 1's; silent, so
        // a key that would prompt fails instead.
        SECURITY_STATUS OpenSoftwareKey(NCRYPT_PROV_HANDLE provider, const std::wstring &name, ScopedNCryptKey &key) {
            return NCryptOpenKey(provider, key.put(), name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        }

        DWORD DwordProperty(NCRYPT_KEY_HANDLE key, LPCWSTR property) {
            DWORD value = 0;
            DWORD got = 0;
            if (NCryptGetProperty(key, property, reinterpret_cast<PBYTE>(&value), sizeof(value), &got, 0) != ERROR_SUCCESS ||
                got != sizeof(value)) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "reading a version 2 software KEK property failed");
            }
            return value;
        }

        // What every version 2 software KEK is: AES, 256 bits, never
        // exportable; and an ACL this library would have made, when this
        // caller may read it (as version 1's VerifyAclIfReadable).
        void VerifySoftwareKey(NCRYPT_KEY_HANDLE key) {
            wchar_t group[32] = {};
            DWORD got = 0;
            if (NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY, reinterpret_cast<PBYTE>(group),
                                  sizeof(group) - sizeof(wchar_t), &got, 0) != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "reading the version 2 software KEK's algorithm failed");
            }
            if (wcscmp(group, NCRYPT_AES_ALGORITHM_GROUP) != 0 || DwordProperty(key, NCRYPT_LENGTH_PROPERTY) != 256) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID, "the version 2 software KEK is not an AES-256 key");
            }
            constexpr DWORD kExportable = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                                          NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG;
            if ((DwordProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY) & kExportable) != 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID, "the version 2 software KEK is exportable");
            }
            try {
                VerifyExistingKeyAcl(key);
            } catch (const HkdfGuardError &e) {
                // An ACL this library would never make: refused, but as an
                // access-control failure, which fixing the ACL repairs - not
                // as a corrupt key to retire.
                if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                    throw KekAccessControlError(
                        (std::string("the version 2 software KEK's ACL: ") + e.what()).c_str());
                }
            }
        }

        // A version 2 software KEK: two handles to the same key, one in ECB
        // mode for single blocks and one in CBC mode - the chaining mode is
        // a property of the handle only, never saved to the key.
        class SoftwareV2Kek : public V2Kek {
        public:
            explicit SoftwareV2Kek(const std::wstring &service) : V2Kek(kProviderTypeSoftware, kCurrentKeyId) {
                OpenProvider(provider_);
                const std::wstring name = V2SoftwareKeyName(service, kCurrentKeyId);
                SECURITY_STATUS status = OpenSoftwareKey(provider_.get(), name, ecb_);
                if (status != ERROR_SUCCESS) {
                    ThrowForNCryptFailure(status, "NCryptOpenKey failed");
                }
                VerifySoftwareKey(ecb_.get());
                status = OpenSoftwareKey(provider_.get(), name, cbc_);
                if (status != ERROR_SUCCESS) {
                    ThrowForNCryptFailure(status, "NCryptOpenKey failed");
                }
                SetMode(ecb_.get(), BCRYPT_CHAIN_MODE_ECB);
                SetMode(cbc_.get(), BCRYPT_CHAIN_MODE_CBC);
                if (!g_cmac_known_answer_passed.load()) {
                    CheckAesCmacImplementation();
                    g_cmac_known_answer_passed.store(true);
                }
                aes_.encrypt_block = [this](const uint8_t *in, uint8_t *out) {
                    DWORD got = 0;
                    if (NCryptEncrypt(ecb_.get(), const_cast<PBYTE>(in), kAesBlockSize, nullptr, out, kAesBlockSize, &got,
                                      NCRYPT_NO_PADDING_FLAG) != ERROR_SUCCESS || got != kAesBlockSize) {
                        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "AES block encryption with the software KEK failed");
                    }
                };
                aes_.cbc_zero_iv = [this](const uint8_t *in, size_t len, uint8_t *out) {
                    // The IV given on every call, so no chaining state
                    // carries over from a previous one.
                    uint8_t iv[kAesBlockSize] = {};
                    NCRYPT_CIPHER_PADDING_INFO padding{};
                    padding.cbSize = sizeof(padding);
                    padding.dwFlags = NCRYPT_CIPHER_NO_PADDING_FLAG;
                    padding.pbIV = iv;
                    padding.cbIV = sizeof(iv);
                    DWORD got = 0;
                    if (NCryptEncrypt(cbc_.get(), const_cast<PBYTE>(in), static_cast<DWORD>(len), &padding, out,
                                      static_cast<DWORD>(len), &got, NCRYPT_PAD_CIPHER_FLAG) != ERROR_SUCCESS ||
                        got != len) {
                        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "AES-CBC with the software KEK failed");
                    }
                };
            }

            void Fingerprint(uint8_t out[kFingerprintLen]) override {
                SecureBuffer<32> value;
                Derive(FingerprintBlock(1), FingerprintBlock(2), value);
                std::memcpy(out, value.data(), kFingerprintLen);
            }

            void WrappingKey(const std::string &service, const uint8_t header[kHeaderLen], SecureBuffer<32> &out) override {
                Derive(WrapBlock(1, service, header, kHeaderLen), WrapBlock(2, service, header, kHeaderLen), out);
            }

        private:
            static void SetMode(NCRYPT_KEY_HANDLE key, LPCWSTR mode) {
                if (NCryptSetProperty(key, NCRYPT_CHAINING_MODE_PROPERTY, reinterpret_cast<PBYTE>(const_cast<LPWSTR>(mode)),
                                      static_cast<DWORD>((wcslen(mode) + 1) * sizeof(wchar_t)), 0) != ERROR_SUCCESS) {
                    throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "setting the software KEK handle's chaining mode failed");
                }
            }

            // Two CMAC blocks make the 256-bit output: counters 1 and 2.
            void Derive(const std::vector<uint8_t> &first, const std::vector<uint8_t> &second, SecureBuffer<32> &out) {
                AesCmac(aes_, first.data(), first.size(), out.data());
                AesCmac(aes_, second.data(), second.size(), out.data() + kAesBlockSize);
            }

            ScopedNCryptProv provider_;
            ScopedNCryptKey ecb_;
            ScopedNCryptKey cbc_;
            AesBlockOperations aes_;
        };

        bool SoftwareKekExists(const std::wstring &service) {
            ScopedNCryptProv provider;
            OpenProvider(provider);
            ScopedNCryptKey key;
            const SECURITY_STATUS status = OpenSoftwareKey(provider.get(), V2SoftwareKeyName(service, kCurrentKeyId), key);
            if (status == NTE_BAD_KEYSET) {
                return false;
            }
            if (status != ERROR_SUCCESS) {
                ThrowForNCryptFailure(status, "NCryptOpenKey failed");
            }
            return true;
        }

        // Creates the software KEK if missing; verifies it if present.
        // Returns whether it created one.
        bool CreateSoftwareKek(const std::wstring &service, const std::vector<std::wstring> &groups) {
            const std::wstring name = V2SoftwareKeyName(service, kCurrentKeyId);
            ScopedNCryptProv provider;
            OpenProvider(provider);
            {
                ScopedNCryptKey existing;
                const SECURITY_STATUS status = OpenSoftwareKey(provider.get(), name, existing);
                if (status == ERROR_SUCCESS) {
                    VerifySoftwareKey(existing.get());
                    VerifyKeyAcl(existing.get(), groups);
                    return false;
                }
                if (status != NTE_BAD_KEYSET) {
                    ThrowForNCryptFailure(status, "NCryptOpenKey failed");
                }
            }

            ScopedNCryptKey key;
            SECURITY_STATUS status = NCryptCreatePersistedKey(provider.get(), key.put(), NCRYPT_AES_ALGORITHM, name.c_str(), 0,
                                                              NCRYPT_MACHINE_KEY_FLAG);
            if (status == NTE_EXISTS) {
                return CreateSoftwareKek(service, groups); // created concurrently: verify that one
            }
            if (status != ERROR_SUCCESS) {
                ThrowForNCryptFailure(status, "NCryptCreatePersistedKey failed");
            }
            DWORD length = 256;
            DWORD export_policy = 0;
            if (NCryptSetProperty(key.get(), NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&length), sizeof(length), 0) !=
                    ERROR_SUCCESS ||
                NCryptSetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                                  sizeof(export_policy), 0) != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "setting the version 2 software KEK's properties failed");
            }
            ApplyKeyAcl(key.get(), groups);
            // Finalizing a machine key is what needs elevation.
            status = NCryptFinalizeKey(key.get(), NCRYPT_SILENT_FLAG);
            if (status == NTE_EXISTS) {
                return CreateSoftwareKek(service, groups);
            }
            if (status != ERROR_SUCCESS) {
                ThrowForNCryptFailure(status, "NCryptFinalizeKey failed");
            }
            key.reset();

            // Reopened and used once before it counts; one that fails is
            // deleted rather than left for a later wrap to find.
            try {
                ScopedNCryptKey reopened;
                status = OpenSoftwareKey(provider.get(), name, reopened);
                if (status != ERROR_SUCCESS) {
                    ThrowForNCryptFailure(status, "NCryptOpenKey failed");
                }
                VerifyKeyAcl(reopened.get(), groups);
                uint8_t fingerprint[kFingerprintLen];
                SoftwareV2Kek(service).Fingerprint(fingerprint);
            } catch (...) {
                DeleteV2Kek(service, kProviderTypeSoftware, kCurrentKeyId);
                throw;
            }
            return true;
        }

        // A TPM that can't do version 2, under RequireTpm or behind an
        // existing TPM key file: event 2008 with the reason, then
        // HKDFGUARD_ERR_PROVIDER_UNAVAILABLE.
        [[noreturn]] void ReportUnusable(const std::wstring &service, const V2TpmUnusable &e) {
            LogVersion2Unavailable(service, e.reason());
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, ("version 2 is unavailable: " + e.reason()).c_str());
        }

        std::unique_ptr<V2Kek> OpenTpmKekOrReport(const std::wstring &service) {
            try {
                return OpenTpmKek(service);
            } catch (const V2TpmUnusable &e) {
                ReportUnusable(service, e);
            }
        }
    } // namespace

    std::optional<std::string> StorageRootKeyProblem(const tpm2::PublicArea &srk) {
        // A storage parent bound to this TPM, usable with its empty
        // authValue through a password session, exempt from lockout, and
        // never a signing key.
        constexpr uint32_t kRequired = tpm2::kObjFixedTpm | tpm2::kObjFixedParent | tpm2::kObjSensitiveDataOrigin |
                                       tpm2::kObjUserWithAuth | tpm2::kObjNoDa | tpm2::kObjRestricted |
                                       tpm2::kObjDecrypt;
        if (srk.name_alg != tpm2::kAlgSha256) {
            return "its nameAlg is not SHA-256";
        }
        if ((srk.attributes & kRequired) != kRequired) {
            return "it lacks a storage root key attribute (fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, "
                   "noDA, restricted or decrypt); attributes " + Hex32(srk.attributes);
        }
        if (srk.attributes & tpm2::kObjSign) {
            return "it is a signing key; attributes " + Hex32(srk.attributes);
        }
        // The inner protection of every child's private blob, the KEK's
        // among them.
        if (srk.symmetric_alg != tpm2::kAlgAes || srk.symmetric_mode != tpm2::kAlgCfb ||
            (srk.symmetric_key_bits != 128 && srk.symmetric_key_bits != 256)) {
            return "it does not protect its children with AES-128 or AES-256 in CFB mode";
        }
        // A restricted decryption key has no scheme of its own.
        if (srk.scheme != tpm2::kAlgNull) {
            return "it has a scheme, which a storage key never has";
        }
        if (srk.type == tpm2::kAlgRsa) {
            // The modulus must really be keyBits long: the buffer's size and
            // its top bit set. Leading zero bytes would make a much shorter
            // key - the one the session salt is then encrypted to - pass as
            // RSA-2048 (found by tests/fuzz/fuzz_srk_rule.cpp).
            if (srk.rsa_key_bits < 2048 || srk.rsa_key_bits % 8 != 0 ||
                srk.rsa_modulus.size() != static_cast<size_t>(srk.rsa_key_bits / 8) ||
                (srk.rsa_modulus[0] & 0x80) == 0) {
                return "its RSA key is shorter than 2048 bits, or its modulus does not match its size";
            }
            if (srk.rsa_exponent != 0 && srk.rsa_exponent != 65537) {
                return "its RSA public exponent is not 65537";
            }
            return std::nullopt;
        }
        if (srk.type == tpm2::kAlgEcc) {
            constexpr uint16_t kEccNistP256 = 0x0003;
            if (srk.ecc_curve != kEccNistP256 || srk.ecc_kdf != tpm2::kAlgNull) {
                return "its ECC key is not a NIST P-256 key without a KDF";
            }
            return std::nullopt;
        }
        return "it is neither an RSA nor an ECC key";
    }

    std::wstring V2SoftwareKeyName(const std::wstring &service, uint32_t key_id) {
        return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id) + L"_aes";
    }

    bool V2KekExists(const std::wstring &service) {
        const KeyStoragePolicy policy = RequirePolicy();
        const auto tpm_file = [&] {
            return TpmKeyFileExists(Store(), TpmKeyFileName(service, kCurrentKeyId), Narrow(service));
        };
        switch (policy) {
            case KeyStoragePolicy::RequireTpm:
                return tpm_file();
            case KeyStoragePolicy::SoftwareOnly:
                return SoftwareKekExists(service);
            case KeyStoragePolicy::PreferTpm:
                // As version 1: the TPM first. An error reading the TPM key
                // file (one that exists but this caller can't read, or that
                // fails a check) propagates, so a TPM KEK is never reported
                // absent because of it.
                return tpm_file() || SoftwareKekExists(service);
            default:
                break;
        }
        throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
    }

    void CreateV2Kek(const std::wstring &service) {
        const std::vector<std::wstring> groups = AclGroups();
        const KeyStoragePolicy policy = RequirePolicy();
        switch (policy) {
            case KeyStoragePolicy::RequireTpm:
                try {
                    if (CreateTpmKek(service, groups)) {
                        LogKekCreated(service, kProviderTypeTpm, HKDFGUARD_OK);
                    }
                } catch (const V2TpmUnusable &e) {
                    ReportUnusable(service, e);
                }
                return;
            case KeyStoragePolicy::SoftwareOnly:
                if (CreateSoftwareKek(service, groups)) {
                    LogKekCreated(service, kProviderTypeSoftware, HKDFGUARD_OK);
                }
                return;
            case KeyStoragePolicy::PreferTpm: {
                // A TPM KEK already in use is never abandoned for the
                // software KSP: with its key file present, a TPM that can't
                // do version 2 is reported, not fallen back from.
                if (TpmKeyFileExists(Store(), TpmKeyFileName(service, kCurrentKeyId), Narrow(service))) {
                    try {
                        CreateTpmKek(service, groups);
                    } catch (const V2TpmUnusable &e) {
                        ReportUnusable(service, e);
                    }
                    return;
                }
                try {
                    if (CreateTpmKek(service, groups)) {
                        LogKekCreated(service, kProviderTypeTpm, HKDFGUARD_OK);
                    }
                    return;
                } catch (const V2TpmUnusable &e) {
                    // The fallback (event 1001 if it creates the software
                    // KEK): the TPM can't do version 2 at all, and no TPM
                    // KEK exists for this service.
                    if (CreateSoftwareKek(service, groups)) {
                        LogKekCreated(service, kProviderTypeSoftware, e.code());
                    }
                    return;
                }
            }
            default:
                break;
        }
        throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
    }

    std::unique_ptr<V2Kek> OpenV2KekForWrap(const std::wstring &service) {
        const KeyStoragePolicy policy = RequirePolicy();
        switch (policy) {
            case KeyStoragePolicy::RequireTpm:
                return OpenTpmKekOrReport(service);
            case KeyStoragePolicy::SoftwareOnly:
                return std::make_unique<SoftwareV2Kek>(service);
            case KeyStoragePolicy::PreferTpm:
                // The TPM KEK if its key file exists - then a TPM that can't
                // do version 2 is reported, never fallen back from - else
                // the software KEK (the one a fallback created).
                if (TpmKeyFileExists(Store(), TpmKeyFileName(service, kCurrentKeyId), Narrow(service))) {
                    return OpenTpmKekOrReport(service);
                }
                return std::make_unique<SoftwareV2Kek>(service);
            default:
                break;
        }
        throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
    }

    std::unique_ptr<V2Kek> OpenV2KekForUnwrap(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        const KeyStoragePolicy policy = RequirePolicy();
        if (key_id != kCurrentKeyId) {
            throw HkdfGuardError(HKDFGUARD_ERR_PAYLOAD_MALFORMED, "unrecognized key id");
        }
        if (provider_type == kProviderTypeTpm) {
            return OpenTpmKekOrReport(service);
        }
        // As version 1: RequireTpm accepts no software KEK, even to unwrap.
        if (policy == KeyStoragePolicy::RequireTpm) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "KeyStoragePolicy requires a TPM KEK");
        }
        return std::make_unique<SoftwareV2Kek>(service);
    }

    bool DeleteV2Kek(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        if (provider_type == kProviderTypeTpm) {
            return DeleteTpmKeyFile(Store(), TpmKeyFileName(service, key_id));
        }
        ScopedNCryptProv provider;
        OpenProvider(provider);
        ScopedNCryptKey key;
        const SECURITY_STATUS status = OpenSoftwareKey(provider.get(), V2SoftwareKeyName(service, key_id), key);
        if (status == NTE_BAD_KEYSET) {
            return false;
        }
        if (status != ERROR_SUCCESS) {
            ThrowForNCryptFailure(status, "NCryptOpenKey failed");
        }
        // NCryptDeleteKey frees the handle on success.
        if (NCryptDeleteKey(key.get(), NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "deleting the version 2 software KEK failed");
        }
        key.release();
        return true;
    }

    V2KekInspection InspectV2Kek(const std::wstring &service, uint8_t provider_type) {
        V2KekInspection result;
        auto invalid = [&](const HkdfGuardError &e) {
            result.state = V2KekInspection::State::Invalid;
            result.problem = e.what();
            return result;
        };
        // Checked before `invalid`: an ACL failure is also KEK_INVALID, but
        // must never be reported as a corrupt key (errors.h).
        auto access_control_invalid = [&](const KekAccessControlError &e) {
            result.state = V2KekInspection::State::AccessControlInvalid;
            result.problem = e.what();
            return result;
        };

        if (provider_type == kProviderTypeTpm) {
            // The key file decides presence. Absent is definite; a file that
            // fails a check is a definite "invalid"; anything else (it can't
            // be read by this account, an I/O error) propagates.
            TpmKeyFile file;
            try {
                file = ReadTpmKeyFile(Store(), TpmKeyFileName(service, kCurrentKeyId), Narrow(service));
            } catch (const KekAccessControlError &e) {
                return access_control_invalid(e);
            } catch (const HkdfGuardError &e) {
                if (e.code() == HKDFGUARD_ERR_KEK_NOT_FOUND) {
                    return result;
                }
                if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                    return invalid(e);
                }
                throw;
            }
            // Then the TPM. One that can't be used for version 2 leaves the
            // KEK unjudged - it throws, with the reason. A key file pinned
            // to a storage root key the TPM no longer has (a cleared TPM) is
            // definitely unusable: invalid. A load or HMAC the TPM refuses
            // propagates, since it can't be told apart here from a TPM that
            // is merely failing now.
            UsableTpm usable;
            try {
                usable = OpenUsableTpm();
            } catch (const V2TpmUnusable &e) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_UNAVAILABLE,
                                     ("the TPM can't be used for version 2: " + e.reason()).c_str());
            }
            std::unique_ptr<TpmV2Kek> kek;
            try {
                kek = std::make_unique<TpmV2Kek>(std::move(usable), std::move(file));
            } catch (const HkdfGuardError &e) {
                if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                    return invalid(e);
                }
                throw;
            }
            kek->Fingerprint(result.fingerprint);
            result.state = V2KekInspection::State::Valid;
            return result;
        }

        if (provider_type == kProviderTypeSoftware) {
            ScopedNCryptProv provider;
            OpenProvider(provider);
            ScopedNCryptKey key;
            const SECURITY_STATUS status = OpenSoftwareKey(provider.get(), V2SoftwareKeyName(service, kCurrentKeyId), key);
            if (status == NTE_BAD_KEYSET) {
                return result;
            }
            if (status != ERROR_SUCCESS) {
                ThrowForNCryptFailure(status, "NCryptOpenKey failed");
            }
            try {
                VerifySoftwareKey(key.get());
            } catch (const KekAccessControlError &e) {
                return access_control_invalid(e);
            } catch (const HkdfGuardError &e) {
                if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                    return invalid(e);
                }
                throw;
            }
            SoftwareV2Kek(service).Fingerprint(result.fingerprint);
            result.state = V2KekInspection::State::Valid;
            return result;
        }

        throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "unknown provider type");
    }

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestV2TpmStore(std::optional<TpmKeyStore> store) {
        g_test_tpm_store = std::move(store);
    }

    void SetTestV2TpmUnusable(std::optional<std::string> reason) {
        g_test_tpm_unusable = std::move(reason);
    }
#endif
} // namespace hkdfguard
