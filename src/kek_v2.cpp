#include "kek_v2.h"
#include "errors.h"
#include "event_log.h"     // LogKekCreated, LogVersion2Unavailable
#include "handle_traits.h" // ScopedNCryptProv, ScopedNCryptKey
#include "key_acl.h"       // ApplyKeyAcl, ValidateKeyUseGroups, VerifyExistingKeyAcl, VerifyKeyAcl
#include "policy.h"        // LoadEffectivePolicy, LoadKeyUseGroupsPolicy, LoadDeployerGroupsPolicy
#include "sp800_108.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <atomic>
#include <cstdio>  // snprintf
#include <cstring> // memcmp, strlen

#ifndef TBS_E_TPM_NOT_FOUND
#define TBS_E_TPM_NOT_FOUND ((SECURITY_STATUS)0x8028400FL)
#endif

namespace hkdfguard {
    namespace {
        // Once the software KSP's derivation has passed its check in this
        // process it isn't repeated; a failure is retried on the next call.
        std::atomic<bool> g_kdf_known_answer_passed{false};

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        std::optional<std::string> g_test_tpm_unusable;
#endif

        constexpr size_t kPrfLen = 32; // one HMAC-SHA-256 output

        // The TPM can't be used for version 2 at all, for `reason`: the
        // Platform Crypto Provider can't be opened, reports no TPM device, or
        // can't create the KEK (with nothing left behind). The one failure
        // PreferTpm answers by falling back to the software KSP, as version
        // 1's TpmUnusableError is. Its code is
        // HKDFGUARD_ERR_PROVIDER_UNAVAILABLE.
        class V2TpmUnusable : public HkdfGuardError {
        public:
            explicit V2TpmUnusable(const std::string &reason)
                : HkdfGuardError(HKDFGUARD_ERR_PROVIDER_UNAVAILABLE,
                                 ("the TPM can't be used for version 2: " + reason).c_str()),
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

        // ---- The two providers ----

        bool IsTpm(uint8_t provider_type) { return provider_type == kProviderTypeTpm; }

        const char *Label(uint8_t provider_type) { return IsTpm(provider_type) ? "TPM" : "software"; }

        std::wstring KeyName(const std::wstring &service, uint8_t provider_type) {
            return IsTpm(provider_type) ? V2TpmKeyName(service, kCurrentKeyId) : V2SoftwareKeyName(service, kCurrentKeyId);
        }

        // As version 1's ThrowForNCryptFailure: "absent", "not allowed" and
        // "no TPM device" kept apart from a provider malfunction.
        [[noreturn]] void ThrowForNCryptFailure(SECURITY_STATUS status, uint8_t provider_type, const char *message) {
            if (status == NTE_BAD_KEYSET) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_NOT_FOUND, (std::string("no version 2 ") + Label(provider_type) +
                                                                   " KEK is provisioned for this service").c_str());
            }
            if (status == NTE_PERM || status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_ACCESS_DENIED,
                                     (std::string("access to the version 2 ") + Label(provider_type) + " KEK was denied").c_str());
            }
            // No TPM device at all proves no TPM KEK can be in use. A TPM
            // that is merely busy, locked out or not ready is deliberately not
            // here: a TPM KEK may well exist behind it.
            if (IsTpm(provider_type) && (status == TBS_E_TPM_NOT_FOUND || status == NTE_DEVICE_NOT_FOUND)) {
                throw V2TpmUnusable("no TPM device is present");
            }
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, (std::string(message) + " (" + Hex32(status) + ")").c_str());
        }

        void OpenProvider(uint8_t provider_type, ScopedNCryptProv &provider) {
            if (IsTpm(provider_type)) {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
                if (g_test_tpm_unusable) {
                    throw V2TpmUnusable(*g_test_tpm_unusable);
                }
#endif
                const SECURITY_STATUS status = NCryptOpenStorageProvider(provider.put(), MS_PLATFORM_CRYPTO_PROVIDER, 0);
                if (status != ERROR_SUCCESS) {
                    throw V2TpmUnusable("the Platform Crypto Provider can't be opened (" + Hex32(status) + ")");
                }
                return;
            }
            if (NCryptOpenStorageProvider(provider.put(), MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "NCryptOpenStorageProvider failed");
            }
        }

        // NCRYPT_MACHINE_KEY_FLAG: a machine key, as version 1's, so any
        // account the ACL admits finds it; NCRYPT_SILENT_FLAG, so a key that
        // would prompt fails instead.
        SECURITY_STATUS OpenKey(NCRYPT_PROV_HANDLE provider, const std::wstring &name, ScopedNCryptKey &key) {
            return NCryptOpenKey(provider, key.put(), name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        }

        // Reads a DWORD property; std::nullopt if the provider doesn't
        // report it (NTE_NOT_SUPPORTED, NTE_NOT_FOUND).
        std::optional<DWORD> DwordProperty(NCRYPT_HANDLE object, LPCWSTR property) {
            DWORD value = 0;
            DWORD got = 0;
            const SECURITY_STATUS status =
                NCryptGetProperty(object, property, reinterpret_cast<PBYTE>(&value), sizeof(value), &got, 0);
            if (status == NTE_NOT_SUPPORTED || status == NTE_NOT_FOUND) {
                return std::nullopt;
            }
            if (status != ERROR_SUCCESS || got != sizeof(value)) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "reading a version 2 KEK property failed");
            }
            return value;
        }

        // What every version 2 KEK is, checked on every open. A violation is
        // HKDFGUARD_ERR_KEK_INVALID: the key isn't one this library makes.
        //
        //   - Its algorithm. The software KSP reports SP800_108_CTR_HMAC (and
        //     the group KEY_DERIVATION); the PCP reports HMAC-SHA256 and no
        //     algorithm group at all, so the name is what's checked on both.
        //   - On the TPM, the PCP's signature key usage, without which the
        //     PCP won't compute an HMAC with it; and hardware backing, from
        //     the provider handle when the key won't say (as version 1's
        //     VerifyHardwareBacked).
        //   - Never exportable.
        //   - An ACL this library would have made, when this caller may read
        //     it (as version 1's VerifyAclIfReadable). A violation is a
        //     KekAccessControlError: fixing the ACL repairs it, not retiring
        //     the key.
        //
        // The key length can't be checked: both providers report
        // NCRYPT_LENGTH_PROPERTY as 0 for these keys. The software KEK is
        // created with a 256-bit length, which CheckSoftwareKdfImplementation
        // shows gives a 32-byte key; the PCP chooses its HMAC key's size.
        void VerifyKey(NCRYPT_KEY_HANDLE key, NCRYPT_PROV_HANDLE provider, uint8_t provider_type) {
            const std::string what = std::string("the version 2 ") + Label(provider_type) + " KEK";
            wchar_t algorithm[64] = {};
            DWORD got = 0;
            if (NCryptGetProperty(key, NCRYPT_ALGORITHM_PROPERTY, reinterpret_cast<PBYTE>(algorithm),
                                  sizeof(algorithm) - sizeof(wchar_t), &got, 0) != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, ("reading " + what + "'s algorithm failed").c_str());
            }
            const wchar_t *expected = IsTpm(provider_type) ? NCRYPT_HMAC_SHA256_ALGORITHM : NCRYPT_SP800108_CTR_HMAC_ALGORITHM;
            if (wcscmp(algorithm, expected) != 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID,
                                     (what + (IsTpm(provider_type) ? " is not an HMAC-SHA-256 key"
                                                                   : " is not an SP 800-108 HMAC key")).c_str());
            }

            if (IsTpm(provider_type)) {
                const std::optional<DWORD> usage = DwordProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY);
                if (!usage || (*usage & NCRYPT_PCP_SIGNATURE_KEY) == 0) {
                    throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID, (what + " lacks the PCP's signature key usage").c_str());
                }
                std::optional<DWORD> impl = DwordProperty(key, NCRYPT_IMPL_TYPE_PROPERTY);
                if (!impl) {
                    impl = DwordProperty(provider, NCRYPT_IMPL_TYPE_PROPERTY);
                }
                if (!impl || (*impl & NCRYPT_IMPL_HARDWARE_FLAG) == 0) {
                    throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID, (what + " is not hardware backed").c_str());
                }
            }

            constexpr DWORD kExportable = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                                          NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG;
            const std::optional<DWORD> export_policy = DwordProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY);
            if (!export_policy) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, ("reading " + what + "'s export policy failed").c_str());
            }
            if ((*export_policy & kExportable) != 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID, (what + " is exportable").c_str());
            }

            try {
                VerifyExistingKeyAcl(key);
            } catch (const HkdfGuardError &e) {
                if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                    throw KekAccessControlError((what + "'s ACL: " + e.what()).c_str());
                }
            }
        }

        // The software KSP's SP 800-108 derivation: one 32-byte output for
        // `label` and `context` (none for the fingerprint, which the KSP
        // frames exactly as an empty one). The KSP builds the block
        // sp800_108.h describes and returns HMAC-SHA-256 of it under the key.
        void KspDerive(NCRYPT_KEY_HANDLE key, const char *label, const std::vector<uint8_t> &context, uint8_t out[kPrfLen]) {
            BCryptBuffer buffers[3] = {};
            ULONG count = 0;
            buffers[count++] = {static_cast<ULONG>(std::strlen(label)), KDF_LABEL, const_cast<char *>(label)};
            if (!context.empty()) {
                buffers[count++] = {static_cast<ULONG>(context.size()), KDF_CONTEXT, const_cast<uint8_t *>(context.data())};
            }
            buffers[count++] = {static_cast<ULONG>(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM,
                                const_cast<wchar_t *>(BCRYPT_SHA256_ALGORITHM)};
            BCryptBufferDesc parameters = {BCRYPTBUFFER_VERSION, count, buffers};
            DWORD got = 0;
            const SECURITY_STATUS status =
                NCryptKeyDerivation(key, &parameters, out, static_cast<DWORD>(kPrfLen), &got, NCRYPT_SILENT_FLAG);
            if (status == NTE_PERM || status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
                ThrowForNCryptFailure(status, kProviderTypeSoftware, "NCryptKeyDerivation failed");
            }
            if (status != ERROR_SUCCESS || got != kPrfLen) {
                SecureZeroMemory(out, kPrfLen);
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "the software KEK's key derivation failed");
            }
        }

        // A version 2 TPM KEK: NCryptSignHash with the PCP's HMAC key is
        // HMAC-SHA-256 of its input, computed in the TPM. The input is at
        // most 196 bytes (a 128-byte service name), well under the 1,024 the
        // PCP accepts.
        class TpmV2Kek : public V2Kek {
        public:
            explicit TpmV2Kek(const std::wstring &service) : V2Kek(kProviderTypeTpm, kCurrentKeyId) {
                OpenProvider(kProviderTypeTpm, provider_);
                const SECURITY_STATUS status = OpenKey(provider_.get(), KeyName(service, kProviderTypeTpm), key_);
                if (status != ERROR_SUCCESS) {
                    ThrowForNCryptFailure(status, kProviderTypeTpm, "NCryptOpenKey failed");
                }
                VerifyKey(key_.get(), provider_.get(), kProviderTypeTpm);
            }

            void Fingerprint(uint8_t out[kFingerprintLen]) override {
                SecureBuffer<32> value;
                Prf(FingerprintBlock(1), value.data());
                std::memcpy(out, value.data(), kFingerprintLen);
            }

            void WrappingKey(const std::string &service, const uint8_t header[kHeaderLen], SecureBuffer<32> &out) override {
                Prf(WrapBlock(1, service, header, kHeaderLen), out.data());
            }

        private:
            // Exactly 32 bytes of output, always: given a shorter buffer the
            // PCP reports success and 32 bytes without writing the result
            // (observed on an AMD firmware TPM), so the size is never left
            // to it.
            void Prf(const std::vector<uint8_t> &block, uint8_t out[kPrfLen]) {
                DWORD got = 0;
                const SECURITY_STATUS status =
                    NCryptSignHash(key_.get(), nullptr, const_cast<PBYTE>(block.data()), static_cast<DWORD>(block.size()),
                                   out, static_cast<DWORD>(kPrfLen), &got, NCRYPT_SILENT_FLAG);
                if (status == NTE_PERM || status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
                    ThrowForNCryptFailure(status, kProviderTypeTpm, "NCryptSignHash failed");
                }
                if (status != ERROR_SUCCESS || got != kPrfLen) {
                    SecureZeroMemory(out, kPrfLen);
                    throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, ("the TPM's HMAC failed (" + Hex32(status) + ")").c_str());
                }
            }

            ScopedNCryptProv provider_;
            ScopedNCryptKey key_;
        };

        // A version 2 software KEK: the KSP's SP800_108_CTR_HMAC key, used
        // through NCryptKeyDerivation, so the key never leaves the KSP.
        class SoftwareV2Kek : public V2Kek {
        public:
            explicit SoftwareV2Kek(const std::wstring &service) : V2Kek(kProviderTypeSoftware, kCurrentKeyId) {
                if (!g_kdf_known_answer_passed.load()) {
                    CheckSoftwareKdfImplementation();
                    g_kdf_known_answer_passed.store(true);
                }
                OpenProvider(kProviderTypeSoftware, provider_);
                const SECURITY_STATUS status = OpenKey(provider_.get(), KeyName(service, kProviderTypeSoftware), key_);
                if (status != ERROR_SUCCESS) {
                    ThrowForNCryptFailure(status, kProviderTypeSoftware, "NCryptOpenKey failed");
                }
                VerifyKey(key_.get(), provider_.get(), kProviderTypeSoftware);
            }

            void Fingerprint(uint8_t out[kFingerprintLen]) override {
                SecureBuffer<32> value;
                KspDerive(key_.get(), kFingerprintLabel, {}, value.data());
                std::memcpy(out, value.data(), kFingerprintLen);
            }

            void WrappingKey(const std::string &service, const uint8_t header[kHeaderLen], SecureBuffer<32> &out) override {
                KspDerive(key_.get(), kWrapLabel, WrapContext(service, header, kHeaderLen), out.data());
            }

        private:
            ScopedNCryptProv provider_;
            ScopedNCryptKey key_;
        };

        std::unique_ptr<V2Kek> OpenKek(const std::wstring &service, uint8_t provider_type) {
            if (IsTpm(provider_type)) {
                return std::make_unique<TpmV2Kek>(service);
            }
            return std::make_unique<SoftwareV2Kek>(service);
        }

        // Whether the service's KEK exists on the provider. A missing key is
        // `false`; anything that leaves it unknown throws - NTE_PERM as
        // KEK_ACCESS_DENIED, never as "absent".
        bool KekExistsOn(const std::wstring &service, uint8_t provider_type) {
            ScopedNCryptProv provider;
            OpenProvider(provider_type, provider);
            ScopedNCryptKey key;
            const SECURITY_STATUS status = OpenKey(provider.get(), KeyName(service, provider_type), key);
            if (status == ERROR_SUCCESS) {
                return true;
            }
            if (status == NTE_BAD_KEYSET) {
                return false;
            }
            ThrowForNCryptFailure(status, provider_type, "NCryptOpenKey failed");
        }

        // The provider couldn't create the KEK: on the TPM, the fallback-
        // eligible V2TpmUnusable (nothing was left behind); on the software
        // KSP, a provider error.
        [[noreturn]] void CannotCreate(uint8_t provider_type, const std::string &step, SECURITY_STATUS status) {
            const std::string reason = step + " failed (" + Hex32(status) + ")";
            if (IsTpm(provider_type)) {
                throw V2TpmUnusable("the TPM can't create the KEK: " + reason);
            }
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, ("creating the version 2 software KEK: " + reason).c_str());
        }

        // Creates the KEK on the provider if missing; verifies it if present.
        // Returns whether it created one, as version 1's CreateKekOnProvider,
        // whose rules it follows: an existing key is verified - its
        // properties, every group the current policy names, and one PRF
        // call - and never touched; a key this call creates is reopened and
        // verified the same way, and deleted if it fails.
        bool CreateKekOn(const std::wstring &service, uint8_t provider_type, const std::vector<std::wstring> &groups) {
            ScopedNCryptProv provider;
            OpenProvider(provider_type, provider);
            const std::wstring name = KeyName(service, provider_type);

            const auto verify = [&](NCRYPT_KEY_HANDLE key) {
                VerifyKey(key, provider.get(), provider_type);
                VerifyKeyAcl(key, groups);
                uint8_t fingerprint[kFingerprintLen];
                OpenKek(service, provider_type)->Fingerprint(fingerprint);
            };
            // An existing KEK - found now, or created concurrently below.
            const auto verify_existing = [&] {
                ScopedNCryptKey existing;
                const SECURITY_STATUS status = OpenKey(provider.get(), name, existing);
                if (status != ERROR_SUCCESS) {
                    ThrowForNCryptFailure(status, provider_type, "NCryptOpenKey failed");
                }
                verify(existing.get());
            };

            {
                ScopedNCryptKey existing;
                const SECURITY_STATUS status = OpenKey(provider.get(), name, existing);
                if (status == ERROR_SUCCESS) {
                    verify(existing.get());
                    return false;
                }
                // Only "absent" proceeds to creation; NTE_PERM (a key this
                // caller may not open) and the rest are errors.
                if (status != NTE_BAD_KEYSET) {
                    ThrowForNCryptFailure(status, provider_type, "NCryptOpenKey failed");
                }
            }

            ScopedNCryptKey key;
            SECURITY_STATUS status = NCryptCreatePersistedKey(
                provider.get(), key.put(),
                IsTpm(provider_type) ? NCRYPT_HMAC_SHA256_ALGORITHM : NCRYPT_SP800108_CTR_HMAC_ALGORITHM, name.c_str(), 0,
                NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
            if (status == NTE_EXISTS) {
                verify_existing();
                return false;
            }
            if (status != ERROR_SUCCESS) {
                CannotCreate(provider_type, "NCryptCreatePersistedKey", status);
            }

            if (IsTpm(provider_type)) {
                // The only usage the PCP finalizes an HMAC key with; without
                // it NCryptFinalizeKey fails with NTE_NOT_SUPPORTED.
                DWORD usage = NCRYPT_PCP_SIGNATURE_KEY;
                status = NCryptSetProperty(key.get(), NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&usage),
                                           sizeof(usage), 0);
                if (status != ERROR_SUCCESS) {
                    CannotCreate(provider_type, "setting the key usage", status);
                }
            } else {
                DWORD length = 256;
                status = NCryptSetProperty(key.get(), NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&length),
                                           sizeof(length), 0);
                if (status != ERROR_SUCCESS) {
                    CannotCreate(provider_type, "setting the key length", status);
                }
            }
            DWORD export_policy = 0;
            status = NCryptSetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&export_policy),
                                       sizeof(export_policy), 0);
            if (status != ERROR_SUCCESS) {
                CannotCreate(provider_type, "setting the export policy", status);
            }
            try {
                ApplyKeyAcl(key.get(), groups);
            } catch (const HkdfGuardError &e) {
                // Only the provider refusing the security descriptor is a
                // provider capability; a key-use group that stopped resolving
                // would fail on the software KSP just the same.
                if (IsTpm(provider_type) && e.code() == HKDFGUARD_ERR_PROVIDER_ERROR) {
                    throw V2TpmUnusable(std::string("the TPM can't create the KEK: ") + e.what());
                }
                throw;
            }

            // Finalizing a machine key is what needs elevation.
            status = NCryptFinalizeKey(key.get(), NCRYPT_SILENT_FLAG);
            if (status == NTE_PERM || status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
                ThrowForNCryptFailure(status, provider_type, "NCryptFinalizeKey failed");
            }
            if (status == NTE_EXISTS) {
                verify_existing();
                return false;
            }
            if (status != ERROR_SUCCESS) {
                CannotCreate(provider_type, "NCryptFinalizeKey", status);
            }

            // Verified on a freshly reopened handle - the PCP reports stale
            // values on the creation handle (kek_store.cpp) - and deleted, on
            // its creation handle, if it fails.
            try {
                verify_existing();
            } catch (const HkdfGuardError &e) {
                const SECURITY_STATUS deleted = NCryptDeleteKey(key.get(), 0);
                key.release(); // NCryptDeleteKey invalidates the handle even on failure
                // Still there: reported, but never as fallback-eligible, so no
                // software KEK is created beside it.
                if (deleted != ERROR_SUCCESS) {
                    throw HkdfGuardError(e.code(), e.what());
                }
                // A key the TPM made but that isn't what was asked for, or
                // won't compute, is the TPM's failure. One that fails only on
                // its ACL isn't: the software KSP would fail the same way.
                const bool acl_only = dynamic_cast<const KekAccessControlError *>(&e) != nullptr;
                if (IsTpm(provider_type) && !acl_only &&
                    (e.code() == HKDFGUARD_ERR_PROVIDER_ERROR || e.code() == HKDFGUARD_ERR_CRYPTO_ERROR ||
                     e.code() == HKDFGUARD_ERR_KEK_INVALID)) {
                    throw V2TpmUnusable(std::string("the TPM's new KEK failed its checks: ") + e.what());
                }
                throw;
            }
            return true;
        }

        // A TPM that can't do version 2 where nothing may replace it: under
        // RequireTpm, or for a payload or KEK that is the TPM's. Event 2008
        // with the reason, then HKDFGUARD_ERR_PROVIDER_UNAVAILABLE.
        [[noreturn]] void ReportUnusable(const std::wstring &service, const V2TpmUnusable &e) {
            LogVersion2Unavailable(service, e.reason());
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, ("version 2 is unavailable: " + e.reason()).c_str());
        }

        std::unique_ptr<V2Kek> OpenTpmKekOrReport(const std::wstring &service) {
            try {
                return OpenKek(service, kProviderTypeTpm);
            } catch (const V2TpmUnusable &e) {
                ReportUnusable(service, e);
            }
        }

        // RAII wipe of a buffer that held key material.
        struct Wiped {
            std::vector<uint8_t> &bytes;
            ~Wiped() { SecureZeroMemory(bytes.data(), bytes.size()); }
        };
    } // namespace

    std::wstring V2TpmKeyName(const std::wstring &service, uint32_t key_id) {
        return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id) + L"_hmac";
    }

    std::wstring V2SoftwareKeyName(const std::wstring &service, uint32_t key_id) {
        return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id) + L"_kdf";
    }

    void CheckSoftwareKdfImplementation() {
        // A throwaway key, never persisted, made the way the software KEK is
        // (SP800_108_CTR_HMAC, 256 bits) but exportable, so its value can be
        // compared with.
        ScopedNCryptProv provider;
        OpenProvider(kProviderTypeSoftware, provider);
        ScopedNCryptKey key;
        DWORD length = 256;
        DWORD exportable = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        if (NCryptCreatePersistedKey(provider.get(), key.put(), NCRYPT_SP800108_CTR_HMAC_ALGORITHM, nullptr, 0,
                                     NCRYPT_SILENT_FLAG) != ERROR_SUCCESS ||
            NCryptSetProperty(key.get(), NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&length), sizeof(length), 0) !=
                ERROR_SUCCESS ||
            NCryptSetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&exportable),
                              sizeof(exportable), 0) != ERROR_SUCCESS ||
            NCryptFinalizeKey(key.get(), NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "the software KSP's key derivation check couldn't run");
        }

        std::vector<uint8_t> blob(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 64);
        Wiped wipe_blob{blob};
        DWORD got = 0;
        if (NCryptExportKey(key.get(), 0, BCRYPT_KEY_DATA_BLOB, nullptr, blob.data(), static_cast<DWORD>(blob.size()), &got,
                            0) != ERROR_SUCCESS ||
            got < sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "the software KSP's key derivation check couldn't run");
        }
        BCRYPT_KEY_DATA_BLOB_HEADER header{};
        std::memcpy(&header, blob.data(), sizeof(header));
        // A 256-bit length must give a 32-byte key: the software KEK's
        // length can't be read back once persisted (VerifyKey).
        if (header.dwMagic != BCRYPT_KEY_DATA_BLOB_MAGIC || header.dwVersion != BCRYPT_KEY_DATA_BLOB_VERSION1 ||
            header.cbKeyData != 32 || got != sizeof(header) + header.cbKeyData) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "the software KSP's SP 800-108 key is not a 256-bit key");
        }
        uint8_t *const secret = blob.data() + sizeof(header);

        const auto expected = [&](const std::vector<uint8_t> &block, uint8_t out[kPrfLen]) {
            if (BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, secret, header.cbKeyData, const_cast<PUCHAR>(block.data()),
                           static_cast<ULONG>(block.size()), out, static_cast<ULONG>(kPrfLen)) != 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "the software KSP's key derivation check couldn't run");
            }
        };
        // The fingerprint, and a wrap context with a header of every byte
        // value 0..39.
        const std::string service = "hkdfguard.kat";
        uint8_t kat_header[kHeaderLen];
        for (size_t i = 0; i < kHeaderLen; ++i) {
            kat_header[i] = static_cast<uint8_t>(i);
        }
        SecureBuffer<32> want, have;
        expected(FingerprintBlock(1), want.data());
        KspDerive(key.get(), kFingerprintLabel, {}, have.data());
        bool match = std::memcmp(want.data(), have.data(), kPrfLen) == 0;
        expected(WrapBlock(1, service, kat_header, kHeaderLen), want.data());
        KspDerive(key.get(), kWrapLabel, WrapContext(service, kat_header, kHeaderLen), have.data());
        match = match && std::memcmp(want.data(), have.data(), kPrfLen) == 0;
        if (!match) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR,
                                 "the software KSP's SP 800-108 derivation is not HMAC-SHA-256 over the expected block");
        }
    }

    bool V2KekExists(const std::wstring &service) {
        switch (RequirePolicy()) {
            case KeyStoragePolicy::RequireTpm:
                try {
                    return KekExistsOn(service, kProviderTypeTpm);
                } catch (const V2TpmUnusable &e) {
                    ReportUnusable(service, e);
                }
            case KeyStoragePolicy::SoftwareOnly:
                return KekExistsOn(service, kProviderTypeSoftware);
            case KeyStoragePolicy::PreferTpm:
                // As version 1: the TPM first, and the software KSP only when
                // the TPM is unusable or has no KEK. NTE_PERM on the TPM - a
                // TPM KEK this caller may not open - propagates, so it is
                // never reported absent.
                try {
                    if (KekExistsOn(service, kProviderTypeTpm)) {
                        return true;
                    }
                } catch (const V2TpmUnusable &) {
                }
                return KekExistsOn(service, kProviderTypeSoftware);
            default:
                break;
        }
        throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
    }

    void CreateV2Kek(const std::wstring &service) {
        const std::vector<std::wstring> groups = AclGroups();
        switch (RequirePolicy()) {
            case KeyStoragePolicy::RequireTpm:
                try {
                    if (CreateKekOn(service, kProviderTypeTpm, groups)) {
                        LogKekCreated(service, kProviderTypeTpm, HKDFGUARD_OK);
                    }
                } catch (const V2TpmUnusable &e) {
                    ReportUnusable(service, e);
                }
                return;
            case KeyStoragePolicy::SoftwareOnly:
                if (CreateKekOn(service, kProviderTypeSoftware, groups)) {
                    LogKekCreated(service, kProviderTypeSoftware, HKDFGUARD_OK);
                }
                return;
            case KeyStoragePolicy::PreferTpm:
                try {
                    if (CreateKekOn(service, kProviderTypeTpm, groups)) {
                        LogKekCreated(service, kProviderTypeTpm, HKDFGUARD_OK);
                    }
                } catch (const V2TpmUnusable &e) {
                    // The fallback (event 1001 if it creates the software
                    // KEK): the TPM is unusable and holds no KEK of this
                    // service - CreateKekOn throws V2TpmUnusable only before
                    // a key is found, or after deleting one it just made. An
                    // existing TPM KEK that fails its checks, or a TPM KEK
                    // this caller may not open, propagates instead: a
                    // software KEK beside it would split the service.
                    if (CreateKekOn(service, kProviderTypeSoftware, groups)) {
                        LogKekCreated(service, kProviderTypeSoftware, e.code());
                    }
                }
                return;
            default:
                break;
        }
        throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid key storage policy");
    }

    std::unique_ptr<V2Kek> OpenV2KekForWrap(const std::wstring &service) {
        switch (RequirePolicy()) {
            case KeyStoragePolicy::RequireTpm:
                return OpenTpmKekOrReport(service);
            case KeyStoragePolicy::SoftwareOnly:
                return OpenKek(service, kProviderTypeSoftware);
            case KeyStoragePolicy::PreferTpm:
                // As version 1: the software KEK only when the TPM has none
                // (the KEK a fallback created) or is unusable. A TPM KEK that
                // fails its checks, or that this caller may not open,
                // propagates rather than quietly wrapping under another key.
                try {
                    return OpenKek(service, kProviderTypeTpm);
                } catch (const V2TpmUnusable &) {
                } catch (const HkdfGuardError &e) {
                    if (e.code() != HKDFGUARD_ERR_KEK_NOT_FOUND) {
                        throw;
                    }
                }
                return OpenKek(service, kProviderTypeSoftware);
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
        return OpenKek(service, kProviderTypeSoftware);
    }

    bool DeleteV2Kek(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        if (provider_type != kProviderTypeTpm && provider_type != kProviderTypeSoftware) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "unknown provider type");
        }
        ScopedNCryptProv provider;
        const std::wstring name =
            IsTpm(provider_type) ? V2TpmKeyName(service, key_id) : V2SoftwareKeyName(service, key_id);
        ScopedNCryptKey key;
        // A TPM that can't be used for version 2 at all (V2TpmUnusable) holds
        // nothing to delete, as version 1's OpenKekDirect treats it.
        try {
            OpenProvider(provider_type, provider);
            const SECURITY_STATUS status = OpenKey(provider.get(), name, key);
            if (status == NTE_BAD_KEYSET) {
                return false;
            }
            if (status != ERROR_SUCCESS) {
                ThrowForNCryptFailure(status, provider_type, "NCryptOpenKey failed");
            }
        } catch (const V2TpmUnusable &) {
            return false;
        }
        // No NCRYPT_SILENT_FLAG: the PCP refuses it here (NTE_BAD_FLAGS), and
        // the key was opened silently already.
        const SECURITY_STATUS deleted = NCryptDeleteKey(key.get(), 0);
        key.release(); // NCryptDeleteKey invalidates the handle even on failure
        if (deleted != ERROR_SUCCESS) {
            ThrowForNCryptFailure(deleted, provider_type, "deleting the version 2 KEK failed");
        }
        return true;
    }

    V2KekInspection InspectV2Kek(const std::wstring &service, uint8_t provider_type) {
        if (provider_type != kProviderTypeTpm && provider_type != kProviderTypeSoftware) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "unknown provider type");
        }
        V2KekInspection result;
        // Absent is definite; so are a key that fails a check of its own
        // (Invalid) and one that fails only on its ACL (AccessControlInvalid,
        // checked first: it is KEK_INVALID too, but must never be reported
        // as corrupt - errors.h). So is a TPM that can't be used for version
        // 2 at all - the Platform Crypto Provider can't be opened, or there
        // is no TPM device: it holds no KEK, as CreateV2Kek's fallback and
        // version 1's OpenKekDirect assume, so it is Absent. Anything else -
        // access denied, a TPM that is busy, a provider error - throws,
        // unjudged.
        bool exists = false;
        try {
            exists = KekExistsOn(service, provider_type);
        } catch (const V2TpmUnusable &) {
            return result;
        }
        if (!exists) {
            return result;
        }
        std::unique_ptr<V2Kek> kek;
        try {
            kek = OpenKek(service, provider_type);
        } catch (const KekAccessControlError &e) {
            result.state = V2KekInspection::State::AccessControlInvalid;
            result.problem = e.what();
            return result;
        } catch (const HkdfGuardError &e) {
            if (e.code() != HKDFGUARD_ERR_KEK_INVALID) {
                throw;
            }
            result.state = V2KekInspection::State::Invalid;
            result.problem = e.what();
            return result;
        }
        kek->Fingerprint(result.fingerprint);
        result.state = V2KekInspection::State::Valid;
        return result;
    }

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestV2TpmUnusable(std::optional<std::string> reason) {
        g_test_tpm_unusable = std::move(reason);
    }
#endif
} // namespace hkdfguard
