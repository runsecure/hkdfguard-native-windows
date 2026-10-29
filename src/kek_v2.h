#pragma once

#include "secure_buffer.h" // SecureBuffer<N>
#include "tpm_key_file.h"  // TpmKeyStore
#include "wire_format.h"   // kFingerprintLen, kHeaderLen

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

// The version 2 KEK (docs/adr/0001-post-quantum-payload-version-2.md): a
// symmetric key the provider holds and uses as a PRF, so there is no public
// key - nothing a quantum computer could work on - and, as in version 1,
// only an account allowed to use the KEK can wrap or unwrap.
//
//   TPM (ProviderType 1): an HMAC-SHA-256 key made by TPM2_Create under the
//     storage root key, kept as a key file (tpm_key_file.h) and used with
//     raw TPM 2.0 commands through TBS (tpm2_device.h) - in a session
//     salted to the storage root key, with the HMAC's result encrypted.
//   Software (ProviderType 2): a persisted, non-exportable AES-256 machine
//     key in the Microsoft Software KSP, used as AES-CMAC (aes_cmac.h). Its
//     name is the version 1 KEK's with "_aes" appended, so the two never
//     collide.
//
// Both derive through sp800_108.h: the fingerprint and the wrapping key are
// PRF outputs, 32 bytes each (one HMAC block, or two CMAC blocks).
//
// Provider choice follows KeyStoragePolicy exactly as version 1's does
// (kek_store.h), with one rule of its own: the TPM is usable for version 2
// only if TBS reaches a TPM 2.0, the storage root key (0x81000001) is a
// SHA-256 storage key, no needed command is blocked, and the TPM's
// HMAC-SHA-256 passes a known-answer test - the Linux library's own vector.
// When it isn't, PreferTpm falls back to the software KSP (event 1001) -
// unless a TPM key file already exists, which proves a TPM KEK is in use -
// and RequireTpm fails with HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, logging
// event 2008 with the reason. Version 2 never falls back to version 1.
//
// `service` is the normalized service name throughout, as in kek_store.h.
namespace hkdfguard {
    class V2Kek {
    public:
        virtual ~V2Kek() = default;

        uint8_t provider_type() const { return provider_type_; }
        uint32_t key_id() const { return key_id_; }

        // The KEK's fingerprint: PRF(KEK, the fingerprint block). Public:
        // it reveals nothing about the KEK.
        virtual void Fingerprint(uint8_t out[kFingerprintLen]) = 0;

        // The wrapping key for a payload with this `header`:
        // PRF(KEK, the wrap block for `service` and `header`).
        virtual void WrappingKey(const std::string &service, const uint8_t header[kHeaderLen], SecureBuffer<32> &out) = 0;

    protected:
        V2Kek(uint8_t provider_type, uint32_t key_id) : provider_type_(provider_type), key_id_(key_id) {}

    private:
        uint8_t provider_type_;
        uint32_t key_id_;
    };

    // Whether the service's version 2 KEK exists, per KeyStoragePolicy.
    // Never creates or modifies anything.
    bool V2KekExists(const std::wstring &service);

    // Creates the service's version 2 KEK if missing, or verifies it if
    // present - the version 2 hkdfguard_create_kek. Needs an elevated caller
    // to create. Throws HkdfGuardError on failure.
    void CreateV2Kek(const std::wstring &service);

    // Opens the service's existing version 2 KEK for wrap (and for
    // hkdfguard_kek_fingerprint), per KeyStoragePolicy. Never creates one.
    std::unique_ptr<V2Kek> OpenV2KekForWrap(const std::wstring &service);

    // Opens the version 2 KEK a payload's routing fields select. Never
    // creates one.
    std::unique_ptr<V2Kek> OpenV2KekForUnwrap(const std::wstring &service, uint8_t provider_type, uint32_t key_id);

    // Deletes the service's version 2 KEK on `provider_type`, if present.
    // Returns whether anything was deleted. For the CLI's retire and the
    // tests; needs an elevated caller.
    bool DeleteV2Kek(const std::wstring &service, uint8_t provider_type, uint32_t key_id);

    // The name of the service's version 2 software KEK in the Microsoft
    // Software KSP.
    std::wstring V2SoftwareKeyName(const std::wstring &service, uint32_t key_id);

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    // Test-only seams, compiled in only with
    // HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE (never in HkdfGuard.dll); not
    // thread-safe. A TPM key store other than ProgramData's; and a TPM that
    // reports itself unusable for version 2, with `reason`, so PreferTpm's
    // fallback and RequireTpm's refusal can be tested on a machine whose
    // TPM works. std::nullopt clears each.
    void SetTestV2TpmStore(std::optional<TpmKeyStore> store);
    void SetTestV2TpmUnusable(std::optional<std::string> reason);
#endif
} // namespace hkdfguard
