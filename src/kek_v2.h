#pragma once

#include "secure_buffer.h" // SecureBuffer<N>
#include "wire_format.h"   // kFingerprintLen, kHeaderLen

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

// The version 2 KEK (docs/adr/0001-post-quantum-payload-version-2.md): a
// symmetric key the provider holds and uses as an HMAC-SHA-256 PRF, so there
// is no public key - nothing a quantum computer could work on - and, as in
// version 1, only an account allowed to use the KEK can wrap or unwrap.
// Both are persisted, non-exportable NCrypt machine keys with version 1's
// ACL, so the provider checks the caller on every use:
//
//   TPM (ProviderType 1): an HMAC-SHA-256 key in the Microsoft Platform
//     Crypto Provider, with the PCP's signature key usage (the only usage
//     it finalizes an HMAC key with). NCryptSignHash over an SP 800-108
//     block returns HMAC-SHA-256 of it, computed in the TPM.
//   Software (ProviderType 2): an SP800_108_CTR_HMAC key in the Microsoft
//     Software KSP, used with NCryptKeyDerivation, which builds the same
//     block from the label and context and returns the same HMAC.
//
// Both derive through sp800_108.h: the fingerprint and the wrapping key are
// one PRF output each, 32 bytes. The software KSP's derivation is checked
// once per process against HMAC-SHA-256 (CheckSoftwareKdfImplementation).
// The TPM's can't be: the PCP won't import a known HMAC key. The
// fingerprint, itself a PRF output, is what pins it - a TPM whose output
// changed would no longer match any payload's fingerprint, and unwrap fails
// with HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH before any decryption.
//
// Provider choice follows KeyStoragePolicy exactly as version 1's does
// (kek_store.h): the TPM is unusable for version 2 when the PCP can't be
// opened, reports no TPM device, or can't create the key (with nothing left
// behind). PreferTpm then falls back to the software KSP (event 1001) -
// unless a TPM KEK already exists for the service - and RequireTpm fails
// with HKDFGUARD_ERR_PROVIDER_UNAVAILABLE, logging event 2008 with the
// reason. Version 2 never falls back to version 1.
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

    // Deletes the service's version 2 KEK on `provider_type`, if present -
    // whether or not it would pass its checks, so a corrupt one can be
    // removed too. Returns whether anything was deleted. For the CLI's
    // retire and the tests; needs an elevated caller. Never compiled into
    // a path HkdfGuard.dll's ABI can reach: the library itself can't delete.
    bool DeleteV2Kek(const std::wstring &service, uint8_t provider_type, uint32_t key_id);

    // What a service's version 2 KEK on one provider is, judged with no
    // KeyStoragePolicy involved - for the CLI's status and retire, which
    // must see every KEK, not just the one policy selects.
    struct V2KekInspection {
        enum class State {
            Absent,  // no KEK of this version on that provider
            Valid,   // present, passes every check; `fingerprint` is set
            Invalid, // present, but fails a check of the key itself; `problem` says which
            // Present, and fails only on its DACL (errors.h's
            // KekAccessControlError). The key may be fine: the remedy is to
            // fix the ACL, never to retire it. `problem` says which check.
            AccessControlInvalid,
        };
        State state = State::Absent;
        uint8_t fingerprint[kFingerprintLen] = {};
        std::string problem;
    };

    // Inspects the KEK on `provider_type` (kProviderTypeTpm or
    // kProviderTypeSoftware). Only a definite answer is returned: anything
    // that leaves the state unknown - access denied, a TPM provider that
    // can't be opened, a provider error - throws, so a KEK that merely can't
    // be checked right now is never reported absent or corrupt.
    V2KekInspection InspectV2Kek(const std::wstring &service, uint8_t provider_type);

    // The names of the service's version 2 KEKs: in the Platform Crypto
    // Provider, and in the Microsoft Software KSP. Version 1's name with a
    // suffix naming the key type, so the two versions never collide.
    std::wstring V2TpmKeyName(const std::wstring &service, uint32_t key_id);
    std::wstring V2SoftwareKeyName(const std::wstring &service, uint32_t key_id);

    // Checks that the Software KSP's SP800_108_CTR_HMAC derivation is
    // HMAC-SHA-256 over sp800_108.h's blocks: with a throwaway exportable
    // key, its output for the fingerprint and for a wrap context is compared
    // with BCrypt's HMAC-SHA-256 of the same blocks. Run once per process
    // before the first software KEK is used. Throws
    // HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR) on a mismatch, or
    // HKDFGUARD_ERR_PROVIDER_ERROR if the check can't run.
    void CheckSoftwareKdfImplementation();

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    // Test-only seam, compiled in only with
    // HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE (never in HkdfGuard.dll); not
    // thread-safe. A TPM that reports itself unusable for version 2, with
    // `reason`, so PreferTpm's fallback and RequireTpm's refusal can be
    // tested on a machine whose TPM works. std::nullopt clears it.
    void SetTestV2TpmUnusable(std::optional<std::string> reason);
#endif
} // namespace hkdfguard
