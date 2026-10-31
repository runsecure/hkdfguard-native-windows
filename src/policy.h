#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hkdfguard {

    enum class KeyStoragePolicy : uint32_t {
        PreferTpm   = 0,
        RequireTpm  = 1,
        SoftwareOnly = 2,

        // Sentinel: the registry value is present but not one of the three
        // values above (wrong type, or an unrecognized DWORD). Not an alias
        // for PreferTpm - see LoadEffectivePolicy. Callers fail closed with
        // HKDFGUARD_ERR_POLICY_INVALID: KekExists, CreateKek and
        // OpenKekForWrap throw after a switch over the three real values;
        // OpenKekForUnwrap checks for this sentinel directly.
        Invalid = 0xFFFFFFFFu,
    };

    // Returns the machine-wide effective policy. Never throws.
    //
    // A *missing* KeyStoragePolicy value (key or value absent) means the
    // default, KeyStoragePolicy::PreferTpm - normal unconfigured-machine
    // behavior, not an error. A policy key that exists but can't be opened
    // (access denied, say) is not "missing": it returns
    // KeyStoragePolicy::Invalid, since the policy it holds is unknown.
    //
    // A value that *is* present but isn't one of the three recognized
    // policies (wrong REG_* type, or a DWORD other than 0/1/2) also returns
    // KeyStoragePolicy::Invalid. This fails closed: whoever wrote an
    // unrecognized value most likely meant a *specific* policy - possibly
    // RequireTpm - and substituting PreferTpm would let a typo quietly
    // weaken protection instead of surfacing as a configuration error.
    // Every caller turns KeyStoragePolicy::Invalid into
    // HKDFGUARD_ERR_POLICY_INVALID.
    //
    // In a build with HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE defined, the
    // override set by SetTestPolicyOverride is checked first; otherwise
    // this always reads the registry.
    KeyStoragePolicy LoadEffectivePolicy() noexcept;

    // The value-to-policy rule LoadEffectivePolicy applies, with no
    // registry I/O, so it can be tested directly. `found`: the value exists
    // (only a missing value is "never configured" and gets the PreferTpm
    // default). `readable`: it was read whole as 4 bytes - a REG_QWORD or a
    // long REG_SZ isn't. Anything present but unreadable, of another type,
    // or not 0/1/2 is KeyStoragePolicy::Invalid.
    KeyStoragePolicy ParseKeyStoragePolicy(bool found, bool readable, unsigned long type, unsigned long value) noexcept;

    // The rule LoadEffectivePolicy applies when the policy *key* can't be
    // opened, with no registry I/O, so it can be tested directly: only "not
    // found" (ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND) is "never
    // configured" and gets the PreferTpm default; any other status (e.g.
    // ERROR_ACCESS_DENIED) is KeyStoragePolicy::Invalid.
    KeyStoragePolicy KeyStoragePolicyForUnopenedKey(long openStatus) noexcept;

// Test-only seam: makes LoadEffectivePolicy() return `policy` instead of
// reading the registry, so tests can exercise every KeyStoragePolicy
// branch deterministically. std::nullopt clears the override.
//
// Compiled in only when HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE is defined,
// which tests/CMakeLists.txt does for test_roundtrip's own copy of this
// file. HkdfGuard.dll's build never defines it, so neither this function
// nor its state exists in the shipped DLL. Not thread-safe: a
// single-threaded test process is the only intended caller.
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestPolicyOverride(std::optional<KeyStoragePolicy> policy) noexcept;
#endif

    // Returns the machine-wide list of principals to be granted key-use
    // (unwrap) access on every KEK created on this machine: the entries of
    // the REG_MULTI_SZ value HKLM\Software\Policies\HkdfGuard\KeyUseGroups,
    // each trimmed of surrounding whitespace, empty entries dropped. Entries
    // are returned as written (group names or "S-1-..." SID strings) - it is
    // key_acl.cpp's job to resolve and vet them. A missing value, a value of
    // the wrong type, or any read failure yields an empty list (fail closed:
    // no additional principals), never an exception.
    //
    // Deliberately a machine policy rather than a caller argument: an
    // application that can call hkdfguard_create_kek must not be able to
    // widen who can unwrap its DEKs; only a machine administrator can.
    std::vector<std::wstring> LoadKeyUseGroupsPolicy();

    // Whether a successful unwrap writes audit event 1003 (see
    // event_log.h), from the REG_DWORD value
    // HKLM\Software\Policies\HkdfGuard\AuditUnwrapSuccess. Read on every
    // successful unwrap, so a change takes effect without restarting the
    // calling process. Never throws.
    //
    // Only an explicit REG_DWORD 0 turns the event off. A missing value, a
    // non-zero DWORD, a value of the wrong type, or any read failure all
    // mean "on": a misconfigured value must never silently reduce auditing.
    // Wrap events and every failure event are written regardless.
    bool LoadAuditUnwrapSuccess() noexcept;

    // The value-to-setting rule LoadAuditUnwrapSuccess applies, with no
    // registry I/O, so it can be tested directly. `found` is false when the
    // key or value doesn't exist (or can't be read).
    bool ParseAuditUnwrapSuccess(bool found, unsigned long type, unsigned long value) noexcept;

    // The floor on every hkdfguard_create_kek / hkdfguard_kek_exists call's
    // wall-clock time when policy doesn't set one, and the most it may set.
    inline constexpr unsigned long kDefaultSetupMinDelayMs = 1000;
    inline constexpr unsigned long kMaxSetupMinDelayMs = 60000;

    // The setup-call floor in milliseconds, from the REG_DWORD value
    // HKLM\Software\Policies\HkdfGuard\SetupMinDelayMs. Read on every setup
    // call. Never throws.
    //
    // Missing: kDefaultSetupMinDelayMs. A REG_DWORD from 0 to
    // kMaxSetupMinDelayMs is used as is (0 disables the floor). Anything
    // else - the wrong type, or above the maximum - also means
    // kDefaultSetupMinDelayMs.
    unsigned long LoadSetupMinDelayMs() noexcept;

    // The value-to-setting rule LoadSetupMinDelayMs applies, with no
    // registry I/O, so it can be tested directly.
    unsigned long ParseSetupMinDelayMs(bool found, unsigned long type, unsigned long value) noexcept;

    // Test-only seam for LoadKeyUseGroupsPolicy(), with the same scope and
    // caveats as SetTestPolicyOverride: absent from HkdfGuard.dll.
    // std::nullopt clears it.
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestKeyUseGroupsOverride(std::optional<std::vector<std::wstring>> groups);
#endif

    // Which security model this machine runs - who the library trusts to
    // have written a key file (see hkdfguard_open_file in hkdfguard.h).
    //
    //   Production: key files must be owned, and their folders writable,
    //     only by SYSTEM, Administrators, TrustedInstaller, or a deployer
    //     group (HkdfGuardDeployers and the DeployerGroups policy) or a
    //     direct member of one. The calling account's own files are not
    //     trusted unless it is such a member - so an application that can
    //     unwrap (and wrap ephemeral keys in memory) cannot persist a key
    //     file its own service will accept.
    //   Developer: the calling account's own files are trusted too, so one
    //     account can provision, wrap to a file and read it back.
    //
    // Same values as the HKDFGUARD_SECURITY_MODEL_* constants in
    // hkdfguard.h.
    enum class SecurityModel : uint32_t {
        Production = 0,
        Developer = 1,

        // Present but not 0 or 1 (or not a REG_DWORD): fails closed with
        // HKDFGUARD_ERR_POLICY_INVALID, for the same reason as
        // KeyStoragePolicy::Invalid - a typo must not pick a model.
        Invalid = 0xFFFFFFFFu,
    };

    // The value-to-setting rule LoadSecurityModel applies, with no registry
    // I/O, so it can be tested directly. Absent means Production: this is
    // a production install unless an administrator says otherwise.
    SecurityModel ParseSecurityModel(bool found, unsigned long type, unsigned long value) noexcept;

    // The REG_DWORD value HKLM\Software\Policies\HkdfGuard\SecurityModel:
    // absent or 0 = Production, 1 = Developer, anything else = Invalid.
    // Read on every call that depends on it. Never throws.
    SecurityModel LoadSecurityModel() noexcept;

    // The REG_MULTI_SZ value HKLM\Software\Policies\HkdfGuard\DeployerGroups,
    // read exactly like LoadKeyUseGroupsPolicy: trimmed, empties dropped,
    // anything unreadable an empty list. Each entry names a group (or SID
    // string) whose members deploy key files; key_acl.cpp vets them with
    // the KeyUseGroups rules (a host-local group, never over-broad). Every
    // entry is also granted key use on KEKs created while it is set, since
    // a deployer must be able to wrap.
    std::vector<std::wstring> LoadDeployerGroupsPolicy();

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    // Test-only seams for the two above, with the same scope and caveats as
    // SetTestPolicyOverride. std::nullopt clears each.
    void SetTestSecurityModelOverride(std::optional<SecurityModel> model) noexcept;
    void SetTestDeployerGroupsOverride(std::optional<std::vector<std::wstring>> groups);
#endif

    // Which payload version this host writes and accepts (wire_format.h;
    // docs/adr/0001-post-quantum-payload-version-2.md):
    //
    //   Version2: the default - the symmetric, post-quantum construction
    //     (kek_v2.h). Wrap writes version 2; unwrap accepts version 2 only.
    //   Version1: classical - the ECDH construction (ecdh_hkdf.h). Wrap
    //     writes version 1; unwrap accepts version 1 only.
    //
    // A host uses exactly one: there is no fallback from one to the other
    // and no migration between them. Each has its own KEK, so the setting
    // also decides which one hkdfguard_create_kek provisions.
    enum class PayloadVersionPolicy : uint32_t {
        Version2 = 0, // ClassicalMode absent or 0
        Version1 = 1, // ClassicalMode 1

        // Present but not 0 or 1 (or not a REG_DWORD), or a policy key that
        // exists but can't be opened: fails closed with
        // HKDFGUARD_ERR_POLICY_INVALID, as KeyStoragePolicy::Invalid does.
        Invalid = 0xFFFFFFFFu,
    };

    // The value-to-setting rule LoadPayloadVersionPolicy applies, with no
    // registry I/O, so it can be tested directly. Absent means Version2.
    PayloadVersionPolicy ParsePayloadVersionPolicy(bool found, unsigned long type, unsigned long value) noexcept;

    // The REG_DWORD value HKLM\Software\Policies\HkdfGuard\ClassicalMode:
    // absent or 0 = Version2, 1 = Version1, anything else = Invalid. Read
    // on every call that depends on it. Never throws.
    PayloadVersionPolicy LoadPayloadVersionPolicy() noexcept;

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    // Test-only seam for LoadPayloadVersionPolicy, with the same scope and
    // caveats as SetTestPolicyOverride. std::nullopt clears it.
    void SetTestPayloadVersionOverride(std::optional<PayloadVersionPolicy> version) noexcept;
#endif

} // namespace hkdfguard
