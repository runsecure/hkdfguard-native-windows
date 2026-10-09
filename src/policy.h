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

        // Sentinel: the registry value was present but is not one of the
        // three values above (wrong type, or an unrecognized DWORD).
        // Deliberately NOT a silent alias for PreferTpm - see
        // LoadEffectivePolicy's comment on why. Every caller that reads a
        // KeyStoragePolicy either switches on all three real values with a
        // trailing "invalid policy" throw after the switch (KekExists,
        // CreateKek, OpenKekForWrap), or checks for this sentinel directly
        // (OpenKekForUnwrap) - both fail closed with
        // HKDFGUARD_ERR_INVALID_POLICY the moment this value appears.
        Invalid = 0xFFFFFFFFu,
    };

    // Returns the machine-wide effective policy.
    // Never throws.
    //
    // A *missing* KeyStoragePolicy value (the registry key or value isn't
    // there at all) falls back to the documented safe default
    // (KeyStoragePolicy::PreferTpm) - that is normal, unconfigured-machine
    // behavior, not an error.
    //
    // A value that *is* present but isn't one of the three recognized
    // policies (wrong REG_* type, or a DWORD other than 0/1/2) returns
    // KeyStoragePolicy::Invalid instead of silently falling back to a
    // default. This is a deliberate fail-closed choice: an admin who typed
    // (or a deployment tool that wrote) an unrecognized value most likely
    // intended a *specific* policy - possibly RequireTpm, the strictest one
    // - and silently substituting PreferTpm would mean a typo can quietly
    // weaken protection instead of being surfaced as the configuration
    // error it is. Every caller of this function turns
    // KeyStoragePolicy::Invalid into HKDFGUARD_ERR_INVALID_POLICY.
    //
    // Reads the real registry value (see policy.cpp). When this translation
    // unit is built with HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE defined, a
    // test policy override - see SetTestPolicyOverride below - is checked
    // first; in a normal (non-test) build that macro is never defined, so
    // this always reads the registry.
    KeyStoragePolicy LoadEffectivePolicy() noexcept;

// Test-only seam: makes LoadEffectivePolicy() return `policy` instead of
// reading the registry, regardless of this machine's actual configured
// policy - lets tests exercise all three KeyStoragePolicy branches
// deterministically. Pass std::nullopt to clear the override and resume
// reading the real registry value.
//
// Compiled in only when HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE is defined -
// tests/CMakeLists.txt defines it for test_roundtrip's own copy of this
// file only. HkdfGuardV1.dll's own build (the top-level CMakeLists.txt) never
// defines it, so this function - and the override state it would control -
// does not exist at all in the shipped DLL; there is no runtime flag or
// code path in release code that could ever activate it. Not thread-safe,
// by design: a single-threaded test process is the only intended caller.
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

    // Test-only seam for LoadKeyUseGroupsPolicy(), with exactly the same
    // scope and caveats as SetTestPolicyOverride above: compiled in only
    // for test binaries, absent from HkdfGuardV1.dll. std::nullopt clears it.
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestKeyUseGroupsOverride(std::optional<std::vector<std::wstring>> groups);
#endif

} // namespace hkdfguard
