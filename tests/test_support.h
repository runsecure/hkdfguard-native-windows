#pragma once

// Helpers shared by the test, probe and benchmark executables.

#include <windows.h>

#include <vector>

// Whether this process runs elevated. Creating a machine-scoped KEK, and
// setting machine policy, both need it.
inline bool IsElevated() {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    return GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) &&
           elevation.TokenIsElevated != 0;
}

// Sets a REG_DWORD under HKLM\Software\Policies\HkdfGuard for as long as
// the object lives - or until restore() - and then puts back whatever was
// there: the old value, or nothing. HkdfGuard.dll reads the real registry,
// so this is how a section pins the policy it tests (see policy.h). Needs
// elevation; active() says whether it took effect.
class ScopedMachinePolicyDword {
public:
    ScopedMachinePolicyDword(const wchar_t* name, DWORD value) : name_(name) {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Policies\\HkdfGuard", 0, nullptr, 0,
                            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key_, nullptr) != ERROR_SUCCESS) {
            key_ = nullptr;
            return;
        }
        DWORD size = 0;
        if (RegQueryValueExW(key_, name_, nullptr, &old_type_, nullptr, &size) == ERROR_SUCCESS) {
            old_.resize(size);
            had_old_ = RegQueryValueExW(key_, name_, nullptr, &old_type_, old_.data(), &size) == ERROR_SUCCESS;
        }
        active_ = RegSetValueExW(key_, name_, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) ==
                  ERROR_SUCCESS;
    }
    ~ScopedMachinePolicyDword() { restore(); }
    ScopedMachinePolicyDword(const ScopedMachinePolicyDword&) = delete;
    ScopedMachinePolicyDword& operator=(const ScopedMachinePolicyDword&) = delete;

    bool active() const { return active_; }

    void restore() {
        if (key_ == nullptr) return;
        if (active_) {
            if (had_old_) {
                RegSetValueExW(key_, name_, 0, old_type_, old_.data(), static_cast<DWORD>(old_.size()));
            } else {
                RegDeleteValueW(key_, name_);
            }
        }
        RegCloseKey(key_);
        key_ = nullptr;
        active_ = false;
    }

private:
    const wchar_t* name_;
    HKEY key_ = nullptr;
    bool active_ = false;
    bool had_old_ = false;
    DWORD old_type_ = 0;
    std::vector<BYTE> old_;
};
