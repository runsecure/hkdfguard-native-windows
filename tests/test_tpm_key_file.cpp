// Hand-rolled test program (no test framework), like test_roundtrip: checks
// src/tpm_key_file.cpp, the version 2 TPM KEK's key file and its store.
// Needs no TPM: the key files here carry a real template-shaped public area
// and a placeholder private blob, which the store never interprets. Exits 0
// if every check passed, 1 otherwise.
//
// Offline, on any machine:
//   1. The file format: round trip, layout, every truncation, extension,
//      bit flip and seeded random edits rejected as KEK_INVALID or accepted -
//      never anything else.
//   2. The KEK template: only exactly its attributes, scheme and policy pass.
//   3. The file's security descriptor: owner, protection, and that
//      VerifyExistingKekDacl accepts it.
// Elevated (skipped otherwise), in a throwaway store under a new C:\ folder
// secured like C:\ProgramData:
//   4. Write, read back, exists, no overwrite, delete; the folders' and the
//      file's security as created.
//   5. Every tampering the store must refuse: a widened file ACL, write
//      rights for another group on the file or the folder, delete-child on a
//      folder above, corrupted contents, a symbolic link in place of the
//      file or of a folder, a store folder pre-created by someone else, the
//      wrong service.
// Unelevated:
//   6. Writing and deleting are refused before anything is created.
#include "tpm_key_file.h"
#include "key_acl.h"
#include "errors.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstdio>
#include <functional>
#include <random>
#include <string>
#include <vector>

using hkdfguard::HkdfGuardError;
using namespace hkdfguard;

namespace {

int g_failures = 0;

void Check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("[PASS] %s\n", what.c_str());
    } else {
        std::printf("[FAIL] %s\n", what.c_str());
        ++g_failures;
    }
}

void Skip(const std::string& what) {
    std::printf("[SKIP] %s\n", what.c_str());
}

constexpr int kOtherException = 1;
int CodeOf(const std::function<void()>& f) {
    try {
        f();
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError& e) {
        return e.code();
    } catch (...) {
        return kOtherException;
    }
}

// Runs one section; an exception that escapes it is that section's failure.
void Guarded(const std::string& section, const std::function<void()>& body) {
    try {
        body();
    } catch (const HkdfGuardError& e) {
        Check(false, section + ": HkdfGuardError, code " + std::to_string(e.code()) + ": " + e.what());
    } catch (const std::exception& e) {
        Check(false, section + ": exception: " + e.what());
    }
}

bool IsElevated() {
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    return GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) &&
           elevation.TokenIsElevated != 0;
}

const std::string kService = "hkdfguardwin.test.tpmkeyfile";
const std::wstring kServiceWide = L"hkdfguardwin.test.tpmkeyfile";

// A key file as provisioning would write it, with a placeholder private
// blob (the store never looks inside it).
TpmKeyFile SampleFile(const std::string& service = kService) {
    TpmKeyFile f;
    f.service = service;
    f.parent_handle = 0x81000001;
    f.parent_name = {0x00, 0x0B};
    f.parent_name.insert(f.parent_name.end(), 32, 0x17);
    tpm2::Writer pub;
    pub.Tpm2b(tpm2::KeyedHashPublicArea(kTpmKekAttributes, tpm2::kAlgSha256, Bytes(32, 0x62)));
    f.public_blob = pub.take();
    tpm2::Writer priv;
    priv.Tpm2b(Bytes(126, 0x61));
    f.private_blob = priv.take();
    return f;
}

bool SameFile(const TpmKeyFile& a, const TpmKeyFile& b) {
    return a.service == b.service && a.parent_handle == b.parent_handle && a.parent_name == b.parent_name &&
           a.public_blob == b.public_blob && a.private_blob == b.private_blob;
}

int ParseCode(const Bytes& b) {
    return CodeOf([&] { ParseTpmKeyFile(b.data(), b.size()); });
}

// ---- Security descriptor helpers (elevated tests) ----

std::wstring SddlOf(const std::wstring& path) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS) {
        return L"";
    }
    LPWSTR text = nullptr;
    ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1,
                                                         OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr);
    std::wstring out = text ? text : L"";
    LocalFree(text);
    LocalFree(sd);
    return out;
}

// Replaces an object's DACL (protected) with the one in `sddl`.
bool SetDacl(const std::wstring& path, const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return false;
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    const DWORD rc = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                           DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                           dacl, nullptr);
    LocalFree(sd);
    return rc == ERROR_SUCCESS;
}

// The DACL part of an object's SDDL ("D:..."), and the same with one more ACE.
std::wstring DaclPart(const std::wstring& sddl) {
    const size_t d = sddl.find(L"D:");
    return d == std::wstring::npos ? L"" : sddl.substr(d);
}

bool AddAce(const std::wstring& path, const std::wstring& ace, std::wstring& original) {
    original = DaclPart(SddlOf(path));
    return !original.empty() && SetDacl(path, original + ace);
}

// An object's security as created: its owner, whether its DACL is
// protected, and every allow ACE as (SID string, mask).
struct ObjectSecurity {
    bool read = false;
    std::wstring owner;
    bool is_protected = false;
    std::vector<std::pair<std::wstring, ACCESS_MASK>> allows;
    int other_aces = 0;
};

ObjectSecurity SecurityOf(const std::wstring& path) {
    ObjectSecurity out;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                              nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS) {
        return out;
    }
    auto sid_string = [](PSID sid) {
        LPWSTR text = nullptr;
        ConvertSidToStringSidW(sid, &text);
        std::wstring s = text ? text : L"";
        LocalFree(text);
        return s;
    };
    out.owner = sid_string(owner);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    GetSecurityDescriptorControl(sd, &control, &revision);
    out.is_protected = (control & SE_DACL_PROTECTED) != 0;
    for (DWORD i = 0; dacl && i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        GetAce(dacl, i, &ace);
        const auto* header = static_cast<const ACE_HEADER*>(ace);
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const auto* allowed = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
            out.allows.emplace_back(sid_string(const_cast<DWORD*>(&allowed->SidStart)), allowed->Mask);
        } else {
            ++out.other_aces;
        }
    }
    LocalFree(sd);
    out.read = true;
    return out;
}

ACCESS_MASK MaskFor(const ObjectSecurity& s, const wchar_t* sid) {
    ACCESS_MASK mask = 0;
    for (const auto& [who, m] : s.allows) {
        if (who == sid) mask |= m;
    }
    return mask;
}

bool CreateFolder(const std::wstring& path, const wchar_t* sddl) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, FALSE};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr)) {
        return false;
    }
    const BOOL ok = CreateDirectoryW(path.c_str(), &sa);
    LocalFree(sa.lpSecurityDescriptor);
    return ok != FALSE;
}

// Removes a folder tree (files, links and folders) as an administrator,
// first giving Administrators full control where it is missing.
void RemoveTree(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return;
    SetDacl(path, L"D:P(A;OICI;FA;;;BA)");
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        WIN32_FIND_DATAW find{};
        HANDLE h = FindFirstFileW((path + L"\\*").c_str(), &find);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                const std::wstring name = find.cFileName;
                if (name != L"." && name != L"..") RemoveTree(path + L"\\" + name);
            } while (FindNextFileW(h, &find));
            FindClose(h);
        }
        RemoveDirectoryW(path.c_str());
    } else if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        RemoveDirectoryW(path.c_str()); // a directory link: removes the link only
    } else {
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(path.c_str());
    }
}

std::wstring NewTestParent() {
    uint8_t r[4];
    BCryptGenRandom(nullptr, r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t name[64];
    std::swprintf(name, 64, L"C:\\HkdfGuardTpmStoreTest-%02x%02x%02x%02x", r[0], r[1], r[2], r[3]);
    return name;
}

// Secured like C:\ProgramData: SYSTEM and Administrators full control,
// Users read & execute, and Users may create folders and files directly in
// it - which the store must accept above its own folders.
constexpr wchar_t kProgramDataLikeSddl[] =
    L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)";

// BUILTIN\Remote Desktop Users: a real local group that is not over-broad,
// so only the write rights granted to it can be what a check refuses.
constexpr wchar_t kOtherGroup[] = L"S-1-5-32-555";

void OfflineChecks() {
    // ---- 1. File format ----
    {
        const TpmKeyFile sample = SampleFile();
        const Bytes bytes = SerializeTpmKeyFile(sample);
        Check(SameFile(ParseTpmKeyFile(bytes.data(), bytes.size()), sample), "a key file round-trips");
        Check(bytes.size() >= 8 && bytes[0] == 'H' && bytes[1] == 'K' && bytes[2] == 'G' && bytes[3] == 'T' &&
                  bytes[4] == 0 && bytes[5] == 1 && bytes[6] == 0 && bytes[7] == 0,
              "layout: magic \"HKGT\", format version 1, reserved 0");
        Check(TpmKeyFileName(L"myapp", 1) == L"hkdfguardwin_myapp_v1.tpmkey", "file name: hkdfguardwin_<service>_v1.tpmkey");

        int parsed_truncations = 0, bad = 0;
        for (size_t len = 0; len < bytes.size(); ++len) {
            const Bytes t(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(len));
            const int code = ParseCode(t);
            if (code == HKDFGUARD_OK) ++parsed_truncations;
            else if (code != HKDFGUARD_ERR_KEK_INVALID) ++bad;
        }
        Check(parsed_truncations == 0, "no truncation of a key file parses");
        Bytes extended = bytes;
        extended.push_back(0);
        Check(ParseCode(extended) == HKDFGUARD_ERR_KEK_INVALID, "one trailing byte is refused");
        for (size_t i = 0; i < bytes.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                Bytes m = bytes;
                m[i] ^= static_cast<uint8_t>(1u << bit);
                const int code = ParseCode(m);
                if (code != HKDFGUARD_OK && code != HKDFGUARD_ERR_KEK_INVALID) ++bad;
            }
        }
        std::mt19937 rng(0x544B4659);
        for (int iteration = 0; iteration < 20000; ++iteration) {
            Bytes m = bytes;
            const int edits = 1 + static_cast<int>(rng() % 4);
            for (int e = 0; e < edits && !m.empty(); ++e) {
                const size_t at = rng() % m.size();
                switch (rng() % 3) {
                    case 0: m[at] = static_cast<uint8_t>(rng()); break;
                    case 1: m.insert(m.begin() + static_cast<std::ptrdiff_t>(at), static_cast<uint8_t>(rng())); break;
                    default: m.erase(m.begin() + static_cast<std::ptrdiff_t>(at)); break;
                }
            }
            const int code = ParseCode(m);
            if (code != HKDFGUARD_OK && code != HKDFGUARD_ERR_KEK_INVALID) ++bad;
        }
        Check(bad == 0, "every mutated key file parses or is refused with KEK_INVALID only");
        Check(ParseCode(Bytes(kMaxTpmKeyFileLen + 1, 0)) == HKDFGUARD_ERR_KEK_INVALID, "a key file over 4096 bytes is refused");

        TpmKeyFile volatile_parent = sample;
        volatile_parent.parent_handle = 0x80000001;
        Check(CodeOf([&] { SerializeTpmKeyFile(volatile_parent); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a parent that isn't a persistent key is never written");
        TpmKeyFile bad_service = sample;
        bad_service.service = "my app";
        Check(CodeOf([&] { SerializeTpmKeyFile(bad_service); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a service name with a disallowed character is never written");
        TpmKeyFile short_name = sample;
        short_name.parent_name.resize(20);
        Check(CodeOf([&] { SerializeTpmKeyFile(short_name); }) == HKDFGUARD_ERR_INTERNAL_ERROR,
              "a parent Name that isn't a SHA-256 Name is never written");
    }

    // ---- 2. The KEK template ----
    {
        const tpm2::PublicArea good = tpm2::ParsePublicArea(
            tpm2::KeyedHashPublicArea(kTpmKekAttributes, tpm2::kAlgSha256, Bytes(32, 0x62)));
        Check(CodeOf([&] { CheckTpmKekPublicArea(good); }) == HKDFGUARD_OK, "the KEK template's public area passes");
        const tpm2::PublicArea from_template = tpm2::ParsePublicArea(TpmKekTemplate());
        Check(from_template.attributes == kTpmKekAttributes && from_template.keyed_hash_unique.empty(),
              "TpmKekTemplate has exactly the KEK attributes and an empty unique for TPM2_Create");

        int refused_missing = 0, required = 0;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            if ((kTpmKekAttributes & (1u << bit)) == 0) continue;
            ++required;
            tpm2::PublicArea a = good;
            a.attributes &= ~(1u << bit);
            if (CodeOf([&] { CheckTpmKekPublicArea(a); }) == HKDFGUARD_ERR_KEK_INVALID) ++refused_missing;
        }
        Check(required == 6 && refused_missing == required,
              "each required attribute missing is refused (sensitiveDataOrigin: a key whose value someone chose)");
        int refused_extra = 0, extras = 0;
        for (uint32_t bit = 0; bit < 32; ++bit) {
            if ((kTpmKekAttributes & (1u << bit)) != 0) continue;
            ++extras;
            tpm2::PublicArea a = good;
            a.attributes |= (1u << bit);
            if (CodeOf([&] { CheckTpmKekPublicArea(a); }) == HKDFGUARD_ERR_KEK_INVALID) ++refused_extra;
        }
        Check(refused_extra == extras, "any other attribute set (decrypt, restricted, encryptedDuplication, ...) is refused");
        tpm2::PublicArea policy = good;
        policy.auth_policy = Bytes(32, 0x01);
        tpm2::PublicArea sha1 = good;
        sha1.name_alg = 0x0004;
        tpm2::PublicArea xor_scheme = good;
        xor_scheme.scheme = tpm2::kAlgXor;
        tpm2::PublicArea rsa = good;
        rsa.type = tpm2::kAlgRsa;
        Check(CodeOf([&] { CheckTpmKekPublicArea(policy); }) == HKDFGUARD_ERR_KEK_INVALID &&
                  CodeOf([&] { CheckTpmKekPublicArea(sha1); }) == HKDFGUARD_ERR_KEK_INVALID &&
                  CodeOf([&] { CheckTpmKekPublicArea(xor_scheme); }) == HKDFGUARD_ERR_KEK_INVALID &&
                  CodeOf([&] { CheckTpmKekPublicArea(rsa); }) == HKDFGUARD_ERR_KEK_INVALID,
              "an authPolicy, a SHA-1 nameAlg, the XOR scheme or a non-keyed-hash object is refused");
    }

    // ---- 3. The file's security descriptor ----
    {
        std::vector<BYTE> sd = BuildKekFileSecurityDescriptor({});
        auto* desc = reinterpret_cast<PSECURITY_DESCRIPTOR>(sd.data());
        PSID owner = nullptr;
        BOOL owner_defaulted = FALSE, present = FALSE, dacl_defaulted = FALSE;
        PACL dacl = nullptr;
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        GetSecurityDescriptorOwner(desc, &owner, &owner_defaulted);
        GetSecurityDescriptorDacl(desc, &present, &dacl, &dacl_defaulted);
        GetSecurityDescriptorControl(desc, &control, &revision);
        Check(owner != nullptr && IsWellKnownSid(owner, WinBuiltinAdministratorsSid), "key file SD: owned by Administrators");
        Check((control & SE_DACL_PROTECTED) != 0, "key file SD: the DACL is protected (nothing inherited)");
        Check(present && CodeOf([&] { VerifyExistingKekDacl(dacl); }) == HKDFGUARD_OK,
              "key file SD: VerifyExistingKekDacl accepts it");
        Check(CodeOf([] { VerifyExistingKekDacl(nullptr); }) == HKDFGUARD_ERR_KEK_INVALID, "VerifyExistingKekDacl refuses no DACL");
        PSECURITY_DESCRIPTOR widened = nullptr;
        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)", SDDL_REVISION_1,
                                                             &widened, nullptr);
        PACL widened_dacl = nullptr;
        GetSecurityDescriptorDacl(widened, &present, &widened_dacl, &dacl_defaulted);
        Check(CodeOf([&] { VerifyExistingKekDacl(widened_dacl); }) == HKDFGUARD_ERR_KEK_INVALID,
              "VerifyExistingKekDacl refuses read access for Everyone (reading the file is using the key)");
        LocalFree(widened);
        Check(IsKekAdministrator(owner), "IsKekAdministrator: Administrators");
        Check(DefaultTpmKeyStore().parent.size() > 3, "DefaultTpmKeyStore locates ProgramData");
    }
}

void ElevatedChecks() {
    const std::wstring parent = NewTestParent();
    const std::wstring squat_parent = parent + L"-squat";
    const TpmKeyStore store{parent};
    const std::wstring keys = parent + L"\\HkdfGuard\\TpmKeys";
    const std::wstring name = TpmKeyFileName(kServiceWide, 1);
    const std::wstring file_path = keys + L"\\" + name;
    const TpmKeyFile sample = SampleFile();

    if (!CreateFolder(parent, kProgramDataLikeSddl)) {
        Check(false, "test setup: create a ProgramData-like folder");
        return;
    }

    // ---- 4. Write, read, exists, no overwrite, delete ----
    Guarded("4. store basics", [&] {
        Check(CodeOf([&] { ReadTpmKeyFile(store, name, kService); }) == HKDFGUARD_ERR_KEK_NOT_FOUND,
              "reading from a store that doesn't exist yet: KEK_NOT_FOUND");
        Check(!TpmKeyFileExists(store, name, kService), "...and it doesn't exist");
        // Run the write from another working directory, to catch a rename
        // that resolves the target against it instead of the store folder.
        wchar_t cwd[MAX_PATH];
        GetCurrentDirectoryW(MAX_PATH, cwd);
        SetCurrentDirectoryW(parent.c_str());
        Check(WriteTpmKeyFile(store, name, sample, {}), "write creates the store folders and the key file");
        SetCurrentDirectoryW(cwd);
        Check(GetFileAttributesW((parent + L"\\" + name).c_str()) == INVALID_FILE_ATTRIBUTES &&
                  GetFileAttributesW(file_path.c_str()) != INVALID_FILE_ATTRIBUTES,
              "the key file is in the store folder, not in the working directory");
        Check(SameFile(ReadTpmKeyFile(store, name, kService), sample), "it reads back exactly");
        Check(TpmKeyFileExists(store, name, kService), "...and exists");
        Check(!WriteTpmKeyFile(store, name, SampleFile(), {}), "a second write doesn't replace it");

        // Provisioning's check of an existing file against the current
        // policy (VerifyTpmKeyFileGrants): written under the same policy it
        // passes; a policy group the file doesn't grant is reported, and the
        // file is left as it was.
        Check(CodeOf([&] { hkdfguard::VerifyTpmKeyFileGrants(store, name, {}); }) == HKDFGUARD_OK,
              "the key file grants every principal the policy it was written under names");
        {
            const int code = CodeOf([&] { hkdfguard::VerifyTpmKeyFileGrants(store, name, {kOtherGroup}); });
            Check(code == HKDFGUARD_ERR_PROVIDER_ERROR,
                  "a key-use group the policy now names but the file doesn't grant is reported (code " +
                      std::to_string(code) + ")");
        }
        Check(SameFile(ReadTpmKeyFile(store, name, kService), sample), "...and the key file is left untouched");
        {
            const std::wstring granted = L"hkdfguardwin_test.keyfile_granted.tpmkey";
            Check(WriteTpmKeyFile(store, granted, sample, {kOtherGroup}) &&
                      CodeOf([&] { hkdfguard::VerifyTpmKeyFileGrants(store, granted, {kOtherGroup}); }) == HKDFGUARD_OK,
                  "a key file written with that group grants it");
            DeleteTpmKeyFile(store, granted);
        }

        // SYSTEM S-1-5-18, Administrators S-1-5-32-544, Users S-1-5-32-545.
        for (const std::wstring& folder : {parent + L"\\HkdfGuard", keys}) {
            const ObjectSecurity sec = SecurityOf(folder);
            const bool ok = sec.read && sec.owner == L"S-1-5-32-544" && sec.is_protected && sec.other_aces == 0 &&
                            sec.allows.size() == 3 && MaskFor(sec, L"S-1-5-18") == FILE_ALL_ACCESS &&
                            MaskFor(sec, L"S-1-5-32-544") == FILE_ALL_ACCESS && MaskFor(sec, L"S-1-5-32-545") == 0x1200A0;
            Check(ok, "store folder as created: owned by Administrators, protected, full control for SYSTEM and "
                      "Administrators only, and Users exactly traverse/read attributes/read control/synchronize");
            if (!ok) std::printf("    %ls: %ls\n", folder.c_str(), SddlOf(folder).c_str());
        }
        const ObjectSecurity file_sec = SecurityOf(file_path);
        const bool file_ok = file_sec.read && file_sec.owner == L"S-1-5-32-544" && file_sec.is_protected &&
                             file_sec.other_aces == 0 && (MaskFor(file_sec, L"S-1-5-18") & FILE_ALL_ACCESS) == FILE_ALL_ACCESS &&
                             (MaskFor(file_sec, L"S-1-5-32-544") & FILE_ALL_ACCESS) == FILE_ALL_ACCESS &&
                             MaskFor(file_sec, L"S-1-5-32-545") == 0;
        Check(file_ok, "the key file as created: owned by Administrators, protected, full control for SYSTEM and "
                       "Administrators, nothing for Users");
        if (!file_ok) std::printf("    %ls: %ls\n", file_path.c_str(), SddlOf(file_path).c_str());

        WIN32_FIND_DATAW find{};
        HANDLE h = FindFirstFileW((keys + L"\\*.tmp").c_str(), &find);
        Check(h == INVALID_HANDLE_VALUE, "no temporary file is left behind");
        if (h != INVALID_HANDLE_VALUE) FindClose(h);

        Check(CodeOf([&] { ReadTpmKeyFile(store, name, "hkdfguardwin.test.other"); }) == HKDFGUARD_ERR_KEK_INVALID,
              "a key file read for a different service is refused");
        Check(DeleteTpmKeyFile(store, name), "delete removes it");
        Check(!TpmKeyFileExists(store, name, kService) && !DeleteTpmKeyFile(store, name), "...and a second delete finds nothing");
    });

    // ---- 5. Tampering ----
    auto fresh = [&] {
        DeleteTpmKeyFile(store, name);
        return WriteTpmKeyFile(store, name, sample, {});
    };
    // A read's code, and whether it failed as an access-control problem
    // (KekAccessControlError), which status reports as "fix the ACL" and
    // retire --corrupt refuses, rather than as corruption.
    auto read_code = [&](bool& access_control) {
        access_control = false;
        try {
            ReadTpmKeyFile(store, name, kService);
            return HKDFGUARD_OK;
        } catch (const hkdfguard::KekAccessControlError& e) {
            access_control = true;
            return e.code();
        } catch (const HkdfGuardError& e) {
            return e.code();
        } catch (...) {
            return kOtherException;
        }
    };
    // Refused for its access control: KEK_INVALID, as an access-control error.
    auto expect_access_control = [&](const std::string& what) {
        bool access_control = false;
        const int code = read_code(access_control);
        Check(code == HKDFGUARD_ERR_KEK_INVALID && access_control,
              what + ", as an access-control failure (code " + std::to_string(code) + ")");
    };
    // Refused for what the file or a folder is: KEK_INVALID, never reported
    // as an access-control error.
    auto expect_invalid = [&](const std::string& what) {
        bool access_control = false;
        const int code = read_code(access_control);
        Check(code == HKDFGUARD_ERR_KEK_INVALID && !access_control,
              what + ", not as an access-control failure (code " + std::to_string(code) + ")");
    };
    Guarded("5. tampering", [&] {
        std::wstring original;
        Check(fresh() && AddAce(file_path, L"(A;;FR;;;WD)", original), "test setup: give Everyone read access to the key file");
        expect_access_control("a key file Everyone may read is refused");
        SetDacl(file_path, original);

        Check(AddAce(file_path, std::wstring(L"(A;;FW;;;") + kOtherGroup + L")", original), "test setup: give another group write access");
        expect_access_control("a key file another group may write is refused");
        SetDacl(file_path, original);

        Check(AddAce(keys, std::wstring(L"(A;;0x2;;;") + kOtherGroup + L")", original), "test setup: let another group add files to the store");
        expect_access_control("a store folder others may add files to is refused");
        SetDacl(keys, original);

        Check(AddAce(parent, std::wstring(L"(A;;0x40;;;") + kOtherGroup + L")", original),
              "test setup: let another group delete entries in a folder above the store");
        expect_access_control("a folder above the store that lets others delete entries is refused");
        SetDacl(parent, original);
        Check(CodeOf([&] { ReadTpmKeyFile(store, name, kService); }) == HKDFGUARD_OK,
              "with every ACL restored, the key file reads again");

        // Corrupted contents.
        {
            HANDLE f = CreateFileW(file_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            uint8_t b = 0;
            DWORD n = 0;
            SetFilePointer(f, 3, nullptr, FILE_BEGIN);
            ReadFile(f, &b, 1, &n, nullptr);
            b ^= 0x01;
            SetFilePointer(f, 3, nullptr, FILE_BEGIN);
            WriteFile(f, &b, 1, &n, nullptr);
            CloseHandle(f);
            expect_invalid("a key file with a corrupted magic is refused");
        }

        // A symbolic link in place of the file, pointing at a valid copy.
        {
            Check(fresh(), "test setup: a fresh key file");
            const std::wstring copy = parent + L"\\copy.tpmkey";
            CopyFileW(file_path.c_str(), copy.c_str(), FALSE);
            DeleteTpmKeyFile(store, name);
            if (CreateSymbolicLinkW(file_path.c_str(), copy.c_str(), 0)) {
                expect_invalid("a symbolic link in place of the key file is refused");
                Check(DeleteTpmKeyFile(store, name) && GetFileAttributesW(copy.c_str()) != INVALID_FILE_ATTRIBUTES,
                      "delete removes the link itself, not what it points at");
            } else {
                Skip("a symbolic link in place of the key file (CreateSymbolicLinkW failed)");
            }
            DeleteFileW(copy.c_str());
        }

        // A directory symbolic link in place of the TpmKeys folder.
        {
            Check(fresh(), "test setup: a fresh key file");
            const std::wstring real = parent + L"\\HkdfGuard\\TpmKeys.real";
            if (MoveFileW(keys.c_str(), real.c_str()) &&
                CreateSymbolicLinkW(keys.c_str(), real.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY)) {
                expect_invalid("a directory symbolic link in place of the store folder is refused");
                RemoveDirectoryW(keys.c_str());
                MoveFileW(real.c_str(), keys.c_str());
            } else {
                Skip("a directory symbolic link in place of the store folder (setup failed)");
            }
            Check(CodeOf([&] { ReadTpmKeyFile(store, name, kService); }) == HKDFGUARD_OK, "with the real folder back, it reads again");
        }

        // A store folder someone else created first.
        {
            Check(CreateFolder(squat_parent, kProgramDataLikeSddl) &&
                      CreateFolder(squat_parent + L"\\HkdfGuard",
                                   (std::wstring(L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;") + kOtherGroup + L")").c_str()),
                  "test setup: a HkdfGuard folder another group controls");
            const TpmKeyStore squatted{squat_parent};
            const int code = CodeOf([&] { WriteTpmKeyFile(squatted, name, sample, {}); });
            Check(code == HKDFGUARD_ERR_KEK_INVALID, "writing into a store folder someone else controls is refused (code " +
                                                         std::to_string(code) + ")");
            Check(GetFileAttributesW((squat_parent + L"\\HkdfGuard\\TpmKeys").c_str()) == INVALID_FILE_ATTRIBUTES,
                  "...before anything is created in it");
        }
    });

    RemoveTree(parent);
    RemoveTree(squat_parent);
    Check(GetFileAttributesW(parent.c_str()) == INVALID_FILE_ATTRIBUTES, "test store removed");
}

void UnelevatedChecks() {
    // ---- 6. Writing needs elevation, checked before anything is created ----
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    std::wstring parent = std::wstring(temp) + L"HkdfGuardTpmStoreUnelevated";
    CreateDirectoryW(parent.c_str(), nullptr);
    const TpmKeyStore store{parent};
    const std::wstring name = TpmKeyFileName(kServiceWide, 1);
    Check(CodeOf([&] { WriteTpmKeyFile(store, name, SampleFile(), {}); }) == HKDFGUARD_ERR_KEK_ACCESS_DENIED,
          "unelevated: writing a TPM key file is refused (KEK_ACCESS_DENIED)");
    Check(GetFileAttributesW((parent + L"\\HkdfGuard").c_str()) == INVALID_FILE_ATTRIBUTES,
          "...before any store folder is created");
    Check(CodeOf([&] { DeleteTpmKeyFile(store, name); }) == HKDFGUARD_ERR_KEK_ACCESS_DENIED,
          "unelevated: deleting a TPM key file is refused (KEK_ACCESS_DENIED)");
    RemoveDirectoryW(parent.c_str());
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Guarded("offline checks", OfflineChecks);
    if (IsElevated()) {
        Guarded("elevated checks", ElevatedChecks);
    } else {
        Skip("store checks on disk (needs elevation)");
        Guarded("unelevated checks", UnelevatedChecks);
    }
    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
