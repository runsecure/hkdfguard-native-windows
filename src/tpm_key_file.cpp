#include "tpm_key_file.h"
#include "errors.h"
#include "key_acl.h"        // BuildKekFileSecurityDescriptor, VerifyExistingKekDacl, IsKekAdministrator
#include "no_follow_open.h" // OpenFolderChain, OpenRelative

#include <windows.h>
#include <aclapi.h>  // GetSecurityInfo
#include <bcrypt.h>  // BCryptGenRandom
#include <sddl.h>    // ConvertStringSidToSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW
#include <shlobj.h>  // SHGetKnownFolderPath, FOLDERID_ProgramData

#include <cstring> // memcpy
#include <string>

// The native rename (FileRenameInformation, class 10). winternl.h declares
// FILE_INFORMATION_CLASS but not this function. Used instead of
// SetFileInformationByHandle(FileRenameInfo), which resolves a bare target
// name against the process's current directory - moving the file out of the
// folder it is in - and refuses a RootDirectory handle (ERROR_INVALID_PARAMETER).
extern "C" NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

namespace hkdfguard {
    namespace {
        using hkdfguard_nofollow::Handle;

        // The store's own folders, below the store's parent.
        constexpr const wchar_t *kStoreFolders[] = {L"HkdfGuard", L"TpmKeys"};

        constexpr uint8_t kMagic[4] = {'H', 'K', 'G', 'T'};
        constexpr uint16_t kFormatVersion = 1;
        constexpr size_t kMaxServiceLen = 128;
        constexpr size_t kParentNameLen = 2 + 32; // nameAlg SHA-256 || digest

        // Rights, as key_file.cpp names them for wrapped-key files: those
        // that change a file or take it over; those that remove, rename or
        // take over a folder or an entry in it; and those that add entries.
        // GENERIC_* appear because an ACE may carry them unmapped.
        constexpr ACCESS_MASK kFileWriteRights = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                                                 FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
                                                 GENERIC_WRITE | GENERIC_ALL;
        constexpr ACCESS_MASK kFolderReplaceRights = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
        constexpr ACCESS_MASK kFolderCreateRights = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE;

        // The store folders' own security descriptor: owned by
        // Administrators, full control for SYSTEM and Administrators, and for
        // BUILTIN\Users only what passing through needs (traverse, read
        // attributes, read the security descriptor - the folder checks read
        // it - and synchronize: 0x1200A0). Nobody else may list the folder,
        // so service names aren't disclosed. Protected: nothing inherited.
        constexpr wchar_t kStoreFolderSddl[] = L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a0;;;BU)";

        // A path for an error message: ASCII as is, anything else as '?'.
        std::string ForMessage(const std::wstring &wide) {
            std::string narrow;
            for (wchar_t c : wide) {
                narrow += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
            }
            return narrow;
        }

        [[noreturn]] void Invalid(const std::string &what) {
            throw HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID, what.c_str());
        }

        // The owner or DACL of the key file, or of a folder of the store or
        // above it, breaks the rules: still KEK_INVALID, but recoverable by
        // fixing the ACL, so never "corrupt" (errors.h).
        [[noreturn]] void AccessControlInvalid(const std::string &what) {
            throw KekAccessControlError(what.c_str());
        }

        // An I/O failure, with the Windows error that caused it.
        [[noreturn]] void IoFailure(const std::string &what, DWORD win32 = GetLastError()) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, (what + " (Windows error " + std::to_string(win32) + ")").c_str());
        }

        // NT SERVICE\TrustedInstaller, which owns C:\ and much of the system
        // drive.
        class TrustedInstallerSid {
        public:
            TrustedInstallerSid() {
                if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &sid_)) {
                    throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "ConvertStringSidToSidW failed");
                }
            }
            ~TrustedInstallerSid() { LocalFree(sid_); }
            TrustedInstallerSid(const TrustedInstallerSid &) = delete;
            TrustedInstallerSid &operator=(const TrustedInstallerSid &) = delete;
            PSID get() const { return sid_; }

        private:
            PSID sid_ = nullptr;
        };

        // Who may own, and hold write-type rights on, an object of the store:
        // the KEK administrators (key_acl.h) - and, for the system folders
        // above the store, TrustedInstaller too. OWNER RIGHTS, CREATOR OWNER
        // and CREATOR GROUP are accepted in an ACE as key_file.cpp accepts
        // them: the first means the owner, checked separately; the others
        // match nobody outside an inherit-only ACE.
        bool MayOwn(PSID sid, bool installer_ok) {
            if (IsKekAdministrator(sid)) {
                return true;
            }
            if (!installer_ok) {
                return false;
            }
            TrustedInstallerSid installer;
            return EqualSid(sid, installer.get()) != FALSE;
        }

        bool MayWrite(PSID sid, bool installer_ok) {
            return MayOwn(sid, installer_ok) || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) ||
                   IsWellKnownSid(sid, WinCreatorOwnerSid) || IsWellKnownSid(sid, WinCreatorGroupSid);
        }

        // The owner and DACL rule, on an object's live security: a trusted
        // owner, a DACL, and no `forbidden` right granted to anyone else.
        // The same ACE walk as key_file.cpp's CheckOwnerAndDacl, with this
        // store's narrower set of trusted principals - a deployer may write
        // wrapped-key files, but never the KEK's - and this store's error
        // code. Returns the security descriptor, LocalAlloc'd, for any
        // further check of its DACL.
        PSECURITY_DESCRIPTOR CheckObjectSecurity(HANDLE object, ACCESS_MASK forbidden, bool installer_ok,
                                                 const std::string &what, PACL *dacl_out = nullptr) {
            PSID owner = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            const DWORD rc = GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                             &owner, nullptr, &dacl, nullptr, &sd);
            if (rc == ERROR_ACCESS_DENIED) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_ACCESS_DENIED, (what + ": its security can't be read").c_str());
            }
            if (rc != ERROR_SUCCESS) {
                AccessControlInvalid(what + ": its security can't be read");
            }
            try {
                const char *trusted = installer_ok ? "SYSTEM, Administrators, HkdfGuardAdmins or TrustedInstaller"
                                                   : "SYSTEM, Administrators or HkdfGuardAdmins";
                if (owner == nullptr || !MayOwn(owner, installer_ok)) {
                    AccessControlInvalid(what + " is not owned by " + trusted);
                }
                // GetSecurityInfo reports a missing and a NULL DACL alike:
                // unrestricted access either way.
                if (dacl == nullptr) {
                    AccessControlInvalid(what + " has no DACL, so everyone has full access to it");
                }
                for (DWORD i = 0; i < dacl->AceCount; ++i) {
                    void *ace = nullptr;
                    if (!GetAce(dacl, i, &ace)) {
                        AccessControlInvalid(what + ": GetAce failed");
                    }
                    const ACE_HEADER *header = static_cast<const ACE_HEADER *>(ace);
                    if (header->AceFlags & INHERIT_ONLY_ACE) {
                        continue; // applies only to children, which are checked on their own
                    }
                    switch (header->AceType) {
                        case ACCESS_DENIED_ACE_TYPE:
                        case ACCESS_DENIED_OBJECT_ACE_TYPE:
                        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                            continue; // a deny only ever takes access away
                        case ACCESS_ALLOWED_ACE_TYPE:
                        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
                            // The same layout up to the SID; a conditional
                            // ACE is judged as if its condition held.
                            const auto *allowed = static_cast<const ACCESS_ALLOWED_ACE *>(ace);
                            PSID sid = const_cast<DWORD *>(&allowed->SidStart);
                            if ((allowed->Mask & forbidden) != 0 && !MayWrite(sid, installer_ok)) {
                                AccessControlInvalid(what + " grants write, delete, ownership or create rights to an account other than " +
                                        trusted);
                            }
                            continue;
                        }
                        default:
                            AccessControlInvalid(what + " has an access-allowed ACE of an unexpected type");
                    }
                }
            } catch (...) {
                LocalFree(sd);
                throw;
            }
            if (dacl_out != nullptr) {
                *dacl_out = dacl;
            }
            return sd;
        }

        void CheckObjectSecurityOnly(HANDLE object, ACCESS_MASK forbidden, bool installer_ok, const std::string &what) {
            LocalFree(CheckObjectSecurity(object, forbidden, installer_ok, what));
        }

        // Maps a failed open in the store to its code: absent, refused, or
        // anything else.
        [[noreturn]] void ThrowOpenFailure(DWORD win32, const std::string &what) {
            switch (win32) {
                case ERROR_FILE_NOT_FOUND:
                case ERROR_PATH_NOT_FOUND:
                    throw HkdfGuardError(HKDFGUARD_ERR_KEK_NOT_FOUND, (what + " does not exist").c_str());
                case ERROR_ACCESS_DENIED:
                    throw HkdfGuardError(HKDFGUARD_ERR_KEK_ACCESS_DENIED, (what + ": access denied").c_str());
                case ERROR_DIRECTORY:
                    Invalid(what + " is not a folder");
                default:
                    IoFailure(what + " could not be opened", win32);
            }
        }

        // An opened store object must be what its name says: a real folder
        // or a real file, not a link or other reparse point.
        void RequireKind(HANDLE object, bool directory, const std::string &what) {
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(object, &info)) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, (what + ": GetFileInformationByHandle failed").c_str());
            }
            if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                Invalid(what + " is a symbolic link, junction or other reparse point");
            }
            if (((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) {
                Invalid(what + (directory ? " is not a folder" : " is a folder"));
            }
            if (!directory && GetFileType(object) != FILE_TYPE_DISK) {
                Invalid(what + " is not a regular file");
            }
        }

        // The store, opened and checked from the drive root down to TpmKeys,
        // every folder by handle relative to the one above it (see
        // no_follow_open.h), so the folders judged are the ones actually
        // walked through. With `create`, missing store folders are created,
        // with kStoreFolderSddl.
        struct OpenStore {
            hkdfguard_nofollow::FolderChain above; // drive root .. the store's parent
            Handle folders[2];                     // HkdfGuard, TpmKeys
            std::wstring keys_path;
            HANDLE keys() const { return folders[1].get(); }
        };

        void OpenStoreFolders(const TpmKeyStore &store, bool create, OpenStore &out) {
            std::wstring parent = store.parent;
            while (parent.size() > 3 && parent.back() == L'\\') {
                parent.pop_back();
            }
            // Walk to the store's parent: the chain to its first store folder
            // ends at the folder holding it.
            hkdfguard_nofollow::Error walk;
            const std::wstring first = parent + (parent.back() == L'\\' ? L"" : L"\\") + kStoreFolders[0];
            if (!hkdfguard_nofollow::OpenFolderChain(first, out.above, walk)) {
                switch (walk.failure) {
                    case hkdfguard_nofollow::Failure::OpenFailed:
                        ThrowOpenFailure(walk.win32, "a folder above the TPM key store");
                    default:
                        Invalid("a folder above the TPM key store is not a local, real folder");
                }
            }
            // The folders down to the store's parent: trusted owners, and
            // nobody else may delete, rename or take over anything in them.
            // Creating entries is allowed there - C:\ProgramData lets Users
            // create folders - since a new entry can't displace the store's.
            for (size_t i = 0; i < out.above.handles.size(); ++i) {
                CheckObjectSecurityOnly(out.above.handles[i].get(), kFolderReplaceRights, true,
                                        "a folder above the TPM key store");
            }

            PSECURITY_DESCRIPTOR folder_sd = nullptr;
            if (create && !ConvertStringSecurityDescriptorToSecurityDescriptorW(kStoreFolderSddl, SDDL_REVISION_1,
                                                                                &folder_sd, nullptr)) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "store folder security descriptor");
            }
            struct FreeSd {
                PSECURITY_DESCRIPTOR sd;
                ~FreeSd() { if (sd) LocalFree(sd); }
            } free_sd{folder_sd};

            HANDLE at = out.above.parent();
            std::wstring path = out.above.parentPath();
            for (size_t i = 0; i < 2; ++i) {
                path += (path.back() == L'\\' ? L"" : L"\\") + std::wstring(kStoreFolders[i]);
                const std::string what = "the TPM key store folder " + ForMessage(path);
                DWORD win32 = 0;
                bool opened = false;
                if (create) {
                    opened = hkdfguard_nofollow::OpenRelative(at, kStoreFolders[i], hkdfguard_nofollow::kFolderAccess,
                                                              hkdfguard_nofollow::kFolderShare, FILE_CREATE,
                                                              FILE_DIRECTORY_FILE, folder_sd, out.folders[i], win32);
                    if (!opened && win32 != ERROR_ALREADY_EXISTS && win32 != ERROR_FILE_EXISTS) {
                        ThrowOpenFailure(win32, what);
                    }
                }
                if (!opened &&
                    !hkdfguard_nofollow::OpenRelative(at, kStoreFolders[i], hkdfguard_nofollow::kFolderAccess,
                                                      hkdfguard_nofollow::kFolderShare, FILE_OPEN, FILE_DIRECTORY_FILE,
                                                      nullptr, out.folders[i], win32)) {
                    ThrowOpenFailure(win32, what);
                }
                RequireKind(out.folders[i].get(), true, what);
                // An existing folder - perhaps created before this library
                // ever ran, by someone else - is held to the same rule as the
                // ones it creates: no one but the KEK administrators may own
                // it, write to it, or even create entries in it.
                CheckObjectSecurityOnly(out.folders[i].get(), kFolderReplaceRights | kFolderCreateRights, false, what);
                at = out.folders[i].get();
            }
            out.keys_path = path;
        }

        void RequireFileName(const std::wstring &name) {
            if (name.empty() || name.size() > 200 || name.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos ||
                name == L"." || name == L"..") {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "invalid TPM key file name");
            }
        }

        void RequireElevated() {
            TOKEN_ELEVATION elevation{};
            DWORD size = 0;
            if (!GetTokenInformation(GetCurrentProcessToken(), TokenElevation, &elevation, sizeof(elevation), &size) ||
                elevation.TokenIsElevated == 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_KEK_ACCESS_DENIED,
                                     "creating or deleting a TPM key file needs an elevated process");
            }
        }

        bool ValidServiceName(const std::string &s) {
            if (s.empty() || s.size() > kMaxServiceLen) {
                return false;
            }
            for (char c : s) {
                const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.';
                if (!ok) {
                    return false;
                }
            }
            return true;
        }
    } // namespace

    Bytes TpmKekTemplate() {
        return tpm2::KeyedHashPublicArea(kTpmKekAttributes, tpm2::kAlgSha256, {});
    }

    void CheckTpmKekPublicArea(const tpm2::PublicArea &area) {
        if (area.type != tpm2::kAlgKeyedHash || area.name_alg != tpm2::kAlgSha256) {
            Invalid("TPM key is not a SHA-256 keyed-hash object");
        }
        if (area.attributes != kTpmKekAttributes) {
            Invalid("TPM key's attributes are not the KEK template's (TPM-generated, fixed to this TPM and its parent, sign-only)");
        }
        if (!area.auth_policy.empty()) {
            Invalid("TPM key has an authorization policy");
        }
        if (area.scheme != tpm2::kAlgHmac || area.scheme_hash != tpm2::kAlgSha256) {
            Invalid("TPM key's scheme is not HMAC-SHA-256");
        }
        if (area.keyed_hash_unique.size() != 32) {
            Invalid("TPM key's unique field is not a SHA-256 digest");
        }
    }

    Bytes SerializeTpmKeyFile(const TpmKeyFile &file) {
        tpm2::Writer w;
        w.Raw(kMagic, sizeof(kMagic));
        w.U16(kFormatVersion);
        w.U16(0);
        w.Tpm2b(reinterpret_cast<const uint8_t *>(file.service.data()), file.service.size());
        w.U32(file.parent_handle);
        w.Tpm2b(file.parent_name);
        w.Raw(file.public_blob);
        w.Raw(file.private_blob);
        Bytes out = w.take();
        // Never write what can't be read back.
        try {
            ParseTpmKeyFile(out.data(), out.size());
        } catch (const HkdfGuardError &) {
            throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "TPM key file contents are invalid");
        }
        return out;
    }

    TpmKeyFile ParseTpmKeyFile(const uint8_t *data, size_t len) {
        if (data == nullptr || len == 0 || len > kMaxTpmKeyFileLen) {
            Invalid("TPM key file has an impossible length");
        }
        TpmKeyFile file;
        tpm2::PublicArea area;
        try {
            tpm2::Reader r(data, len);
            const Bytes magic = r.Raw(sizeof(kMagic));
            if (magic != Bytes(kMagic, kMagic + sizeof(kMagic))) {
                Invalid("not a TPM key file (wrong magic)");
            }
            if (r.U16() != kFormatVersion) {
                Invalid("TPM key file has an unknown format version");
            }
            if (r.U16() != 0) {
                Invalid("TPM key file's reserved field is not zero");
            }
            const Bytes service = r.Tpm2b(kMaxServiceLen);
            file.service.assign(service.begin(), service.end());
            if (!ValidServiceName(file.service)) {
                Invalid("TPM key file's service name is invalid");
            }
            file.parent_handle = r.U32();
            if ((file.parent_handle >> 24) != 0x81) {
                Invalid("TPM key file's parent is not a persistent key");
            }
            file.parent_name = r.Tpm2b(tpm2::kMaxName);
            if (file.parent_name.size() != kParentNameLen || file.parent_name[0] != 0x00 ||
                file.parent_name[1] != tpm2::kAlgSha256) {
                Invalid("TPM key file's parent Name is not a SHA-256 Name");
            }
            file.public_blob = r.Tpm2bWithSize(tpm2::kMaxStructure);
            file.private_blob = r.Tpm2bWithSize(tpm2::kMaxStructure);
            r.ExpectEnd();
            if (file.private_blob.size() <= 2) {
                Invalid("TPM key file's private part is empty");
            }
            area = tpm2::ParsePublicArea(Bytes(file.public_blob.begin() + 2, file.public_blob.end()));
        } catch (const HkdfGuardError &e) {
            if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                throw;
            }
            // tpm2_marshal's parsers report PROVIDER_ERROR; here a malformed
            // structure means a malformed key file.
            Invalid(std::string("TPM key file is malformed: ") + e.what());
        }
        CheckTpmKekPublicArea(area);
        return file;
    }

    std::wstring TpmKeyFileName(const std::wstring &service, uint32_t key_id) {
        return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id) + L".tpmkey";
    }

    TpmKeyStore DefaultTpmKeyStore() {
        PWSTR path = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path)) || path == nullptr) {
            CoTaskMemFree(path);
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "ProgramData could not be located");
        }
        TpmKeyStore store{path};
        CoTaskMemFree(path);
        return store;
    }

    TpmKeyFile ReadTpmKeyFile(const TpmKeyStore &store, const std::wstring &file_name, const std::string &service) {
        RequireFileName(file_name);
        OpenStore opened;
        OpenStoreFolders(store, false, opened);

        // FILE_SHARE_READ only: nobody can write the file while it's read,
        // and a writer that has it open makes this fail rather than read
        // half a file.
        Handle file;
        DWORD win32 = 0;
        if (!hkdfguard_nofollow::OpenRelative(opened.keys(), file_name, GENERIC_READ, FILE_SHARE_READ, FILE_OPEN,
                                              FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY, nullptr, file, win32)) {
            ThrowOpenFailure(win32, "the TPM key file");
        }
        RequireKind(file.get(), false, "the TPM key file");

        // Its ACL is the KEK's access control: owned and writable only by
        // the KEK administrators, and - as VerifyExistingKeyAcl requires of
        // a KSP key - SYSTEM and Administrators present and nothing granted,
        // at any level, to an over-broad principal: read access here *is*
        // the right to use the key.
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR sd = CheckObjectSecurity(file.get(), kFileWriteRights, false, "the TPM key file", &dacl);
        try {
            VerifyExistingKekDacl(dacl);
        } catch (const HkdfGuardError &e) {
            LocalFree(sd);
            if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                AccessControlInvalid(std::string("the TPM key file: ") + e.what());
            }
            throw;
        } catch (...) {
            LocalFree(sd);
            throw;
        }
        LocalFree(sd);

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.get(), &size)) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "GetFileSizeEx failed on the TPM key file");
        }
        if (size.QuadPart <= 0 || size.QuadPart > static_cast<LONGLONG>(kMaxTpmKeyFileLen)) {
            Invalid("TPM key file has an impossible length");
        }
        Bytes contents(static_cast<size_t>(size.QuadPart));
        DWORD total = 0;
        while (total < contents.size()) {
            DWORD got = 0;
            if (!ReadFile(file.get(), contents.data() + total, static_cast<DWORD>(contents.size() - total), &got, nullptr)) {
                throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR, "ReadFile failed on the TPM key file");
            }
            if (got == 0) {
                Invalid("TPM key file ended early");
            }
            total += got;
        }
        uint8_t extra = 0;
        DWORD got_extra = 0;
        if (!ReadFile(file.get(), &extra, 1, &got_extra, nullptr) || got_extra != 0) {
            Invalid("TPM key file is longer than its size");
        }

        TpmKeyFile parsed = ParseTpmKeyFile(contents.data(), contents.size());
        if (parsed.service != service) {
            Invalid("TPM key file belongs to a different service");
        }
        return parsed;
    }

    bool TpmKeyFileExists(const TpmKeyStore &store, const std::wstring &file_name, const std::string &service) {
        try {
            ReadTpmKeyFile(store, file_name, service);
            return true;
        } catch (const HkdfGuardError &e) {
            if (e.code() == HKDFGUARD_ERR_KEK_NOT_FOUND) {
                return false;
            }
            throw;
        }
    }

    bool WriteTpmKeyFile(const TpmKeyStore &store, const std::wstring &file_name, const TpmKeyFile &file,
                         const std::vector<std::wstring> &additional_groups) {
        RequireFileName(file_name);
        RequireElevated(); // before anything is created: see tpm_key_file.h
        const Bytes contents = SerializeTpmKeyFile(file);
        const std::vector<BYTE> file_sd = BuildKekFileSecurityDescriptor(additional_groups);

        OpenStore opened;
        OpenStoreFolders(store, true, opened);

        // Already there? Then nothing is written; the rename below refuses
        // to replace one that appears meanwhile.
        {
            Handle existing;
            DWORD win32 = 0;
            if (hkdfguard_nofollow::OpenRelative(opened.keys(), file_name, FILE_READ_ATTRIBUTES,
                                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0,
                                                 nullptr, existing, win32)) {
                return false;
            }
            if (win32 != ERROR_FILE_NOT_FOUND) {
                ThrowOpenFailure(win32, "the TPM key file");
            }
        }

        // A temporary name of its own, created with the final ACL.
        uint8_t random[8];
        if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO_ERROR, "BCryptGenRandom failed");
        }
        std::wstring temp_name = file_name + L".";
        for (uint8_t b : random) {
            static const wchar_t *digits = L"0123456789abcdef";
            temp_name += digits[b >> 4];
            temp_name += digits[b & 15];
        }
        temp_name += L".tmp";

        Handle temp;
        DWORD win32 = 0;
        if (!hkdfguard_nofollow::OpenRelative(opened.keys(), temp_name, GENERIC_WRITE | DELETE | READ_CONTROL, 0,
                                              FILE_CREATE, FILE_NON_DIRECTORY_FILE,
                                              const_cast<BYTE *>(file_sd.data()), temp, win32)) {
            ThrowOpenFailure(win32, "a temporary TPM key file");
        }
        // Until it has its final name, the temporary file goes on any exit.
        bool committed = false;
        struct DeleteUnlessCommitted {
            HANDLE file;
            const bool &committed;
            ~DeleteUnlessCommitted() {
                if (!committed) {
                    FILE_DISPOSITION_INFO dispose{TRUE};
                    SetFileInformationByHandle(file, FileDispositionInfo, &dispose, sizeof(dispose));
                }
            }
        } cleanup{temp.get(), committed};

        DWORD total = 0;
        while (total < contents.size()) {
            DWORD put = 0;
            if (!WriteFile(temp.get(), contents.data() + total, static_cast<DWORD>(contents.size() - total), &put, nullptr) ||
                put == 0) {
                IoFailure("WriteFile failed on the TPM key file");
            }
            total += put;
        }
        if (!FlushFileBuffers(temp.get())) {
            IoFailure("FlushFileBuffers failed on the TPM key file");
        }

        // Rename to the final name, never replacing a file already there:
        // the native rename, with the target named relative to the store
        // folder's handle, so it lands exactly there and no path is looked
        // up. (FILE_RENAME_INFO has FILE_RENAME_INFORMATION's layout.)
        constexpr NTSTATUS kStatusObjectNameCollision = static_cast<NTSTATUS>(0xC0000035L);
        constexpr auto kFileRenameInformation = static_cast<FILE_INFORMATION_CLASS>(10);
        const size_t name_bytes = file_name.size() * sizeof(wchar_t);
        std::vector<BYTE> rename_buffer(sizeof(FILE_RENAME_INFO) + name_bytes);
        auto *rename = reinterpret_cast<FILE_RENAME_INFO *>(rename_buffer.data());
        rename->ReplaceIfExists = FALSE;
        rename->RootDirectory = opened.keys();
        rename->FileNameLength = static_cast<DWORD>(name_bytes);
        std::memcpy(rename->FileName, file_name.data(), name_bytes);
        IO_STATUS_BLOCK io{};
        const NTSTATUS renamed = NtSetInformationFile(temp.get(), &io, rename, static_cast<ULONG>(rename_buffer.size()),
                                                      kFileRenameInformation);
        if (renamed == kStatusObjectNameCollision) {
            return false; // the cleanup removes the temporary file
        }
        if (renamed < 0) {
            IoFailure("renaming the TPM key file into place failed", RtlNtStatusToDosError(renamed));
        }
        committed = true;
        temp.reset();

        // Read back through every check a later open makes; a file that
        // fails them is removed rather than left behind.
        try {
            ReadTpmKeyFile(store, file_name, file.service);
        } catch (...) {
            DeleteTpmKeyFile(store, file_name);
            throw;
        }
        return true;
    }

    void VerifyTpmKeyFileGrants(const TpmKeyStore &store, const std::wstring &file_name,
                                const std::vector<std::wstring> &additional_groups) {
        RequireFileName(file_name);
        OpenStore opened;
        OpenStoreFolders(store, false, opened);
        Handle file;
        DWORD win32 = 0;
        if (!hkdfguard_nofollow::OpenRelative(opened.keys(), file_name, READ_CONTROL, FILE_SHARE_READ, FILE_OPEN,
                                              FILE_NON_DIRECTORY_FILE, nullptr, file, win32)) {
            ThrowOpenFailure(win32, "the TPM key file");
        }
        RequireKind(file.get(), false, "the TPM key file");
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (GetSecurityInfo(file.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
                            &sd) != ERROR_SUCCESS) {
            IoFailure("reading the TPM key file's ACL failed");
        }
        try {
            VerifyKekDaclGrants(dacl, additional_groups);
        } catch (const HkdfGuardError &e) {
            LocalFree(sd);
            if (e.code() == HKDFGUARD_ERR_PROVIDER_ERROR) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER_ERROR,
                    "the existing TPM key file's ACL doesn't grant every principal the current policy names "
                    "(SYSTEM, Administrators, HkdfGuardAdmins, HkdfGuardUsers, HkdfGuardDeployers, KeyUseGroups, "
                    "DeployerGroups); nothing was changed. Add the missing grant to the key file, or retire the KEK "
                    "and provision again");
            }
            throw;
        } catch (...) {
            LocalFree(sd);
            throw;
        }
        LocalFree(sd);
    }

    bool DeleteTpmKeyFile(const TpmKeyStore &store, const std::wstring &file_name) {
        RequireFileName(file_name);
        RequireElevated();
        OpenStore opened;
        try {
            OpenStoreFolders(store, false, opened);
        } catch (const HkdfGuardError &e) {
            if (e.code() == HKDFGUARD_ERR_KEK_NOT_FOUND) {
                return false;
            }
            throw;
        }
        Handle file;
        DWORD win32 = 0;
        if (!hkdfguard_nofollow::OpenRelative(opened.keys(), file_name, DELETE | FILE_READ_ATTRIBUTES, 0, FILE_OPEN,
                                              FILE_NON_DIRECTORY_FILE, nullptr, file, win32)) {
            if (win32 == ERROR_FILE_NOT_FOUND) {
                return false;
            }
            ThrowOpenFailure(win32, "the TPM key file");
        }
        // A link in the file's place is removed as the link itself
        // (OpenRelative opens reparse points as themselves); nothing it
        // points at is touched.
        FILE_DISPOSITION_INFO dispose{TRUE};
        if (!SetFileInformationByHandle(file.get(), FileDispositionInfo, &dispose, sizeof(dispose))) {
            IoFailure("deleting the TPM key file failed");
        }
        return true;
    }
} // namespace hkdfguard
