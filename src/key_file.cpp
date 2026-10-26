// Reading a wrapped-key file for hkdfguard_open_file (see hkdfguard.h for the
// contract). Its own file, rather than part of hkdfguard.cpp, so the test
// executable can compile and call ReadWrappedKeyFile directly, the same way
// kek_store.cpp is shared.
#include "key_file.h"

#include "../include/hkdfguard.h"
#include "errors.h"
#include "event_log.h"   // LogDeveloperModeKeyFile
#include "key_acl.h"     // ResolveDeployerPrincipals
#include "policy.h"      // LoadSecurityModel, LoadDeployerGroupsPolicy
#include "wire_format.h" // ParseWrappedDek, kTotalLen

#include "secure_buffer.h" // SecureBuffer - holds a small file's bytes while they're inspected
#include "no_follow_open.h" // OpenFolderChain / OpenRelative - the path walk that never follows a link

#include <windows.h>
#include <aclapi.h> // GetSecurityInfo
#include <cstring>
#include <string>
#include <vector>

namespace hkdfguard {
    namespace {
        // Longest path hkdfguard_open_file reads from its `path` argument, in
        // bytes: the Win32 limit of 32,767 UTF-16 code units, each at most three
        // UTF-8 bytes. Bounds the strnlen below the same way kMaxServiceLen does
        // for a service name.
        constexpr size_t kMaxPathBytes = 32767 * 3;

        // UTF-8 path -> UTF-16 for CreateFileW. Unlike a service name, a path may
        // legitimately contain any Unicode character, so it is converted rather
        // than restricted to a charset - but never with replacement characters,
        // which could silently open a different file than the one named.
        std::wstring PathToWide(const char *path) {
            size_t len = strnlen(path, kMaxPathBytes + 1);
            if (len == 0 || len > kMaxPathBytes) {
                throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "path is empty or too long");
            }
            int wide_len = MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, path, static_cast<int>(len), nullptr, 0);
            if (wide_len <= 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "path is not valid UTF-8");
            }
            std::wstring wide(static_cast<size_t>(wide_len), L'\0');
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, static_cast<int>(len), wide.data(), wide_len);
            return wide;
        }

        // Maps why CreateFileW failed onto the three file-error codes.
        int32_t FileOpenErrorCode(DWORD error) noexcept {
            switch (error) {
                case ERROR_FILE_NOT_FOUND:
                case ERROR_PATH_NOT_FOUND:
                case ERROR_INVALID_DRIVE:
                case ERROR_BAD_NETPATH:
                case ERROR_BAD_NET_NAME:
                    return HKDFGUARD_ERR_FILE_NOT_FOUND;
                case ERROR_ACCESS_DENIED:
                    return HKDFGUARD_ERR_FILE_ACCESS_DENIED;
                default:
                    // Sharing violations (a writer has it open), invalid names,
                    // and anything else.
                    return HKDFGUARD_ERR_FILE_IO;
            }
        }

        // Drops the "\\?\" extended-length prefix (and turns "\\?\UNC\server"
        // back into "\\server"), so a path spelled with the prefix and the
        // prefixed form GetFinalPathNameByHandle always returns both compare
        // against the plain spelling.
        std::wstring StripExtendedPrefix(std::wstring p) {
            if (p.rfind(L"\\\\?\\UNC\\", 0) == 0) {
                return L"\\\\" + p.substr(8);
            }
            if (p.rfind(L"\\\\?\\", 0) == 0) {
                return p.substr(4);
            }
            return p;
        }

        // The fully-qualified path the caller actually spelled - relative paths
        // resolved against the current directory - with no link followed and
        // nothing expanded. GetFullPathNameW works on the text alone. This is
        // what the opened handle's own path is compared against in
        // ReadWrappedKeyFile.
        std::wstring ExpectedFullPath(const std::wstring &path) {
            DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
            if (needed == 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "GetFullPathName failed");
            }
            std::wstring full(needed, L'\0');
            DWORD written = GetFullPathNameW(path.c_str(), needed, full.data(), nullptr);
            if (written == 0 || written >= needed) {
                throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARGUMENT, "GetFullPathName failed");
            }
            full.resize(written);
            return full;
        }

        // Only "<letter>:\..." on a local volume is allowed, decided before
        // anything is opened. Refused: UNC paths (\\server\share, \\?\UNC\...),
        // the device namespace (\\.\pipe\..., \\.\PhysicalDrive0, and DOS device
        // names such as NUL or CON, which GetFullPathName turns into \\.\NUL),
        // mapped network drives and SUBST drives. Opening a path on a server
        // would make this process connect and authenticate to that server - a
        // credential leak if the path is attacker-influenced. Links further
        // down the path are the walk's job (OpenFolderChain).
        void RequireLocalDrivePath(const std::wstring &full) {
            if (!hkdfguard_nofollow::IsLocalDrivePath(full)) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path is not on a local drive");
            }
        }

        // The kernel's canonical DOS path for an open handle - reflecting every
        // reparse point traversed to reach it, which is the point - with the
        // extended prefix stripped so it compares against ExpectedFullPath.
        // Sized by retrying: grows to whatever the call last reported, plus one.
        std::wstring FinalPathOfHandle(HANDLE file) {
            std::wstring final(MAX_PATH, L'\0');
            for (int attempt = 0; attempt < 4; ++attempt) {
                DWORD written = GetFinalPathNameByHandleW(
                    file, final.data(), static_cast<DWORD>(final.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (written == 0) {
                    // ERROR_PATH_NOT_FOUND here means the file's volume has no
                    // drive letter - reachable only through a volume mount point.
                    throw HkdfGuardError(
                        GetLastError() == ERROR_PATH_NOT_FOUND ? HKDFGUARD_ERR_FILE_UNTRUSTED : HKDFGUARD_ERR_FILE_IO,
                        "GetFinalPathNameByHandle failed");
                }
                if (written < final.size()) {
                    final.resize(written);
                    return StripExtendedPrefix(final);
                }
                final.assign(static_cast<size_t>(written) + 1, L'\0');
            }
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "GetFinalPathNameByHandle could not size its result");
        }

        // MARK: Who may have written the file

        // Rights on the key file that let a principal change what it holds,
        // delete or rename it, or take it over. Read access is not here: a
        // wrapped DEK is ciphertext, so reading it gains nothing. GENERIC_*
        // appear because an ACE may carry them unmapped.
        constexpr ACCESS_MASK kFileWriteRights = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                                                 FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
                                                 GENERIC_WRITE | GENERIC_ALL;

        // Rights on a folder in the key's path that let a principal remove
        // or rename an entry in it (FILE_DELETE_CHILD), remove or rename the
        // folder itself (DELETE), or take it over (WRITE_DAC, WRITE_OWNER) -
        // any of which lets them put a file of their choosing where the key
        // was. Refused on every folder in the path, the drive root included.
        constexpr ACCESS_MASK kFolderReplaceRights = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

        // Rights on a folder that let a principal create new entries in it:
        // "create files / write data" (FILE_ADD_FILE), "create folders /
        // append data" (FILE_ADD_SUBDIRECTORY), and GENERIC_WRITE, which
        // maps to both. Refused on the key file's own folder and every folder above it - except the drive root (see
        // kDriveRootRights) - so C:\ProgramData and C:\Windows\Temp, which
        // let Users create entries, and a folder that inherited that from
        // them, are refused.
        constexpr ACCESS_MASK kFolderCreateRights = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE;

        // What a folder between the drive root and the key file - its own
        // folder included - may grant nobody untrusted.
        constexpr ACCESS_MASK kFolderRights = kFolderReplaceRights | kFolderCreateRights;

        // What the drive root may grant nobody untrusted: only the replace
        // rights. A default C:\ lets Authenticated Users create folders in
        // it (FILE_ADD_SUBDIRECTORY), and applying kFolderCreateRights there
        // would mean no key file on the system drive could ever be trusted.
        // Creating a new folder beside the key's top-level folder can't
        // displace that folder, and the folders below the root are held to
        // kFolderRights themselves.
        constexpr ACCESS_MASK kDriveRootRights = kFolderReplaceRights;

        // NT SERVICE\TrustedInstaller, which owns C:\ and much of the system
        // drive: S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464.
        class TrustedInstallerSid {
        public:
            TrustedInstallerSid() {
                SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
                if (!AllocateAndInitializeSid(&nt, 6, SECURITY_SERVICE_ID_BASE_RID, 956008885, 3418522649,
                                              1831038044, 1853292631, 2271478464, 0, 0, &sid_)) {
                    throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "AllocateAndInitializeSid failed");
                }
            }

            ~TrustedInstallerSid() { FreeSid(sid_); }

            TrustedInstallerSid(const TrustedInstallerSid &) = delete;

            TrustedInstallerSid &operator=(const TrustedInstallerSid &) = delete;

            PSID get() const { return sid_; }

        private:
            PSID sid_ = nullptr;
        };

        // The SID of the account this process runs as (TokenUser), or the
        // one new files get as their owner (TokenOwner - Administrators when
        // elevated), as an owned buffer.
        std::vector<BYTE> ProcessTokenSid(TOKEN_INFORMATION_CLASS which) {
            DWORD size = 0;
            GetTokenInformation(GetCurrentProcessToken(), which, nullptr, 0, &size);
            std::vector<BYTE> info(size);
            if (size == 0 || !GetTokenInformation(GetCurrentProcessToken(), which, info.data(), size, &size)) {
                throw HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR, "GetTokenInformation failed");
            }
            PSID sid = which == TokenOwner ? reinterpret_cast<const TOKEN_OWNER *>(info.data())->Owner
                                           : reinterpret_cast<const TOKEN_USER *>(info.data())->User.Sid;
            const auto *bytes = static_cast<const BYTE *>(sid);
            return std::vector<BYTE>(bytes, bytes + GetLengthSid(sid));
        }

        // The principals a key file and its folders may be owned by, and
        // the only ones that may hold the write-type rights above. Always
        // SYSTEM, BUILTIN\Administrators and TrustedInstaller
        // (Administrators because an elevated administrator's files are
        // owned by the group, not the user). Then, by security model (see
        // SecurityModel in policy.h):
        //
        //   Production: each deployer group (HkdfGuardDeployers and the
        //     DeployerGroups policy) and each direct member of one - see
        //     ResolveDeployerPrincipals. The account this process runs as is
        //     trusted only if it is such a member, so an application runner
        //     can't persist a key file its own service would accept.
        //   Developer: the account this process runs as.
        //
        // OWNER RIGHTS is accepted in an ACE because it means "whoever owns
        // this", and the owner is checked separately. CREATOR OWNER and
        // CREATOR GROUP are accepted because outside an inherit-only ACE
        // they match nobody.
        class TrustedPrincipals {
        public:
            // Reads the security model (and, for Production, the deployer
            // groups) at construction. Throws HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID)
            // for an invalid SecurityModel value, and
            // HKDFGUARD_ERR_WIN_GROUP_INVALID for a bad DeployerGroups entry.
            TrustedPrincipals() : model_(LoadSecurityModel()) {
                switch (model_) {
                    case SecurityModel::Developer:
                        extra_.push_back(ProcessTokenSid(TokenUser));
                        break;
                    case SecurityModel::Production:
                        extra_ = ResolveDeployerPrincipals(LoadDeployerGroupsPolicy());
                        break;
                    default:
                        throw HkdfGuardError(HKDFGUARD_ERR_POLICY_INVALID, "invalid SecurityModel policy");
                }
            }

            SecurityModel model() const { return model_; }

            bool MayOwn(PSID sid) const {
                if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
                    EqualSid(sid, trusted_installer_.get())) {
                    return true;
                }
                for (const std::vector<BYTE> &extra: extra_) {
                    if (EqualSid(sid, const_cast<BYTE *>(extra.data()))) {
                        return true;
                    }
                }
                return false;
            }

            bool MayWrite(PSID sid) const {
                return MayOwn(sid) || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) ||
                       IsWellKnownSid(sid, WinCreatorOwnerSid) || IsWellKnownSid(sid, WinCreatorGroupSid);
            }

            // Who, besides SYSTEM, Administrators and TrustedInstaller, is
            // trusted - for error messages.
            const char *Others() const {
                return model_ == SecurityModel::Developer ? "this account" : "a deployer group or its member";
            }

        private:
            SecurityModel model_;
            std::vector<std::vector<BYTE>> extra_;
            TrustedInstallerSid trusted_installer_;
        };

        // The owner/DACL test itself, on an already-fetched owner and DACL.
        // `what` names the object for the error message.
        void CheckOwnerAndDacl(PSID owner, PACL dacl, bool dacl_present, ACCESS_MASK forbidden,
                               const TrustedPrincipals &trusted, const char *what) {
            if (owner == nullptr || !trusted.MayOwn(owner)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_FILE_UNTRUSTED,
                    (std::string(what) + " is not owned by SYSTEM, Administrators, TrustedInstaller or " +
                     trusted.Others()).c_str());
            }
            if (!dacl_present || dacl == nullptr) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED,
                                     (std::string(what) + " has no DACL, so everyone has full access to it").c_str());
            }
            for (DWORD i = 0; i < dacl->AceCount; ++i) {
                void *ace = nullptr;
                if (!GetAce(dacl, i, &ace)) {
                    throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, (std::string(what) + ": GetAce failed").c_str());
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
                        // The same layout up to the SID: header, mask, SID.
                        // A callback (conditional) ACE is judged as if its
                        // condition held, since it may.
                        const ACCESS_ALLOWED_ACE *allowed = static_cast<const ACCESS_ALLOWED_ACE *>(ace);
                        PSID sid = const_cast<DWORD *>(&allowed->SidStart);
                        const ACCESS_MASK granted = allowed->Mask & forbidden;
                        if (granted != 0 && !trusted.MayWrite(sid)) {
                            // Only create rights - a folder below the drive
                            // root that, like C:\ProgramData, lets others
                            // add entries - gets its own message, so the
                            // fix (remove those rights) is obvious.
                            // (On the file itself the same bits are write
                            // access, reported as such.)
                            const bool create_only =
                                    forbidden == kFolderRights && (granted & ~kFolderCreateRights) == 0;
                            throw HkdfGuardError(
                                HKDFGUARD_ERR_FILE_UNTRUSTED,
                                (std::string(what) +
                                 (create_only
                                      ? " lets an account other than SYSTEM, Administrators, TrustedInstaller or "
                                      : " grants write, delete or ownership rights to an account other than SYSTEM, "
                                        "Administrators, TrustedInstaller or ") +
                                 trusted.Others() + (create_only ? " create files or folders in it" : "")).c_str());
                        }
                        continue;
                    }
                    default:
                        // Object and compound allow ACEs never belong on a
                        // file system object; one that can't be read can't
                        // be vouched for.
                        throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED,
                                             (std::string(what) + " has an access-allowed ACE of an unexpected type").c_str());
                }
            }
        }

        // CheckOwnerAndDacl on an open handle's live security descriptor.
        void CheckHandleSecurity(HANDLE handle, ACCESS_MASK forbidden, const TrustedPrincipals &trusted,
                                 const char *what) {
            PSID owner = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            DWORD rc = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                       &owner, nullptr, &dacl, nullptr, &sd);
            if (rc != ERROR_SUCCESS) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, (std::string(what) + ": its security could not be read").c_str());
            }
            try {
                // GetSecurityInfo reports a missing DACL and a NULL DACL
                // alike, as dacl == nullptr - both mean unrestricted access.
                CheckOwnerAndDacl(owner, dacl, true, forbidden, trusted, what);
            } catch (...) {
                LocalFree(sd);
                throw;
            }
            LocalFree(sd);
        }

        // UTF-16 -> UTF-8, for naming a folder in an error message only.
        std::string NarrowForMessage(const std::wstring &wide) {
            int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0,
                                          nullptr, nullptr);
            if (len <= 0) {
                return "(unprintable path)";
            }
            std::string narrow(static_cast<size_t>(len), '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), narrow.data(), len, nullptr,
                                nullptr);
            return narrow;
        }

        // Every folder above the key file, from its own folder up to the
        // drive root, must pass the same owner test. The folders below the
        // drive root - the key file's own folder included - must grant
        // nobody else kFolderRights: no one else may rename a file of their
        // choosing over the key, move the key's folder out of the way and
        // one of their own into its place, or even create entries there.
        // The drive root itself (chain.handles[0]) is held to
        // kDriveRootRights only: a trusted owner, and no one else may
        // rename or delete what is directly beneath it, but creating new
        // folders there - which a default C:\ allows every authenticated
        // user - is permitted. A key file directly in the drive root gets
        // the drive-root treatment for its folder.
        //
        // Checked on the handles the walk opened each folder through
        // (already confirmed real folders, not reparse points), so it is the
        // folders actually traversed that are judged - nothing is looked up
        // by name again.
        void CheckFolderChain(const hkdfguard_nofollow::FolderChain &chain, const TrustedPrincipals &trusted) {
            for (size_t i = 0; i < chain.handles.size(); ++i) {
                const bool drive_root = i == 0;
                const std::string what = (drive_root ? "the drive root (" : "a folder in the path (") +
                                         NarrowForMessage(chain.paths[i]) + ")";
                CheckHandleSecurity(chain.handles[i].get(), drive_root ? kDriveRootRights : kFolderRights, trusted,
                                    what.c_str());
            }
        }

        // MARK: Plaintext keys written as text

        // Longest text form of a DEK recognised, surrounding whitespace
        // included. Every length up to it is below a payload's, so no
        // payload can be mistaken for one.
        constexpr size_t kMaxPlaintextTextLen = 96;
        static_assert(kMaxPlaintextTextLen < kTotalLen && HKDFGUARD_DEK_LEN < kTotalLen,
                      "plaintext detection must never be able to refuse a real payload");

        // Branch-free byte classification for LooksLikePlaintextDek. Every
        // helper returns 0 or 1 and is straight-line arithmetic on uint32_t,
        // with no data-dependent branch or table lookup.

        // 1 if a == b, else 0 (inputs below 2^31).
        uint32_t CtEq(uint32_t a, uint32_t b) {
            return ((a ^ b) - 1u) >> 31;
        }

        // 1 if lo <= c <= hi, else 0 (inputs below 2^31): both differences
        // wrap negative exactly when c is inside.
        uint32_t CtInRange(uint32_t c, uint32_t lo, uint32_t hi) {
            return (((lo - 1u) - c) & (c - (hi + 1u))) >> 31 & 1u;
        }

        // a if cond is 1, b if it is 0.
        uint32_t CtSelect(uint32_t cond, uint32_t a, uint32_t b) {
            return b ^ ((a ^ b) & (0u - cond));
        }

        // ASCII whitespace: space, tab, LF, form feed, CR.
        uint32_t CtIsWhitespace(uint32_t c) {
            return CtEq(c, ' ') | CtEq(c, '\t') | CtEq(c, '\n') | CtEq(c, '\f') | CtEq(c, '\r');
        }

        uint32_t CtIsHex(uint32_t c) {
            return CtInRange(c, '0', '9') | CtInRange(c, 'a', 'f') | CtInRange(c, 'A', 'F');
        }

        // Membership of c in the base64 alphabet whose 62nd and 63rd
        // characters are c62 and c63; its 6-bit value goes to `value`.
        uint32_t CtBase64(uint32_t c, uint32_t c62, uint32_t c63, uint32_t &value) {
            uint32_t upper = CtInRange(c, 'A', 'Z');
            uint32_t lower = CtInRange(c, 'a', 'z');
            uint32_t digit = CtInRange(c, '0', '9');
            uint32_t s62 = CtEq(c, c62);
            uint32_t s63 = CtEq(c, c63);
            value = ((c - 'A') & (0u - upper)) | ((c - ('a' - 26u)) & (0u - lower)) |
                    ((c + (52u - '0')) & (0u - digit)) | (62u & (0u - s62)) | (63u & (0u - s63));
            return upper | lower | digit | s62 | s63;
        }

        // 32 raw bytes, or 32 bytes written as text: hex (either case, 64
        // digits) or base64 (standard or URL-safe, with or without its one
        // '=' of padding - the CLI's own DEK input is standard, padded),
        // with any leading or trailing whitespace an editor or `echo` adds.
        // Every one of these is too short to be a payload anyway;
        // recognising them is what turns "wrong file" into "this key is
        // exposed".
        //
        // Constant-time in the contents: the only
        // branches are on the length, which the file's size already gives
        // away. Every byte is visited twice (once to find the text between
        // the surrounding whitespace, once to test it against all three
        // alphabets at once) and every decision is mask arithmetic, so how
        // long this takes says nothing about where in a would-be key the
        // first non-matching byte sits. Nothing is decoded, so the key is
        // never reassembled. Base64 is 43 characters, or 44 ending in '=',
        // all in one alphabet, whose last character's 2 unused bits are
        // zero - the canonical encoding of 32 bytes.
        bool LooksLikePlaintextDek(const uint8_t *bytes, size_t len) {
            if (len == HKDFGUARD_DEK_LEN) {
                return true;
            }
            if (len > kMaxPlaintextTextLen) {
                return false;
            }
            const uint32_t n = static_cast<uint32_t>(len);

            // Pass 1: the first and last non-whitespace positions.
            uint32_t seen = 0, start = 0, end = 0;
            for (uint32_t i = 0; i < n; ++i) {
                uint32_t text = CtIsWhitespace(bytes[i]) ^ 1u;
                start = CtSelect(text & (seen ^ 1u), i, start);
                end = CtSelect(text, i, end);
                seen |= text;
            }
            const uint32_t text_len = (end - start + 1u) & (0u - seen);

            // Pass 2: every byte between them against every alphabet, plus
            // the values of the last two (the last may be the '=' of padding).
            uint32_t hex_ok = 1, std_ok = 1, url_ok = 1, padded = 0;
            uint32_t std_last = 0, std_prev = 0, url_last = 0, url_prev = 0;
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t c = bytes[i];
                const uint32_t outside = (CtInRange(i, start, end) & seen) ^ 1u;
                const uint32_t is_end = CtEq(i, end);
                const uint32_t is_prev = CtEq(i + 1u, end);
                const uint32_t pad = is_end & CtEq(c, '=');
                uint32_t std_value = 0, url_value = 0;
                const uint32_t std_member = CtBase64(c, '+', '/', std_value);
                const uint32_t url_member = CtBase64(c, '-', '_', url_value);
                hex_ok &= CtIsHex(c) | outside;
                std_ok &= std_member | pad | outside;
                url_ok &= url_member | pad | outside;
                padded |= pad;
                std_last = CtSelect(is_end, std_value, std_last);
                std_prev = CtSelect(is_prev, std_value, std_prev);
                url_last = CtSelect(is_end, url_value, url_last);
                url_prev = CtSelect(is_prev, url_value, url_prev);
            }

            // 43 data characters carry 258 bits: the last one's low 2 must be 0.
            const uint32_t shape = (CtEq(text_len, 43) & (padded ^ 1u)) | (CtEq(text_len, 44) & padded);
            const uint32_t std_canonical = CtEq(CtSelect(padded, std_prev, std_last) & 3u, 0);
            const uint32_t url_canonical = CtEq(CtSelect(padded, url_prev, url_last) & 3u, 0);
            const uint32_t hex = hex_ok & CtEq(text_len, 2 * HKDFGUARD_DEK_LEN);
            const uint32_t base64 = shape & ((std_ok & std_canonical) | (url_ok & url_canonical));
            return (seen & (hex | base64)) == 1u;
        }

        // Reads a file already known to be no longer than
        // kMaxPlaintextTextLen into a buffer that's wiped afterwards, and
        // reports whether it holds a DEK as text. Nothing read here is ever
        // copied to the caller. A read error just means "can't tell", and
        // the caller reports the file as too short, which it is.
        bool SmallFileLooksLikePlaintextDek(HANDLE file) {
            SecureBuffer<kMaxPlaintextTextLen + 1> contents;
            DWORD total = 0;
            while (total < contents.size()) {
                DWORD got = 0;
                if (!ReadFile(file, contents.data() + total, static_cast<DWORD>(contents.size() - total), &got, nullptr)) {
                    return false;
                }
                if (got == 0) {
                    break;
                }
                total += got;
            }
            return LooksLikePlaintextDek(contents.data(), total);
        }
    } // namespace

    void CheckKeyFileSecurity(PSECURITY_DESCRIPTOR sd, KeyFileObject object) {
        PSID owner = nullptr;
        BOOL owner_defaulted = FALSE;
        PACL dacl = nullptr;
        BOOL dacl_present = FALSE;
        BOOL dacl_defaulted = FALSE;
        if (!GetSecurityDescriptorOwner(sd, &owner, &owner_defaulted) ||
            !GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "security descriptor could not be read");
        }
        TrustedPrincipals trusted;
        switch (object) {
            case KeyFileObject::File:
                CheckOwnerAndDacl(owner, dacl, dacl_present != FALSE, kFileWriteRights, trusted, "the file");
                break;
            case KeyFileObject::Folder:
                CheckOwnerAndDacl(owner, dacl, dacl_present != FALSE, kFolderRights, trusted, "a folder in the path");
                break;
            case KeyFileObject::DriveRoot:
                CheckOwnerAndDacl(owner, dacl, dacl_present != FALSE, kDriveRootRights, trusted, "the drive root");
                break;
        }
    }

    bool IsTrustedKeyFilePrincipal(PSID sid) {
        return TrustedPrincipals().MayOwn(sid);
    }

    SecurityModel CallerMayWriteKeyFiles(bool &may_write) {
        TrustedPrincipals trusted;
        std::vector<BYTE> owner = ProcessTokenSid(TokenOwner);
        may_write = trusted.MayOwn(owner.data());
        return trusted.model();
    }

    bool LooksLikePlaintextKeyForTest(const uint8_t *bytes, size_t len) {
        return LooksLikePlaintextDek(bytes, len);
    }

    std::wstring KeyFilePathToWide(const char *path) {
        return PathToWide(path);
    }

    // Reads exactly kTotalLen bytes of a wrapped-key file into `out` and
    // validates them - see hkdfguard_open_file in hkdfguard.h for the
    // contract. Throws HkdfGuardError on every failure; the caller zeroes
    // `out`.
    void ReadWrappedKeyFile(const char *path, uint8_t *out) {
        std::wstring wide_path = PathToWide(path);
        std::wstring expected = StripExtendedPrefix(ExpectedFullPath(wide_path));
        RequireLocalDrivePath(expected);

        // Walk to the file's folder one component at a time, each opened
        // relative to the one above it and refused if it is a reparse point
        // - so no junction or directory symbolic link is ever followed, and
        // in particular none pointing at \\server\share: nothing is opened
        // on another machine, so no credentials are offered to one. See
        // no_follow_open.h.
        hkdfguard_nofollow::FolderChain chain;
        hkdfguard_nofollow::Error walk;
        if (!hkdfguard_nofollow::OpenFolderChain(expected, chain, walk)) {
            switch (walk.failure) {
                case hkdfguard_nofollow::Failure::NotLocalDrive:
                    throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path is not on a local drive");
                case hkdfguard_nofollow::Failure::ReparsePoint:
                    throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED,
                                         "a folder in the path is a symbolic link, junction or other reparse point");
                case hkdfguard_nofollow::Failure::NotADirectory:
                    throw HkdfGuardError(HKDFGUARD_ERR_FILE_NOT_FOUND, "a component of the path is a file, not a folder");
                case hkdfguard_nofollow::Failure::OpenFailed:
                    // A folder that doesn't exist is "not found"; one that
                    // can't be opened to read its security can't be vouched
                    // for.
                    if (FileOpenErrorCode(walk.win32) == HKDFGUARD_ERR_FILE_NOT_FOUND) {
                        throw HkdfGuardError(HKDFGUARD_ERR_FILE_NOT_FOUND, "a folder in the path does not exist");
                    }
                    throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED,
                                         "a folder in the path could not be opened to check its security");
                default:
                    throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED,
                                         "the path names an alternate data stream or has an empty component");
            }
        }

        // Short names in the folders: the walk followed no link, so the
        // deepest folder's canonical path differs from the spelled one only
        // if some folder was spelled with its 8.3 short name ("PROGRA~1"),
        // which GetFinalPathNameByHandle expands. Checked before the file is
        // opened, so "C:\PROGRA~1\missing.key" is refused as a short name
        // rather than reported as merely not found. Asked of a local handle,
        // so nothing leaves the machine.
        if (CompareStringOrdinal(FinalPathOfHandle(chain.parent()).c_str(), -1, chain.parentPath().c_str(), -1,
                                 TRUE) != CSTR_EQUAL) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path uses an 8.3 short name");
        }

        // The file itself, relative to its folder. FILE_SHARE_READ only:
        // while this handle is open nobody can write the file, and if a
        // writer already has it open this fails with a sharing violation
        // instead of reading a half-written payload. FILE_OPEN_REPARSE_POINT
        // (always added by OpenRelative): a symbolic link here opens as the
        // link itself, so the reparse check below sees it.
        hkdfguard_nofollow::Handle file_handle;
        DWORD open_error = 0;
        if (!hkdfguard_nofollow::OpenRelative(
                chain.parent(), chain.leaf, GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY, nullptr,
                file_handle, open_error)) {
            throw HkdfGuardError(FileOpenErrorCode(open_error), "opening the file failed");
        }
        HANDLE file = file_handle.get();

        // Only a regular on-disk file. A pipe, console or other device is
        // refused before any ReadFile, since reading one could block
        // indefinitely or return arbitrary data.
        if (GetFileType(file) != FILE_TYPE_DISK) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "path is not a regular file");
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file, &info)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "GetFileInformationByHandle failed");
        }
        // The object at the path itself must not be a link (or any other
        // reparse point - dedup'd and cloud placeholder files included, since
        // their real contents aren't what this handle would read).
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path is a symbolic link or other reparse point");
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "path is a directory");
        }
        // And the file's own name. Short names are refused rather than
        // accepted: they are a second, auto-generated name for the same file,
        // and a check that matches one spelling can miss the other.
        // Case-insensitive, like the file system.
        std::wstring actual = FinalPathOfHandle(file);
        if (CompareStringOrdinal(actual.c_str(), -1, expected.c_str(), -1, TRUE) != CSTR_EQUAL) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path uses an 8.3 short name");
        }

        // Who could have written what is about to be read. A wrapped DEK is
        // ciphertext, so reading it gains nothing - but *replacing* it does:
        // anyone who can write the file, or put another one in its place,
        // and can also wrap under the service's KEK could plant a DEK they
        // know, and unwrap would accept it as genuine. So the file and every
        // folder above it must be owned by SYSTEM, Administrators,
        // TrustedInstaller or this account, and grant nobody else write,
        // delete or ownership rights - nor, on the folders below the drive
        // root, the right to create entries (see kFileWriteRights,
        // kFolderRights and kDriveRootRights). Checked on the open handle,
        // after the path checks above, so it's the file actually read that
        // is judged. (The OS refusing the open itself is reported as
        // HKDFGUARD_ERR_FILE_ACCESS_DENIED, above.) Who counts as trusted depends on the security model - see
        // TrustedPrincipals; developer mode is announced in the event log.
        TrustedPrincipals trusted;
        if (trusted.model() == SecurityModel::Developer) {
            LogDeveloperModeKeyFile();
        }
        CheckHandleSecurity(file, kFileWriteRights, trusted, "the file");
        CheckFolderChain(chain, trusted);

        // Decided on the size first. A DEK-sized file is never read at all:
        // if it really is a plaintext key, it never enters this process's
        // memory. A file too short to be a payload but short enough to be a
        // DEK written as text (hex or base64) is read into a wiped buffer to
        // tell which; its bytes are never copied to the caller.
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "GetFileSizeEx failed");
        }
        if (size.QuadPart == HKDFGUARD_DEK_LEN) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_PLAINTEXT_KEY, "file is the size of a plaintext DEK");
        }
        if (size.QuadPart < static_cast<LONGLONG>(kTotalLen)) {
            if (size.QuadPart <= static_cast<LONGLONG>(kMaxPlaintextTextLen) &&
                SmallFileLooksLikePlaintextDek(file)) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_PLAINTEXT_KEY, "file holds a DEK written as hex or base64");
            }
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_TOO_SHORT, "file is shorter than a wrapped payload");
        }
        if (size.QuadPart > static_cast<LONGLONG>(kTotalLen)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_TOO_LONG, "file is longer than a wrapped payload");
        }

        // ReadFile may return fewer bytes than asked for, so loop until the
        // payload is complete or the file runs out.
        DWORD total = 0;
        while (total < kTotalLen) {
            DWORD got = 0;
            if (!ReadFile(file, out + total, static_cast<DWORD>(kTotalLen - total), &got, nullptr)) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "ReadFile failed");
            }
            if (got == 0) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_TOO_SHORT, "file ended before a full wrapped payload");
            }
            total += got;
        }
        // The size was checked above and nobody can write while this handle
        // is open, so this should always hit end of file - confirmed rather
        // than assumed, so "exactly kTotalLen bytes" is a fact about what was
        // read, not just about what GetFileSizeEx reported.
        uint8_t extra = 0;
        DWORD got_extra = 0;
        if (!ReadFile(file, &extra, 1, &got_extra, nullptr)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "ReadFile failed");
        }
        if (got_extra != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_TOO_LONG, "file is longer than a wrapped payload");
        }

        // The structural checks hkdfguard_unwrap_dek makes before it touches
        // a KEK: version, provider type, reserved bytes, KeyId. (The salt
        // has no structure - any 32 bytes are a valid salt - so there is
        // nothing more to check without the KEK.) Called directly, those
        // throw the payload codes (HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED for an
        // unknown version, HKDFGUARD_ERR_PAYLOAD_MALFORMED for everything
        // else). Here they are re-thrown as HKDFGUARD_ERR_FILE_MALFORMED:
        // what this call reports is a verdict on the *file* - it is the
        // right size but doesn't hold a valid wrapped key - the same code
        // other platforms' builds of this ABI report for a malformed key
        // file, unknown version included.
        try {
            ParseWrappedDek(out, static_cast<int32_t>(kTotalLen));
        } catch (const HkdfGuardError &e) {
            if (e.code() == HKDFGUARD_ERR_PAYLOAD_MALFORMED || e.code() == HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_MALFORMED, e.what());
            }
            throw;
        }
    }

} // namespace hkdfguard
