// Reading a wrapped-key file for hkdfguard_open_file (see hkdfguard.h for the
// contract). Its own file, rather than part of hkdfguard.cpp, so the test
// executable can compile and call ReadWrappedKeyFile directly - with the
// test-only seams (e.g. ecdh_hkdf.h's SetTestEcdhProviderFault) that are
// compiled into the test's copies of these sources but never into
// HkdfGuardV1.dll - the same way kek_store.cpp is shared.
#include "key_file.h"

#include "../include/hkdfguard.h"
#include "ecdh_hkdf.h"   // ValidateEphemeralPublicKey
#include "errors.h"
#include "wire_format.h" // ParseWrappedDek, kTotalLen

#include <windows.h>
#include <cstring>
#include <string>

namespace hkdfguard {
    namespace {
        // Longest path hkdfguard_open_file reads from its `path` argument, in
        // bytes: the Win32 limit of 32,767 UTF-16 code units, each at most three
        // UTF-8 bytes. Bounds the strnlen below the same way kMaxServiceLen does
        // for a service name.
        constexpr size_t kMaxPathBytes = 32767 * 3;

        // Owns a Win32 file HANDLE. Not handle_traits.h's ScopedHandle: that
        // treats 0 as "no handle", but CreateFileW reports failure as
        // INVALID_HANDLE_VALUE.
        class ScopedFile {
        public:
            explicit ScopedFile(HANDLE h) : handle_(h) {
            }

            ~ScopedFile() {
                if (valid()) {
                    CloseHandle(handle_);
                }
            }

            ScopedFile(const ScopedFile &) = delete;

            ScopedFile &operator=(const ScopedFile &) = delete;

            bool valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }
            HANDLE get() const { return handle_; }

        private:
            HANDLE handle_;
        };

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

        // The long-name form of `path` from GetLongPathName, which walks the path
        // component by component through the directory listing - expanding any
        // 8.3 short name ("PROGRA~1") to its real name, but reporting a link by
        // its own name, never its target. Empty if any component doesn't exist.
        std::wstring TryLongPathName(const std::wstring &path) {
            DWORD needed = GetLongPathNameW(path.c_str(), nullptr, 0);
            if (needed == 0) {
                return {};
            }
            std::wstring long_form(needed, L'\0');
            DWORD written = GetLongPathNameW(path.c_str(), long_form.data(), needed);
            if (written == 0 || written >= needed) {
                return {};
            }
            long_form.resize(written);
            return long_form;
        }

        // 8.3 short names are refused outright rather than expanded. They are a
        // second, auto-generated name for the same file, and their history -
        // checks that matched one spelling but not the other, and a name that
        // isn't chosen by whoever created the file - makes them a liability for
        // a path that decides which key file a privileged process reads.
        //
        // The test is exact, not a guess from "~" characters: a path is refused
        // only if the file system itself expands one of its components to a
        // different name, so a genuine long name such as "report~1.key" is
        // fine. Case differences don't count; the file system ignores case.
        // If the file doesn't exist, its folder is checked instead, so
        // "C:\PROGRA~1\missing.key" is refused too rather than reported as
        // merely not found.
        void RejectShortNames(const std::wstring &full) {
            std::wstring checked = full;
            std::wstring long_form = TryLongPathName(checked);
            if (long_form.empty()) {
                size_t sep = full.find_last_of(L'\\');
                if (sep == std::wstring::npos || sep < 3) {
                    return; // nothing above a drive root to check
                }
                checked = full.substr(0, sep);
                long_form = TryLongPathName(checked);
                if (long_form.empty()) {
                    return; // the folder doesn't exist either: CreateFileW reports it
                }
            }
            if (CompareStringOrdinal(
                    StripExtendedPrefix(long_form).c_str(), -1, StripExtendedPrefix(checked).c_str(), -1, TRUE) !=
                CSTR_EQUAL) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path uses an 8.3 short name");
            }
        }

        // The fully-qualified path the caller actually spelled - relative paths
        // resolved against the current directory - with no link followed and
        // nothing expanded (8.3 short names are refused, see RejectShortNames).
        // This is what the opened handle's own path is compared against in
        // ReadWrappedKeyFile: any difference means the open went somewhere other
        // than where the caller pointed.
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

        // Only "<letter>:\..." on a local drive is allowed, decided before
        // anything is opened. Refused: UNC paths (\\server\share, \\?\UNC\...),
        // the device namespace (\\.\pipe\..., \\.\PhysicalDrive0, and DOS device
        // names such as NUL or CON, which GetFullPathName turns into \\.\NUL),
        // and mapped network drives. Opening a path on a server would make this
        // process connect and authenticate to that server - a credential leak if
        // the path is attacker-influenced - before any later check could refuse
        // the result.
        void RequireLocalDrivePath(const std::wstring &full) {
            const bool drive_path =
                    full.size() >= 3 &&
                    ((full[0] >= L'A' && full[0] <= L'Z') || (full[0] >= L'a' && full[0] <= L'z')) &&
                    full[1] == L':' && full[2] == L'\\';
            if (!drive_path) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path is not a local drive path");
            }
            if (GetDriveTypeW(full.substr(0, 3).c_str()) == DRIVE_REMOTE) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path is on a network drive");
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
    } // namespace

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
        // After the local-drive check: GetLongPathName reads directory
        // listings, which must never mean contacting a server.
        RejectShortNames(expected);

        // A directory can't be opened without FILE_FLAG_BACKUP_SEMANTICS, so
        // CreateFileW would report one as ERROR_ACCESS_DENIED - checked first
        // only so that case reads as "not a regular file" rather than as a
        // permissions problem. The handle checks below are what's
        // authoritative.
        DWORD attributes = GetFileAttributesW(wide_path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "path is a directory");
        }

        // FILE_SHARE_READ only: while this handle is open nobody can write
        // the file, and if a writer already has it open this fails with a
        // sharing violation instead of reading a half-written payload.
        // FILE_FLAG_OPEN_REPARSE_POINT: a symbolic link at the path opens as
        // the link itself, so the reparse check below sees it instead of
        // the open silently following it. SECURITY_IDENTIFICATION: should a
        // path ever reach a named pipe despite the checks above, its server
        // could identify this process but not impersonate it.
        ScopedFile file(CreateFileW(
            wide_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        if (!file.valid()) {
            throw HkdfGuardError(FileOpenErrorCode(GetLastError()), "CreateFileW failed");
        }

        // Only a regular on-disk file. A pipe, console or other device is
        // refused before any ReadFile, since reading one could block
        // indefinitely or return arbitrary data.
        if (GetFileType(file.get()) != FILE_TYPE_DISK) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "path is not a regular file");
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file.get(), &info)) {
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
        // And nothing above it may be one either: FILE_FLAG_OPEN_REPARSE_POINT
        // only covers the final component, so a junction or directory
        // symbolic link in a parent folder is still followed by the open.
        // The handle's canonical path reflects that; if it isn't the path
        // the caller spelled, something redirected the open. (Also catches
        // SUBST drives, whose canonical path is the directory they alias.)
        // Case-insensitive, like the file system.
        std::wstring actual = FinalPathOfHandle(file.get());
        if (CompareStringOrdinal(actual.c_str(), -1, expected.c_str(), -1, TRUE) != CSTR_EQUAL) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_UNTRUSTED, "path resolves through a link, junction or SUBST drive");
        }

        // Decided on the size alone, before reading a byte. In particular a
        // DEK-sized file is never read at all: if it really is a plaintext
        // key, it never enters this process's memory.
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file.get(), &size)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "GetFileSizeEx failed");
        }
        if (size.QuadPart == HKDFGUARD_DEK_LEN) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_PLAINTEXT_KEY, "file is the size of a plaintext DEK");
        }
        if (size.QuadPart < static_cast<LONGLONG>(kTotalLen)) {
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
            if (!ReadFile(file.get(), out + total, static_cast<DWORD>(kTotalLen - total), &got, nullptr)) {
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
        if (!ReadFile(file.get(), &extra, 1, &got_extra, nullptr)) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_IO, "ReadFile failed");
        }
        if (got_extra != 0) {
            throw HkdfGuardError(HKDFGUARD_ERR_FILE_TOO_LONG, "file is longer than a wrapped payload");
        }

        // The checks hkdfguard_unwrap_dek makes before it touches a KEK: the
        // payload's structure, then its ephemeral public key is a real P-256
        // point. Called directly, those throw the payload codes
        // (HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED for an unknown version,
        // HKDFGUARD_ERR_PAYLOAD_MALFORMED for everything else). Here they
        // are re-thrown as HKDFGUARD_ERR_FILE_MALFORMED: what this call
        // reports is a verdict on the *file* - it is the right size but
        // doesn't hold a valid wrapped key - which is also how the Linux and
        // macOS builds of this ABI report a malformed key file, unknown
        // version included. The one exception passes through untouched: the
        // point check throws HKDFGUARD_ERR_CRYPTO_ERROR if the software ECDH
        // provider it validates with can't be opened at all, which says
        // nothing about the file.
        try {
            ParsedWrappedDek parsed = ParseWrappedDek(out, static_cast<int32_t>(kTotalLen));
            ValidateEphemeralPublicKey(parsed.ephemeral_pub);
        } catch (const HkdfGuardError &e) {
            if (e.code() == HKDFGUARD_ERR_PAYLOAD_MALFORMED || e.code() == HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED) {
                throw HkdfGuardError(HKDFGUARD_ERR_FILE_MALFORMED, e.what());
            }
            throw;
        }
    }

} // namespace hkdfguard
