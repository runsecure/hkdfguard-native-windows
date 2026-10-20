#pragma once

// Opening a local file without ever following a link to get there.
//
// CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT stops only at the *last*
// component of a path: a junction or directory symbolic link in any folder
// above it is still followed. Checking the opened handle's real path
// afterwards catches that, but too late. A directory symbolic link can point
// at \\server\share (Windows follows local-to-remote links by default), so
// the open itself would already have made this process connect and
// authenticate to that server - handing it an NTLM challenge-response it
// could relay - before any check refused the result.
//
// So the path is walked instead: the drive root is opened, then each folder,
// one component at a time, *relative to the handle of the folder above it*
// (NtCreateFile with a RootDirectory), each with FILE_OPEN_REPARSE_POINT so
// a reparse point is opened as itself and refused before anything goes
// through it. No path is ever resolved by name past the drive root, and
// nothing is ever opened on another machine.
//
// Shared by HkdfGuard.dll (hkdfguard_open_file, key_file.cpp) and
// hkdfguard.exe (--dek-file and the wrapped-key output path). Header-only and
// exception-free, so the CLI can use it without linking anything from src/
// and each caller turns a failure into its own error type.

#include <windows.h>
#include <winternl.h> // NtCreateFile, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, RtlNtStatusToDosError

#include <string>
#include <utility>
#include <vector>

#if defined(_MSC_VER)
#pragma comment(lib, "ntdll.lib")
#endif

// NtCreateFile's dispositions and options. winternl.h defines most of them;
// defined here only where a given SDK doesn't.
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_CREATE
#define FILE_CREATE 0x00000002
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif
#ifndef FILE_SEQUENTIAL_ONLY
#define FILE_SEQUENTIAL_ONLY 0x00000004
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000
#endif

namespace hkdfguard_nofollow {

    // Owns a file HANDLE (CloseHandle). Movable, so a chain of them can live
    // in a vector.
    class Handle {
    public:
        Handle() = default;
        explicit Handle(HANDLE h) : handle_(h) {
        }
        ~Handle() { reset(); }
        Handle(const Handle &) = delete;
        Handle &operator=(const Handle &) = delete;
        Handle(Handle &&other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {
        }
        Handle &operator=(Handle &&other) noexcept {
            if (this != &other) {
                reset();
                handle_ = std::exchange(other.handle_, nullptr);
            }
            return *this;
        }

        void reset() {
            if (valid()) {
                CloseHandle(handle_);
            }
            handle_ = nullptr;
        }
        bool valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
        HANDLE get() const { return handle_; }

    private:
        HANDLE handle_ = nullptr;
    };

    enum class Failure {
        None,
        NotLocalDrive, // not "<letter>:\...", or the drive is a network, SUBST or device drive
        InvalidPath,   // an empty component, or one naming an alternate data stream
        ReparsePoint,  // a folder in the path is a symbolic link, junction or other reparse point
        NotADirectory, // a component above the last one is a file
        OpenFailed,    // a folder could not be opened; see win32
    };

    struct Error {
        Failure failure = Failure::None;
        DWORD win32 = 0;  // for OpenFailed: why
        std::wstring at;  // the path up to and including the component that failed
    };

    // Whether a drive letter's object-manager target (QueryDosDeviceW) is a
    // local volume device: exactly "\Device\<name>", nothing after it, and
    // not a network or redirector device. Case-insensitive, as the object
    // manager is. A SUBST drive's target is a path ("\??\C:\folder",
    // "\??\UNC\server\share"); a mapped drive's, or one redefined with a raw
    // target, is a device *with* a path ("\Device\Mup\server\share",
    // "\Device\LanmanRedirector\;Z:...\server\share"). Both are refused by
    // the "nothing after it" rule; the name list catches a bare redirector.
    inline bool IsLocalVolumeDeviceTarget(const std::wstring &device) {
        static const wchar_t kPrefix[] = L"\\Device\\";
        const size_t prefix_len = ARRAYSIZE(kPrefix) - 1;
        if (device.size() <= prefix_len ||
            CompareStringOrdinal(device.c_str(), static_cast<int>(prefix_len), kPrefix, static_cast<int>(prefix_len),
                                 TRUE) != CSTR_EQUAL) {
            return false;
        }
        const std::wstring name = device.substr(prefix_len);
        if (name.find(L'\\') != std::wstring::npos || name.find(L'/') != std::wstring::npos) {
            return false;
        }
        std::wstring upper = name;
        CharUpperBuffW(upper.data(), static_cast<DWORD>(upper.size()));
        for (const wchar_t *network : {L"MUP", L"REDIRECTOR", L"RDPDR", L"WEBDAV", L"NAMEDPIPE", L"MAILSLOT", L"NFS"}) {
            if (upper.find(network) != std::wstring::npos) {
                return false;
            }
        }
        return true;
    }

    // Whether `full` - a fully-qualified path, as GetFullPathNameW returns it -
    // is on a local drive, decided without touching the file system: the
    // drive letter must name a local volume device. Refuses UNC and device
    // paths, mapped network drives, and SUBST drives (whose target is another
    // path, possibly a share - opening their root would already reach it).
    // The drive letter's target is read first (QueryDosDeviceW reads an
    // object-manager link and opens nothing); only for a local volume is
    // GetDriveTypeW asked as well. OpenFolderChain checks this again before
    // every walk, so a drive letter redefined after an earlier check is
    // still caught before its root is opened.
    inline bool IsLocalDrivePath(const std::wstring &full) {
        const bool drive_path =
                full.size() >= 3 &&
                ((full[0] >= L'A' && full[0] <= L'Z') || (full[0] >= L'a' && full[0] <= L'z')) &&
                full[1] == L':' && full[2] == L'\\';
        if (!drive_path) {
            return false;
        }
        wchar_t target[1024] = {};
        if (QueryDosDeviceW(full.substr(0, 2).c_str(), target, ARRAYSIZE(target)) == 0) {
            return false;
        }
        if (!IsLocalVolumeDeviceTarget(target)) {
            return false;
        }
        const UINT type = GetDriveTypeW(full.substr(0, 3).c_str());
        return type != DRIVE_REMOTE && type != DRIVE_NO_ROOT_DIR && type != DRIVE_UNKNOWN;
    }

    // Opens or creates `name` - a single path component, never containing a
    // separator - relative to the folder open as `parent` (or, with a null
    // `parent`, the absolute NT path `name`). FILE_OPEN_REPARSE_POINT is
    // always added, so a reparse point at `name` is opened as itself, not
    // followed. `sd` is the new file's security descriptor for FILE_CREATE.
    // SYNCHRONIZE and FILE_READ_ATTRIBUTES are always added, as CreateFileW
    // adds them - without the latter, a write- or delete-only handle could
    // not even be checked (GetFileInformationByHandle,
    // GetFinalPathNameByHandle) before it is used.
    // On failure returns false with `win32` set (RtlNtStatusToDosError).
    inline bool OpenRelative(
        HANDLE parent, const std::wstring &name, ACCESS_MASK access, ULONG share, ULONG disposition, ULONG options,
        PSECURITY_DESCRIPTOR sd, Handle &out, DWORD &win32) {
        if (name.empty() || name.size() * sizeof(wchar_t) > 0xFFFE) {
            win32 = ERROR_INVALID_NAME;
            return false;
        }
        UNICODE_STRING object_name;
        object_name.Buffer = const_cast<PWSTR>(name.c_str());
        object_name.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
        object_name.MaximumLength = object_name.Length;
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(&attributes, &object_name, OBJ_CASE_INSENSITIVE, parent, sd);

        IO_STATUS_BLOCK io{};
        HANDLE h = nullptr;
        NTSTATUS status = NtCreateFile(
            &h, access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, share, disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
        if (status < 0) {
            win32 = RtlNtStatusToDosError(status);
            return false;
        }
        out = Handle(h);
        return true;
    }

    // Every folder from the drive root down to the one holding the last
    // component of a path, each opened relative to the one above it and
    // confirmed to be a real folder - not a reparse point - before the next
    // is opened through it. The handles stay open, so a caller can check
    // each folder's security on the very object it walked through, and open
    // the last component relative to parent().
    struct FolderChain {
        std::vector<Handle> handles;     // root first
        std::vector<std::wstring> paths; // "C:\", "C:\a", "C:\a\b", ... - one per handle
        std::wstring leaf;               // the last component's name

        HANDLE parent() const { return handles.back().get(); }
        const std::wstring &parentPath() const { return paths.back(); }
    };

    // Access each folder is opened with: enough to read its attributes and
    // its security descriptor, nothing that could change it. Shared with
    // everyone, so walking a folder never blocks anyone else.
    constexpr ACCESS_MASK kFolderAccess = READ_CONTROL | FILE_READ_ATTRIBUTES;
    constexpr ULONG kFolderShare = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // Walks `full` - fully qualified, already passed IsLocalDrivePath - down
    // to the folder holding its last component. Fails, without opening
    // anything past it, at the first folder that is a reparse point or not a
    // folder, or that can't be opened.
    inline bool OpenFolderChain(const std::wstring &full, FolderChain &chain, Error &error) {
        chain = FolderChain{};
        error = Error{};

        // Components after "C:\". GetFullPathNameW has already removed "."
        // and "..", so an empty component means a doubled separator.
        std::vector<std::wstring> components;
        size_t start = 3;
        while (start <= full.size()) {
            size_t sep = full.find(L'\\', start);
            if (sep == std::wstring::npos) sep = full.size();
            std::wstring component = full.substr(start, sep - start);
            if (!component.empty() || sep != full.size()) {
                components.push_back(component);
            }
            start = sep + 1;
        }
        std::wstring root = full.substr(0, 3);
        if (components.empty()) {
            error = {Failure::InvalidPath, 0, root};
            return false;
        }
        for (const std::wstring &c : components) {
            // ':' after the drive names an alternate data stream.
            if (c.empty() || c.find(L':') != std::wstring::npos) {
                error = {Failure::InvalidPath, 0, full};
                return false;
            }
        }

        // Checked again here, immediately before the root is opened by name -
        // the one name-based open in the walk - so a drive letter redefined
        // since the caller's own check can't send it to a server.
        if (!IsLocalDrivePath(full)) {
            error = {Failure::NotLocalDrive, 0, root};
            return false;
        }

        Handle root_handle;
        DWORD win32 = 0;
        if (!OpenRelative(nullptr, L"\\??\\" + root, kFolderAccess, kFolderShare, FILE_OPEN, FILE_DIRECTORY_FILE,
                          nullptr, root_handle, win32)) {
            error = {Failure::OpenFailed, win32, root};
            return false;
        }
        chain.handles.push_back(std::move(root_handle));
        chain.paths.push_back(root);

        std::wstring path = root;
        for (size_t i = 0; i + 1 < components.size(); ++i) {
            path += (i == 0 ? L"" : L"\\") + components[i];
            Handle folder;
            if (!OpenRelative(chain.parent(), components[i], kFolderAccess, kFolderShare, FILE_OPEN, 0, nullptr,
                              folder, win32)) {
                error = {Failure::OpenFailed, win32, path};
                return false;
            }
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(folder.get(), &info)) {
                error = {Failure::OpenFailed, GetLastError(), path};
                return false;
            }
            if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                error = {Failure::ReparsePoint, 0, path};
                return false;
            }
            if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                error = {Failure::NotADirectory, 0, path};
                return false;
            }
            chain.handles.push_back(std::move(folder));
            chain.paths.push_back(path);
        }
        chain.leaf = components.back();
        return true;
    }

} // namespace hkdfguard_nofollow
