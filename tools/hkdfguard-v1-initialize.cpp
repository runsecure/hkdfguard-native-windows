// CLI tool: provisions a service's machine-wide KEK, and separately wraps a
// caller-supplied Data Encryption Key (DEK) under an already-provisioned
// KEK, writing the wrapped payload to a file.
//
// Two subcommands, strictly separated:
//
//   provision --service-name|-sn <name>
//       Calls hkdfguard_create_kek, which creates the KEK if it is missing
//       or re-verifies an existing one (properties and ACL). Never wraps a
//       DEK, never touches a file.
//       This is the *only* subcommand that may create a KEK.
//
//   wrap --key-file-path|-kf <path> --service-name|-sn <name> \
//        --dek-stdin --group|-g <name> [--force|-f]
//       Calls hkdfguard_wrap_dek against the service's *existing* KEK and
//       writes the wrapped payload to <path>. Never provisions a KEK - if
//       none exists yet for this service, this fails with KEK_NOT_FOUND and
//       a hint to run "provision" first. The DEK (32 raw bytes,
//       base64-encoded) is read from stdin rather than a command-line
//       argument, specifically so it never appears in this process's argv -
//       and is therefore not visible to other processes on the same host
//       via a command-line/process listing (e.g. a WMI query) for the life
//       of this process, unlike a plain --dek=<value> argument would be.
//
// Calls into hkdfguard.dll through its stable C ABI - hkdfguard_kek_exists,
// hkdfguard_create_kek, and hkdfguard_wrap_dek - the same interface any
// other-language caller uses; this tool links only against
// include/hkdfguard.h and the hkdfguard import library, nothing from src/.
//
// The KEK's `service` identity is exactly --service-name's value, passed
// straight through to the hkdfguard_* calls as `service`, and shared
// between the two subcommands - "provision" and "wrap" for the same
// service name operate on the same KEK. The KEK itself is meant to be
// long-lived: DEKs are re-minted every release under the same service
// name, and if a genuinely new KEK is ever wanted, the service name is
// simply versioned (e.g. "myapp.v2") - there is no in-place key rotation.
// Creating a KEK (provision, the first run for a given service name) needs
// an elevated process; wrapping against an existing one (wrap) does not,
// subject to the key's ACL.
//
// The wrapped payload is written to <key-file-path> with an explicit,
// non-inherited DACL: the calling account (the process token's owner SID)
// gets read+write, --group's account gets read-only, and no one else is
// granted anything - the Windows analog of this project's macOS/Linux
// tools' POSIX 0640 (owner rw, one group r, no one else). Set atomically
// at file-creation time via CreateFileW's own security-attributes
// parameter, not applied after the fact. --group is a "wrap"-only concept:
// it governs the wrapped-key *file's* ACL, not the KEK's - which principals
// may use the KEK is a separate, machine-level registry policy
// (KeyUseGroups; see include/hkdfguard.h), not something either subcommand
// accepts on the command line.
//
// With --force against a pre-existing file, that file's old contents are
// securely overwritten in place (8 alternating all-zero/random passes,
// each flushed before the next starts) and deleted before the new file is
// created - see SecureOverwriteAndRemoveIfExists/WriteWrappedKeyFile below
// for the exact sequence and its one intentional fallback, matching this
// project's macOS implementation pass-for-pass. Only ever runs when
// --force is passed; without it, an existing file is never touched at all
// (WriteWrappedKeyFile's plain CREATE_NEW fails outright instead).
//
// The wrapped-key path must be a real file reached through real directories:
// a symbolic link, junction, or other reparse point at the path or anywhere
// above it is refused outright, never followed, both with and without
// --force. There is no legitimate reason for a secrets file to live behind a
// link, and allowing one would let whoever can plant a link in the output
// directory redirect an elevated `wrap --force` at an arbitrary file. See the
// "output path must be a real file" section below for exactly how that is
// enforced on open handles rather than on re-queried paths.

#include "hkdfguard.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring> // _stricmp
#include <exception>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
    constexpr wchar_t kProgramName[] = L"hkdfguard-v1-initialize";
    // Narrow-string twin of kProgramName, for use in narrow (std::string)
    // error/hint text - everything in this tool that isn't a PrintUsage-style
    // fwprintf is narrow, matching the non-UNICODE Win32 API variants and
    // std::string this tool uses throughout.
    constexpr char kProgramNameNarrow[] = "hkdfguard-v1-initialize";
    constexpr size_t kDekLen = 32;
    // Generous starting capacity for the wrapped payload - retried once at the
    // library-reported size on HKDFGUARD_ERR_BUFFER_TOO_SMALL, so this only
    // needs to be a reasonable common case, not an absolute upper bound.
    // Matches the macOS/Linux tools' own initial-capacity constant.
    constexpr int32_t kInitialWrappedCapacity = 512;
    // Number of secure-overwrite passes SecureOverwriteAndRemoveIfExists below
    // performs on a pre-existing file before deleting it, alternating an
    // all-zero pass and a random-bytes pass, four times each.
    constexpr size_t kSecureOverwritePassCount = 8;

    // This tool's own operational-error type - deliberately not reusing the
    // DLL's internal HkdfGuardError (src/errors.h), since this tool depends
    // only on the public C ABI (include/hkdfguard.h) and the import library,
    // nothing from src/. Carries a narrow std::string message, matching the
    // narrow (non-UNICODE) Win32 API variants and std::string arguments this
    // tool uses throughout - so every fprintf of it must use %s, never %ls.
    struct CliError {
        std::string message;

        explicit CliError(std::string m) : message(std::move(m)) {
        }
    };

    // Renders a Win32 error code (as returned by GetLastError(), or an NTSTATUS
    // cast to DWORD for a BCrypt failure) as a human-readable string, the
    // standard documented FormatMessageW idiom.
    std::string FormatWin32Error(DWORD code) {
        LPSTR buf = nullptr;

        DWORD len = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPSTR>(&buf),
            0,
            nullptr);

        std::string result =
                (len > 0 && buf != nullptr)
                    ? std::string(buf, len)
                    : "(unknown error)";

        if (buf != nullptr) {
            LocalFree(buf);
        }

        while (!result.empty() &&
               (result.back() == '\r' ||
                result.back() == '\n')) {
            result.pop_back();
        }

        return result;
    }

    // Minimal RAII wrapper for a Win32 file HANDLE - this tool's own local
    // copy of the same idea src/handle_traits.h uses for NCrypt/BCrypt handles
    // elsewhere in this project, kept local since this tool intentionally
    // depends only on the public hkdfguard.h header, nothing from src/.
    class ScopedFileHandle {
    public:
        explicit ScopedFileHandle(HANDLE h = INVALID_HANDLE_VALUE) : handle_(h) {
        }

        ~ScopedFileHandle() { reset(); }

        ScopedFileHandle(const ScopedFileHandle &) = delete;

        ScopedFileHandle &operator=(const ScopedFileHandle &) = delete;

        void reset(HANDLE h = INVALID_HANDLE_VALUE) {
            if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
                CloseHandle(handle_);
            }
            handle_ = h;
        }

        HANDLE get() const { return handle_; }
        bool valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }

    private:
        HANDLE handle_;
    };

    // MARK: - Argument parsing

    struct ProvisionArgs {
        std::string serviceName;
    };

    struct WrapArgs {
        std::string keyFilePath;
        std::string serviceName;
        std::string groupName;
        bool force = false;
        bool dekStdin = false;
    };

    enum class ParseOutcome { Run, Help };

    void PrintUsage() {
        fwprintf(
            stderr,
            L"Usage:\n"
            L"  %ls provision --service-name|-sn <name>\n"
            L"  %ls wrap --key-file-path|-kf <path> --service-name|-sn <name> "
            L"--dek-stdin --group|-g <name> [--force|-f]\n"
            L"\n"
            L"The DEK for \"wrap\" is 32 raw bytes, base64-encoded, read from stdin.\n"
            L"Run \"%ls provision --help\" or \"%ls wrap --help\" for details.\n",
            kProgramName, kProgramName, kProgramName, kProgramName);
    }

    void PrintProvisionUsage() {
        fwprintf(
            stderr,
            L"Usage: %ls provision --service-name|-sn <name>\n"
            L"\n"
            L"Ensures the named service's machine-wide KEK exists and passes\n"
            L"verification: calls hkdfguard_create_kek, which creates the KEK if\n"
            L"missing, or re-verifies an existing KEK's properties and ACL. Never\n"
            L"wraps a DEK, never touches a file. Run it from an elevated process.\n",
            kProgramName);
    }

    void PrintWrapUsage() {
        fwprintf(
            stderr,
            L"Usage: %ls wrap --key-file-path|-kf <path> --service-name|-sn <name> "
            L"--dek-stdin --group|-g <name> [--force|-f]\n"
            L"\n"
            L"Wraps the DEK (32 raw bytes, base64-encoded, read from stdin) under\n"
            L"the named service's existing machine-wide KEK and writes the\n"
            L"wrapped payload to <path>. Never creates a KEK - run\n"
            L"\"%ls provision --service-name|-sn <name>\" first if one does not\n"
            L"yet exist for this service.\n",
            kProgramName, kProgramName);
    }

    // Throws CliError on any parse failure; returns ParseOutcome::Help if
    // --help/-h was seen (in which case `out` is left unpopulated - the caller
    // must check the return value before using `out`). Starts at argv[2] -
    // argv[1] is the subcommand name, already consumed by main() to dispatch
    // here.
    ParseOutcome ParseProvisionArgs(int argc, char *argv[], ProvisionArgs &out) {
        std::optional<std::string> serviceName;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                return ParseOutcome::Help;
            } else if (arg == "--service-name" || arg == "-sn") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--service-name must not be empty");
                }
                serviceName = value;
            } else {
                throw CliError("unrecognized argument: " + arg);
            }
        }

        if (!serviceName) throw CliError("missing required --service-name|-sn");

        out.serviceName = *serviceName;
        return ParseOutcome::Run;
    }

    // Same argv[2]-onward convention as ParseProvisionArgs above.
    ParseOutcome ParseWrapArgs(int argc, char *argv[], WrapArgs &out) {
        std::optional<std::string> keyFilePath;
        std::optional<std::string> serviceName;
        std::optional<std::string> groupName;
        bool force = false;
        bool dekStdin = false;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                return ParseOutcome::Help;
            } else if (arg == "--force" || arg == "-f") {
                force = true;
            } else if (arg == "--dek-stdin") {
                dekStdin = true;
            } else if (arg == "--key-file-path" || arg == "-kf") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--key-file-path must not be empty");
                }
                keyFilePath = value;
            } else if (arg == "--service-name" || arg == "-sn") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--service-name must not be empty");
                }
                serviceName = value;
            } else if (arg == "--group" || arg == "-g") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--group must not be empty");
                }
                groupName = value;
            } else {
                throw CliError("unrecognized argument: " + arg);
            }
        }

        if (!keyFilePath) throw CliError("missing required --key-file-path|-kf");
        if (!serviceName) throw CliError("missing required --service-name|-sn");
        if (!groupName) throw CliError("missing required --group|-g");
        if (!dekStdin) {
            throw CliError("missing required --dek-stdin (the DEK must be provided as base64 text on stdin)");
        }

        out.keyFilePath = *keyFilePath;
        out.serviceName = *serviceName;
        out.groupName = *groupName;
        out.force = force;
        out.dekStdin = dekStdin;
        return ParseOutcome::Run;
    }

    // MARK: - Base64 / stdin

    // Decodes `input` (standard base64) into raw bytes via CNG's Crypt32
    // string-conversion API - no third-party dependency needed, matching this
    // project's general preference for native platform APIs over external
    // crates/packages. CRYPT_STRING_BASE64 tolerates embedded whitespace
    // (spaces, tabs, CR, LF), so a trailing newline from how `input` was
    // produced (e.g. piped from a shell) needs no separate trimming here.
    std::vector<BYTE> Base64Decode(const std::string &input) {
        DWORD size = 0;
        if (!CryptStringToBinary(
            input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, nullptr, &size, nullptr,
            nullptr)) {
            throw CliError("DEK is not valid base64: " + FormatWin32Error(GetLastError()));
        }
        std::vector<BYTE> out(size);
        if (!CryptStringToBinary(
            input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, out.data(), &size, nullptr,
            nullptr)) {
            throw CliError("DEK is not valid base64: " + FormatWin32Error(GetLastError()));
        }
        out.resize(size);
        return out;
    }

    // Upper bound on how much stdin "wrap --dek-stdin" will accept. A 32-byte
    // DEK is 44 base64 characters; this leaves generous room for line breaks
    // and whitespace while letting the reader below use one fixed allocation.
    constexpr size_t kMaxDekStdinLen = 4096;

    // Reads all of stdin (expected to be base64 text for the DEK) into a
    // std::string. Used only by "wrap --dek-stdin", specifically so the DEK
    // never appears in this process's argv - see this file's header comment.
    //
    // Everything this function touches holds DEK text, so it is written to
    // leave no unwiped copy behind:
    //   - `result` reserves its full capacity up front and input beyond
    //     kMaxDekStdinLen is refused, so the string never reallocates - a
    //     reallocation would free the old buffer with DEK text still in it,
    //     out of reach of the caller's later SecureZeroMemory.
    //   - The stack read buffer `buf` is wiped on every exit path,
    //     including the throws, by `bufGuard`.
    //   - On any failure `result` is wiped before it is discarded.
    // On success the caller owns `result` (moved out, not copied) and wipes
    // it - see RunWrap.
    std::string ReadDekBase64FromStdin() {
        std::string result;
        result.reserve(kMaxDekStdinLen);

        char buf[512];
        struct BufGuard {
            char *p;
            size_t n;
            ~BufGuard() { SecureZeroMemory(p, n); }
        } bufGuard{buf, sizeof(buf)};

        auto failWiped = [&result](const std::string &message) -> CliError {
            SecureZeroMemory(result.data(), result.size());
            result.clear();
            return CliError(message);
        };

        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
            if (result.size() + n > kMaxDekStdinLen) {
                throw failWiped(
                    "stdin for --dek-stdin is larger than " + std::to_string(kMaxDekStdinLen) +
                    " bytes; expected a base64-encoded 32-byte DEK");
            }
            result.append(buf, n);
        }
        if (ferror(stdin)) {
            throw failWiped("failed to read DEK from stdin");
        }
        if (result.empty()) {
            throw failWiped("no data read from stdin for --dek-stdin");
        }
        return result;
    }

    // MARK: - Wrap / provision

    std::string DescribeStatus(int32_t code) {
        switch (code) {
            case HKDFGUARD_OK: return "success";
            case HKDFGUARD_ERR_INVALID_ARG: return "invalid argument (bad service name or DEK length)";
            case HKDFGUARD_ERR_BUFFER_TOO_SMALL: return "output buffer too small";
            case HKDFGUARD_ERR_PROVIDER: return "KEK provider/key open or create failed";
            case HKDFGUARD_ERR_CRYPTO: return "a cryptographic operation failed";
            case HKDFGUARD_ERR_AUTH_FAILED: return "AES-GCM authentication failed";
            case HKDFGUARD_ERR_MALFORMED: return "wrapped payload is not valid";
            case HKDFGUARD_ERR_INTERNAL: return "an internal error occurred in hkdfguard.dll";
            case HKDFGUARD_ERR_SERVICE_NAME_INVALID: return "service name is malformed (ASCII letters, digits and '.' only, 1-128 bytes)";
            case HKDFGUARD_ERR_INVALID_POLICY: return "invalid key storage policy";
            case HKDFGUARD_ERR_GROUP_INVALID: return "a KeyUseGroups policy entry is unresolvable, not a group, over-broad, or not host-local";
            case HKDFGUARD_ERR_KEK_MISMATCH: return "wrapped payload was not produced under this service's current KEK";
            case HKDFGUARD_ERR_KEK_NOT_FOUND: return "no KEK is provisioned for this service";
            case HKDFGUARD_ERR_ACCESS_DENIED: return "this KEK exists, but this account is not authorized to use it";
            case HKDFGUARD_ERR_KEK_ACL_INVALID: return "a KEK already exists under this service name, but its ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal - it was left untouched; investigate it, or provision under a new (versioned) service name";
            default: return "unknown status code " + std::to_string(code);
        }
    }

    // Calls hkdfguard_wrap_dek, retrying once at the library-reported required
    // size if the initial buffer was too small - same pattern as the
    // macOS/Linux tools' own wrap helper. Never provisions a KEK - a missing
    // KEK surfaces as HKDFGUARD_ERR_KEK_NOT_FOUND, with a hint pointing at
    // this tool's "provision" subcommand.
    std::vector<uint8_t> WrapDek(const std::string &service, const std::vector<BYTE> &dek) {
        std::vector<uint8_t> wrapped(static_cast<size_t>(kInitialWrappedCapacity));
        int32_t wrappedLen = static_cast<int32_t>(wrapped.size());

        int32_t rc = hkdfguard_wrap_dek(
            service.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrappedLen);

        if (rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
            // wrappedLen now holds the size the library actually needs; retry once at that size.
            wrapped.assign(static_cast<size_t>(wrappedLen), 0);
            rc = hkdfguard_wrap_dek(
                service.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrappedLen);
        }

        if (rc != HKDFGUARD_OK) {
            std::string message = "hkdfguard_wrap_dek failed: " + DescribeStatus(rc);
            if (rc == HKDFGUARD_ERR_KEK_NOT_FOUND) {
                message += std::string(" (run \"") + kProgramNameNarrow +
                           " provision --service-name " + service + "\" first)";
            }
            throw CliError(message);
        }

        wrapped.resize(static_cast<size_t>(wrappedLen));
        return wrapped;
    }

    // Makes sure the service's machine-wide KEK exists and is acceptable,
    // creating it if not. This is "provision"'s entire job - hkdfguard_wrap_dek
    // never creates a KEK, so a service's first deployment must provision one
    // here before "wrap" is ever run for it. Which principals may later
    // unwrap, and whether the KEK is TPM- or software-backed, come from the
    // machine's registry policy, not from this tool - see include/hkdfguard.h.
    //
    // hkdfguard_create_kek is called unconditionally, even when the KEK
    // already exists. It is idempotent, and for an existing key it is the
    // only call that re-verifies the key's properties and its ACL (a real
    // DACL, SYSTEM and Administrators present, nothing granted to an
    // over-broad principal). Skipping it whenever hkdfguard_kek_exists said
    // "yes" would let a pre-planted or later-widened KEK pass provisioning
    // unchecked. hkdfguard_kek_exists only chooses the message printed.
    void EnsureKekProvisioned(const std::string &service) {
        int32_t exists = 0;
        int32_t rc = hkdfguard_kek_exists(service.c_str(), &exists);
        if (rc != HKDFGUARD_OK) {
            throw CliError("hkdfguard_kek_exists failed: " + DescribeStatus(rc));
        }

        rc = hkdfguard_create_kek(service.c_str());
        if (rc != HKDFGUARD_OK) {
            std::string message = "hkdfguard_create_kek failed: " + DescribeStatus(rc);
            if (rc == HKDFGUARD_ERR_ACCESS_DENIED) {
                // For a new KEK, NCryptFinalizeKey rejects a non-elevated
                // process with NTE_PERM (see kek_store.cpp's
                // ThrowForNCryptFailure). For an existing KEK, verification
                // reads its ACL, which a key-use-only account cannot do.
                // Either way, provisioning belongs in an elevated process.
                message += exists != 0
                               ? " (verifying an existing KEK's ACL requires an elevated process)"
                               : " (creating a new KEK requires an elevated process; this account may lack rights)";
            }
            throw CliError(message);
        }

        if (exists != 0) {
            fprintf(stdout, "verified existing KEK for service \"%s\"\n", service.c_str());
        } else {
            fprintf(stdout, "created KEK for service \"%s\"\n", service.c_str());
        }
    }

    // Enforces that --service-name - the exact value passed to
    // the hkdfguard_* calls as `service` - contains only ASCII alphanumeric
    // characters or '.', matching this project's macOS/Linux tools.
    void ValidateServiceCharset(const std::string &service) {
        for (wchar_t c: service) {
            bool isAsciiAlnum = (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
            if (!isAsciiAlnum && c != L'.') {
                throw CliError(
                    "combined service name \"" + service + "\" must contain only alphanumeric characters or '.'");
            }
        }
    }

    // MARK: - Security descriptor: owner read/write, one named group read-only

    // Fetches the current process token's owner SID (TokenOwner) - the SID
    // Windows itself documents as "the default owner for objects this process
    // creates" - as an owned buffer (copied out of the token info block, which
    // is about to be freed).
    std::vector<BYTE> GetProcessOwnerSid() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            throw CliError("OpenProcessToken failed: " + FormatWin32Error(GetLastError()));
        }
        DWORD size = 0;
        GetTokenInformation(hToken, TokenOwner, nullptr, 0, &size);
        if (size == 0) {
            DWORD err = GetLastError();
            CloseHandle(hToken);
            throw CliError("GetTokenInformation(TokenOwner) size query failed: " + FormatWin32Error(err));
        }
        std::vector<BYTE> buf(size);
        BOOL ok = GetTokenInformation(hToken, TokenOwner, buf.data(), size, &size);
        DWORD err = ok ? 0 : GetLastError();
        CloseHandle(hToken);
        if (!ok) {
            throw CliError("GetTokenInformation(TokenOwner) failed: " + FormatWin32Error(err));
        }

        auto *tokenOwner = reinterpret_cast<TOKEN_OWNER *>(buf.data());
        DWORD sidLen = GetLengthSid(tokenOwner->Owner);
        std::vector<BYTE> sid(sidLen);
        if (!CopySid(sidLen, sid.data(), tokenOwner->Owner)) {
            throw CliError("CopySid(owner) failed: " + FormatWin32Error(GetLastError()));
        }
        return sid;
    }

    // Resolves `groupName` (a local or domain group name, e.g. "Administrators"
    // or "MYDOMAIN\SomeGroup") to its SID, rejecting anything that isn't
    // actually a group account (a plain user name, for instance) so a typo
    // doesn't silently grant read access to the wrong kind of principal.
    std::vector<BYTE> ResolveGroupSid(const std::string &groupName) {
        DWORD sidSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE sidType;
        // First call: size query. LookupAccountNameW returns FALSE here even
        // on the expected path (buffers too small); the real signal is that
        // sidSize/domainSize come back non-zero.
        LookupAccountName(nullptr, groupName.c_str(), nullptr, &sidSize, nullptr, &domainSize, &sidType);
        if (sidSize == 0) {
            throw CliError("--group \"" + groupName + "\" could not be resolved: " + FormatWin32Error(GetLastError()));
        }
        std::vector<BYTE> sid(sidSize);
        std::string domain(domainSize, L'\0');
        if (!LookupAccountName(
            nullptr, groupName.c_str(), sid.data(), &sidSize, domain.data(), &domainSize, &sidType)) {
            throw CliError("--group \"" + groupName + "\" could not be resolved: " + FormatWin32Error(GetLastError()));
        }
        if (sidType != SidTypeGroup && sidType != SidTypeAlias && sidType != SidTypeWellKnownGroup) {
            throw CliError("--group \"" + groupName + "\" does not name a group account");
        }
        return sid;
    }

    // Owns every buffer a security descriptor granting "owner read/write, one
    // group read-only, no one else, no inherited ACEs" needs to stay alive for
    // as long as it's in use - a self-contained bundle rather than several
    // out-parameters the caller would otherwise have to keep in sync by hand.
    // The Windows analog of this project's macOS/Linux tools' POSIX 0640
    // (owner rw, one group r, no one else).
    class OwnerReadWriteGroupReadSecurity {
    public:
        OwnerReadWriteGroupReadSecurity(std::vector<BYTE> ownerSid, std::vector<BYTE> groupSid)
            : ownerSid_(std::move(ownerSid)), groupSid_(std::move(groupSid)) {
            PSID owner = SidPtr(ownerSid_);
            PSID group = SidPtr(groupSid_);

            DWORD aclSize = static_cast<DWORD>(
                sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(owner) +
                GetLengthSid(group));
            // ACL buffers must be DWORD-aligned, per Windows' own documented
            // requirement; round up rather than trust the sum above to already
            // land on a boundary.
            aclSize = (aclSize + 7) & ~static_cast<DWORD>(7);

            aclBuf_.resize(aclSize);
            PACL acl = reinterpret_cast<PACL>(aclBuf_.data());
            if (!InitializeAcl(acl, aclSize, ACL_REVISION)) {
                throw CliError("InitializeAcl failed: " + FormatWin32Error(GetLastError()));
            }
            if (!AddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ | FILE_GENERIC_WRITE, owner)) {
                throw CliError("AddAccessAllowedAce(owner) failed: " + FormatWin32Error(GetLastError()));
            }
            if (!AddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ, group)) {
                throw CliError("AddAccessAllowedAce(group) failed: " + FormatWin32Error(GetLastError()));
            }

            if (!InitializeSecurityDescriptor(&sd_, SECURITY_DESCRIPTOR_REVISION)) {
                throw CliError("InitializeSecurityDescriptor failed: " + FormatWin32Error(GetLastError()));
            }
            if (!SetSecurityDescriptorOwner(&sd_, owner, FALSE)) {
                throw CliError("SetSecurityDescriptorOwner failed: " + FormatWin32Error(GetLastError()));
            }
            if (!SetSecurityDescriptorDacl(&sd_, TRUE, acl, FALSE)) {
                throw CliError("SetSecurityDescriptorDacl failed: " + FormatWin32Error(GetLastError()));
            }
            // Blocks this DACL from being merged with any inherited ACEs from
            // the parent directory - without this, a permissive parent-folder
            // ACL could silently widen access beyond the two ACEs just set.
            if (!SetSecurityDescriptorControl(&sd_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
                throw CliError("SetSecurityDescriptorControl failed: " + FormatWin32Error(GetLastError()));
            }
        }

        // Valid only for as long as this object is alive - the returned
        // SECURITY_ATTRIBUTES' lpSecurityDescriptor points at this object's own
        // sd_ member, which in turn points into ownerSid_/groupSid_/aclBuf_,
        // all owned together right here.
        SECURITY_ATTRIBUTES attributes() const {
            SECURITY_ATTRIBUTES sa{};
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = const_cast<SECURITY_DESCRIPTOR *>(&sd_);
            sa.bInheritHandle = FALSE;
            return sa;
        }

    private:
        static PSID SidPtr(std::vector<BYTE> &sid) { return static_cast<PSID>(static_cast<void *>(sid.data())); }

        std::vector<BYTE> ownerSid_;
        std::vector<BYTE> groupSid_;
        std::vector<BYTE> aclBuf_;
        SECURITY_DESCRIPTOR sd_{};
    };

    // MARK: - Writing the wrapped key file

    // Fills `buffer` with cryptographically random bytes via CNG's system RNG
    // - the same BCryptGenRandom call this project's own AES-GCM code
    // (src/aes_gcm.cpp) uses for nonces, not a plain PRNG.
    void FillRandom(std::vector<BYTE> &buffer) {
        NTSTATUS status =
                BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            throw CliError(
                "BCryptGenRandom failed (status 0x" + std::to_string(static_cast<unsigned long>(status)) + ")");
        }
    }

    // MARK: - The output path must be a real file, exactly where it was spelled

    // The wrapped-key path is the one thing on this tool's command line that
    // names a location the tool will *write to and, with --force, destroy*.
    // Nothing legitimate ever needs that location to be a symbolic link,
    // junction, or any other reparse point, or to be reached through one -
    // but an attacker who can create one in a directory the operator writes
    // to could redirect an (often elevated) `wrap --force` into overwriting
    // and deleting an arbitrary file, or a plain `wrap` into creating one
    // somewhere it never meant to (CREATE_NEW happily follows a *dangling*
    // symlink and creates its target). So: refuse, don't tolerate. The
    // helpers below enforce that three ways, all on handles already open
    // (never by re-querying a path that could be swapped underneath):
    //
    //   1. The object itself must not carry FILE_ATTRIBUTE_REPARSE_POINT -
    //      every CreateFile in this section passes
    //      FILE_FLAG_OPEN_REPARSE_POINT precisely so a symlink at the path
    //      opens *as the link* and gets caught here, rather than being
    //      silently followed.
    //   2. It must be a file, not a directory.
    //   3. The kernel's own resolved path for the handle
    //      (GetFinalPathNameByHandle) must equal the fully-qualified,
    //      long-name form of what the caller typed - which is what catches a
    //      junction or symlink in a *parent* component, where flag (1) on the
    //      leaf can't see it.
    //
    // A consequence of (3) worth knowing: a path through a SUBST drive or a
    // mapped network drive resolves to a different canonical form and is
    // refused too. A secrets file belongs on a real local path anyway.

    // GetLongPathName for a path that must exist; empty on failure, with
    // GetLastError() left set for the caller.
    std::string TryLongPathName(const std::string &path) {
        DWORD needed = GetLongPathNameA(path.c_str(), nullptr, 0);
        if (needed == 0) {
            return {};
        }
        std::string longForm(needed, '\0');
        DWORD written = GetLongPathNameA(path.c_str(), longForm.data(), needed);
        if (written == 0 || written >= needed) {
            return {};
        }
        longForm.resize(written);
        return longForm;
    }

    // Fully-qualified, long-name (no 8.3 short names) form of `path`, as the
    // caller spelled it - *not* resolved through any reparse point. This is
    // the "expected" side of check (3) above.
    //
    // GetLongPathName only works on paths that exist, and the wrapped-key
    // file usually doesn't yet. So if the full path doesn't resolve, the
    // parent directory (which must exist) is long-named instead and the leaf
    // name is appended as typed.
    std::string FullLongPath(const std::string &path) {
        DWORD needed = GetFullPathNameA(path.c_str(), 0, nullptr, nullptr);
        if (needed == 0) {
            throw CliError("GetFullPathName failed for " + path + ": " + FormatWin32Error(GetLastError()));
        }
        std::string full(needed, '\0');
        DWORD written = GetFullPathNameA(path.c_str(), needed, full.data(), nullptr);
        if (written == 0 || written >= needed) {
            throw CliError("GetFullPathName failed for " + path + ": " + FormatWin32Error(GetLastError()));
        }
        full.resize(written);

        std::string longForm = TryLongPathName(full);
        if (!longForm.empty()) {
            return longForm;
        }
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            throw CliError("GetLongPathName failed for " + full + ": " + FormatWin32Error(err));
        }

        size_t sep = full.find_last_of("\\/");
        if (sep == std::string::npos || sep + 1 >= full.size()) {
            throw CliError("cannot determine the file name in " + path);
        }
        std::string parent = (sep <= 2) ? full.substr(0, sep + 1) : full.substr(0, sep);
        std::string parentLong = TryLongPathName(parent);
        if (parentLong.empty()) {
            throw CliError(
                "the directory for " + path + " (" + parent + ") does not exist or cannot be resolved: " +
                FormatWin32Error(GetLastError()));
        }
        if (parentLong.back() != '\\') {
            parentLong.push_back('\\');
        }
        return parentLong + full.substr(sep + 1);
    }

    // The kernel's canonical DOS path for an open handle, with the "\\?\"
    // (or "\\?\UNC\") prefix GetFinalPathNameByHandle always adds stripped
    // back off so it compares directly against FullLongPath's output. This is
    // the "actual" side of check (3) above - it reflects every reparse point
    // that was traversed to reach the object, which is the whole point.
    std::string FinalPathOfHandle(HANDLE file, const std::string &path) {
        // Sized by retrying rather than by trusting the size query: the ANSI
        // variant's "buffer too small" return has been observed to *exclude*
        // the terminator (the documented contract says include), so a buffer
        // of exactly that size is always one short. Growing to whatever the
        // call last reported, plus one, and retrying converges either way.
        const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
        std::string final(MAX_PATH, '\0');
        DWORD written = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            written = GetFinalPathNameByHandleA(file, final.data(), static_cast<DWORD>(final.size()), flags);
            if (written == 0) {
                throw CliError(
                    "GetFinalPathNameByHandle failed for " + path + ": " + FormatWin32Error(GetLastError()));
            }
            if (written < final.size()) {
                break;
            }
            final.assign(static_cast<size_t>(written) + 1, '\0');
        }
        if (written >= final.size()) {
            throw CliError("GetFinalPathNameByHandle could not size its result for " + path);
        }
        final.resize(written);

        if (final.rfind("\\\\?\\UNC\\", 0) == 0) {
            final = "\\\\" + final.substr(8);
        } else if (final.rfind("\\\\?\\", 0) == 0) {
            final = final.substr(4);
        }
        return final;
    }

    // Removes trailing path separators, except on a bare drive root ("C:\"),
    // so a directory path compares equal whether or not it was spelled with
    // one.
    std::string TrimTrailingSeparators(std::string p) {
        while (p.size() > 3 && (p.back() == '\\' || p.back() == '/')) {
            p.pop_back();
        }
        return p;
    }

    // Checks (1)-(3) above against an already-open handle. `expected` is the
    // FullLongPath form the handle is supposed to be sitting at;
    // `allowDirectory` is set only for the parent-directory pre-check in
    // ValidateOutputPathIsReal, never for the wrapped-key file itself.
    void RequireRealObjectAtExpectedPath(
        HANDLE file, const std::string &expected, const std::string &path, bool allowDirectory) {
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file, &info)) {
            throw CliError("GetFileInformationByHandle failed for " + path + ": " + FormatWin32Error(GetLastError()));
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            throw CliError(
                path + " is a symbolic link, junction, or other reparse point; the wrapped-key path must be a "
                "real file (and a real directory above it), not a link");
        }
        if (!allowDirectory && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            throw CliError(path + " is a directory, not a file");
        }

        std::string actual = TrimTrailingSeparators(FinalPathOfHandle(file, path));
        std::string want = TrimTrailingSeparators(expected);
        if (_stricmp(actual.c_str(), want.c_str()) != 0) {
            throw CliError(
                path + " resolves through a symbolic link, junction, SUBST or mapped drive to \"" + actual +
                "\"; the wrapped-key path must be a real local path with no links in it");
        }
    }

    // Fail-fast version of the checks above, run before any KEK or DEK work
    // so a bad output path is rejected without touching the key store or
    // reading the DEK at all: the parent directory must be a real directory
    // at its spelled location, and if something already exists at the leaf
    // it must not be a reparse point. The authoritative checks are still the
    // ones made on the actual write/overwrite handles later
    // (SecureOverwriteAndRemoveIfExists / WriteWrappedKeyFile) - this is the
    // friendly early exit, not the security boundary, since a path can
    // always change between a pre-check and a later open.
    void ValidateOutputPathIsReal(const std::string &path) {
        std::string full = FullLongPath(path);

        size_t sep = full.find_last_of("\\/");
        if (sep == std::string::npos) {
            throw CliError("cannot determine the parent directory of " + path);
        }
        // Keep the separator for a drive root ("C:\"), drop it otherwise.
        std::string parent = (sep <= 2) ? full.substr(0, sep + 1) : full.substr(0, sep);

        {
            // FILE_FLAG_BACKUP_SEMANTICS is what CreateFile requires to open a
            // *directory* handle at all; FILE_FLAG_OPEN_REPARSE_POINT so a
            // junction opens as itself (see the section comment above).
            ScopedFileHandle dir(CreateFile(
                parent.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (!dir.valid()) {
                throw CliError(
                    "cannot open the directory for " + path + " (" + parent + "): " +
                    FormatWin32Error(GetLastError()));
            }
            RequireRealObjectAtExpectedPath(dir.get(), parent, parent, /*allowDirectory=*/true);
        }

        {
            // FILE_FLAG_BACKUP_SEMANTICS here too, so that if the leaf turns
            // out to be a directory or junction it still opens and is caught
            // by the checks, rather than failing to open and being deferred.
            ScopedFileHandle leaf(CreateFile(
                path.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (leaf.valid()) {
                RequireRealObjectAtExpectedPath(leaf.get(), full, path, /*allowDirectory=*/false);
            }
            // Not existing yet is fine (that's the normal first-run case);
            // any other open failure is left for the real write to report.
        }
    }

    // Marks the file behind an open handle for deletion when its last handle
    // closes. Deleting through the handle that was just inspected - rather
    // than by path via DeleteFile - means nothing can be swapped in at that
    // path between the inspection and the delete. The handle must have been
    // opened with DELETE access.
    void DeleteViaHandle(HANDLE file, const std::string &path) {
        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition))) {
            throw CliError("failed to remove " + path + ": " + FormatWin32Error(GetLastError()));
        }
    }

    // Before a --force overwrite is allowed to destroy an existing wrapped-key
    // file, this overwrites its *current* contents in place -
    // kSecureOverwritePassCount (8) alternating all-zero/random passes, each
    // flushed to the storage medium before the next pass starts so they're
    // genuinely sequential rather than coalesced by the page cache - and only
    // then deletes it. Only ever called when --force was passed; without
    // --force, an existing file is never touched at all
    // (WriteWrappedKeyFile's CREATE_NEW fails outright instead).
    //
    // The file is opened with FILE_FLAG_OPEN_REPARSE_POINT and vetted by
    // RequireRealObjectAtExpectedPath before a single byte is written, and is
    // deleted through that same handle (DeleteViaHandle) rather than by
    // path - see the section comment above for why. A symlink or junction
    // at or above the path is refused, never followed.
    //
    // If the file doesn't exist, this is a no-op. If it exists but can't be
    // opened for writing (ERROR_ACCESS_DENIED, or ERROR_SHARING_VIOLATION if
    // another process has it open) the overwrite passes are skipped entirely
    // and this falls back to a delete-only open, per explicit product
    // direction: destroying the old bytes first is worth attempting, but not
    // worth failing the whole command over when this process isn't even
    // allowed to write to the file it's about to replace. That fallback is
    // vetted the same way before it deletes anything.
    //
    // Caveat this can't fully solve, worth knowing rather than assuming away:
    // on SSDs generally (wear leveling) and on any filesystem that does
    // copy-on-write or transparent compression, writing new bytes to a file's
    // logical offsets does not guarantee those bytes land on the same physical
    // storage cells the old bytes occupied - the old bytes can persist in
    // already-remapped blocks until the medium itself reclaims them. This is a
    // best-effort measure against casual recovery, not a cryptographic
    // guarantee against a determined attacker with access to the raw storage.
    void SecureOverwriteAndRemoveIfExists(const std::string &path) {
        ScopedFileHandle file(CreateFile(
            path.c_str(), GENERIC_WRITE | DELETE, 0 /* exclusive access for the duration of the passes */, nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!file.valid()) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                return; // nothing to overwrite or delete
            }
            if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
                // Can't write to it - skip the overwrite passes and go
                // straight to removing it, still through a vetted handle.
                ScopedFileHandle del(CreateFile(
                    path.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                if (!del.valid()) {
                    DWORD delErr = GetLastError();
                    if (delErr == ERROR_FILE_NOT_FOUND || delErr == ERROR_PATH_NOT_FOUND) {
                        return;
                    }
                    throw CliError("failed to remove " + path + ": " + FormatWin32Error(delErr));
                }
                RequireRealObjectAtExpectedPath(del.get(), FullLongPath(path), path, /*allowDirectory=*/false);
                DeleteViaHandle(del.get(), path);
                return;
            }
            throw CliError("failed to open " + path + " for secure overwrite: " + FormatWin32Error(err));
        }

        // Vet the handle before writing anything through it.
        RequireRealObjectAtExpectedPath(file.get(), FullLongPath(path), path, /*allowDirectory=*/false);

        LARGE_INTEGER fileSize{};
        if (!GetFileSizeEx(file.get(), &fileSize)) {
            throw CliError("failed to get size of " + path + ": " + FormatWin32Error(GetLastError()));
        }

        if (fileSize.QuadPart > 0) {
            std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart), 0);

            for (size_t pass = 0; pass < kSecureOverwritePassCount; ++pass) {
                if (pass % 2 == 0) {
                    std::fill(buffer.begin(), buffer.end(), static_cast<BYTE>(0)); // "step 1": all-zero
                } else {
                    FillRandom(buffer); // "step 2": random bits, via the OS CSPRNG
                }

                LARGE_INTEGER zero{};
                if (!SetFilePointerEx(file.get(), zero, nullptr, FILE_BEGIN)) {
                    throw CliError(
                        "failed to seek " + path + " during secure-overwrite pass " + std::to_string(pass + 1) +
                        ": " + FormatWin32Error(GetLastError()));
                }

                DWORD totalWritten = 0;
                const DWORD bufferSize = static_cast<DWORD>(buffer.size());
                while (totalWritten < bufferSize) {
                    DWORD written = 0;
                    if (!WriteFile(file.get(), buffer.data() + totalWritten, bufferSize - totalWritten, &written,
                                   nullptr)) {
                        throw CliError(
                            "failed to write secure-overwrite pass " + std::to_string(pass + 1) + " to " + path +
                            ": " + FormatWin32Error(GetLastError()));
                    }
                    totalWritten += written;
                }

                if (!FlushFileBuffers(file.get())) {
                    throw CliError(
                        "failed to flush " + path + " during secure-overwrite pass " + std::to_string(pass + 1) +
                        ": " + FormatWin32Error(GetLastError()));
                }
            }

            SecureZeroMemory(buffer.data(), buffer.size());
        }

        // Delete through the very handle that was vetted and overwritten -
        // the file disappears when ScopedFileHandle closes it on return.
        DeleteViaHandle(file.get(), path);
    }

    // Opens `path` fresh (CREATE_NEW - atomically fails if it already exists,
    // this tool's actual correctness guarantee against the exists-then-create
    // race, same role O_EXCL/O_CREAT plays in the macOS/Linux tools) and writes
    // `bytes` to it, with `security`'s ACL attached from the moment the file is
    // created - no window where it briefly exists with broader (e.g.
    // inherited-from-parent-directory) permissions before being locked down
    // after the fact.
    //
    // FILE_FLAG_OPEN_REPARSE_POINT matters even here: without it, CREATE_NEW
    // *follows* a symlink whose target doesn't exist yet and creates that
    // target - so an attacker-planted dangling link would turn "create my
    // key file here" into "create a file wherever the link points." With the
    // flag, a link at the path is seen as an existing object and CREATE_NEW
    // fails with ERROR_FILE_EXISTS instead. The resolved-path check right
    // after creation then catches a junction in a parent directory; on a
    // mismatch the just-created (still empty) file is deleted through its
    // own handle before anything is written to it.
    void WriteWrappedKeyFile(
        const std::string &path, const std::vector<uint8_t> &bytes, const OwnerReadWriteGroupReadSecurity &security) {
        SECURITY_ATTRIBUTES sa = security.attributes();
        ScopedFileHandle file(CreateFile(
            path.c_str(), GENERIC_WRITE | DELETE, 0, &sa, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!file.valid()) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_EXISTS) {
                throw CliError(path + " already exists; pass --force|-f to overwrite");
            }
            throw CliError("failed to open " + path + " for writing: " + FormatWin32Error(err));
        }

        try {
            RequireRealObjectAtExpectedPath(file.get(), FullLongPath(path), path, /*allowDirectory=*/false);
        } catch (const CliError &) {
            // Nothing has been written yet; don't leave an empty file behind
            // at wherever the path actually resolved to.
            FILE_DISPOSITION_INFO disposition{};
            disposition.DeleteFile = TRUE;
            SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition));
            throw;
        }

        DWORD totalWritten = 0;
        const DWORD bytesSize = static_cast<DWORD>(bytes.size());
        while (totalWritten < bytesSize) {
            DWORD written = 0;
            if (!WriteFile(file.get(), bytes.data() + totalWritten, bytesSize - totalWritten, &written, nullptr)) {
                throw CliError("failed to write " + path + ": " + FormatWin32Error(GetLastError()));
            }
            totalWritten += written;
        }
    }

    // MARK: - Run: provision

    void RunProvision(const ProvisionArgs &args) {
        // `service` is not secret -- it's a logical identifier, not key
        // material.
        ValidateServiceCharset(args.serviceName);
        EnsureKekProvisioned(args.serviceName);
    }

    // MARK: - Run: wrap

    void RunWrap(WrapArgs &args) {
        // Fast, friendly pre-check: fail before ever touching the TPM/Software
        // Key Storage Provider if the output path obviously already exists and
        // --force wasn't passed. WriteWrappedKeyFile's CREATE_NEW is the actual
        // correctness guarantee against the exists-then-create race; this is
        // purely a fail-fast convenience on top of it.
        if (!args.force) {
            DWORD attrs = GetFileAttributes(args.keyFilePath.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                throw CliError(args.keyFilePath + " already exists; pass --force|-f to overwrite");
            }
        }

        // The output path must be a real file at a real location - no
        // symlink, junction, or other reparse point at or above it. Checked
        // here, before any KEK or DEK work, so a bad path is rejected cheaply;
        // the write/overwrite code re-checks on its own handles regardless.
        ValidateOutputPathIsReal(args.keyFilePath);

        // Resolved before any TPM/Software Key Storage Provider work, so a bad
        // --group name fails fast rather than after an expensive (and, with
        // --force, destructive) operation has already run. Doesn't touch any
        // secret material either way.
        OwnerReadWriteGroupReadSecurity security(GetProcessOwnerSid(), ResolveGroupSid(args.groupName));

        // `service` (and its UTF-8 form) is not secret -- it's a logical
        // identifier, not key material -- so both live for the rest of this
        // function's scope, including the final status message below.
        ValidateServiceCharset(args.serviceName);
        const std::string &service = args.serviceName;

        std::vector<uint8_t> wrapped;
        {
            // Both the base64 *text* read from stdin and the decoded
            // plaintext DEK *bytes* (`dek`) are secret, and both are scoped as
            // tightly as possible around exactly the statements that need
            // them: read+decode, wipe the text immediately (it has now served
            // its one purpose), validate the byte length, wrap, then `dek` is
            // wiped by `dekGuard` the instant this block ends -- immediately
            // after WrapDek is done with it, not at the end of RunWrap()
            // (which would otherwise leave it sitting in memory, unused but
            // unwiped, through the potentially-slow 8-pass secure-overwrite
            // and the final file write below). Matches the "shrink the scope
            // to shrink the lifetime" technique this project's own DLL uses
            // for the exact same reason (e.g. hkdfguard.cpp's `wrapping_key`,
            // ecdh_hkdf.cpp's `prk`/`t1`) -- hkdfguard_wrap_dek itself reads
            // the plaintext DEK directly from whatever pointer it's given and
            // never copies or zeroes it internally (see aes_gcm.cpp's own
            // comment on this), so this caller-side zeroing is not optional
            // defense-in-depth -- it is the only place this ever happens at
            // all.
            std::string dekBase64 = ReadDekBase64FromStdin();
            std::vector<BYTE> dek = Base64Decode(dekBase64);

            // The base64 text has now served its only purpose: wipe this
            // process's one owned copy of it right here rather than leaving
            // it sitting around, unused but unwiped, until dekBase64's
            // destructor runs (which does not zero its buffer, it only
            // deallocates it).
            SecureZeroMemory(dekBase64.data(), dekBase64.size());
            dekBase64.clear();

            // Zeroes `dek` -- up to its *capacity*, not just its current
            // size -- the instant this block ends, on every exit path (the
            // length-validation throw immediately below, or falling off the
            // end after a successful WrapDek call). Capacity rather than size
            // because Base64Decode's std::vector<BYTE> is sized once from
            // CryptStringToBinaryW's size query and then (in the extremely
            // unlikely case the real decode reports fewer bytes than that
            // query did) shrunk with resize(), which reduces size() but is not
            // guaranteed to reduce the underlying allocation -- zeroing only
            // up to size() in that edge case would leave a few stale plaintext
            // bytes sitting in the still-allocated tail of the buffer.
            struct DekGuard {
                std::vector<BYTE> &buf;

                ~DekGuard() {
                    SecureZeroMemory(buf.data(), buf.capacity());
                }
            } dekGuard{dek};

            if (dek.size() != kDekLen) {
                throw CliError(
                    "DEK must decode to exactly " + std::to_string(kDekLen) + " bytes, got " +
                    std::to_string(dek.size()));
            }

            // No provisioning happens here - "wrap" only ever opens an
            // existing KEK. If none exists yet for this service, WrapDek's
            // HKDFGUARD_ERR_KEK_NOT_FOUND path below reports that and points
            // at "provision".
            wrapped = WrapDek(service, dek);
            // dekGuard zeroes `dek` here, as this block ends -- immediately
            // after WrapDek returns the wrapped (encrypted, no longer secret)
            // form, which is the only thing that survives past this point.
        }

        if (args.force) {
            SecureOverwriteAndRemoveIfExists(args.keyFilePath);
        }

        WriteWrappedKeyFile(args.keyFilePath, wrapped, security);

        fprintf(
            stdout, "wrapped key written to %s (%zu bytes, owner read/write + %s read-only, service \"%s\")\n",
            args.keyFilePath.c_str(), wrapped.size(), args.groupName.c_str(), service.c_str());
    }
} // namespace

int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 2;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h") {
        PrintUsage();
        return 0;
    }

    if (command == "provision") {
        ProvisionArgs args;
        try {
            if (ParseProvisionArgs(argc, argv, args) == ParseOutcome::Help) {
                PrintProvisionUsage();
                return 0;
            }
        } catch (const CliError &e) {
            fprintf(stderr, "error: %s\n", e.message.c_str());
            PrintProvisionUsage();
            return 2;
        }

        try {
            RunProvision(args);
            return 0;
        } catch (const CliError &e) {
            fprintf(stderr, "error: %s\n", e.message.c_str());
            return 1;
        } catch (const std::exception &e) {
            fprintf(stderr, "error: %hs\n", e.what());
            return 1;
        }
    }

    if (command == "wrap") {
        WrapArgs args;
        try {
            if (ParseWrapArgs(argc, argv, args) == ParseOutcome::Help) {
                PrintWrapUsage();
                return 0;
            }
        } catch (const CliError &e) {
            fprintf(stderr, "error: %s\n", e.message.c_str());
            PrintWrapUsage();
            return 2;
        }

        try {
            RunWrap(args);
            return 0;
        } catch (const CliError &e) {
            fprintf(stderr, "error: %s\n", e.message.c_str());
            return 1;
        } catch (const std::exception &e) {
            fprintf(stderr, "error: %hs\n", e.what());
            return 1;
        }
    }

    fprintf(stderr, "error: unrecognized command \"%s\"\n", command.c_str());
    PrintUsage();
    return 2;
}
