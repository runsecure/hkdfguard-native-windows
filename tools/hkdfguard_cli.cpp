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
//        (--dek-stdin | --dek-file <path>) [--group|-g <name>] [--force|-f]
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
// Calls into HkdfGuard.dll through its stable C ABI - hkdfguard_kek_exists,
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
// non-inherited DACL: the calling account (the process token's owner SID -
// Administrators when run elevated) gets read+write and no one else is
// granted anything - the Windows analog of the Linux tool's POSIX 0600.
// With --group, that group also gets read-only: the analog of the Linux
// tool's --group, mode 0640 (owner rw, one group r, no one else). Set
// atomically at file-creation time via CreateFileW's own
// security-attributes parameter, not applied after the fact. --group is a
// "wrap"-only concept:
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
#include <aclapi.h> // SetSecurityInfo - protecting the key file's DACL on its handle
#include <bcrypt.h>
#include <sddl.h> // ConvertStringSidToSidA - over-broad --group check

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring> // _stricmp
#include <exception>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
    constexpr wchar_t kProgramName[] = L"hkdfguard";
    // Narrow-string twin of kProgramName, for use in narrow (std::string)
    // error/hint text - everything in this tool that isn't a PrintUsage-style
    // fwprintf is narrow, matching the non-UNICODE Win32 API variants and
    // std::string this tool uses throughout.
    constexpr char kProgramNameNarrow[] = "hkdfguard";
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
        std::optional<std::string> groupName; // --group: who besides the owner may read the file
        bool force = false;
        bool dekStdin = false;
        std::optional<std::string> dekFile; // --dek-file: read the DEK from this file instead of stdin
    };

    enum class ParseOutcome { Run, Help };

    // The one usage text, printed for every help request and after every
    // usage error - the Linux tool's, line for line, with this platform's
    // paths and examples.
    void PrintUsage() {
        fwprintf(
            stderr,
            L"Usage:\n"
            L"  %ls provision --service-name|-sn <name>\n"
            L"  %ls wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>)\n"
            L"       [--group|-g <name>] [--force|-f]\n"
            L"\n"
            L"provision  ensures a KEK exists for the service. Run once, at deployment time, from an\n"
            L"           elevated prompt; this is the only command that makes the (deliberately slow)\n"
            L"           setup calls.\n"
            L"wrap       wraps a DEK under the service's existing KEK and writes the payload to\n"
            L"           --key-file-path, readable by its owner only, or also by --group's\n"
            L"           members (read-only). Fails if the KEK has not been provisioned.\n"
            L"\n"
            L"The DEK is base64 of exactly 32 bytes, read from stdin or a file -- never\n"
            L"from a command-line argument or an environment variable, both of which are\n"
            L"readable by other processes of the same user.\n"
            L"\n"
            L"Examples:\n"
            L"  %ls provision -sn svc\n"
            L"  $dekBase64 | %ls wrap -kf C:\\ProgramData\\app\\key.bin -sn svc --dek-stdin\n"
            L"  %ls wrap -kf C:\\ProgramData\\app\\key.bin -sn svc --dek-file C:\\ProgramData\\app\\dek.b64\n",
            kProgramName, kProgramName, kProgramName, kProgramName, kProgramName);
    }

    // Stores a flag's value, refusing a second one rather than letting the
    // last win: `-kf a.key ... -kf b.key` is ambiguous about which file the
    // operator meant, and silently picking one is how the wrong key file gets
    // written or the wrong service's KEK gets used. `flag` is the flag's long
    // name. The Linux tool's set_once.
    void SetOnce(std::optional<std::string> &slot, const char *flag, const std::string &value) {
        if (slot) {
            throw CliError(std::string("give ") + flag + " at most once");
        }
        slot = value;
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
                SetOnce(serviceName, "--service-name", value);
            } else if (arg == "--key-file-path" || arg == "-kf" || arg == "--dek-stdin" || arg == "--dek-file" ||
                       arg == "--force" || arg == "-f" || arg == "--group" || arg == "-g") {
                throw CliError(arg + " is not valid for `provision`; it belongs to `wrap`");
            } else {
                throw CliError("unrecognized argument for `provision`: " + arg);
            }
        }

        if (!serviceName) throw CliError("provision: missing required --service-name|-sn");

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
        std::optional<std::string> dekFile;
        // Rejects a second DEK source rather than letting the last one win:
        // silently ignoring one of two explicitly requested inputs is exactly
        // the kind of ambiguity that leads to wrapping the wrong key.
        auto oneSource = [&]() {
            if (dekStdin || dekFile) {
                throw CliError("give exactly one of --dek-stdin or --dek-file");
            }
        };

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                return ParseOutcome::Help;
            } else if (arg == "--force" || arg == "-f") {
                if (force) {
                    throw CliError("give --force at most once");
                }
                force = true;
            } else if (arg == "--dek-stdin") {
                oneSource();
                dekStdin = true;
            } else if (arg == "--dek-file") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--dek-file must not be empty");
                }
                oneSource();
                dekFile = value;
            } else if (arg == "--key-file-path" || arg == "-kf") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--key-file-path must not be empty");
                }
                SetOnce(keyFilePath, "--key-file-path", value);
            } else if (arg == "--service-name" || arg == "-sn") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--service-name must not be empty");
                }
                SetOnce(serviceName, "--service-name", value);
            } else if (arg == "--group" || arg == "-g") {
                if (i + 1 >= argc) {
                    throw CliError(arg + " requires a value");
                }
                std::string value = argv[++i];
                if (value.empty()) {
                    throw CliError("--group must not be empty");
                }
                SetOnce(groupName, "--group", value);
            } else {
                throw CliError("unrecognized argument for `wrap`: " + arg);
            }
        }

        if (!keyFilePath) throw CliError("wrap: missing required --key-file-path|-kf");
        if (!serviceName) throw CliError("wrap: missing required --service-name|-sn");
        if (!dekStdin && !dekFile) throw CliError("wrap: missing required --dek-stdin or --dek-file <path>");

        out.keyFilePath = *keyFilePath;
        out.serviceName = *serviceName;
        out.groupName = groupName;
        out.force = force;
        out.dekStdin = dekStdin;
        out.dekFile = dekFile;
        return ParseOutcome::Run;
    }

    // MARK: - The DEK's one buffer

    // Upper bound on how much stdin "wrap --dek-stdin" will accept - the
    // Linux tool's MAX_DEK_INPUT_LEN. A 32-byte DEK is 44 base64 characters;
    // 64 leaves room for a UTF-8 byte-order mark and a trailing CRLF, and
    // nothing longer can be a valid DEK under the rules DecodeDek applies.
    constexpr size_t kMaxDekStdinLen = 64;

    // Any DEK input that isn't strict, padded, standard base64 - the Linux
    // tool's wording. Deliberately fixed: it names no character, offset or
    // bit pattern, so a mistyped DEK never puts part of itself into a log.
    constexpr char kInvalidBase64DekMessage[] =
            "the DEK input is not valid base64 (standard alphabet, padded, at most one trailing newline)";

    // Refusing to read the DEK from an interactive console - the Linux
    // tool's wording, with this tool's own example.
    constexpr char kTerminalDekMessage[] =
            "refusing to read the DEK from an interactive terminal, where it would be echoed and kept in the "
            "scrollback; pipe it in instead, e.g. $dekBase64 | hkdfguard.exe wrap ... --dek-stdin";

    // Refusing UTF-16 input - the Linux tool's wording.
    constexpr char kUtf16DekMessage[] =
            "the DEK input is UTF-16 encoded; send it as ASCII or UTF-8 base64 text "
            "(in PowerShell, set [Console]::OutputEncoding or $OutputEncoding to UTF-8)";

    // Every copy of the DEK this program makes - the base64 text it reads
    // from stdin, and the bytes that decodes to - lives in one fixed
    // allocation, never grown or moved, wiped before it's freed. It is
    // locked into RAM with VirtualLock, so the DEK is never written to the
    // page file: the Linux CLI's DekScratch, with VirtualLock for mlock. Two
    // pages, well inside the default minimum working set VirtualLock draws
    // on. One allocation, not one per buffer, for the same reason as on
    // Linux: locks work on whole pages.
    //
    // This covers the CLI's own copies. Windows has no counterpart of
    // Linux's mlockall, so the library's transient copies (on its stack,
    // while it wraps) are not locked; process hardening (see main) still
    // keeps them out of crash dumps and away from same-user processes.
    class DekScratch {
    public:
        // One byte more than accepted, so over-long input is detected
        // without reading past the buffer.
        static constexpr size_t kTextCapacity = kMaxDekStdinLen + 1;
        // Enough for any base64 decoding of kMaxDekStdinLen characters.
        static constexpr size_t kDecodedCapacity = (kMaxDekStdinLen / 4) * 3 + 3;

        DekScratch() {
            base_ = static_cast<BYTE *>(VirtualAlloc(nullptr, kSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (base_ == nullptr) {
                throw CliError("could not allocate the DEK's buffer: " + FormatWin32Error(GetLastError()));
            }
            locked_ = VirtualLock(base_, kSize) != FALSE;
            if (!locked_) {
                fprintf(stderr,
                        "warning: could not lock the DEK's buffer into memory (VirtualLock: %s); it could be "
                        "written to the page file\n",
                        FormatWin32Error(GetLastError()).c_str());
            }
        }

        ~DekScratch() {
            SecureZeroMemory(base_, kSize);
            if (locked_) {
                VirtualUnlock(base_, kSize);
            }
            VirtualFree(base_, 0, MEM_RELEASE);
        }

        DekScratch(const DekScratch &) = delete;
        DekScratch &operator=(const DekScratch &) = delete;

        char *text() { return reinterpret_cast<char *>(base_); }
        BYTE *decoded() { return base_ + kTextCapacity; }

        // Wipes the base64 text as soon as it has been decoded.
        void WipeText() {
            SecureZeroMemory(base_, kTextCapacity);
            textLen = 0;
        }

        size_t textLen = 0;
        size_t decodedLen = 0;

    private:
        static constexpr size_t kSize = kTextCapacity + kDecodedCapacity;
        BYTE *base_ = nullptr;
        bool locked_ = false;
    };

    // Reads all of stdin (expected to be base64 text for the DEK) into
    // `scratch`. Used only by "wrap --dek-stdin", specifically so the DEK
    // never appears in this process's argv - see this file's header comment.
    // ReadFile on the stdin handle, not the C runtime's fread: the CRT keeps
    // its own buffer for a FILE stream, which would hold a copy of the DEK
    // text this code could neither lock nor wipe.
    // Reads at most kMaxDekStdinLen bytes from `in` into scratch's text
    // buffer, refusing more. `what` names the source in errors, as the Linux
    // tool's read_bounded does ("the DEK on stdin", "--dek-file").
    void ReadBoundedInto(HANDLE in, const std::string &what, DekScratch &scratch) {
        for (;;) {
            DWORD got = 0;
            DWORD room = static_cast<DWORD>(DekScratch::kTextCapacity - scratch.textLen);
            if (!ReadFile(in, scratch.text() + scratch.textLen, room, &got, nullptr)) {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE) {
                    break; // the writing end of a pipe closed: end of input
                }
                throw CliError("failed to read " + what + ": " + FormatWin32Error(err));
            }
            if (got == 0) {
                break;
            }
            scratch.textLen += got;
            if (scratch.textLen > kMaxDekStdinLen) {
                // UTF-16 doubles the text, so it is over the limit long
                // before DecodeDek could say why: name it here instead.
                const auto *bytes = reinterpret_cast<const unsigned char *>(scratch.text());
                if ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF)) {
                    throw CliError(kUtf16DekMessage);
                }
                throw CliError(
                    what + " is longer than " + std::to_string(kMaxDekStdinLen) +
                    " bytes; expected base64 of a 32-byte DEK");
            }
        }
        // Empty input is reported by DecodeDek, as on Linux.
    }

    void ReadDekBase64FromStdin(DekScratch &scratch) {
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        if (in == nullptr || in == INVALID_HANDLE_VALUE) {
            throw CliError("no stdin to read the DEK from for --dek-stdin");
        }
        // A DEK typed or pasted at a console is echoed and stays in the
        // console's scrollback: refuse a console outright rather than read
        // it. GetConsoleMode succeeds only on a console input handle - a pipe
        // or a file fails it - so this doesn't refuse NUL or other character
        // devices, which are not consoles.
        DWORD consoleMode = 0;
        if (GetConsoleMode(in, &consoleMode)) {
            throw CliError(kTerminalDekMessage);
        }
        ReadBoundedInto(in, "the DEK on stdin", scratch);
    }

    // All ones if `a` and `b` are both negative, else zero - without a
    // branch: their AND is negative exactly then, and its sign bit, taken
    // through an unsigned shift (fully defined, unlike a signed one), is
    // stretched into a mask by negation.
    inline int32_t BothNegativeMask(int32_t a, int32_t b) {
        return -static_cast<int32_t>(static_cast<uint32_t>(a & b) >> 31);
    }

    // The 6-bit value of a standard-alphabet base64 character, or -1 - in
    // constant time: no branch and no table lookup depends on `c`, which is
    // a character of the secret DEK text. The same arithmetic as RustCrypto's
    // base64ct (which the Linux tool uses) and libsodium: start at -1 and,
    // for each range, add a correction masked to apply only when `c` is in
    // it. Every term is computed for every character.
    inline int32_t Base64ValueCt(uint8_t c) {
        const int32_t ch = c;
        int32_t value = -1;
        value += BothNegativeMask(('A' - 1) - ch, ch - ('Z' + 1)) & (ch - 'A' + 1);      // 'A'..'Z' -> 0..25
        value += BothNegativeMask(('a' - 1) - ch, ch - ('z' + 1)) & (ch - 'a' + 26 + 1); // 'a'..'z' -> 26..51
        value += BothNegativeMask(('0' - 1) - ch, ch - ('9' + 1)) & (ch - '0' + 52 + 1); // '0'..'9' -> 52..61
        value += BothNegativeMask(('+' - 1) - ch, ch - ('+' + 1)) & (62 + 1);            // '+' -> 62
        value += BothNegativeMask(('/' - 1) - ch, ch - ('/' + 1)) & (63 + 1);            // '/' -> 63
        return value;
    }

    // Decodes scratch's base64 text into its decoded bytes, by the Linux
    // tool's rules exactly, so the same input is accepted or refused on both:
    //
    //   - A leading UTF-8 byte-order mark (EF BB BF) is skipped: some
    //     PowerShell and .NET configurations prepend one when piping text to
    //     a native process. A UTF-16 byte-order mark is refused as such, since
    //     the fix there is on the sending side.
    //   - Exactly one trailing newline (LF or CRLF) is tolerated, as written
    //     by `echo`, `printf '%s\n'` or an editor. Nothing else: no other
    //     whitespace, anywhere.
    //   - Then strict standard base64 (RFC 4648 section 4, the `+/` alphabet)
    //     with canonical padding: a length that's a multiple of 4, `=` only
    //     as the last one or two characters, and the unused bits before the
    //     padding zero - what base64ct, which the Linux tool uses, accepts.
    //
    // Constant time with respect to the secret text, as base64ct is on
    // Linux: every character goes through Base64ValueCt, problems are
    // collected into one flag rather than reported where they're found, and
    // the flag is checked once, after the whole input has been processed.
    // Only public facts decide anything earlier: the length, where the
    // padding is, the byte-order mark and the trailing newline. Any malformed
    // input gets the same fixed message, which names no character, offset or
    // bit pattern. Decodes straight into the locked buffer, so no decoded
    // byte is ever anywhere else, and wipes its own temporaries.
    void DecodeDek(DekScratch &scratch) {
        const unsigned char *text = reinterpret_cast<const unsigned char *>(scratch.text());
        size_t len = scratch.textLen;

        if (len >= 3 && text[0] == 0xEF && text[1] == 0xBB && text[2] == 0xBF) {
            text += 3;
            len -= 3;
        } else if (len >= 2 && ((text[0] == 0xFF && text[1] == 0xFE) || (text[0] == 0xFE && text[1] == 0xFF))) {
            throw CliError(kUtf16DekMessage);
        }
        if (len >= 1 && text[len - 1] == '\n') {
            --len;
            if (len >= 1 && text[len - 1] == '\r') {
                --len;
            }
        }
        if (len == 0) {
            throw CliError("the DEK input is empty");
        }
        if (len % 4 != 0) {
            throw CliError(kInvalidBase64DekMessage);
        }
        // How many '=' end the input. A valid DEK always ends in exactly one,
        // so this decides nothing about the key; a data character there just
        // means no padding, and is decoded like any other.
        const size_t padding = (text[len - 1] == '=') ? ((text[len - 2] == '=') ? 2 : 1) : 0;
        const size_t decodedLen = len / 4 * 3 - padding;
        if (decodedLen > DekScratch::kDecodedCapacity) {
            throw CliError(kInvalidBase64DekMessage);
        }

        BYTE *out = scratch.decoded();
        size_t written = 0;
        uint32_t bad = 0;    // nonzero once anything is wrong; checked only at the end
        int32_t v[4] = {};   // the current group's four 6-bit values
        uint32_t group = 0;  // and the 24 bits they make
        for (size_t i = 0; i < len; i += 4) {
            const bool last = (i + 4 == len);
            for (size_t j = 0; j < 4; ++j) {
                // Padding positions (public: fixed by the length and the
                // count above) decode as 0. Everywhere else, including any
                // '=' out of place, the constant-time lookup decides, and -1
                // sets the flag.
                const bool isPadding = last && j >= 4 - padding;
                v[j] = isPadding ? 0 : Base64ValueCt(text[i + j]);
                bad |= static_cast<uint32_t>(v[j]) >> 31;
            }
            group = (static_cast<uint32_t>(v[0] & 0x3F) << 18) | (static_cast<uint32_t>(v[1] & 0x3F) << 12) |
                    (static_cast<uint32_t>(v[2] & 0x3F) << 6) | static_cast<uint32_t>(v[3] & 0x3F);
            if (last) {
                // Canonical: the bits the padding leaves unused must be zero.
                const uint32_t unusedBits = (padding == 2) ? 0xFFFFu : (padding == 1) ? 0xFFu : 0u;
                bad |= (group & unusedBits);
            }
            out[written++] = static_cast<BYTE>(group >> 16);
            if (!(last && padding == 2)) out[written++] = static_cast<BYTE>(group >> 8);
            if (!(last && padding >= 1)) out[written++] = static_cast<BYTE>(group);
        }
        SecureZeroMemory(v, sizeof(v));
        SecureZeroMemory(&group, sizeof(group));
        if (bad != 0) {
            // The partly decoded bytes stay in the locked buffer, which its
            // destructor wipes as this exception unwinds.
            throw CliError(kInvalidBase64DekMessage);
        }
        scratch.decodedLen = written;
    }

    // MARK: - Wrap / provision

    std::string DescribeStatus(int32_t code) {
        switch (code) {
            case HKDFGUARD_OK: return "success";
            case HKDFGUARD_ERR_INVALID_ARGUMENT: return "invalid argument (null pointer or wrong DEK length)";
            case HKDFGUARD_ERR_BUFFER_TOO_SMALL: return "output buffer too small";
            case HKDFGUARD_ERR_PROVIDER_UNAVAILABLE: return "no KEK provider is available on this host";
            case HKDFGUARD_ERR_PROVIDER_ERROR: return "KEK provider/key open or create failed";
            case HKDFGUARD_ERR_CRYPTO_ERROR: return "a cryptographic operation failed";
            case HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED: return "AES-GCM authentication failed";
            case HKDFGUARD_ERR_PAYLOAD_MALFORMED: return "wrapped payload is not valid";
            case HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED: return "wrapped payload uses a format version this build does not understand";
            case HKDFGUARD_ERR_INTERNAL_ERROR: return "an internal error occurred in HkdfGuard.dll";
            case HKDFGUARD_ERR_PROCESS_HARDENING_FAILED: return "could not harden this process against memory disclosure (crash-report heap, same-user debugging and code injection)";
            case HKDFGUARD_ERR_INVALID_SERVICE_NAME: return "service name is missing or malformed (ASCII letters, digits and '.' only, 1-128 bytes, not starting with '.', no \"..\")";
            case HKDFGUARD_ERR_POLICY_INVALID: return "invalid key storage policy";
            case HKDFGUARD_ERR_WIN_GROUP_INVALID: return "a KeyUseGroups policy entry is unresolvable, not a group, over-broad, or not host-local";
            case HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH: return "wrapped payload was not produced under this service's current KEK";
            case HKDFGUARD_ERR_KEK_NOT_FOUND: return "no KEK is provisioned for this service";
            case HKDFGUARD_ERR_KEK_ACCESS_DENIED: return "this KEK exists, but this account is not authorized to use it";
            case HKDFGUARD_ERR_KEK_INVALID: return "a KEK already exists under this service name, but its ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal - it was left untouched; investigate it, or provision under a new (versioned) service name";
            case HKDFGUARD_ERR_FILE_NOT_FOUND: return "the wrapped-key file does not exist";
            case HKDFGUARD_ERR_FILE_ACCESS_DENIED: return "this account may not read the wrapped-key file";
            case HKDFGUARD_ERR_FILE_IO: return "the wrapped-key file is not a regular file, is open for writing, or could not be read";
            case HKDFGUARD_ERR_FILE_TOO_SHORT: return "the wrapped-key file is shorter than a wrapped key";
            case HKDFGUARD_ERR_FILE_TOO_LONG: return "the wrapped-key file is longer than a wrapped key";
            case HKDFGUARD_ERR_FILE_PLAINTEXT_KEY: return "the file looks like an UNWRAPPED 32-byte key (raw, or its hex or base64) - it may hold a plaintext key; treat it as exposed";
            case HKDFGUARD_ERR_FILE_MALFORMED: return "the wrapped-key file is the right size but does not hold a valid wrapped key";
            case HKDFGUARD_ERR_FILE_UNTRUSTED: return "the wrapped-key path is, or passes through, a symbolic link, junction or other reparse point, uses an 8.3 short name, or is not on a local drive (UNC, mapped or SUBST drive, device); or the file or a folder above it is owned by, or lets, an account other than SYSTEM, Administrators, TrustedInstaller or the caller write or replace it";
            default: return "unknown status code " + std::to_string(code);
        }
    }

    // Calls hkdfguard_wrap_dek, retrying once at the library-reported required
    // size if the initial buffer was too small - same pattern as the
    // macOS/Linux tools' own wrap helper. Never provisions a KEK - a missing
    // KEK surfaces as HKDFGUARD_ERR_KEK_NOT_FOUND, with a hint pointing at
    // this tool's "provision" subcommand.
    std::vector<uint8_t> WrapDek(const std::string &service, const BYTE *dek, size_t dekLen) {
        std::vector<uint8_t> wrapped(static_cast<size_t>(kInitialWrappedCapacity));
        int32_t wrappedLen = static_cast<int32_t>(wrapped.size());

        int32_t rc = hkdfguard_wrap_dek(
            service.c_str(), dek, static_cast<int32_t>(dekLen), wrapped.data(), &wrappedLen);

        if (rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
            // wrappedLen now holds the size the library actually needs; retry once at that size.
            wrapped.assign(static_cast<size_t>(wrappedLen), 0);
            rc = hkdfguard_wrap_dek(
                service.c_str(), dek, static_cast<int32_t>(dekLen), wrapped.data(), &wrappedLen);
        }

        if (rc != HKDFGUARD_OK) {
            // The Linux tool's wording for the one failure an operator is most
            // likely to hit, with the command that fixes it.
            if (rc == HKDFGUARD_ERR_KEK_NOT_FOUND) {
                throw CliError(
                    "no KEK is provisioned for service \"" + service + "\"; run `" + kProgramNameNarrow +
                    " provision --service-name " + service + "` first");
            }
            std::string message = "hkdfguard_wrap_dek failed: " + DescribeStatus(rc);
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
            if (rc == HKDFGUARD_ERR_KEK_ACCESS_DENIED) {
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

        // The Linux tool's wording.
        if (exists != 0) {
            fprintf(stdout, "KEK already provisioned for service \"%s\"; verified, nothing to do\n", service.c_str());
        } else {
            fprintf(stdout, "KEK provisioned for service \"%s\"\n", service.c_str());
        }
    }

    // Enforces that --service-name - the exact value passed to
    // the hkdfguard_* calls as `service` - contains only ASCII alphanumeric
    // characters or '.', does not start with '.', and does not contain "..",
    // matching this project's macOS/Linux tools. The library enforces the
    // same rules; checking here first gives the operator a specific message.
    void ValidateServiceCharset(const std::string &service) {
        constexpr size_t kMaxServiceLen = 128; // the ABI's limit
        if (service.size() > kMaxServiceLen) {
            throw CliError(
                "--service-name must be at most " + std::to_string(kMaxServiceLen) + " bytes, got " +
                std::to_string(service.size()));
        }
        for (wchar_t c: service) {
            bool isAsciiAlnum = (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
            if (!isAsciiAlnum && c != L'.') {
                throw CliError(
                    "combined service name \"" + service + "\" must contain only alphanumeric characters or '.'");
            }
        }
        if (!service.empty() && (service.front() == '.' || service.find("..") != std::string::npos)) {
            throw CliError(
                "combined service name \"" + service + "\" may not start with '.' or contain \"..\"");
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

    // Principals --group must never name: each is effectively "everybody" on
    // the host (or every user of a logon type, every local account, every
    // service), so granting it read access to the wrapped-key file would let
    // almost any process replace a DEK the service will unwrap - see the
    // rollback note in README.md - or copy the file elsewhere. The same set
    // the DLL refuses as a KEK key-use group (src/key_acl.cpp's
    // kOverBroadSids/kOverBroadSidStrings), duplicated here because this tool
    // deliberately depends only on the public C ABI, nothing from src/. Keep
    // the two lists in sync.
    constexpr WELL_KNOWN_SID_TYPE kOverBroadGroupSids[] = {
        WinNullSid,
        WinWorldSid, // Everyone
        WinAnonymousSid,
        WinAuthenticatedUserSid,
        WinInteractiveSid,
        WinNetworkSid,
        WinBatchSid,
        WinServiceSid,
        WinBuiltinUsersSid,
        WinBuiltinGuestsSid,
        WinLocalAccountSid,     // S-1-5-113 "Local account"
        WinThisOrganizationSid, // S-1-5-15 "This Organization"
        WinRemoteLogonIdSid,    // S-1-5-14 "REMOTE INTERACTIVE LOGON"
        WinLocalSid,            // S-1-2-0 "LOCAL"
        WinConsoleLogonSid,     // S-1-2-1 "CONSOLE LOGON"
    };

    constexpr const char *kOverBroadGroupSidStrings[] = {
        "S-1-5-80-0", // NT SERVICE\ALL SERVICES
    };

    bool IsOverBroadGroupSid(PSID sid) {
        for (WELL_KNOWN_SID_TYPE type: kOverBroadGroupSids) {
            BYTE known[SECURITY_MAX_SID_SIZE];
            DWORD knownSize = sizeof(known);
            if (!CreateWellKnownSid(type, nullptr, known, &knownSize)) {
                throw CliError("CreateWellKnownSid failed: " + FormatWin32Error(GetLastError()));
            }
            if (EqualSid(sid, known)) {
                return true;
            }
        }
        for (const char *sidString: kOverBroadGroupSidStrings) {
            PSID known = nullptr;
            if (!ConvertStringSidToSidA(sidString, &known)) {
                throw CliError("ConvertStringSidToSid failed: " + FormatWin32Error(GetLastError()));
            }
            const bool match = EqualSid(sid, known) != FALSE;
            LocalFree(known);
            if (match) {
                return true;
            }
        }
        return false;
    }

    // Whether `domain` - a ReferencedDomainName from LookupAccountName - is
    // this host: its own computer name, BUILTIN, NT AUTHORITY or NT SERVICE
    // (case-insensitive). The library's IsHostLocalAccountDomain, which the
    // CLI can't call (it isn't exported).
    bool IsHostLocalDomain(const std::string &domain) {
        if (domain.empty()) {
            return false;
        }
        for (const char *fixed: {"BUILTIN", "NT AUTHORITY", "NT SERVICE"}) {
            if (_stricmp(domain.c_str(), fixed) == 0) {
                return true;
            }
        }
        char computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        return GetComputerNameA(computer, &size) && _stricmp(domain.c_str(), computer) == 0;
    }

    // Resolves `groupName` (a group on this host, e.g. "App_1234" or
    // "BUILTIN\Performance Log Users") to its SID, rejecting anything that
    // isn't actually a group account (a plain user name, for instance) so a
    // typo doesn't silently grant read access to the wrong kind of
    // principal, rejecting an over-broad group (Everyone, Users,
    // Authenticated Users, ... - see kOverBroadGroupSids above), and
    // rejecting a domain group. The checks are on the resolved SID and
    // domain, so they can't be dodged by spelling (e.g. "BUILTIN\Users").
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
        std::string domain(domainSize, '\0');
        if (!LookupAccountName(
            nullptr, groupName.c_str(), sid.data(), &sidSize, domain.data(), &domainSize, &sidType)) {
            throw CliError("--group \"" + groupName + "\" could not be resolved: " + FormatWin32Error(GetLastError()));
        }
        domain.resize(domainSize); // on success, the length without the NUL
        if (sidType != SidTypeGroup && sidType != SidTypeAlias && sidType != SidTypeWellKnownGroup) {
            throw CliError("--group \"" + groupName + "\" does not name a group account");
        }
        if (IsOverBroadGroupSid(sid.data())) {
            throw CliError(
                "--group \"" + groupName + "\" is an over-broad group (it covers essentially every account or "
                "process on this host); name a dedicated group for the service that unwraps this key, such as "
                "a local group created for it");
        }
        // Host-local only, as the library requires of KeyUseGroups: a
        // --group reader must also be granted the KEK, and the library
        // refuses a domain group there, so a domain group here would be a
        // file ACE for readers who can never unwrap it. Judged on the domain
        // the name resolved to, not on how it was spelled, so an unqualified
        // name that falls through to a domain group is caught too.
        if (!IsHostLocalDomain(domain)) {
            throw CliError(
                "--group \"" + groupName + "\" resolves to a group in domain \"" + domain + "\"; only groups on "
                "this host (local groups, BUILTIN, NT AUTHORITY or NT SERVICE) are accepted, as for the "
                "KeyUseGroups policy");
        }
        return sid;
    }

    // Owns every buffer a security descriptor granting "owner read/write,
    // optionally one group read-only, no one else, no inherited ACEs" needs
    // to stay alive for as long as it's in use - a self-contained bundle
    // rather than several out-parameters the caller would otherwise have to
    // keep in sync by hand. The Windows analog of the Linux tool's POSIX 0600
    // (no group) and 0640 (with --group: owner rw, one group r, no one else).
    class KeyFileSecurity {
    public:
        KeyFileSecurity(std::vector<BYTE> ownerSid, std::optional<std::vector<BYTE>> groupSid)
            : ownerSid_(std::move(ownerSid)), groupSid_(groupSid ? std::move(*groupSid) : std::vector<BYTE>{}) {
            PSID owner = SidPtr(ownerSid_);
            PSID group = groupSid_.empty() ? nullptr : SidPtr(groupSid_);

            DWORD aclSize = static_cast<DWORD>(
                sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(owner) +
                (group ? (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(group) : 0));
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
            if (group != nullptr && !AddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ, group)) {
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
            // ACL could silently widen access beyond the ACEs just set.
            if (!SetSecurityDescriptorControl(&sd_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
                throw CliError("SetSecurityDescriptorControl failed: " + FormatWin32Error(GetLastError()));
            }
        }

        // Valid only for as long as this object is alive - the returned
        // SECURITY_ATTRIBUTES' lpSecurityDescriptor points at this object's own
        // sd_ member, which in turn points into ownerSid_/groupSid_/aclBuf_,
        // all owned together right here.
        // The DACL itself, for re-applying it as protected on the open file.
        PACL Dacl() const { return reinterpret_cast<PACL>(const_cast<BYTE *>(aclBuf_.data())); }

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
    // helpers below enforce that four ways, all on handles already open
    // (never by re-querying a path that could be swapped underneath):
    //
    //   1. The object itself must not carry FILE_ATTRIBUTE_REPARSE_POINT -
    //      every CreateFile in this section passes
    //      FILE_FLAG_OPEN_REPARSE_POINT precisely so a symlink at the path
    //      opens *as the link* and gets caught here, rather than being
    //      silently followed.
    //   2. It must be a file, not a directory.
    //   3. The kernel's own resolved path for the handle
    //      (GetFinalPathNameByHandle) must equal the fully-qualified form of
    //      what the caller typed - which is what catches a junction or
    //      symlink in a *parent* component, where flag (1) on the leaf can't
    //      see it. (A path using 8.3 short names is refused before this, in
    //      FullLongPath.)
    //   4. The file must have exactly one name (no hard links), since
    //      neither (1) nor (3) can tell that a file is also reachable at
    //      another path, and overwriting it would change that file too.
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

    // Fully-qualified form of `path`, as the caller spelled it - *not*
    // resolved through any reparse point. This is the "expected" side of
    // check (3) above.
    //
    // 8.3 short names ("PROGRA~1") are refused rather than expanded, here
    // and in HkdfGuard.dll's hkdfguard_open_file alike: they are a second,
    // auto-generated name for the same file, with a history of checks that
    // matched one spelling but not the other. The test is exact, not a guess
    // from "~" characters: GetLongPathName walks the path through the
    // directory listing, and a path is refused only if that changes one of
    // its components (ignoring case). A genuine long name such as
    // "report~1.key" passes.
    //
    // GetLongPathName only works on paths that exist, and the wrapped-key
    // file usually doesn't yet. So if the full path doesn't resolve, the
    // parent directory (which must exist) is checked instead; the leaf of a
    // file that doesn't exist yet has no short name to check.
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

        auto refuseShortName = [&path]() {
            throw CliError(
                path + " uses an 8.3 short name (such as PROGRA~1); spell every folder and the file "
                "with its full name");
        };

        std::string longForm = TryLongPathName(full);
        if (!longForm.empty()) {
            if (_stricmp(longForm.c_str(), full.c_str()) != 0) {
                refuseShortName();
            }
            return full;
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
        if (_stricmp(parentLong.c_str(), parent.c_str()) != 0) {
            refuseShortName();
        }
        return full;
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

    // Checks (1)-(4) above against an already-open handle. `expected` is the
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
        // (4) A hard link is not a reparse point, so (1) cannot see it, and
        // GetFinalPathNameByHandle reports whichever name the handle was
        // opened by, so (3) cannot either. But a file with more than one
        // name is the same data under another path: --force's overwrite
        // passes would destroy that other file's contents. A wrapped-key
        // file never legitimately has a second name, so refuse it. (Creating
        // a hard link needs write access to the target on current Windows,
        // which limits who could plant one, but this check costs nothing.)
        if (!allowDirectory && info.nNumberOfLinks != 1) {
            throw CliError(
                path + " has " + std::to_string(info.nNumberOfLinks) +
                " hard links; the wrapped-key path must be a file with exactly one name, so that "
                "overwriting it cannot alter a file at some other path");
        }

        std::string actual = TrimTrailingSeparators(FinalPathOfHandle(file, path));
        std::string want = TrimTrailingSeparators(expected);
        if (_stricmp(actual.c_str(), want.c_str()) != 0) {
            throw CliError(
                path + " resolves through a symbolic link, junction, SUBST or mapped drive to \"" + actual +
                "\"; the wrapped-key path must be a real local path with no links in it");
        }
    }

    // Refuses `path` unless it names a file on a local drive: never a UNC
    // path (\\server\share\..., \\?\UNC\...), a device or \\?\ path, or a
    // mapped network drive. Decided from the path text alone (GetFullPathName
    // does no I/O; GetDriveType asks only the local mount manager) and before
    // anything touches the path, so this process never connects or
    // authenticates to a server named in it - which would hand that server
    // the caller's NTLM credentials. A SUBST drive passes here and is caught
    // later, where the opened handle's real path must match the spelled one.
    // `what` names the path in the message.
    void RequireLocalDrivePath(const std::string &path, const std::string &what) {
        char fullBuf[MAX_PATH * 4];
        DWORD fullLen = GetFullPathNameA(path.c_str(), static_cast<DWORD>(sizeof(fullBuf)), fullBuf, nullptr);
        if (fullLen == 0 || fullLen >= sizeof(fullBuf)) {
            throw CliError("failed to resolve " + what + ": " + FormatWin32Error(GetLastError()));
        }
        const std::string full(fullBuf, fullLen);
        const bool driveLetter = full.size() >= 3 && std::isalpha(static_cast<unsigned char>(full[0])) &&
                                 full[1] == ':' && full[2] == '\\';
        if (!driveLetter || GetDriveTypeA(full.substr(0, 3).c_str()) == DRIVE_REMOTE) {
            throw CliError(
                what + " is not on a local drive (UNC paths, mapped network drives and devices are refused)");
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
        const std::string &path, const std::vector<uint8_t> &bytes, const KeyFileSecurity &security) {
        SECURITY_ATTRIBUTES sa = security.attributes();
        ScopedFileHandle file(CreateFile(
            path.c_str(), GENERIC_WRITE | DELETE | WRITE_DAC, 0, &sa, CREATE_NEW,
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

        // Protect the DACL on the file itself, before a byte is written. The
        // descriptor CreateFile was given carries SE_DACL_PROTECTED, but a
        // new file's descriptor is built by the kernel from it, and the
        // protection bit isn't reliably kept: an unprotected DACL would pick
        // up a parent folder's inheritable ACEs the next time someone
        // propagates that folder's permissions to its children. Re-applied
        // through the handle with PROTECTED_DACL_SECURITY_INFORMATION, it
        // stays exactly the ACEs built above. Failing that, the (still
        // empty) file is removed.
        DWORD protectError = SetSecurityInfo(
            file.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
            nullptr, security.Dacl(), nullptr);
        if (protectError != ERROR_SUCCESS) {
            FILE_DISPOSITION_INFO disposition{};
            disposition.DeleteFile = TRUE;
            SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition));
            throw CliError("failed to protect the ACL of " + path + ": " + FormatWin32Error(protectError));
        }

        // Write the payload and flush it to storage, so a reported success
        // survives a crash. On any failure the file is deleted through its
        // own handle (it goes when ScopedFileHandle closes it): a failed wrap
        // never leaves an empty or truncated key file behind, for the next
        // `wrap` to call "already exists" or a service to read as malformed -
        // the same rule as the Linux tool's finish_key_file.
        auto discard = [&file](const std::string &message) {
            FILE_DISPOSITION_INFO disposition{};
            disposition.DeleteFile = TRUE;
            SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition));
            throw CliError(message);
        };
        DWORD totalWritten = 0;
        const DWORD bytesSize = static_cast<DWORD>(bytes.size());
        while (totalWritten < bytesSize) {
            DWORD written = 0;
            if (!WriteFile(file.get(), bytes.data() + totalWritten, bytesSize - totalWritten, &written, nullptr)) {
                discard("failed to write " + path + ": " + FormatWin32Error(GetLastError()));
            }
            if (written == 0) {
                // A successful write of nothing would otherwise loop forever.
                discard("failed to write " + path + ": the write made no progress");
            }
            totalWritten += written;
        }
        if (!FlushFileBuffers(file.get())) {
            discard("failed to flush " + path + " to storage: " + FormatWin32Error(GetLastError()));
        }
    }

    // MARK: - Reading the DEK from a file

    // The SID of the account this process runs as (TokenUser), as an owned
    // buffer - for the --dek-file trust check, which accepts the file's own
    // user, as the Linux tool accepts a file owned by its euid.
    std::vector<BYTE> GetProcessUserSid() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            throw CliError("OpenProcessToken failed: " + FormatWin32Error(GetLastError()));
        }
        DWORD size = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
        std::vector<BYTE> buf(size);
        BOOL ok = size != 0 && GetTokenInformation(hToken, TokenUser, buf.data(), size, &size);
        DWORD err = ok ? 0 : GetLastError();
        CloseHandle(hToken);
        if (!ok) {
            throw CliError("GetTokenInformation(TokenUser) failed: " + FormatWin32Error(err));
        }
        PSID user = reinterpret_cast<TOKEN_USER *>(buf.data())->User.Sid;
        std::vector<BYTE> sid(GetLengthSid(user));
        if (!CopySid(static_cast<DWORD>(sid.size()), sid.data(), user)) {
            throw CliError("CopySid(user) failed: " + FormatWin32Error(GetLastError()));
        }
        return sid;
    }

    // An account's name for an error message ("DOMAIN\\name"), or its SID
    // string when it can't be resolved.
    std::string AccountNameOf(PSID sid) {
        char name[256], domain[256];
        DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(nullptr, sid, name, &nameLen, domain, &domainLen, &use)) {
            return domainLen > 0 ? std::string(domain) + "\\" + name : std::string(name);
        }
        LPSTR text = nullptr;
        if (ConvertSidToStringSidA(sid, &text)) {
            std::string s(text);
            LocalFree(text);
            return s;
        }
        return "(unknown account)";
    }

    // A --dek-file holds the plaintext DEK, so it must be readable by
    // nobody but the accounts that could read it anyway - the Linux tool's
    // "owned by root or this user, no group or other bits at all", in ACL
    // form. Judged on the open handle, so it's the file actually read:
    //   - the owner is SYSTEM, Administrators or this account;
    //   - the DACL grants nothing (any right, read included) to anyone else.
    //     Deny and inherit-only ACEs don't count; OWNER RIGHTS is the owner,
    //     checked above; CREATOR OWNER and CREATOR GROUP match nobody outside
    //     an inherit-only ACE; any other kind of allow ACE can't be vouched
    //     for, so it is refused.
    // Stricter than the key-file rule, which allows others to read: a key
    // file is ciphertext, this is not.
    void RequireTrustedDekFile(HANDLE file, const std::string &path) {
        PSID owner = nullptr;
        PACL dacl = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        DWORD rc = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                   &owner, nullptr, &dacl, nullptr, &sd);
        if (rc != ERROR_SUCCESS) {
            throw CliError("failed to read the security of --dek-file " + path + ": " + FormatWin32Error(rc));
        }
        struct FreeSd {
            PSECURITY_DESCRIPTOR p;
            ~FreeSd() { LocalFree(p); }
        } freeSd{sd};

        std::vector<BYTE> user = GetProcessUserSid();
        auto trusted = [&](PSID sid) {
            return IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
                   EqualSid(sid, user.data());
        };
        const std::string fix =
                "; a plaintext DEK file must be readable by SYSTEM, Administrators and this account only "
                "(for example: icacls \"" + path + "\" /inheritance:r /grant:r \"%USERNAME%:R\")";
        if (owner == nullptr || !trusted(owner)) {
            throw CliError(
                "--dek-file " + path + " is owned by " + (owner ? AccountNameOf(owner) : std::string("no one")) +
                ", which is neither SYSTEM, Administrators nor this account" + fix);
        }
        if (dacl == nullptr) {
            throw CliError("--dek-file " + path + " has no DACL, so every account can read it" + fix);
        }
        for (DWORD i = 0; i < dacl->AceCount; ++i) {
            void *ace = nullptr;
            if (!GetAce(dacl, i, &ace)) {
                throw CliError("failed to read the ACL of --dek-file " + path + ": " + FormatWin32Error(GetLastError()));
            }
            const auto *header = static_cast<const ACE_HEADER *>(ace);
            if (header->AceFlags & INHERIT_ONLY_ACE) {
                continue;
            }
            switch (header->AceType) {
                case ACCESS_DENIED_ACE_TYPE:
                case ACCESS_DENIED_OBJECT_ACE_TYPE:
                case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                    continue;
                case ACCESS_ALLOWED_ACE_TYPE:
                case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
                    PSID sid = const_cast<DWORD *>(&static_cast<const ACCESS_ALLOWED_ACE *>(ace)->SidStart);
                    if (!trusted(sid) && !IsWellKnownSid(sid, WinCreatorOwnerRightsSid) &&
                        !IsWellKnownSid(sid, WinCreatorOwnerSid) && !IsWellKnownSid(sid, WinCreatorGroupSid)) {
                        throw CliError("--dek-file " + path + " grants access to " + AccountNameOf(sid) + fix);
                    }
                    continue;
                }
                default:
                    throw CliError("--dek-file " + path + " has an access-allowed ACE of an unexpected type" + fix);
            }
        }
    }

    // Reads the DEK's base64 text from --dek-file into `scratch`. The path
    // rules are the key file's (see "The output path must be a real file"
    // above), checked before and on the open handle:
    //   - on a local drive: never UNC, a mapped network drive or a device,
    //     decided before anything is opened, so this process never connects
    //     or authenticates to a server named in the path;
    //   - no 8.3 short name anywhere in it;
    //   - a regular file, opened without following a reparse point, and at
    //     the spelled path: no symbolic link or junction at it or above it;
    // then RequireTrustedDekFile, then at most kMaxDekStdinLen bytes. Opened
    // with read sharing only, so nobody can change it while it's read.
    // Unlike the key file, a hard link isn't refused: nothing here writes
    // through it, and the Linux tool doesn't refuse one either.
    void ReadDekFile(const std::string &path, DekScratch &scratch) {
        RequireLocalDrivePath(path, "--dek-file " + path);
        const std::string expected = FullLongPath(path); // refuses 8.3 short names

        ScopedFileHandle file(CreateFile(
            path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        if (!file.valid()) {
            throw CliError("failed to open --dek-file " + path + ": " + FormatWin32Error(GetLastError()));
        }
        if (GetFileType(file.get()) != FILE_TYPE_DISK) {
            throw CliError("--dek-file " + path + " is not a regular file");
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file.get(), &info)) {
            throw CliError("failed to examine --dek-file " + path + ": " + FormatWin32Error(GetLastError()));
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            throw CliError("--dek-file " + path + " is a symbolic link, junction or other reparse point; refusing to follow it");
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            throw CliError("--dek-file " + path + " is not a regular file");
        }
        const std::string actual = TrimTrailingSeparators(FinalPathOfHandle(file.get(), path));
        if (_stricmp(actual.c_str(), TrimTrailingSeparators(expected).c_str()) != 0) {
            throw CliError(
                "--dek-file " + path + " resolves through a symbolic link, junction, SUBST or mapped drive to \"" +
                actual + "\"; give its real local path");
        }
        RequireTrustedDekFile(file.get(), path);
        ReadBoundedInto(file.get(), "--dek-file", scratch);
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
        // First, before anything - even the exists pre-check below - touches
        // a path: a UNC or mapped-drive path would make this process connect
        // to the server it names. The same rule as hkdfguard_open_file.
        RequireLocalDrivePath(args.keyFilePath, args.keyFilePath);
        if (args.dekFile) {
            RequireLocalDrivePath(*args.dekFile, "--dek-file " + *args.dekFile);
        }

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
        // secret material either way. Without --group: owner-only.
        KeyFileSecurity security(
            GetProcessOwnerSid(),
            args.groupName ? std::optional<std::vector<BYTE>>(ResolveGroupSid(*args.groupName)) : std::nullopt);

        // `service` (and its UTF-8 form) is not secret -- it's a logical
        // identifier, not key material -- so both live for the rest of this
        // function's scope, including the final status message below.
        ValidateServiceCharset(args.serviceName);
        const std::string &service = args.serviceName;

        std::vector<uint8_t> wrapped;
        {
            // Both the base64 *text* read from stdin and the decoded
            // plaintext DEK *bytes* are secret. Both live only in `scratch`
            // (locked into RAM, see DekScratch), which is wiped the instant
            // this block ends - immediately after WrapDek is done with it,
            // not at the end of RunWrap() (which would otherwise leave it in
            // memory through the potentially-slow 8-pass secure-overwrite and
            // the final file write below). hkdfguard_wrap_dek reads the
            // plaintext DEK directly from the pointer it's given and never
            // copies or zeroes it (see aes_gcm.cpp), so this caller-side
            // wiping is the only place it happens at all.
            DekScratch scratch;
            if (args.dekFile) {
                ReadDekFile(*args.dekFile, scratch);
            } else {
                ReadDekBase64FromStdin(scratch);
            }
            DecodeDek(scratch);
            // The base64 text has served its only purpose.
            scratch.WipeText();

            if (scratch.decodedLen != kDekLen) {
                throw CliError(
                    "the DEK must decode to exactly " + std::to_string(kDekLen) + " bytes, got " +
                    std::to_string(scratch.decodedLen));
            }

            // No provisioning happens here - "wrap" only ever opens an
            // existing KEK. If none exists yet for this service, WrapDek's
            // HKDFGUARD_ERR_KEK_NOT_FOUND path below reports that and points
            // at "provision".
            wrapped = WrapDek(service, scratch.decoded(), scratch.decodedLen);
            // `scratch` is wiped, unlocked and freed here, as this block
            // ends - only the wrapped (encrypted, no longer secret) form
            // survives past this point.
        }

        if (args.force) {
            SecureOverwriteAndRemoveIfExists(args.keyFilePath);
        }

        WriteWrappedKeyFile(args.keyFilePath, wrapped, security);

        // The same wording as the Linux tool.
        const std::string access =
                args.groupName ? "owner read/write + " + *args.groupName + " read-only" : std::string("owner read/write");
        fprintf(
            stdout, "wrapped key written to %s (%zu bytes, %s, service \"%s\")\n",
            args.keyFilePath.c_str(), wrapped.size(), access.c_str(), service.c_str());
    }
} // namespace

int main(int argc, char *argv[]) {
    // Before anything is read: this process holds a plaintext DEK, so it
    // must not be dumpable, debuggable or injectable by other processes of
    // the same user - including through threads the key storage provider
    // starts later, which is what the strict flag adds on Windows (see
    // hkdfguard_harden_process_with_flags). Refuse to run rather than handle
    // a DEK unprotected - the same rule as the Linux CLI.
    {
        int rc = hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE);
        if (rc != HKDFGUARD_OK) {
            fprintf(stderr, "error: %s; refusing to handle key material\n", DescribeStatus(rc).c_str());
            return 1;
        }
    }

    if (argc < 2) {
        fprintf(stderr, "error: missing subcommand: expected `provision` or `wrap`\n");
        PrintUsage();
        return 2;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h" || command == "help") {
        PrintUsage();
        return 0;
    }

    if (command == "provision") {
        ProvisionArgs args;
        try {
            if (ParseProvisionArgs(argc, argv, args) == ParseOutcome::Help) {
                PrintUsage();
                return 0;
            }
        } catch (const CliError &e) {
            fprintf(stderr, "error: %s\n", e.message.c_str());
            PrintUsage();
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
                PrintUsage();
                return 0;
            }
        } catch (const CliError &e) {
            fprintf(stderr, "error: %s\n", e.message.c_str());
            PrintUsage();
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

    fprintf(stderr, "error: unknown subcommand \"%s\": expected `provision` or `wrap`\n", command.c_str());
    PrintUsage();
    return 2;
}
