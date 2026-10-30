// CLI tool: provisions a service's machine-wide KEK, separately wraps a
// caller-supplied Data Encryption Key (DEK) under an already-provisioned
// KEK, writing the wrapped payload to a file, and retires (deletes) a KEK
// once nothing needs it.
//
// Four subcommands, strictly separated:
//
//   provision --service-name|-sn <name>
//       Calls hkdfguard_create_kek, which creates the KEK if it is missing
//       or re-verifies an existing one (properties and ACL), then prints
//       its fingerprint (hkdfguard_kek_fingerprint) for the operator to
//       record. Never wraps a DEK, never touches a file.
//       This is the *only* subcommand that may create a KEK.
//
//   retire --service-name|-sn <name> (--fingerprint|-fp <hex> | --corrupt)
//          [--provider tpm|software] [--version 1|2]
//       Deletes the service's KEK of this host's payload version (or
//       --version's), after the operator proves which KEK they mean by
//       supplying its fingerprint - or, with --corrupt, only if the key
//       under the service's name definitely fails its KEK checks (version
//       1: not a P-256 ECDH key; version 2: a key file or AES key that fails
//       them), so has no fingerprint. The *only* subcommand that deletes keys, and
//       deliberately implemented here rather than in the library: the DLL's
//       C ABI offers no delete, so no application that loads it gets a
//       one-call wipe. Requires an elevated process. Every payload wrapped
//       under a retired KEK is permanently unrecoverable. Logged as event
//       1004. --provider exists because a Windows service can have a KEK on
//       each of two providers.
//
//   status --service-name|-sn <name>
//       Reports the payload version this host uses, whether the service has
//       a KEK of it, which provider holds it, and its fingerprint, and lists
//       every other key under the service's name - of either version.
//       Read-only: never creates or deletes a key.
//
//   prepare-store
//       Creates the payload version 2 TPM key store's folders
//       (ProgramData\HkdfGuard\TpmKeys) with their ACL, or checks them if they
//       exist. Run by the installer as SYSTEM, so no user can create
//       ProgramData\HkdfGuard first and block provisioning; safe to run again
//       from an elevated prompt. Never creates or deletes a key.
//
//   wrap --key-file-path|-kf <path> --service-name|-sn <name> \
//        (--dek-stdin | --dek-file <path>) [--group|-g <name>] [--force|-f]
//       Calls hkdfguard_wrap_dek against the service's *existing* KEK and
//       writes the wrapped payload to <path>. Never provisions a KEK - if
//       none exists yet for this service, this fails with KEK_NOT_FOUND and
//       a hint to run "provision" first. The DEK (32 raw bytes,
//       base64-encoded) is read from stdin or a file, never from argv, so it
//       is not visible to other processes via a command-line/process listing
//       (e.g. a WMI query).
//
// Calls into HkdfGuard.dll through its stable C ABI - hkdfguard_kek_exists,
// hkdfguard_create_kek, hkdfguard_kek_fingerprint and hkdfguard_wrap_dek -
// for everything it does with the KEK the policy selects. retire and status
// need more than the ABI gives - one provider's key, and a delete - because
// the ABI deliberately has no way to delete a key or address one provider's
// copy. For a payload version 1 KEK they open the persisted key directly
// with NCrypt (see "KEK inspection and retirement" below). A payload
// version 2 KEK can't be inspected that way - its fingerprint needs the KEK
// itself - so for it they use the library's own version 2 key code,
// compiled into this tool (see "Payload version 2 KEKs" below, and
// tools/CMakeLists.txt). Nothing else from src/ is compiled in.
//
// The KEK's `service` identity is exactly --service-name's value, passed
// straight through to the hkdfguard_* calls, so every subcommand given the
// same service name operates on the same KEK. The KEK is meant to be
// long-lived: DEKs are re-minted every release under the same service
// name, and a new KEK is obtained by versioning the service name (e.g.
// "myapp.v2") - there is no in-place key rotation.
// Creating a KEK (provision, the first run for a given service name) needs
// an elevated process; wrapping against an existing one (wrap) does not,
// subject to the key's ACL.
//
// The wrapped payload is written to <key-file-path> with an explicit,
// non-inherited DACL: the calling account (the process token's owner SID -
// Administrators when run elevated) gets read+write and no one else is
// granted anything (in POSIX terms, 0600). With --group, that group also
// gets read-only (0640). The DACL is set atomically at file-creation time
// via CreateFileW's security-attributes parameter, not applied after the
// fact. --group governs only the wrapped-key *file's* ACL, not the KEK's:
// which principals may use the KEK is a machine-level registry policy
// (KeyUseGroups; see include/hkdfguard.h), not a command-line option.
//
// With --force against a pre-existing file, that file's old contents are
// securely overwritten in place (8 alternating all-zero/random passes,
// each flushed before the next starts) and deleted before the new file is
// created - see SecureOverwriteAndRemoveIfExists/WriteWrappedKeyFile below
// for the exact sequence and its one intentional fallback. Without --force,
// an existing file is never touched (WriteWrappedKeyFile's FILE_CREATE fails
// instead).
//
// The wrapped-key path must be a real file reached through real directories:
// a symbolic link, junction, or other reparse point at the path or anywhere
// above it is refused outright, never followed, both with and without
// --force. There is no legitimate reason for a secrets file to live behind a
// link, and allowing one would let whoever can plant a link in the output
// directory redirect an elevated `wrap --force` at an arbitrary file. See the
// "output path must be a real file" section below for how that is enforced
// on open handles rather than on re-queried paths. The folders
// above it must be ones hkdfguard_open_file will read from: no account but
// SYSTEM, Administrators, TrustedInstaller and the caller may create, delete
// or rename entries in any of them below the drive root (see "The folders a
// key file may be read from" below) - refused before the DEK is read.

#include "hkdfguard.h"
#include "no_follow_open.h" // the path walk shared with hkdfguard_open_file - see tools/CMakeLists.txt
// The library's version 2 key code, compiled into this tool for retire and
// status only (see "Payload version 2 KEKs" below, and tools/CMakeLists.txt).
#include "errors.h"  // hkdfguard::HkdfGuardError
#include "kek_v2.h"  // InspectV2Kek, DeleteV2Kek
#include "policy.h"  // LoadPayloadVersionPolicy

#include <windows.h>
#include <aclapi.h> // SetSecurityInfo - protecting the key file's DACL on its handle
#include <bcrypt.h>
#include <ncrypt.h> // retire/status: opening, inspecting and deleting the persisted KEK
#include <sddl.h> // ConvertStringSidToSidW - over-broad --group check
#include <io.h> // _get_osfhandle: whether stdout/stderr is a console (Print)

#include <algorithm>
#include <array>
#include <bit> // std::bit_cast - LARGE_INTEGER to LONGLONG
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
    constexpr wchar_t kProgramName[] = L"hkdfguard";
    // Narrow twin of kProgramName, for the tool's narrow (std::string)
    // error/hint text; only PrintUsage is wide.
    constexpr char kProgramNameNarrow[] = "hkdfguard";

    // Text in this tool is UTF-8 inside (what the library's ABI takes) and
    // UTF-16 at every Win32 call; these convert between the two, and Print*
    // write output. Defined with the path code below.
    std::wstring Utf8ToWide(const std::string &s);
    std::string WideToUtf8(const std::wstring &w);
    bool EqualsIgnoreCase(const std::string &a, const std::string &b);
    void Print(FILE *stream, const std::string &utf8);
    void Printf(FILE *stream, const char *format, ...);
    void PrintfW(FILE *stream, const wchar_t *format, ...);
    constexpr size_t kDekLen = 32;
    // Starting capacity for the wrapped payload; WrapDek retries once at the
    // library-reported size on HKDFGUARD_ERR_BUFFER_TOO_SMALL, so this is a
    // common case, not an upper bound.
    constexpr int32_t kInitialWrappedCapacity = 512;
    // Secure-overwrite passes on a pre-existing file before deletion:
    // all-zero and random-bytes, alternating, four times each.
    constexpr size_t kSecureOverwritePassCount = 8;

    // This tool's operational-error type. Not the DLL's HkdfGuardError
    // (src/errors.h): apart from the version 2 key code compiled in for
    // retire and status, whose HkdfGuardErrors are turned into CliErrors
    // where they are caught, this tool depends only on the public C ABI. The
    // message is narrow, so every fprintf of it uses %s, never %ls.
    struct CliError {
        std::string message;

        explicit CliError(std::string m) : message(std::move(m)) {
        }
    };

    // Renders a Win32 error code (from GetLastError(), or an NTSTATUS cast to
    // DWORD for a BCrypt failure) as a human-readable string.
    std::string FormatWin32Error(DWORD code) {
        LPWSTR buf = nullptr;

        DWORD len = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            code,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buf),
            0,
            nullptr);

        std::string result =
                (len > 0 && buf != nullptr)
                    ? WideToUtf8(std::wstring(buf, len))
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

    constexpr size_t kFingerprintLen = HKDFGUARD_KEK_FINGERPRINT_LEN;
    using Fingerprint = std::array<uint8_t, kFingerprintLen>;

    // The two key storage providers a service's KEK can live on.
    enum class KekProvider { Tpm, Software };

    struct RetireArgs {
        std::string serviceName;
        std::optional<Fingerprint> fingerprint; // --fingerprint: a valid KEK, by its fingerprint
        bool corrupt = false;                   // --corrupt: a key under the name that fails its KEK checks
        std::optional<KekProvider> provider;    // --provider: which provider's key, when both have one
        std::optional<int> version;             // --version: which payload version's KEK (default: this host's)
    };

    struct StatusArgs {
        std::string serviceName;
    };

    enum class ParseOutcome { Run, Help };

    // The one usage text, printed for every help request and after every
    // usage error.
    void PrintUsage() {
        PrintfW(
            stderr,
            L"Usage:\n"
            L"  %ls provision --service-name|-sn <name>\n"
            L"  %ls wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>)\n"
            L"       [--group|-g <name>] [--force|-f]\n"
            L"  %ls retire --service-name|-sn <name> (--fingerprint|-fp <hex> | --corrupt)\n"
            L"       [--provider tpm|software] [--version 1|2]\n"
            L"  %ls status --service-name|-sn <name>\n"
            L"  %ls prepare-store\n"
            L"\n"
            L"provision  ensures a KEK exists for the service. Run once, at deployment time, from an\n"
            L"           elevated prompt; this is the only command that creates keys. Prints the\n"
            L"           KEK's fingerprint -- record it. The KEK is the one for this host's payload\n"
            L"           version: 2 (post-quantum) unless ClassicalMode is 1.\n"
            L"wrap       wraps a DEK under the service's existing KEK and writes the payload to\n"
            L"           --key-file-path, readable by its owner only, or also by --group's\n"
            L"           members (read-only). Fails if the KEK has not been provisioned.\n"
            L"retire     deletes the service's KEK, only if its fingerprint matches <hex> (64 hex\n"
            L"           characters, as printed by provision). The only command that deletes keys;\n"
            L"           needs an elevated prompt. Everything wrapped under that KEK becomes\n"
            L"           permanently unrecoverable: migrate to a new service name first. With\n"
            L"           --corrupt instead, deletes the key only if it fails its KEK checks (version\n"
            L"           1: not a P-256 ECDH key; version 2: a key file or AES key that fails them,\n"
            L"           but never one whose only fault is its access list - fix that instead).\n"
            L"           --provider picks the key when both providers hold one; --version picks\n"
            L"           the payload version's KEK, by default this host's.\n"
            L"status     reports the payload version, whether the service has a KEK, which provider\n"
            L"           holds it, and its fingerprint, and lists every other key under its name.\n"
            L"           Read-only: never creates or deletes anything.\n"
            L"prepare-store  creates the TPM key store's folders (ProgramData\\HkdfGuard\\TpmKeys)\n"
            L"           with their access list, or checks them; refuses a folder someone else\n"
            L"           created there first. Run by the installer; needs an elevated prompt.\n"
            L"\n"
            L"The DEK is base64 of exactly 32 bytes, read from stdin or a file -- never\n"
            L"from a command-line argument or an environment variable, both of which are\n"
            L"readable by other processes of the same user.\n"
            L"\n"
            L"Examples:\n"
            L"  %ls provision -sn svc\n"
            L"  $dekBase64 | %ls wrap -kf C:\\HkdfGuardKeys\\app\\key.bin -sn svc --dek-stdin\n"
            L"  %ls wrap -kf C:\\HkdfGuardKeys\\app\\key.bin -sn svc --dek-file C:\\Users\\me\\dek.b64\n"
            L"\n"
            L"Every folder above --key-file-path, up to but not including the drive root, must let\n"
            L"no account but SYSTEM, Administrators, TrustedInstaller and the reader create, delete\n"
            L"or rename entries in it -- so not C:\\ProgramData or C:\\Windows\\Temp. Prepare a folder\n"
            L"of its own from an elevated prompt:\n"
            L"  icacls C:\\HkdfGuardKeys /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F\n"
            L"         *S-1-5-32-545:(OI)(CI)RX\n"
            L"  %ls status -sn svc\n"
            L"  %ls retire -sn svc -fp <fingerprint printed by provision>\n",
            kProgramName, kProgramName, kProgramName, kProgramName, kProgramName, kProgramName, kProgramName,
            kProgramName, kProgramName, kProgramName);
    }

    // The subcommand list every "missing/unknown subcommand" error names.
    // Matches the macOS tool's message (tests/test_cli.ps1), so it lists only the
    // subcommands both share; prepare-store is the Windows installer's.
    constexpr char kSubcommandList[] = "`provision`, `wrap`, `retire` or `status`";

    // Stores a flag's value, refusing a second one rather than letting the
    // last win: `-kf a.key ... -kf b.key` is ambiguous about which file the
    // operator meant, and silently picking one is how the wrong key file gets
    // written or the wrong service's KEK gets used. `flag` is the flag's long
    // name.
    void SetOnce(std::optional<std::string> &slot, const char *flag, const std::string &value) {
        if (slot) {
            throw CliError(std::string("give ") + flag + " at most once");
        }
        slot = value;
    }

    // Throws CliError on any parse failure; returns ParseOutcome::Help if
    // --help/-h was seen (in which case `out` is left unpopulated - the caller
    // must check the return value before using `out`). Starts at argv[2] -
    // argv[1] is the subcommand name, already consumed by wmain() to dispatch
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

    // Exactly 64 hex digits, either case. No separators or prefixes: the
    // value is meant to be pasted from provision's output, and a strict
    // format keeps a truncated paste from ever looking valid.
    Fingerprint ParseFingerprintHex(const std::string &text) {
        if (text.size() != kFingerprintLen * 2) {
            throw CliError(
                "--fingerprint must be exactly " + std::to_string(kFingerprintLen * 2) + " hex characters, got " +
                std::to_string(text.size()));
        }
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        Fingerprint bytes{};
        for (size_t i = 0; i < kFingerprintLen; ++i) {
            int hi = nibble(text[2 * i]);
            int lo = nibble(text[2 * i + 1]);
            if (hi < 0 || lo < 0) {
                throw CliError("--fingerprint must contain only hex characters (0-9, a-f, A-F)");
            }
            bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return bytes;
    }

    // Reads a flag's value (argv[i + 1]), refusing a missing or empty one.
    std::string FlagValue(int argc, char *argv[], int &i, const std::string &flag, const char *longName) {
        if (i + 1 >= argc) {
            throw CliError(flag + " requires a value");
        }
        std::string value = argv[++i];
        if (value.empty()) {
            throw CliError(std::string(longName) + " must not be empty");
        }
        return value;
    }

    // Same argv[2]-onward convention as ParseProvisionArgs above.
    ParseOutcome ParseRetireArgs(int argc, char *argv[], RetireArgs &out) {
        std::optional<std::string> serviceName;
        std::optional<std::string> fingerprintText;
        std::optional<std::string> providerText;
        std::optional<std::string> versionText;
        bool corrupt = false;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                return ParseOutcome::Help;
            } else if (arg == "--service-name" || arg == "-sn") {
                SetOnce(serviceName, "--service-name", FlagValue(argc, argv, i, arg, "--service-name"));
            } else if (arg == "--fingerprint" || arg == "-fp") {
                SetOnce(fingerprintText, "--fingerprint", FlagValue(argc, argv, i, arg, "--fingerprint"));
            } else if (arg == "--provider") {
                SetOnce(providerText, "--provider", FlagValue(argc, argv, i, arg, "--provider"));
            } else if (arg == "--version") {
                SetOnce(versionText, "--version", FlagValue(argc, argv, i, arg, "--version"));
            } else if (arg == "--corrupt") {
                if (corrupt) {
                    throw CliError("give --corrupt at most once");
                }
                corrupt = true;
            } else {
                throw CliError("unrecognized argument for `retire`: " + arg);
            }
        }

        if (!serviceName) throw CliError("retire: missing required --service-name|-sn");
        if (fingerprintText && corrupt) {
            throw CliError(
                "retire: --fingerprint and --corrupt are mutually exclusive: a KEK with a readable fingerprint is "
                "not corrupt");
        }
        if (!fingerprintText && !corrupt) {
            throw CliError(
                "retire: missing required --fingerprint|-fp (the 64-hex-character value printed by provision), or "
                "--corrupt for a key under the service's name that fails its KEK checks");
        }

        out.serviceName = *serviceName;
        out.corrupt = corrupt;
        if (fingerprintText) {
            out.fingerprint = ParseFingerprintHex(*fingerprintText);
        }
        if (providerText) {
            if (*providerText == "tpm") {
                out.provider = KekProvider::Tpm;
            } else if (*providerText == "software") {
                out.provider = KekProvider::Software;
            } else {
                throw CliError("--provider must be `tpm` or `software`, got \"" + *providerText + "\"");
            }
        }
        if (versionText) {
            if (*versionText == "1") {
                out.version = 1;
            } else if (*versionText == "2") {
                out.version = 2;
            } else {
                throw CliError("--version must be `1` or `2`, got \"" + *versionText + "\"");
            }
        }
        return ParseOutcome::Run;
    }

    // Same argv[2]-onward convention as ParseProvisionArgs above.
    ParseOutcome ParseStatusArgs(int argc, char *argv[], StatusArgs &out) {
        std::optional<std::string> serviceName;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                return ParseOutcome::Help;
            } else if (arg == "--service-name" || arg == "-sn") {
                SetOnce(serviceName, "--service-name", FlagValue(argc, argv, i, arg, "--service-name"));
            } else {
                throw CliError("unrecognized argument for `status`: " + arg);
            }
        }
        if (!serviceName) throw CliError("status: missing required --service-name|-sn");
        out.serviceName = *serviceName;
        return ParseOutcome::Run;
    }

    // MARK: - The DEK's one buffer

    // Upper bound on how much DEK input "wrap" will accept. A 32-byte DEK is
    // 44 base64 characters;
    // 64 leaves room for a UTF-8 byte-order mark and a trailing CRLF, and
    // nothing longer can be a valid DEK under the rules DecodeDek applies.
    constexpr size_t kMaxDekStdinLen = 64;

    // Any DEK input that isn't strict, padded, standard base64. Deliberately
    // fixed: it names no character, offset or bit pattern, so a mistyped DEK
    // never puts part of itself into a log.
    constexpr char kInvalidBase64DekMessage[] =
            "the DEK input is not valid base64 (standard alphabet, padded, at most one trailing newline)";

    // Refusing to read the DEK from an interactive console.
    constexpr char kTerminalDekMessage[] =
            "refusing to read the DEK from an interactive terminal, where it would be echoed and kept in the "
            "scrollback; pipe it in instead, e.g. $dekBase64 | hkdfguard.exe wrap ... --dek-stdin";

    // Refusing UTF-16 input.
    constexpr char kUtf16DekMessage[] =
            "the DEK input is UTF-16 encoded; send it as ASCII or UTF-8 base64 text "
            "(in PowerShell, set [Console]::OutputEncoding or $OutputEncoding to UTF-8)";

    // Every copy of the DEK this program makes - the base64 text it reads
    // from stdin, and the bytes that decodes to - lives in one fixed
    // allocation, never grown or moved, wiped before it's freed. It is
    // locked into RAM with VirtualLock, so the DEK is never written to the
    // page file. Two pages, well inside the default minimum working set
    // VirtualLock draws on. One allocation, not one per buffer, because locks
    // work on whole pages.
    //
    // This covers the CLI's own copies. Windows has no process-wide memory
    // lock, so the library's transient copies (on its stack, while it wraps)
    // are not locked; process hardening (see main) still keeps them out of
    // crash dumps and away from same-user processes.
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
                Printf(stderr,
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

    // Reads at most kMaxDekStdinLen bytes from `in` into scratch's text
    // buffer, refusing more. `what` names the source in errors ("the DEK on
    // stdin", "--dek-file"). Uses ReadFile, not the C runtime's fread: the
    // CRT keeps its own buffer for a FILE stream, which would hold a copy of
    // the DEK text this code could neither lock nor wipe.
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
        // Empty input is reported by DecodeDek.
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
    // a character of the secret DEK text. The same arithmetic as base64ct and
    // libsodium: start at -1 and, for each range, add a correction masked to
    // apply only when `c` is in it. Every term is computed for every
    // character.
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

    // Decodes scratch's base64 text into its decoded bytes, by these rules:
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
    //     padding zero.
    //
    // Constant time with respect to the secret text: every character goes
    // through Base64ValueCt, problems are
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
            case HKDFGUARD_ERR_PROVIDER_UNAVAILABLE: return "payload version 2 is unavailable on this host: the TPM can't be used for it, and the KeyStoragePolicy (or an existing TPM KEK) rules out the software key store -- event 2008 in the Application log names the reason";
            case HKDFGUARD_ERR_PROVIDER_ERROR: return "KEK provider/key open or create failed";
            case HKDFGUARD_ERR_CRYPTO_ERROR: return "a cryptographic operation failed";
            case HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED: return "AES-GCM authentication failed";
            case HKDFGUARD_ERR_PAYLOAD_MALFORMED: return "wrapped payload is not valid";
            case HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED: return "wrapped payload uses a format version this build does not understand";
            case HKDFGUARD_ERR_PAYLOAD_VERSION_REFUSED: return "wrapped payload is not the payload version this host uses (version 2 unless ClassicalMode is 1): it was wrapped under the other setting, and this host accepts one version only";
            case HKDFGUARD_ERR_INTERNAL_ERROR: return "an internal error occurred in HkdfGuard.dll";
            case HKDFGUARD_ERR_PROCESS_HARDENING_FAILED: return "could not harden this process against memory disclosure (crash-report heap, same-user debugging and code injection)";
            case HKDFGUARD_ERR_INVALID_SERVICE_NAME: return "service name is missing or malformed (ASCII letters, digits and '.' only, 1-128 bytes, not starting with '.', no \"..\")";
            case HKDFGUARD_ERR_POLICY_INVALID: return "invalid machine policy: HKLM\\Software\\Policies\\HkdfGuard\\KeyStoragePolicy is not 0, 1 or 2, or SecurityModel or ClassicalMode is not 0 or 1";
            case HKDFGUARD_ERR_WIN_GROUP_INVALID: return "a KeyUseGroups or DeployerGroups policy entry is unresolvable, not a group, over-broad, or not host-local (or a deployer group's members could not be read)";
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
            case HKDFGUARD_ERR_FILE_UNTRUSTED: return "the wrapped-key path is, or passes through, a symbolic link, junction or other reparse point, uses an 8.3 short name, or is not on a local drive (UNC, mapped or SUBST drive, device); or the file or a folder above it is owned by, or lets, an untrusted account write or replace it (trusted are SYSTEM, Administrators and TrustedInstaller, plus the deployer groups and their members under the production security model, or this account under the developer model); or a folder above it, other than the drive root, lets such an account create files or folders in it (as C:\\ProgramData and C:\\Windows\\Temp do)";
            default: return "unknown status code " + std::to_string(code);
        }
    }

    // Calls hkdfguard_wrap_dek, retrying once at the library-reported required
    // size if the initial buffer was too small. Never provisions a KEK - a missing
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
            // The failure an operator is most likely to hit, with the
            // command that fixes it.
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
    // Returns true if this call created the KEK.
    bool EnsureKekProvisioned(const std::string &service) {
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

        if (exists != 0) {
            Printf(stdout, "KEK already provisioned for service \"%s\"; verified, nothing to do\n", service.c_str());
        } else {
            Printf(stdout, "KEK provisioned for service \"%s\"\n", service.c_str());
        }
        return exists == 0;
    }

    std::string HexString(const uint8_t *bytes, size_t len) {
        static const char kDigits[] = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            out.push_back(kDigits[bytes[i] >> 4]);
            out.push_back(kDigits[bytes[i] & 0x0F]);
        }
        return out;
    }

    std::string HexString(const Fingerprint &fp) {
        return HexString(fp.data(), fp.size());
    }

    // The library's answer for the KEK `service` resolves to - the one a
    // wrap would use (hkdfguard_kek_fingerprint). Returns the status code;
    // `out` is filled only on HKDFGUARD_OK.
    int32_t ReadKekFingerprint(const std::string &service, Fingerprint &out) {
        int32_t len = static_cast<int32_t>(out.size());
        int32_t rc = hkdfguard_kek_fingerprint(service.c_str(), out.data(), &len);
        if (rc == HKDFGUARD_OK && len != static_cast<int32_t>(out.size())) {
            return HKDFGUARD_ERR_INTERNAL_ERROR;
        }
        return rc;
    }

    // Enforces that --service-name - the exact value passed to
    // the hkdfguard_* calls as `service` - contains only ASCII alphanumeric
    // characters or '.', does not start with '.', and does not contain "..".
    // The library enforces the
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
    // creates" - copied out of the token info block.
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
    // depends only on the public C ABI. Keep the two lists in sync.
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
        WinTerminalServerSid,   // S-1-5-13 "TERMINAL SERVER USER"
        WinNTLMAuthenticationSid,     // S-1-5-64-10 "NTLM Authentication"
        WinSChannelAuthenticationSid, // S-1-5-64-14 "SChannel Authentication"
        WinDigestAuthenticationSid,   // S-1-5-64-21 "Digest Authentication"
    };

    constexpr const char *kOverBroadGroupSidStrings[] = {
        "S-1-5-80-0",   // NT SERVICE\ALL SERVICES
        "S-1-5-17",     // NT AUTHORITY\IUSR: every anonymous IIS request
        "S-1-5-32-568", // BUILTIN\IIS_IUSRS: every IIS application pool
        "S-1-5-1",      // NT AUTHORITY\DIALUP
        "S-1-5-1000",   // NT AUTHORITY\OTHER ORGANIZATION
        "S-1-5-64-36",  // NT AUTHORITY\Cloud Account Authentication
    };

    // S-1-5-21-<domain>-513: "Domain Users", called "None" in the local SAM -
    // the primary group of every account in its domain, so on this host every
    // local user. No fixed SID, so recognized by shape (the DLL's
    // IsDomainUsersRid does the same).
    bool IsDomainUsersRid(PSID sid) {
        static const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        if (!IsValidSid(sid) ||
            memcmp(GetSidIdentifierAuthority(sid)->Value, nt.Value, sizeof(nt.Value)) != 0 ||
            *GetSidSubAuthorityCount(sid) != 5) {
            return false;
        }
        return *GetSidSubAuthority(sid, 0) == SECURITY_NT_NON_UNIQUE &&
               *GetSidSubAuthority(sid, 4) == DOMAIN_GROUP_RID_USERS;
    }

    bool IsOverBroadGroupSid(PSID sid) {
        if (IsDomainUsersRid(sid)) {
            return true;
        }
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
            if (!ConvertStringSidToSidW(Utf8ToWide(sidString).c_str(), &known)) {
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
            if (EqualsIgnoreCase(domain, fixed)) {
                return true;
            }
        }
        wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        return GetComputerNameW(computer, &size) && EqualsIgnoreCase(domain, WideToUtf8(computer));
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
        const std::wstring wideName = Utf8ToWide(groupName);
        LookupAccountNameW(nullptr, wideName.c_str(), nullptr, &sidSize, nullptr, &domainSize, &sidType);
        if (sidSize == 0) {
            throw CliError("--group \"" + groupName + "\" could not be resolved: " + FormatWin32Error(GetLastError()));
        }
        std::vector<BYTE> sid(sidSize);
        std::wstring wideDomain(domainSize, L'\0');
        if (!LookupAccountNameW(
            nullptr, wideName.c_str(), sid.data(), &sidSize, wideDomain.data(), &domainSize, &sidType)) {
            throw CliError("--group \"" + groupName + "\" could not be resolved: " + FormatWin32Error(GetLastError()));
        }
        wideDomain.resize(domainSize); // on success, the length without the NUL
        const std::string domain = WideToUtf8(wideDomain);
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
    // while it is in use (in POSIX terms, 0600, or 0640 with --group).
    class KeyFileSecurity {
    public:
        KeyFileSecurity(std::vector<BYTE> ownerSid, std::optional<std::vector<BYTE>> groupSid)
            : ownerSid_(std::move(ownerSid)), groupSid_(groupSid ? std::move(*groupSid) : std::vector<BYTE>{}) {
            PSID owner = SidPtr(ownerSid_);
            PSID group = groupSid_.empty() ? nullptr : SidPtr(groupSid_);

            DWORD aclSize = static_cast<DWORD>(
                sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(owner) +
                (group ? (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(group) : 0));
            // ACL buffers must be DWORD-aligned; round up rather than trust
            // the sum above to land on a boundary.
            aclSize = (aclSize + 7) & ~static_cast<DWORD>(7);

            aclBuf_.resize(aclSize);
            PACL acl = reinterpret_cast<PACL>(aclBuf_.data());
            if (!InitializeAcl(acl, aclSize, ACL_REVISION)) {
                throw CliError("InitializeAcl failed: " + FormatWin32Error(GetLastError()));
            }
            // DELETE too, so the owner can replace its own key file with the
            // next release's (`wrap --force` overwrites it, then deletes it
            // through that handle). Without it a deployer - who, by the
            // recommended folder grant, has Modify on the key folder but not
            // "delete subfolders and files" - couldn't, since this DACL is
            // protected and inherits nothing from the folder.
            if (!AddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, owner)) {
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
            // Blocks inherited ACEs from the parent directory, which could
            // otherwise widen access beyond the ACEs just set.
            if (!SetSecurityDescriptorControl(&sd_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
                throw CliError("SetSecurityDescriptorControl failed: " + FormatWin32Error(GetLastError()));
            }
        }

        // The DACL itself, for re-applying it as protected on the open file.
        PACL Dacl() const { return reinterpret_cast<PACL>(const_cast<BYTE *>(aclBuf_.data())); }

        // Valid only while this object is alive: lpSecurityDescriptor points
        // at sd_, which points into ownerSid_/groupSid_/aclBuf_.
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

    // Fills `buffer` with cryptographically random bytes from CNG's system
    // RNG.
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
    // symlink and creates its target). And a directory symbolic link can
    // point at \\server\share: following one would make this process connect
    // and authenticate to that server before anything could refuse it. So:
    // refuse, don't tolerate - and never follow a link even to find out.
    //
    //   0. The path is walked, never resolved by name (no_follow_open.h):
    //      the drive root, then each folder opened relative to the handle of
    //      the one above it, each refused if it is a reparse point before
    //      anything is opened through it, then the file relative to its
    //      folder. Nothing reached through a link is ever opened.
    //   1. The object itself must not carry FILE_ATTRIBUTE_REPARSE_POINT -
    //      it is opened with FILE_OPEN_REPARSE_POINT, so a link at the path
    //      opens *as the link* and gets caught here.
    //   2. It must be a file, not a directory.
    //   3. The kernel's own resolved path for the handle
    //      (GetFinalPathNameByHandle) must equal the fully-qualified form of
    //      what the caller typed. After (0) the only way they can differ is
    //      a component spelled with its 8.3 short name ("PROGRA~1"), which
    //      is refused.
    //   4. The file must have exactly one name (no hard links), since
    //      neither (1) nor (3) can tell that a file is also reachable at
    //      another path, and overwriting it would change that file too.
    //
    // SUBST and mapped network drives are refused before (0), from the
    // drive letter alone. A secrets file belongs on a real local path.

    // Fully-qualified form of `path`, as the caller spelled it -
    // GetFullPathName works on the text alone, so nothing is opened and no
    // link is followed. This is the "expected" side of check (3) above.
    std::string FullPath(const std::string &path) {
        const std::wstring wide = Utf8ToWide(path);
        DWORD needed = GetFullPathNameW(wide.c_str(), 0, nullptr, nullptr);
        if (needed == 0) {
            throw CliError("GetFullPathName failed for " + path + ": " + FormatWin32Error(GetLastError()));
        }
        std::wstring full(needed, L'\0');
        DWORD written = GetFullPathNameW(wide.c_str(), needed, full.data(), nullptr);
        if (written == 0 || written >= needed) {
            throw CliError("GetFullPathName failed for " + path + ": " + FormatWin32Error(GetLastError()));
        }
        full.resize(written);
        return WideToUtf8(full);
    }

    // Arguments arrive as UTF-16 (wmain) and are held as UTF-8, the encoding
    // the library's ABI takes; every Win32 call is the W form, through these
    // two conversions. Both are exact for well-formed text - nothing is
    // best-fit mapped to a look-alike character - so the library sees the
    // service name and paths exactly as they were typed.
    std::wstring Utf8ToWide(const std::string &s) {
        if (s.empty()) return {};
        const int len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (len <= 0) {
            throw CliError("text is not valid UTF-8: " + FormatWin32Error(GetLastError()));
        }
        std::wstring wide(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), wide.data(), len);
        return wide;
    }

    // Win32 text (final paths, account names, error messages) to UTF-8. A
    // lone surrogate, which NTFS permits in a name, becomes U+FFFD; such text
    // is only ever shown, never turned back into a path.
    std::string WideToUtf8(const std::wstring &w) {
        if (w.empty()) return {};
        const int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        std::string utf8(static_cast<size_t>(len > 0 ? len : 0), '\0');
        if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), utf8.data(), len, nullptr, nullptr);
        return utf8;
    }

    // Case-insensitive comparison the way the file system compares names:
    // ordinal and culture-independent, so "É" matches "é" (as it does on
    // disk) while no two distinct characters are folded together.
    bool EqualsIgnoreCase(const std::string &a, const std::string &b) {
        const std::wstring wa = Utf8ToWide(a);
        const std::wstring wb = Utf8ToWide(b);
        return CompareStringOrdinal(wa.c_str(), static_cast<int>(wa.size()), wb.c_str(), static_cast<int>(wb.size()),
                                    TRUE) == CSTR_EQUAL;
    }

    // Output: on a console the text is written as UTF-16 (WriteConsoleW), so
    // it reads correctly whatever the console's code page; redirected to a
    // file or pipe it is UTF-8 bytes.
    void Print(FILE *stream, const std::string &utf8) {
        fflush(stream);
        HANDLE console = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(stream)));
        DWORD mode = 0;
        if (console != INVALID_HANDLE_VALUE && GetConsoleMode(console, &mode)) {
            // Not Utf8ToWide: output must never throw, so an invalid byte
            // (none is expected) becomes U+FFFD instead of an error.
            const int len = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            std::wstring wide(static_cast<size_t>(len > 0 ? len : 0), L'\0');
            if (len > 0) MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), len);
            size_t done = 0;
            while (done < wide.size()) {
                DWORD written = 0;
                if (!WriteConsoleW(console, wide.data() + done, static_cast<DWORD>(wide.size() - done), &written,
                                   nullptr) ||
                    written == 0) {
                    break;
                }
                done += written;
            }
            return;
        }
        fwrite(utf8.data(), 1, utf8.size(), stream);
        fflush(stream);
    }

    void Printf(FILE *stream, const char *format, ...) {
        va_list args;
        va_start(args, format);
        va_list sizing;
        va_copy(sizing, args);
        const int len = vsnprintf(nullptr, 0, format, sizing);
        va_end(sizing);
        std::vector<char> buffer(static_cast<size_t>(len > 0 ? len : 0) + 1, '\0');
        if (len > 0) vsnprintf(buffer.data(), buffer.size(), format, args);
        va_end(args);
        Print(stream, std::string(buffer.data(), static_cast<size_t>(len > 0 ? len : 0)));
    }

    void PrintfW(FILE *stream, const wchar_t *format, ...) {
        va_list args;
        va_start(args, format);
        va_list sizing;
        va_copy(sizing, args);
        const int len = _vscwprintf(format, sizing);
        va_end(sizing);
        std::vector<wchar_t> buffer(static_cast<size_t>(len > 0 ? len : 0) + 1, L'\0');
        if (len > 0) vswprintf(buffer.data(), buffer.size(), format, args);
        va_end(args);
        Print(stream, WideToUtf8(std::wstring(buffer.data(), static_cast<size_t>(len > 0 ? len : 0))));
    }

    std::string FinalPathOfHandle(HANDLE file, const std::string &path);
    std::string TrimTrailingSeparators(std::string p);

    // Check (0): opens every folder from the drive root down to the one
    // holding `full`'s last component, never following a link (see
    // no_follow_open.h), then refuses an 8.3 short name anywhere in those
    // folders - check (3) on the deepest one, whose canonical path spells
    // every folder above it. `what` names the path in messages. `full` must
    // already have passed RequireLocalDrivePath.
    hkdfguard_nofollow::FolderChain WalkToParent(const std::string &full, const std::string &what) {
        hkdfguard_nofollow::FolderChain chain;
        hkdfguard_nofollow::Error error;
        if (!hkdfguard_nofollow::OpenFolderChain(Utf8ToWide(full), chain, error)) {
            const std::string at = WideToUtf8(error.at);
            switch (error.failure) {
                case hkdfguard_nofollow::Failure::NotLocalDrive:
                    throw CliError(
                        what + " is not on a local drive (UNC paths, mapped network and SUBST drives, and devices are "
                        "refused)");
                case hkdfguard_nofollow::Failure::ReparsePoint:
                    throw CliError(
                        what + " resolves through a symbolic link, junction or other reparse point at \"" + at +
                        "\"; it must be a real local path with no links in it (nothing was opened through the link)");
                case hkdfguard_nofollow::Failure::NotADirectory:
                    throw CliError(what + ": \"" + at + "\" is a file, not a folder");
                case hkdfguard_nofollow::Failure::OpenFailed:
                    if (error.win32 == ERROR_FILE_NOT_FOUND || error.win32 == ERROR_PATH_NOT_FOUND) {
                        throw CliError("the directory for " + what + " (" + at + ") does not exist");
                    }
                    throw CliError("cannot open the folder \"" + at + "\" in " + what + ": " + FormatWin32Error(error.win32));
                default:
                    throw CliError(what + " names an alternate data stream or has an empty folder name");
            }
        }
        const std::string parent = WideToUtf8(chain.parentPath());
        const std::string actual = TrimTrailingSeparators(FinalPathOfHandle(chain.parent(), what));
        if (!EqualsIgnoreCase(actual, TrimTrailingSeparators(parent))) {
            throw CliError(
                what + " uses an 8.3 short name (such as PROGRA~1); spell every folder and the file with its full name");
        }
        return chain;
    }

    // The kernel's canonical DOS path for an open handle, with the "\\?\"
    // (or "\\?\UNC\") prefix GetFinalPathNameByHandle always adds stripped
    // back off so it compares directly against FullPath's output. This is
    // the "actual" side of check (3) above - it reflects every reparse point
    // that was traversed to reach the object, which is the whole point.
    std::string FinalPathOfHandle(HANDLE file, const std::string &path) {
        // Sized by retrying rather than by trusting the size query alone:
        // growing to whatever the call last reported, plus one, converges
        // whether or not that count included the terminator.
        const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
        std::wstring wide(MAX_PATH, L'\0');
        DWORD written = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            written = GetFinalPathNameByHandleW(file, wide.data(), static_cast<DWORD>(wide.size()), flags);
            if (written == 0) {
                throw CliError(
                    "GetFinalPathNameByHandle failed for " + path + ": " + FormatWin32Error(GetLastError()));
            }
            if (written < wide.size()) {
                break;
            }
            wide.assign(static_cast<size_t>(written) + 1, L'\0');
        }
        if (written >= wide.size()) {
            throw CliError("GetFinalPathNameByHandle could not size its result for " + path);
        }
        wide.resize(written);

        std::string final_path = WideToUtf8(wide);
        if (final_path.rfind("\\\\?\\UNC\\", 0) == 0) {
            final_path = "\\\\" + final_path.substr(8);
        } else if (final_path.rfind("\\\\?\\", 0) == 0) {
            final_path = final_path.substr(4);
        }
        return final_path;
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
    // FullPath form the handle is supposed to be sitting at;
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

        // Reached only through the walk, so a difference here can only be an
        // 8.3 short name in the last component.
        std::string actual = TrimTrailingSeparators(FinalPathOfHandle(file, path));
        std::string want = TrimTrailingSeparators(expected);
        if (!EqualsIgnoreCase(actual, want)) {
            throw CliError(
                path + " uses an 8.3 short name (such as PROGRA~1), resolving to \"" + actual +
                "\"; spell every folder and the file with its full name");
        }
    }

    // Refuses a path that Win32 would quietly rewrite or redirect, so the
    // file opened is the one typed. In every folder and the file name:
    //   - a trailing '.' or space, which Win32 path handling strips
    //     ("key.bin." would be written as "key.bin");
    //   - a reserved device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9, the
    //     superscript-digit COM/LPT forms, CONIN$, CONOUT$), with or without
    //     an extension, since Win32 programs open the device rather than a
    //     file of that name.
    // And the path must not end in a separator: it has to name a file.
    // `.` and `..` components, a drive ("C:") and the "?" of a \\?\ prefix
    // are left for the other checks.
    void RequireExactPathNames(const std::string &path, const std::string &what) {
        if (!path.empty() && (path.back() == '\\' || path.back() == '/')) {
            throw CliError(what + " ends in a path separator; give the path of a file");
        }
        static const char *const kReserved[] = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"};
        size_t start = 0;
        while (start <= path.size()) {
            size_t end = path.find_first_of("\\/", start);
            if (end == std::string::npos) end = path.size();
            const std::string part = path.substr(start, end - start);
            start = end + 1;
            const bool drive = part.size() == 2 && part[1] == ':';
            if (part.empty() || part == "." || part == ".." || part == "?" || drive) {
                continue;
            }
            if (part.back() == '.' || part.back() == ' ') {
                throw CliError(what + ": \"" + part + "\" ends in a " + (part.back() == '.' ? "dot" : "space") +
                               ", which Windows drops from the name; remove it");
            }
            // The device name is the part before the first dot, without
            // trailing spaces: "nul.txt" and "COM1 .key" are devices too.
            std::string stem = part.substr(0, part.find('.'));
            while (!stem.empty() && stem.back() == ' ') stem.pop_back();
            bool reserved = false;
            for (const char *name : kReserved) {
                reserved = reserved || EqualsIgnoreCase(stem, name);
            }
            const std::wstring wide = Utf8ToWide(stem);
            if (wide.size() == 4) {
                const std::wstring prefix = wide.substr(0, 3);
                const wchar_t digit = wide[3];
                const bool comOrLpt = CompareStringOrdinal(prefix.c_str(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
                                      CompareStringOrdinal(prefix.c_str(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL;
                const bool deviceDigit = (digit >= L'0' && digit <= L'9') || digit == L'\x00B9' ||
                                         digit == L'\x00B2' || digit == L'\x00B3';
                reserved = reserved || (comOrLpt && deviceDigit);
            }
            if (reserved) {
                throw CliError(what + ": \"" + part + "\" is a reserved Windows device name; Windows programs would "
                               "open the device rather than a file, so choose another name");
            }
        }
    }

    // Refuses `path` unless it names a file on a local drive: never a UNC
    // path (\\server\share\..., \\?\UNC\...), a device or \\?\ path, or a
    // mapped network drive, nor a SUBST drive (whose target is another path,
    // possibly a share). Decided from the path text and the drive letter
    // alone (see hkdfguard_nofollow::IsLocalDrivePath - nothing is opened)
    // and before anything touches the path, so this process never connects
    // or authenticates to a server named in it - which would hand that
    // server the caller's NTLM credentials. Links further down the path are
    // the walk's job (WalkToParent). `what` names the path in the message.
    void RequireLocalDrivePath(const std::string &path, const std::string &what) {
        wchar_t fullBuf[MAX_PATH * 4];
        DWORD fullLen = GetFullPathNameW(Utf8ToWide(path).c_str(), static_cast<DWORD>(std::size(fullBuf)), fullBuf, nullptr);
        if (fullLen == 0 || fullLen >= std::size(fullBuf)) {
            throw CliError("failed to resolve " + what + ": " + FormatWin32Error(GetLastError()));
        }
        if (!hkdfguard_nofollow::IsLocalDrivePath(std::wstring(fullBuf, fullLen))) {
            throw CliError(
                what + " is not on a local drive (UNC paths, mapped network and SUBST drives, and devices are "
                "refused)");
        }
    }

    std::vector<BYTE> GetProcessUserSid();
    std::string AccountNameOf(PSID sid);

    // MARK: - The folders a key file may be read from
    //
    // hkdfguard_open_file refuses a key file (HKDFGUARD_ERR_FILE_UNTRUSTED)
    // unless every folder above it - the drive root included - is owned by
    // SYSTEM, Administrators, TrustedInstaller or the reading account and
    // lets no other account delete, rename or take over its entries, and
    // unless every folder below the drive root - the key file's own folder
    // included - also lets no other account create files or folders in it.
    // The drive root is exempt from that last part only: a default
    // C:\ lets Authenticated Users create folders, and the folders below it
    // are judged themselves. See src/key_file.cpp, whose rule this mirrors
    // ACE for ACE so that wrap never writes a file the library would refuse
    // to read. (The library judges against the account *reading* the file;
    // here "this account" is the one running wrap - the closest this tool
    // can know.)
    //
    // So C:\ProgramData (Users may create entries in it), any folder under
    // it, C:\Windows\Temp, and a folder made directly under C:\ that still
    // inherits Authenticated Users: Modify are all refused, before the DEK
    // is read or a provider is touched, with the fix in the message.

    // Rights the library refuses to anyone untrusted, on every folder (the
    // drive root included) and, below the drive root, also the create rights.
    constexpr ACCESS_MASK kFolderReplaceRights = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    constexpr ACCESS_MASK kFolderCreateRights = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE;

    // Shared system folders that let every user create entries. Never the
    // thing to fix - the key belongs somewhere else - so the message says so
    // instead of suggesting icacls on them.
    bool IsSharedSystemFolder(const std::string &folder) {
        auto same = [&folder](const std::string &other) {
            return !other.empty() && EqualsIgnoreCase(TrimTrailingSeparators(other), folder);
        };
        auto env = [](const wchar_t *name) {
            wchar_t value[MAX_PATH * 2] = {};
            DWORD len = GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
            return (len > 0 && len < std::size(value)) ? WideToUtf8(std::wstring(value, len)) : std::string();
        };
        wchar_t windows[MAX_PATH + 1] = {};
        UINT len = GetSystemWindowsDirectoryW(windows, MAX_PATH + 1);
        const std::string windowsTemp = (len > 0 && len <= MAX_PATH) ? WideToUtf8(std::wstring(windows, len)) + "\\Temp" : "";
        return same(env(L"ProgramData")) || same(env(L"PUBLIC")) || same(windowsTemp);
    }

    // The fix for a folder that fails the rule, as icacls commands an
    // administrator can paste into an elevated prompt. /inheritance:r drops
    // every inherited ACE and /grant:r sets the three that are wanted; an
    // ACE set on the folder itself (`explicitSid`, as "*S-1-..."; empty when
    // the offending ACE was inherited) survives both, so it is removed first.
    std::string KeyFolderFix(const std::string &folder, const std::string &explicitSid = std::string()) {
        if (IsSharedSystemFolder(folder)) {
            return "; " + folder + " is a shared system folder - do not change its permissions; keep key files in a "
                   "folder of their own instead, for example one directly under the drive root, prepared from an "
                   "elevated prompt with:\n"
                   "  mkdir C:\\HkdfGuardKeys\\<app>\n"
                   "  icacls C:\\HkdfGuardKeys /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F "
                   "*S-1-5-32-545:(OI)(CI)RX HkdfGuardDeployers:(OI)(CI)M\n"
                   "  icacls C:\\HkdfGuardKeys /setowner *S-1-5-32-544 /T\n"
                   "(see \"Where to keep key files\" in docs/admin-guide.md)";
        }
        return "; remove every other account's rights to it, from an elevated prompt:\n" +
               (explicitSid.empty() ? std::string()
                                    : "  icacls \"" + folder + "\" /remove:g " + explicitSid + "\n") +
               "  icacls \"" + folder + "\" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F "
               "*S-1-5-32-545:(OI)(CI)RX HkdfGuardDeployers:(OI)(CI)M\n"
               "  icacls \"" + folder + "\" /setowner *S-1-5-32-544 /T\n"
               "then check that `icacls \"" + folder + "\"` lists only SYSTEM, Administrators, Users (RX) and "
               "HkdfGuardDeployers (M), and "
               "that every folder above it passes too (see \"Where to keep key files\" in docs/admin-guide.md)";
    }

    // "*S-1-..." for icacls, or empty if the SID can't be rendered.
    std::string IcaclsSid(PSID sid) {
        LPWSTR text = nullptr;
        if (!ConvertSidToStringSidW(sid, &text)) {
            return std::string();
        }
        std::string s = "*" + WideToUtf8(text);
        LocalFree(text);
        return s;
    }

    // Applies the library's folder rule to every folder of a walked chain,
    // on the handles the walk opened (so it is the folders actually
    // traversed that are judged). `path` is --key-file-path as given. Who
    // is trusted is the library's answer, under the machine's security
    // model (hkdfguard_key_file_principal_trusted), not a copy of its rule:
    // SYSTEM, Administrators and TrustedInstaller always, then the deployer
    // groups and their members (production) or this account (developer).
    void RequireTrustedKeyFileFolders(const hkdfguard_nofollow::FolderChain &chain, const std::string &path) {
        int model = HKDFGUARD_SECURITY_MODEL_PRODUCTION;
        int ignored = 0;
        int32_t modelRc = hkdfguard_security_model(&model, &ignored);
        if (modelRc != HKDFGUARD_OK) {
            throw CliError("could not read the security model: " + DescribeStatus(modelRc));
        }
        const bool developer = model == HKDFGUARD_SECURITY_MODEL_DEVELOPER;
        const std::string others = developer ? "this account" : "a deployer group (HkdfGuardDeployers or DeployerGroups) "
                                                                "or a direct member of one";
        std::vector<std::pair<std::vector<BYTE>, bool>> cache;
        auto mayOwn = [&](PSID sid) {
            for (const auto &entry: cache) {
                if (EqualSid(sid, const_cast<BYTE *>(entry.first.data()))) return entry.second;
            }
            LPWSTR text = nullptr;
            if (!ConvertSidToStringSidW(sid, &text)) {
                throw CliError("ConvertSidToStringSid failed: " + FormatWin32Error(GetLastError()));
            }
            const std::string sidString = WideToUtf8(text);
            LocalFree(text);
            int trusted = 0;
            int32_t rc = hkdfguard_key_file_principal_trusted(sidString.c_str(), &trusted);
            if (rc != HKDFGUARD_OK) {
                throw CliError("could not check who may write key files: " + DescribeStatus(rc));
            }
            const auto *bytes = static_cast<const BYTE *>(sid);
            cache.emplace_back(std::vector<BYTE>(bytes, bytes + GetLengthSid(sid)), trusted != 0);
            return trusted != 0;
        };
        auto mayWrite = [&](PSID sid) {
            return mayOwn(sid) || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) ||
                   IsWellKnownSid(sid, WinCreatorOwnerSid) || IsWellKnownSid(sid, WinCreatorGroupSid);
        };
        const std::string why =
                "hkdfguard_open_file would refuse to read a key file there (HKDFGUARD_ERR_FILE_UNTRUSTED, -39): "
                "every folder from the key file's own up to, but not including, the drive root must let no account "
                "other than SYSTEM, Administrators, TrustedInstaller or " + others + " create, delete or "
                "rename entries in it, or change its permissions (" + (developer ? "developer" : "production") +
                " security model)";

        for (size_t i = 0; i < chain.handles.size(); ++i) {
            const bool driveRoot = i == 0;
            const std::string folder = TrimTrailingSeparators(WideToUtf8(chain.paths[i]));
            const std::string what = "--key-file-path " + path + ": " + (driveRoot ? "the drive root " : "the folder ") +
                                     "\"" + folder + "\"";
            PSID owner = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            DWORD rc = GetSecurityInfo(chain.handles[i].get(), SE_FILE_OBJECT,
                                       OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl,
                                       nullptr, &sd);
            if (rc != ERROR_SUCCESS) {
                throw CliError(what + ": its security could not be read (" + FormatWin32Error(rc) +
                               "), so hkdfguard_open_file could not vouch for it either");
            }
            struct FreeSd {
                PSECURITY_DESCRIPTOR p;
                ~FreeSd() { LocalFree(p); }
            } freeSd{sd};
            const std::string fix = driveRoot ? std::string("; keep the key file on a drive whose root is not open "
                                                            "to other accounts")
                                              : KeyFolderFix(folder);
            if (owner == nullptr || !mayOwn(owner)) {
                throw CliError(what + " is owned by " + (owner ? AccountNameOf(owner) : std::string("no one")) +
                               ", which is neither SYSTEM, Administrators, TrustedInstaller nor " + others + "; " +
                               why + fix);
            }
            if (dacl == nullptr) {
                throw CliError(what + " has no DACL, so every account has full access to it; " + why + fix);
            }
            const ACCESS_MASK forbidden = driveRoot ? kFolderReplaceRights : (kFolderReplaceRights | kFolderCreateRights);
            for (DWORD a = 0; a < dacl->AceCount; ++a) {
                void *ace = nullptr;
                if (!GetAce(dacl, a, &ace)) {
                    throw CliError(what + ": its ACL could not be read: " + FormatWin32Error(GetLastError()));
                }
                const auto *header = static_cast<const ACE_HEADER *>(ace);
                if (header->AceFlags & INHERIT_ONLY_ACE) {
                    continue; // applies only to what is created inside it
                }
                switch (header->AceType) {
                    case ACCESS_DENIED_ACE_TYPE:
                    case ACCESS_DENIED_OBJECT_ACE_TYPE:
                    case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                        continue;
                    case ACCESS_ALLOWED_ACE_TYPE:
                    case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
                        const auto *allowed = static_cast<const ACCESS_ALLOWED_ACE *>(ace);
                        PSID sid = const_cast<DWORD *>(&allowed->SidStart);
                        const ACCESS_MASK granted = allowed->Mask & forbidden;
                        if (granted == 0 || mayWrite(sid)) {
                            continue;
                        }
                        const bool createOnly = (granted & ~kFolderCreateRights) == 0;
                        const bool inherited = (header->AceFlags & INHERITED_ACE) != 0;
                        throw CliError(what + " lets " + AccountNameOf(sid) +
                                       (createOnly ? " create files or folders in it"
                                                   : " delete, rename or replace its entries, or change its permissions") +
                                       (inherited ? " (an inherited permission)" : "") + "; " + why +
                                       (driveRoot || inherited ? fix : KeyFolderFix(folder, IcaclsSid(sid))));
                    }
                    default:
                        throw CliError(what + " has an access-allowed ACE of an unexpected type; " + why + fix);
                }
            }
        }
    }

    // Fail-fast version of the checks above, run before any KEK or DEK work
    // so a bad output path is rejected without touching the key store or
    // reading the DEK: every folder down to the file's must be real
    // (WalkToParent) and pass the library's folder rule
    // (RequireTrustedKeyFileFolders), and if something already exists at the
    // leaf it must pass checks (1)-(4). Returns whether something exists there. The
    // authoritative checks are still the ones made on the actual
    // write/overwrite handles later (SecureOverwriteAndRemoveIfExists /
    // WriteWrappedKeyFile) - this is the friendly early exit, not the
    // security boundary, since a path can always change between a
    // pre-check and a later open.
    bool ValidateOutputPathIsReal(const std::string &path) {
        const std::string full = FullPath(path);
        hkdfguard_nofollow::FolderChain chain = WalkToParent(full, path);
        RequireTrustedKeyFileFolders(chain, path);

        hkdfguard_nofollow::Handle leaf;
        DWORD err = 0;
        if (hkdfguard_nofollow::OpenRelative(
                chain.parent(), chain.leaf, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, nullptr, leaf, err)) {
            RequireRealObjectAtExpectedPath(leaf.get(), full, path, /*allowDirectory=*/false);
            return true;
        }
        // Not existing yet is the normal first-run case. Anything else
        // (access denied, in use) means something is there; the real
        // write reports what.
        return err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND;
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
    // then deletes it. Called only with --force.
    //
    // The file is reached by the walk (WalkToParent), opened relative to its
    // folder without following a reparse point, and vetted by
    // RequireRealObjectAtExpectedPath before a single byte is written, and is
    // deleted through that same handle (DeleteViaHandle) rather than by
    // path - see the section comment above for why. A symlink or junction
    // at or above the path is refused, never followed.
    //
    // If the file doesn't exist, this is a no-op. If it exists but can't be
    // opened for writing (ERROR_ACCESS_DENIED, or ERROR_SHARING_VIOLATION if
    // another process has it open) the overwrite passes are skipped entirely
    // and this falls back to a delete-only open, by design: destroying the
    // old bytes first is worth attempting, but not
    // worth failing the whole command over when this process isn't even
    // allowed to write to the file it's about to replace. That fallback is
    // vetted the same way before it deletes anything.
    //
    // Caveat: on SSDs generally (wear leveling) and on any filesystem that does
    // copy-on-write or transparent compression, writing new bytes to a file's
    // logical offsets does not guarantee those bytes land on the same physical
    // storage cells the old bytes occupied - the old bytes can persist in
    // already-remapped blocks until the medium itself reclaims them. This is a
    // best-effort measure against casual recovery, not a cryptographic
    // guarantee against a determined attacker with access to the raw storage.
    void SecureOverwriteAndRemoveIfExists(const std::string &path) {
        const std::string full = FullPath(path);
        hkdfguard_nofollow::FolderChain chain = WalkToParent(full, path);
        RequireTrustedKeyFileFolders(chain, path); // re-checked on these handles, before anything is destroyed
        hkdfguard_nofollow::Handle file;
        DWORD err = 0;
        if (!hkdfguard_nofollow::OpenRelative(
                chain.parent(), chain.leaf, GENERIC_WRITE | DELETE, 0 /* exclusive access for the duration of the passes */,
                FILE_OPEN, FILE_NON_DIRECTORY_FILE, nullptr, file, err)) {
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                return; // nothing to overwrite or delete
            }
            if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
                // Can't write to it - skip the overwrite passes and go
                // straight to removing it, still through a vetted handle.
                hkdfguard_nofollow::Handle del;
                DWORD delErr = 0;
                if (!hkdfguard_nofollow::OpenRelative(
                        chain.parent(), chain.leaf, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, FILE_NON_DIRECTORY_FILE, nullptr, del, delErr)) {
                    if (delErr == ERROR_FILE_NOT_FOUND || delErr == ERROR_PATH_NOT_FOUND) {
                        return;
                    }
                    throw CliError("failed to remove " + path + ": " + FormatWin32Error(delErr));
                }
                RequireRealObjectAtExpectedPath(del.get(), full, path, /*allowDirectory=*/false);
                DeleteViaHandle(del.get(), path);
                return;
            }
            throw CliError("failed to open " + path + " for secure overwrite: " + FormatWin32Error(err));
        }

        // Vet the handle before writing anything through it.
        RequireRealObjectAtExpectedPath(file.get(), full, path, /*allowDirectory=*/false);

        LARGE_INTEGER sizeField{};
        if (!GetFileSizeEx(file.get(), &sizeField)) {
            throw CliError("failed to get size of " + path + ": " + FormatWin32Error(GetLastError()));
        }
        const auto fileSize = std::bit_cast<LONGLONG>(sizeField); // the whole union, not one member

        if (fileSize > 0) {
            std::vector<BYTE> buffer(static_cast<size_t>(fileSize), 0);

            for (size_t pass = 0; pass < kSecureOverwritePassCount; ++pass) {
                if (pass % 2 == 0) {
                    std::fill(buffer.begin(), buffer.end(), static_cast<BYTE>(0)); // all-zero pass
                } else {
                    FillRandom(buffer); // random pass, via the OS CSPRNG
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
        // the file disappears when its handle closes on return.
        DeleteViaHandle(file.get(), path);
    }

    // Creates `path` fresh (FILE_CREATE atomically fails if it already
    // exists - the guarantee against an exists-then-create race) and writes
    // `bytes` to it, with `security`'s ACL attached from the moment the file
    // is created, so it never briefly exists with broader (e.g. inherited)
    // permissions.
    //
    // Created relative to its folder's handle from the walk (WalkToParent),
    // so no link above it is followed. A link *at* the path is an existing
    // name, so FILE_CREATE fails with "already exists" rather than following
    // a dangling symlink to create its target - which would turn "create my
    // key file here" into "create a file wherever the link points". The
    // resolved-path check right after creation catches an 8.3 short name;
    // on a mismatch the just-created (still empty) file is deleted through
    // its own handle before anything is written to it.
    void WriteWrappedKeyFile(
        const std::string &path, const std::vector<uint8_t> &bytes, const KeyFileSecurity &security) {
        SECURITY_ATTRIBUTES sa = security.attributes();
        const std::string full = FullPath(path);
        hkdfguard_nofollow::FolderChain chain = WalkToParent(full, path);
        RequireTrustedKeyFileFolders(chain, path); // re-checked on the handles the file is created through
        hkdfguard_nofollow::Handle file;
        DWORD err = 0;
        if (!hkdfguard_nofollow::OpenRelative(
                chain.parent(), chain.leaf, GENERIC_WRITE | DELETE | WRITE_DAC, 0, FILE_CREATE,
                FILE_NON_DIRECTORY_FILE, sa.lpSecurityDescriptor, file, err)) {
            if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
                throw CliError(path + " already exists; pass --force|-f to overwrite");
            }
            throw CliError("failed to open " + path + " for writing: " + FormatWin32Error(err));
        }

        try {
            RequireRealObjectAtExpectedPath(file.get(), full, path, /*allowDirectory=*/false);
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
        // own handle (it goes when that handle closes): a failed wrap
        // never leaves an empty or truncated key file behind, for the next
        // `wrap` to call "already exists" or a service to read as malformed.
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

    // The SID of the account this process runs as (TokenUser) - for the
    // --dek-file trust check, which accepts a file owned by this account.
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
        wchar_t name[256], domain[256];
        DWORD nameLen = static_cast<DWORD>(std::size(name)), domainLen = static_cast<DWORD>(std::size(domain));
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, sid, name, &nameLen, domain, &domainLen, &use)) {
            return domainLen > 0 ? WideToUtf8(domain) + "\\" + WideToUtf8(name) : WideToUtf8(name);
        }
        LPWSTR text = nullptr;
        if (ConvertSidToStringSidW(sid, &text)) {
            std::string s = WideToUtf8(text);
            LocalFree(text);
            return s;
        }
        return "(unknown account)";
    }

    // A --dek-file holds the plaintext DEK, so it must be readable by
    // nobody but the accounts that could read it anyway. Judged on the open
    // handle, so it's the file actually read:
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
    //   - reached by the walk (WalkToParent): no symbolic link or junction
    //     above it is ever followed, so nothing is opened on another machine;
    //   - a regular file, opened without following a reparse point;
    //   - no 8.3 short name anywhere in it;
    // then RequireTrustedDekFile, then at most kMaxDekStdinLen bytes. Opened
    // with read sharing only, so nobody can change it while it's read.
    // Unlike the key file, a hard link isn't refused: nothing here writes
    // through it.
    void ReadDekFile(const std::string &path, DekScratch &scratch) {
        const std::string what = "--dek-file " + path;
        RequireLocalDrivePath(path, what);
        const std::string expected = FullPath(path);
        hkdfguard_nofollow::FolderChain chain = WalkToParent(expected, what);

        hkdfguard_nofollow::Handle file;
        DWORD err = 0;
        if (!hkdfguard_nofollow::OpenRelative(
                chain.parent(), chain.leaf, GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0, nullptr, file, err)) {
            throw CliError("failed to open " + what + ": " + FormatWin32Error(err));
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
        if (!EqualsIgnoreCase(actual, TrimTrailingSeparators(expected))) {
            throw CliError(
                what + " uses an 8.3 short name (such as PROGRA~1), resolving to \"" + actual +
                "\"; give its full local path");
        }
        RequireTrustedDekFile(file.get(), path);
        ReadBoundedInto(file.get(), "--dek-file", scratch);
    }

    // MARK: - KEK inspection and retirement (retire and status only)
    //
    // The library's ABI answers for "the KEK this service resolves to under
    // the KeyStoragePolicy", and deliberately cannot delete anything. Retire
    // needs more than that: the exact persisted key on one specific
    // provider, opened once, checked, and deleted through that same handle.
    // So this section opens the key directly with NCrypt, exactly as
    // kek_store.cpp does (machine scope, silent), and nothing here ever
    // creates or modifies a key.

    // Owns an NCrypt provider or key handle (a copy of src/handle_traits.h's:
    // this version 1 code predates the version 2 key code compiled in from
    // src/, and keeps to the ABI and NCrypt alone).
    class ScopedNCryptHandle {
    public:
        ScopedNCryptHandle() = default;
        ~ScopedNCryptHandle() { reset(); }
        ScopedNCryptHandle(const ScopedNCryptHandle &) = delete;
        ScopedNCryptHandle &operator=(const ScopedNCryptHandle &) = delete;
        ScopedNCryptHandle(ScopedNCryptHandle &&other) noexcept : handle_(other.release()) {
        }
        ScopedNCryptHandle &operator=(ScopedNCryptHandle &&other) noexcept {
            if (this != &other) {
                reset();
                handle_ = other.release();
            }
            return *this;
        }

        void reset() {
            if (handle_ != 0) {
                NCryptFreeObject(handle_);
                handle_ = 0;
            }
        }
        // Forgets the handle without freeing it - for NCryptDeleteKey, which
        // frees the handle itself, even when it fails.
        NCRYPT_HANDLE release() {
            NCRYPT_HANDLE h = handle_;
            handle_ = 0;
            return h;
        }
        NCRYPT_HANDLE get() const { return handle_; }
        NCRYPT_HANDLE *put() {
            reset();
            return &handle_;
        }

    private:
        NCRYPT_HANDLE handle_ = 0;
    };

    LPCWSTR NCryptProviderName(KekProvider p) {
        return p == KekProvider::Tpm ? MS_PLATFORM_CRYPTO_PROVIDER : MS_KEY_STORAGE_PROVIDER;
    }

    const char *ProviderLabel(KekProvider p) {
        return p == KekProvider::Tpm ? "Microsoft Platform Crypto Provider (TPM)"
                                     : "Microsoft Software Key Storage Provider";
    }

    const char *ProviderFlag(KekProvider p) {
        return p == KekProvider::Tpm ? "tpm" : "software";
    }

    // The persisted name of `service`'s KEK. Must equal kek_store.cpp's
    // KeyName(service, kCurrentKeyId) - a FROZEN format there. `service` is
    // already validated and lowercased, so the widen is exact.
    std::wstring KekKeyName(const std::string &service) {
        return L"hkdfguardwin_" + Utf8ToWide(service) + L"_v1";
    }

    std::string NCryptErrorText(SECURITY_STATUS status) {
        char code[16];
        snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(status));
        return FormatWin32Error(static_cast<DWORD>(status)) + " (" + code + ")";
    }

#ifndef TBS_E_TPM_NOT_FOUND
#define TBS_E_TPM_NOT_FOUND ((SECURITY_STATUS)0x8028400FL)
#endif

    struct OpenedKek {
        KekProvider provider;
        ScopedNCryptHandle storage; // kept open for as long as the key handle
        ScopedNCryptHandle key;
    };

    // Opens `service`'s KEK on `provider`, or returns nullopt when that
    // provider definitely holds none: the key name doesn't exist there
    // (NTE_BAD_KEYSET), or - TPM only - this machine has no usable TPM
    // provider at all, so nothing can be stored on it. Anything else
    // (access denied, a TPM that is busy or errors) throws: a key may well
    // be there, and "can't tell" must never be reported as "absent".
    std::optional<OpenedKek> OpenKekDirect(const std::string &service, KekProvider provider) {
        OpenedKek result{provider, {}, {}};
        SECURITY_STATUS status = NCryptOpenStorageProvider(
            reinterpret_cast<NCRYPT_PROV_HANDLE *>(result.storage.put()), NCryptProviderName(provider), 0);
        if (status != ERROR_SUCCESS) {
            if (provider == KekProvider::Tpm) {
                return std::nullopt;
            }
            throw CliError(
                std::string("cannot open the ") + ProviderLabel(provider) + ": " + NCryptErrorText(status));
        }

        std::wstring name = KekKeyName(service);
        status = NCryptOpenKey(
            static_cast<NCRYPT_PROV_HANDLE>(result.storage.get()),
            reinterpret_cast<NCRYPT_KEY_HANDLE *>(result.key.put()), name.c_str(), 0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (status == ERROR_SUCCESS) {
            return std::optional<OpenedKek>(std::move(result));
        }
        if (status == NTE_BAD_KEYSET) {
            return std::nullopt;
        }
        if (provider == KekProvider::Tpm && (status == TBS_E_TPM_NOT_FOUND || status == NTE_DEVICE_NOT_FOUND)) {
            return std::nullopt;
        }
        if (status == NTE_PERM || status == static_cast<SECURITY_STATUS>(ERROR_ACCESS_DENIED)) {
            throw CliError(
                "a KEK for service \"" + service + "\" exists on the " + ProviderLabel(provider) +
                ", but this account may not open it (run from an elevated prompt)");
        }
        throw CliError(
            "cannot inspect the KEK for service \"" + service + "\" on the " + ProviderLabel(provider) + ": " +
            NCryptErrorText(status));
    }

    // What a persisted key under a service's name turned out to be.
    struct KeyInspection {
        bool isP256Ecdh = false;
        Fingerprint fingerprint{}; // valid only when isP256Ecdh
        std::string description;   // what it is instead, when not
    };

    // Reads `key`'s algorithm group, length and public key. A P-256 ECDH key
    // gets its fingerprint, computed exactly as the library's
    // ComputeKekFingerprint does: SHA-256 of the raw X || Y coordinates.
    // Anything else is reported as such - but only on a *definite* answer
    // (the properties read fine and describe another kind of key). A query
    // that fails throws instead, so a key that merely couldn't be read right
    // now is never classified as corrupt and deleted for it.
    KeyInspection InspectKey(NCRYPT_KEY_HANDLE key, const std::string &where) {
        KeyInspection result;

        wchar_t group[64] = {};
        DWORD cb = 0;
        SECURITY_STATUS status = NCryptGetProperty(
            key, NCRYPT_ALGORITHM_GROUP_PROPERTY, reinterpret_cast<PBYTE>(group),
            sizeof(group) - sizeof(wchar_t), &cb, 0);
        if (status != ERROR_SUCCESS) {
            throw CliError("cannot read the algorithm of " + where + ": " + NCryptErrorText(status));
        }
        if (wcscmp(group, NCRYPT_ECDH_ALGORITHM_GROUP) != 0) {
            std::string narrow;
            for (const wchar_t *c = group; *c != L'\0'; ++c) {
                narrow.push_back(*c >= 0x20 && *c < 0x7F ? static_cast<char>(*c) : '?');
            }
            result.description = "a key of algorithm group " + (narrow.empty() ? std::string("(unnamed)") : narrow);
            return result;
        }

        DWORD length = 0;
        status = NCryptGetProperty(key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&length), sizeof(length), &cb, 0);
        if (status != ERROR_SUCCESS) {
            throw CliError("cannot read the key length of " + where + ": " + NCryptErrorText(status));
        }
        if (length != 256) {
            result.description = "a " + std::to_string(length) + "-bit ECDH key";
            return result;
        }

        cb = 0;
        status = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &cb, 0);
        std::vector<BYTE> blob;
        if (status == ERROR_SUCCESS && cb >= sizeof(BCRYPT_ECCKEY_BLOB)) {
            blob.resize(cb);
            status = NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), cb, &cb, 0);
        }
        if (status != ERROR_SUCCESS || cb < sizeof(BCRYPT_ECCKEY_BLOB)) {
            throw CliError(
                "cannot export the public key of " + where + ": " +
                (status != ERROR_SUCCESS ? NCryptErrorText(status) : std::string("short blob")));
        }
        const auto *header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB *>(blob.data());
        constexpr size_t kPointLen = 64;
        if (header->dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || header->cbKey != 32 ||
            cb < sizeof(BCRYPT_ECCKEY_BLOB) + kPointLen) {
            result.description = "a 256-bit ECDH key on a curve other than P-256";
            return result;
        }

        NTSTATUS hs = BCryptHash(
            BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, blob.data() + sizeof(BCRYPT_ECCKEY_BLOB),
            static_cast<ULONG>(kPointLen), result.fingerprint.data(), static_cast<ULONG>(result.fingerprint.size()));
        if (!BCRYPT_SUCCESS(hs)) {
            throw CliError("cannot hash the public key of " + where + ": " + FormatWin32Error(static_cast<DWORD>(hs)));
        }
        result.isP256Ecdh = true;
        return result;
    }

    // Every persisted key under `service`'s name, on both providers, in that
    // order, each opened and inspected. `only` restricts it to one.
    struct FoundKek {
        OpenedKek opened;
        KeyInspection inspection;
    };

    std::vector<FoundKek> FindKeks(const std::string &service, std::optional<KekProvider> only = std::nullopt) {
        std::vector<FoundKek> found;
        for (KekProvider p : {KekProvider::Tpm, KekProvider::Software}) {
            if (only && *only != p) {
                continue;
            }
            std::optional<OpenedKek> opened = OpenKekDirect(service, p);
            if (!opened) {
                continue;
            }
            std::string where = std::string("the KEK for service \"") + service + "\" on the " + ProviderLabel(p);
            KeyInspection inspection = InspectKey(static_cast<NCRYPT_KEY_HANDLE>(opened->key.get()), where);
            found.push_back(FoundKek{std::move(*opened), std::move(inspection)});
        }
        return found;
    }

    std::string DescribeFound(const FoundKek &k) {
        return std::string(ProviderFlag(k.opened.provider)) + ": " +
               (k.inspection.isP256Ecdh ? "fingerprint " + HexString(k.inspection.fingerprint)
                                        : k.inspection.description);
    }

    bool ProcessIsElevated() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return false;
        }
        TOKEN_ELEVATION elevation{};
        DWORD size = 0;
        bool elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
                        elevation.TokenIsElevated != 0;
        CloseHandle(token);
        return elevated;
    }

    // Records the retirement as event 1004 (warning) under the library's
    // event source, with this account as the event's user - the same shape
    // as the library's own events (src/event_log.cpp). Returns false if the
    // event could not be written; the caller says so, since a deletion
    // nobody can later find in the log is worth an operator's attention.
    bool LogKekRetired(const std::string &text) {
        constexpr DWORD kEvtKekRetired = 1004; // src/event_messages.mc
        HANDLE source = RegisterEventSourceW(nullptr, L"hkdfguard-native-windows");
        if (source == nullptr) {
            return false;
        }
        std::wstring full = Utf8ToWide(text);
        wchar_t exe[MAX_PATH] = {};
        DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
        full += L" Process: " + std::wstring(n > 0 && n < MAX_PATH ? exe : L"(unknown)") + L" (PID " +
                std::to_wstring(GetCurrentProcessId()) + L").";
        LPCWSTR strings[1] = {full.c_str()};
        std::vector<BYTE> sid;
        try {
            sid = GetProcessUserSid();
        } catch (const CliError &) {
            sid.clear();
        }
        BOOL ok = ReportEventW(
            source, EVENTLOG_WARNING_TYPE, 0, kEvtKekRetired, sid.empty() ? nullptr : sid.data(), 1, 0, strings,
            nullptr);
        DeregisterEventSource(source);
        return ok != FALSE;
    }

    // Lowercases an already-ValidateServiceCharset-checked name: the exact
    // form the library stores and names its keys by.
    std::string LowercaseService(const std::string &service) {
        std::string out = service;
        for (char &c : out) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        return out;
    }

    // MARK: - Payload version 2 KEKs (retire and status only)
    //
    // A version 2 KEK can't be inspected from outside the way a version 1
    // KEK can: it has no public key, and its fingerprint is a PRF output of
    // the KEK itself - computed in the TPM through TBS for a TPM key file,
    // or with AES-CMAC over the Software KSP's AES key. So for these two
    // subcommands this tool compiles the library's own version 2 key code
    // (src/kek_v2.h and what it needs; see tools/CMakeLists.txt) rather
    // than a second copy of it. It is used only to inspect and delete; the
    // DLL that applications load still has no delete.

    // The payload version this host uses (ClassicalMode), read as the
    // library reads it.
    int HostPayloadVersion() {
        switch (hkdfguard::LoadPayloadVersionPolicy()) {
            case hkdfguard::PayloadVersionPolicy::Version2:
                return 2;
            case hkdfguard::PayloadVersionPolicy::Version1:
                return 1;
            default:
                throw CliError(DescribeStatus(HKDFGUARD_ERR_POLICY_INVALID));
        }
    }

    const char *PayloadVersionDescription(int version) {
        return version == 2 ? "2 (post-quantum; ClassicalMode absent or 0)" : "1 (classical; ClassicalMode 1)";
    }

    uint8_t V2ProviderType(KekProvider p) {
        return p == KekProvider::Tpm ? hkdfguard::kProviderTypeTpm : hkdfguard::kProviderTypeSoftware;
    }

    // Where each provider keeps a version 2 KEK.
    const char *V2ProviderLabel(KekProvider p) {
        return p == KekProvider::Tpm ? "TPM (a key file in ProgramData\\HkdfGuard\\TpmKeys)"
                                     : "Microsoft Software Key Storage Provider (an AES-256 key)";
    }

    struct FoundV2Kek {
        KekProvider provider;
        hkdfguard::V2KekInspection inspection;
    };

    // Every version 2 KEK under `service`'s name, on both providers in that
    // order; `only` restricts it to one. As FindKeks: only a definite answer
    // is accepted - a provider that can't be judged (access denied, a TPM
    // that can't be used for version 2) throws, so "can't tell" is never
    // reported as "absent".
    std::vector<FoundV2Kek> FindV2Keks(const std::string &service, std::optional<KekProvider> only = std::nullopt) {
        std::vector<FoundV2Kek> found;
        for (KekProvider p : {KekProvider::Tpm, KekProvider::Software}) {
            if (only && *only != p) {
                continue;
            }
            hkdfguard::V2KekInspection inspection;
            try {
                inspection = hkdfguard::InspectV2Kek(Utf8ToWide(service), V2ProviderType(p));
            } catch (const hkdfguard::HkdfGuardError &e) {
                throw CliError(
                    "cannot inspect the payload version 2 KEK for service \"" + service + "\" on the " +
                    V2ProviderLabel(p) + ": " + e.what() + " (" + DescribeStatus(e.code()) + ")");
            }
            if (inspection.state != hkdfguard::V2KekInspection::State::Absent) {
                found.push_back(FoundV2Kek{p, std::move(inspection)});
            }
        }
        return found;
    }

    Fingerprint ToFingerprint(const uint8_t *bytes) {
        Fingerprint fp{};
        std::copy(bytes, bytes + kFingerprintLen, fp.begin());
        return fp;
    }

    bool IsValidV2(const FoundV2Kek &k) {
        return k.inspection.state == hkdfguard::V2KekInspection::State::Valid;
    }

    // Fails only on its access control (owner or DACL): not corrupt, and
    // never retired as such - fixing the ACL is the remedy.
    bool IsAccessControlInvalidV2(const FoundV2Kek &k) {
        return k.inspection.state == hkdfguard::V2KekInspection::State::AccessControlInvalid;
    }

    std::string DescribeFoundV2(const FoundV2Kek &k) {
        std::string state;
        if (IsValidV2(k)) {
            state = "fingerprint " + HexString(k.inspection.fingerprint, kFingerprintLen);
        } else if (IsAccessControlInvalidV2(k)) {
            state = "access list invalid (" + k.inspection.problem +
                    "); fix the access list, do not retire it - every DEK wrapped under it would be lost";
        } else {
            state = "invalid (" + k.inspection.problem + ")";
        }
        return std::string(ProviderFlag(k.provider)) + ": " + state;
    }

    // MARK: - Security model

    // The security model in force, and whether this account may persist key
    // files under it (hkdfguard_security_model).
    struct SecurityModelInfo {
        int model = HKDFGUARD_SECURITY_MODEL_PRODUCTION;
        bool mayWriteKeyFiles = false;
    };

    SecurityModelInfo ReadSecurityModel() {
        int model = 0;
        int mayWrite = 0;
        int32_t rc = hkdfguard_security_model(&model, &mayWrite);
        if (rc != HKDFGUARD_OK) {
            throw CliError("could not read the security model: " + DescribeStatus(rc));
        }
        return SecurityModelInfo{model, mayWrite != 0};
    }

    const char *SecurityModelName(int model) {
        return model == HKDFGUARD_SECURITY_MODEL_DEVELOPER ? "developer" : "production";
    }

    void RequireMayPersistKeyFiles() {
        SecurityModelInfo info = ReadSecurityModel();
        if (!info.mayWriteKeyFiles) {
            throw CliError(
                std::string("under the ") + SecurityModelName(info.model) +
                " security model this account may not persist key files: only an elevated administrator or a "
                "member of a deployer group (HkdfGuardDeployers, or a group in "
                "HKLM\\Software\\Policies\\HkdfGuard\\DeployerGroups) may, and a key file this account wrote "
                "would be refused by hkdfguard_open_file. Nothing was written");
        }
    }

    // MARK: - Run: status

    // Read-only. Exits 0 whenever there was a definite answer (present,
    // absent, corrupt or unusable) and 1 when there wasn't (access denied, a
    // provider error), so scripts can tell "no key" from "can't tell".
    // The version 1 part of status: the KEK the KeyStoragePolicy selects,
    // and any other version 1 key under the service's name.
    void RunStatusV1(const std::string &service) {
        int32_t exists = 0;
        int32_t rc = hkdfguard_kek_exists(service.c_str(), &exists);
        if (rc != HKDFGUARD_OK) {
            throw CliError("could not determine the KEK state for service \"" + service + "\": " + DescribeStatus(rc));
        }
        std::vector<FoundKek> found = FindKeks(service);

        if (exists == 0) {
            Printf(stdout, "kek: absent\n");
        } else {
            Fingerprint fp{};
            rc = ReadKekFingerprint(service, fp);
            if (rc == HKDFGUARD_ERR_PROVIDER_ERROR && !found.empty()) {
                // A key exists under the name but fails the library's
                // property checks, so the library won't say which one it
                // selected. List what is there instead of guessing.
                bool anyP256 = false;
                for (const FoundKek &k : found) {
                    anyP256 = anyP256 || k.inspection.isP256Ecdh;
                }
                if (anyP256) {
                    Printf(stdout, "kek: unusable (%s)\n", DescribeStatus(rc).c_str());
                } else {
                    Printf(stdout, "kek: corrupt (not a P-256 ECDH key; see retire --corrupt)\n");
                }
                for (const FoundKek &k : found) {
                    Printf(stdout, "key under this name: %s\n", DescribeFound(k).c_str());
                }
                return;
            }
            if (rc != HKDFGUARD_OK) {
                throw CliError(
                    "a KEK exists for service \"" + service + "\" but its fingerprint could not be read: " +
                    DescribeStatus(rc));
            }

            Printf(stdout, "kek: present\n");
            for (auto it = found.begin(); it != found.end(); ++it) {
                if (it->inspection.isP256Ecdh && it->inspection.fingerprint == fp) {
                    Printf(stdout, "provider: %s\n", ProviderLabel(it->opened.provider));
                    found.erase(it);
                    break;
                }
            }
            Printf(stdout, "fingerprint: %s\n", HexString(fp).c_str());
        }

        // A key on a provider the KeyStoragePolicy doesn't select is unused
        // today but would be picked up if the policy changed - worth seeing.
        for (const FoundKek &k : found) {
            Printf(stdout, "other key under this name (not selected by the KeyStoragePolicy): %s\n",
                    DescribeFound(k).c_str());
        }
    }

    // The version 2 part of status, in the same shape: the KEK the
    // KeyStoragePolicy selects (through the library's ABI), then every other
    // version 2 KEK under the service's name.
    void RunStatusV2(const std::string &service) {
        int32_t exists = 0;
        int32_t rc = hkdfguard_kek_exists(service.c_str(), &exists);
        if (rc == HKDFGUARD_ERR_KEK_INVALID) {
            // A key file (or AES key) under the name that fails its checks:
            // the library won't even say whether a KEK exists. Show what is
            // there - as version 1's status does for a corrupt key - but a
            // key whose only fault is its access list is not corrupt, and
            // its remedy is the opposite one.
            const std::vector<FoundV2Kek> found = FindV2Keks(service);
            const bool any_corrupt = std::any_of(found.begin(), found.end(), [](const FoundV2Kek &k) {
                return k.inspection.state == hkdfguard::V2KekInspection::State::Invalid;
            });
            const bool any_access = std::any_of(found.begin(), found.end(), IsAccessControlInvalidV2);
            if (any_access && !any_corrupt) {
                Printf(stdout, "kek: access list invalid (%s; fix the key's access list - do not retire it)\n",
                        DescribeStatus(rc).c_str());
            } else {
                Printf(stdout, "kek: corrupt (%s; see retire --corrupt)\n", DescribeStatus(rc).c_str());
            }
            for (const FoundV2Kek &k : found) {
                Printf(stdout, "key under this name: %s\n", DescribeFoundV2(k).c_str());
            }
            return;
        }
        if (rc != HKDFGUARD_OK) {
            throw CliError("could not determine the KEK state for service \"" + service + "\": " + DescribeStatus(rc));
        }
        std::vector<FoundV2Kek> found = FindV2Keks(service);

        if (exists == 0) {
            Printf(stdout, "kek: absent\n");
        } else {
            Fingerprint fp{};
            rc = ReadKekFingerprint(service, fp);
            if (rc != HKDFGUARD_OK && !found.empty()) {
                // The library won't use what is there; list it instead of
                // guessing which one it would have selected.
                Printf(stdout, "kek: unusable (%s)\n", DescribeStatus(rc).c_str());
                for (const FoundV2Kek &k : found) {
                    Printf(stdout, "key under this name: %s\n", DescribeFoundV2(k).c_str());
                }
                return;
            }
            if (rc != HKDFGUARD_OK) {
                throw CliError(
                    "a KEK exists for service \"" + service + "\" but its fingerprint could not be read: " +
                    DescribeStatus(rc));
            }

            Printf(stdout, "kek: present\n");
            for (auto it = found.begin(); it != found.end(); ++it) {
                if (IsValidV2(*it) && ToFingerprint(it->inspection.fingerprint) == fp) {
                    Printf(stdout, "provider: %s\n", V2ProviderLabel(it->provider));
                    found.erase(it);
                    break;
                }
            }
            Printf(stdout, "fingerprint: %s\n", HexString(fp).c_str());
        }

        for (const FoundV2Kek &k : found) {
            Printf(stdout, "other key under this name (not selected by the KeyStoragePolicy): %s\n",
                    DescribeFoundV2(k).c_str());
        }
    }

    void RunStatus(const StatusArgs &args) {
        ValidateServiceCharset(args.serviceName);
        const std::string service = LowercaseService(args.serviceName);
        Printf(stdout, "service: %s\n", service.c_str());
        {
            const SecurityModelInfo info = ReadSecurityModel();
            Printf(stdout, "security model: %s (this account %s persist key files)\n",
                    SecurityModelName(info.model), info.mayWriteKeyFiles ? "may" : "may not");
        }
        const int version = HostPayloadVersion();
        Printf(stdout, "payload version: %s\n", PayloadVersionDescription(version));

        if (version == 2) {
            RunStatusV2(service);
        } else {
            RunStatusV1(service);
        }

        // A KEK of the other payload version is never used on this host -
        // wrap and unwrap take only this host's version - but would be if
        // ClassicalMode changed. Shown, but its absence or a failure to look
        // is only a note.
        try {
            if (version == 2) {
                for (const FoundKek &k : FindKeks(service)) {
                    Printf(stdout, "other key under this name (payload version 1, unused while ClassicalMode is absent or 0): %s\n",
                            DescribeFound(k).c_str());
                }
            } else {
                for (const FoundV2Kek &k : FindV2Keks(service)) {
                    Printf(stdout, "other key under this name (payload version 2, unused while ClassicalMode is 1): %s\n",
                            DescribeFoundV2(k).c_str());
                }
            }
        } catch (const CliError &e) {
            Printf(stdout, "note: could not check for payload version %d keys under this name: %s\n",
                    version == 2 ? 1 : 2, e.message.c_str());
        }
    }

    // MARK: - Run: retire

    // Deletes `service`'s KEK on one provider, only after confirming it is
    // the key the operator means: by fingerprint, or (--corrupt) by its not
    // being a P-256 ECDH key at all. The key is opened once and checked, and
    // the delete goes through that same handle, so what is deleted is
    // exactly what was checked. (Replacing a machine key between the check
    // and the delete takes administrator rights, which retire's caller has
    // anyway.) Afterwards the name is re-opened on that provider to confirm
    // the key is gone.
    // retire for a payload version 2 KEK, with the same rules as version 1:
    // exactly one candidate, confirmed by fingerprint - or, with --corrupt,
    // only one that definitely fails its KEK checks - then deleted, logged,
    // and confirmed gone. The checks and the delete are the library's own
    // (InspectV2Kek, DeleteV2Kek). Between them the key is looked up by name
    // again; replacing it in that window takes administrator rights, which
    // retire's caller has anyway.
    void RunRetireV2(const RetireArgs &args, const std::string &service) {
        std::vector<FoundV2Kek> found = FindV2Keks(service, args.provider);
        if (found.empty()) {
            throw CliError(
                "no payload version 2 KEK exists for service \"" + service + "\"" +
                (args.provider ? std::string(" on the ") + V2ProviderLabel(*args.provider) : std::string()) +
                "; nothing to retire");
        }
        if (found.size() > 1) {
            throw CliError(
                "found a payload version 2 KEK for service \"" + service + "\" on both providers (" +
                DescribeFoundV2(found[0]) + "; " + DescribeFoundV2(found[1]) +
                "); refusing to choose which one to delete -- nothing was deleted. Run `" + kProgramNameNarrow +
                " status` to see which one the KeyStoragePolicy selects, then pass --provider tpm or --provider "
                "software");
        }
        const FoundV2Kek &target = found.front();
        const KekProvider provider = target.provider;
        const std::string where =
            std::string("the payload version 2 KEK for service \"") + service + "\" on the " + V2ProviderLabel(provider);
        const Fingerprint target_fp = ToFingerprint(target.inspection.fingerprint);

        // A key whose only fault is its access list is never deleted: its
        // material may be intact, and deleting it would destroy every DEK
        // wrapped under it. Fixing the ACL is the remedy; once fixed, it has
        // a fingerprint again and can be retired with --fingerprint if that
        // is really wanted.
        if (IsAccessControlInvalidV2(target)) {
            throw CliError(
                where + " fails only its access-list checks (" + target.inspection.problem +
                "), which is not corruption; nothing was deleted. Restore its access list (SYSTEM, Administrators "
                "and HkdfGuardAdmins full control, the key-use groups read, nothing else; for a TPM key file, its "
                "folders as provision created them), then run `" + kProgramNameNarrow + " status` again");
        }
        if (args.fingerprint) {
            if (!IsValidV2(target)) {
                throw CliError(
                    where + " fails its KEK checks (" + target.inspection.problem +
                    "), so it has no fingerprint to confirm; if it is genuinely corrupt, retire it with --corrupt");
            }
            if (target_fp != *args.fingerprint) {
                throw CliError(
                    "fingerprint mismatch for service \"" + service + "\": " + where + " has fingerprint " +
                    HexString(target_fp) + ", not " + HexString(*args.fingerprint) + "; nothing was deleted");
            }
        } else if (IsValidV2(target)) {
            throw CliError(
                where + " is a valid KEK (fingerprint " + HexString(target_fp) +
                "), not corrupt; nothing was deleted -- retire a valid KEK with --fingerprint");
        }

        bool deleted = false;
        try {
            deleted = hkdfguard::DeleteV2Kek(Utf8ToWide(service), V2ProviderType(provider), 1);
        } catch (const hkdfguard::HkdfGuardError &e) {
            throw CliError("deleting " + where + " failed: " + e.what() + "; run `" + kProgramNameNarrow +
                           " status` to see whether it remains");
        }
        if (!deleted) {
            throw CliError(where + " disappeared before it could be deleted; run `" + kProgramNameNarrow + " status`");
        }

        // Recorded the moment the delete succeeds, as for version 1.
        const std::string identity =
            args.fingerprint ? "fingerprint " + HexString(*args.fingerprint)
                             : "corrupt: " + target.inspection.problem;
        const bool logged = LogKekRetired(
            "Payload version 2 KEK retired for service '" + service + "' on the " + V2ProviderLabel(provider) + " (" +
            identity + ") by " + kProgramNameNarrow +
            " retire. Every DEK wrapped under it is permanently unrecoverable.");
        if (!logged) {
            Printf(stderr, "warning: the retirement could not be recorded in the Application event log (event 1004)\n");
        }

        if (!FindV2Keks(service, provider).empty()) {
            throw CliError(where + " was deleted, but a key under its name is still found; investigate before relying on it being gone");
        }

        Printf(stdout, "retired KEK for service \"%s\" (payload version 2, %s, %s)\n", service.c_str(), identity.c_str(),
                V2ProviderLabel(provider));
        if (args.fingerprint) {
            Printf(stdout, "every payload wrapped under it is now permanently unrecoverable\n");
        }

        try {
            std::vector<FoundV2Kek> remaining = FindV2Keks(service);
            if (!remaining.empty()) {
                Printf(stdout, "note: service \"%s\" still has a payload version 2 KEK on the other provider (%s); run `%s status`\n",
                        service.c_str(), DescribeFoundV2(remaining.front()).c_str(), kProgramNameNarrow);
            } else if (!args.fingerprint) {
                Printf(stdout, "service \"%s\" can now be provisioned again\n", service.c_str());
            }
        } catch (const CliError &e) {
            Printf(stdout, "note: could not check the other provider for a key under this name: %s\n",
                    e.message.c_str());
        }
    }

    void RunRetire(const RetireArgs &args) {
        ValidateServiceCharset(args.serviceName);
        const std::string service = LowercaseService(args.serviceName);

        // Deleting a machine-wide key needs Administrators (or
        // HkdfGuardAdmins) rights, and retire is a security administrator's
        // act, so it refuses up front rather than failing part-way.
        if (!ProcessIsElevated()) {
            throw CliError("retire must run from an elevated prompt (Run as administrator); nothing was deleted");
        }

        // Which version's KEK: --version, or this host's. Each version's KEK
        // is its own key, with its own fingerprint.
        const int version = args.version ? *args.version : HostPayloadVersion();
        if (version == 2) {
            RunRetireV2(args, service);
            return;
        }

        std::vector<FoundKek> found = FindKeks(service, args.provider);
        if (found.empty()) {
            throw CliError(
                "no KEK exists for service \"" + service + "\"" +
                (args.provider ? std::string(" on the ") + ProviderLabel(*args.provider) : std::string()) +
                "; nothing to retire");
        }
        if (found.size() > 1) {
            throw CliError(
                "found a key for service \"" + service + "\" on both providers (" + DescribeFound(found[0]) + "; " +
                DescribeFound(found[1]) +
                "); refusing to choose which one to delete -- nothing was deleted. Run `" + kProgramNameNarrow +
                " status` to see which one the KeyStoragePolicy selects, then pass --provider tpm or --provider "
                "software");
        }
        FoundKek &target = found.front();
        const KekProvider provider = target.opened.provider;
        const std::string where = std::string("the KEK for service \"") + service + "\" on the " + ProviderLabel(provider);

        if (args.fingerprint) {
            if (!target.inspection.isP256Ecdh) {
                throw CliError(
                    where + " is " + target.inspection.description +
                    ", not a P-256 ECDH key, so it has no fingerprint to confirm; if it is genuinely corrupt, "
                    "retire it with --corrupt");
            }
            if (target.inspection.fingerprint != *args.fingerprint) {
                throw CliError(
                    "fingerprint mismatch for service \"" + service + "\": " + where + " has fingerprint " +
                    HexString(target.inspection.fingerprint) + ", not " + HexString(*args.fingerprint) +
                    "; nothing was deleted");
            }
        } else if (target.inspection.isP256Ecdh) {
            throw CliError(
                where + " is a valid P-256 ECDH key (fingerprint " + HexString(target.inspection.fingerprint) +
                "), not corrupt; nothing was deleted -- retire a valid KEK with --fingerprint");
        }

        // NCryptDeleteKey frees the key handle itself, even on failure.
        SECURITY_STATUS status =
            NCryptDeleteKey(static_cast<NCRYPT_KEY_HANDLE>(target.opened.key.release()), 0);
        if (status != ERROR_SUCCESS) {
            throw CliError(
                "deleting " + where + " failed: " + NCryptErrorText(status) + "; run `" + kProgramNameNarrow +
                " status` to see whether it remains");
        }

        // Recorded the moment the delete succeeds, before anything else can
        // fail: a KEK deleted with no event in the log is the one outcome
        // this must never have.
        const std::string identity =
            args.fingerprint ? "fingerprint " + HexString(*args.fingerprint)
                             : "corrupt: " + target.inspection.description + ", not a P-256 ECDH key";
        const bool logged = LogKekRetired(
            "KEK retired for service '" + service + "' on the " + ProviderLabel(provider) + " (" + identity +
            ") by " + kProgramNameNarrow + " retire. Every DEK wrapped under it is permanently unrecoverable.");
        if (!logged) {
            Printf(stderr, "warning: the retirement could not be recorded in the Application event log (event 1004)\n");
        }

        // Then confirm it's gone, by reopening the name on that provider.
        if (OpenKekDirect(service, provider)) {
            throw CliError(where + " was deleted, but a key under its name is still found; investigate before relying on it being gone");
        }

        Printf(stdout, "retired KEK for service \"%s\" (%s, %s)\n", service.c_str(), identity.c_str(),
                ProviderLabel(provider));
        if (args.fingerprint) {
            Printf(stdout, "every payload wrapped under it is now permanently unrecoverable\n");
        }

        // A key on the other provider, if any, is untouched - and may be the
        // one the service now resolves to. The deletion has already
        // succeeded, so a failure to look is only a note, never an error.
        try {
            std::vector<FoundKek> remaining = FindKeks(service);
            if (!remaining.empty()) {
                Printf(stdout, "note: service \"%s\" still has a key on the other provider (%s); run `%s status`\n",
                        service.c_str(), DescribeFound(remaining.front()).c_str(), kProgramNameNarrow);
            } else if (!args.fingerprint) {
                Printf(stdout, "service \"%s\" can now be provisioned again\n", service.c_str());
            }
        } catch (const CliError &e) {
            Printf(stdout, "note: could not check the other provider for a key under this name: %s\n",
                    e.message.c_str());
        }
    }

    // MARK: - Run: provision

    void RunProvision(const ProvisionArgs &args) {
        ValidateServiceCharset(args.serviceName);
        const bool created = EnsureKekProvisioned(args.serviceName);

        Fingerprint fp{};
        int32_t rc = ReadKekFingerprint(args.serviceName, fp);
        if (rc != HKDFGUARD_OK) {
            throw CliError(
                "the KEK for service \"" + args.serviceName + "\" exists but its fingerprint could not be read: " +
                DescribeStatus(rc));
        }
        // A KEK this operator didn't create could have been planted by
        // another administrator; the fingerprint is how to tell.
        if (created) {
            Printf(stdout, "fingerprint: %s -- record this; retire requires it\n", HexString(fp).c_str());
        } else {
            Printf(stdout, "fingerprint: %s -- confirm it matches the one recorded when this service was provisioned\n",
                    HexString(fp).c_str());
        }
        // Which version's KEK that was: the one this host's ClassicalMode
        // selects. Each version has its own KEK and fingerprint.
        Printf(stdout, "payload version: %s\n", PayloadVersionDescription(HostPayloadVersion()));
    }

    // MARK: - Run: wrap

    void RunWrap(WrapArgs &args) {
        // First, before anything touches a path: a UNC or mapped-drive path
        // would make this process connect to the server it names. The same
        // rule as hkdfguard_open_file. Before even that, the names
        // themselves: the path is used exactly as typed or not at all.
        RequireExactPathNames(args.keyFilePath, "--key-file-path " + args.keyFilePath);
        if (args.dekFile) {
            RequireExactPathNames(*args.dekFile, "--dek-file " + *args.dekFile);
        }
        RequireLocalDrivePath(args.keyFilePath, args.keyFilePath);
        if (args.dekFile) {
            RequireLocalDrivePath(*args.dekFile, "--dek-file " + *args.dekFile);
        }

        // The output path must be a real file at a real location - no
        // symlink, junction, or other reparse point at or above it, and none
        // followed to find out (see WalkToParent) - in folders
        // hkdfguard_open_file would trust (RequireTrustedKeyFileFolders: no
        // other account may create, delete or rename entries in any folder
        // below the drive root). Checked here, before any KEK or DEK work,
        // so a bad path is rejected cheaply; the write/overwrite code
        // re-checks on its own handles regardless. wrap never creates a
        // missing folder - a folder it made would inherit its parent's
        // rights, create rights included - so the operator prepares the
        // folder (docs/admin-guide.md) and a missing one is an error.
        //
        // Also fail before touching a key storage provider if the output
        // path already exists and --force wasn't passed. WriteWrappedKeyFile's
        // FILE_CREATE is the actual guarantee against the exists-then-create
        // race; this is a fail-fast convenience.
        const bool exists = ValidateOutputPathIsReal(args.keyFilePath);
        if (exists && !args.force) {
            throw CliError(args.keyFilePath + " already exists; pass --force|-f to overwrite");
        }

        // Resolved before any key storage provider work, so a bad --group
        // name fails before an expensive (and, with --force, destructive)
        // operation runs. Without --group: owner-only.
        KeyFileSecurity security(
            GetProcessOwnerSid(),
            args.groupName ? std::optional<std::vector<BYTE>>(ResolveGroupSid(*args.groupName)) : std::nullopt);

        // `service` is a logical identifier, not secret.
        ValidateServiceCharset(args.serviceName);
        const std::string &service = args.serviceName;

        std::vector<uint8_t> wrapped;
        {
            // Both the base64 text and the decoded DEK bytes are secret and
            // live only in `scratch` (locked into RAM, see DekScratch), which
            // is wiped when this block ends - right after WrapDek, not
            // through the slow secure-overwrite and file write below.
            // hkdfguard_wrap_dek never zeroes the DEK it is given (see
            // aes_gcm.cpp), so this caller-side wipe is the one that counts.
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

            // Never provisions: a missing KEK is reported by WrapDek with a
            // pointer to "provision".
            wrapped = WrapDek(service, scratch.decoded(), scratch.decodedLen);
            // Only the wrapped (encrypted) form survives past this block.
        }

        // Wrapping in memory is open to any account with key use on the KEK;
        // *persisting* the result is not. Under the production security
        // model (the default) only SYSTEM, Administrators, TrustedInstaller
        // and the deployer groups' members are trusted to have written a
        // key file - see hkdfguard_security_model - so a file this account
        // wrote would be refused by hkdfguard_open_file anyway. Asked of
        // the library, which applies exactly the rule it reads files by,
        // and checked before anything on disk is touched (--force's
        // overwrite included). After the wrap, so that every input is
        // still validated first.
        RequireMayPersistKeyFiles();

        if (args.force) {
            SecureOverwriteAndRemoveIfExists(args.keyFilePath);
        }

        WriteWrappedKeyFile(args.keyFilePath, wrapped, security);

        const std::string access =
                args.groupName ? "owner read/write + " + *args.groupName + " read-only" : std::string("owner read/write");
        Printf(
            stdout, "wrapped key written to %s (%zu bytes, %s, service \"%s\")\n",
            args.keyFilePath.c_str(), wrapped.size(), access.c_str(), service.c_str());
    }

    // Parses and runs one subcommand. Exit codes: 0 success, 1 operational
    // failure, 2 usage error (followed by the usage text).
    template <typename Args, typename Parse, typename Run>
    int Dispatch(int argc, char *argv[], Parse parse, Run run) {
        Args args;
        try {
            if (parse(argc, argv, args) == ParseOutcome::Help) {
                PrintUsage();
                return 0;
            }
        } catch (const CliError &e) {
            Printf(stderr, "error: %s\n", e.message.c_str());
            PrintUsage();
            return 2;
        }

        try {
            run(args);
            return 0;
        } catch (const CliError &e) {
            Printf(stderr, "error: %s\n", e.message.c_str());
            return 1;
        } catch (const std::exception &e) {
            Printf(stderr, "error: %hs\n", e.what());
            return 1;
        }
    }
} // namespace

int wmain(int argc, wchar_t *wargv[]) {
    // Before anything is read: this process holds a plaintext DEK, so it
    // must not be dumpable, debuggable or injectable by other processes of
    // the same user - including through threads the key storage provider
    // starts later, which is what the strict flag adds on Windows (see
    // hkdfguard_harden_process_with_flags). Refuse to run rather than handle
    // a DEK unprotected.
    {
        int rc = hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE);
        if (rc != HKDFGUARD_OK) {
            Printf(stderr, "error: %s; refusing to handle key material\n", DescribeStatus(rc).c_str());
            return 1;
        }
    }

    // The arguments as UTF-8, the encoding the rest of the tool and the
    // library's ABI work in. The conversion is exact or it fails: a lone
    // surrogate has no UTF-8 form, and a best-fit substitute would mean
    // acting on a different name than the one typed.
    std::vector<std::string> utf8Args;
    for (int i = 0; i < argc; ++i) {
        const int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) {
            Printf(stderr, "error: argument %d is not valid Unicode text\n", i);
            return 2;
        }
        std::string arg(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1, arg.data(), len, nullptr, nullptr);
        arg.resize(static_cast<size_t>(len) - 1); // without the terminator
        utf8Args.push_back(std::move(arg));
    }
    std::vector<char *> argv;
    for (std::string &arg : utf8Args) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    if (argc < 2) {
        Printf(stderr, "error: missing subcommand: expected %s\n", kSubcommandList);
        PrintUsage();
        return 2;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h" || command == "help") {
        PrintUsage();
        return 0;
    }

    if (command == "provision") {
        return Dispatch<ProvisionArgs>(argc, argv.data(), ParseProvisionArgs, RunProvision);
    }
    if (command == "wrap") {
        return Dispatch<WrapArgs>(argc, argv.data(), ParseWrapArgs, RunWrap);
    }
    if (command == "retire") {
        return Dispatch<RetireArgs>(argc, argv.data(), ParseRetireArgs, RunRetire);
    }
    if (command == "status") {
        return Dispatch<StatusArgs>(argc, argv.data(), ParseStatusArgs, RunStatus);
    }
    if (command == "prepare-store") {
        // No arguments: the store's place is fixed (ProgramData, located
        // through the known-folder API, never the environment).
        if (argc != 2) {
            Printf(stderr, "error: prepare-store takes no arguments\n");
            PrintUsage();
            return 2;
        }
        try {
            const std::wstring path = hkdfguard::PrepareTpmKeyStore(hkdfguard::DefaultTpmKeyStore());
            PrintfW(stdout, L"TPM key store ready: %ls\n", path.c_str());
            return 0;
        } catch (const hkdfguard::HkdfGuardError &e) {
            // The library's own message: the status codes' generic text
            // (DescribeStatus) is about KEKs, which this doesn't touch.
            Printf(stderr, "error: preparing the TPM key store failed: %s\n", e.what());
            if (e.code() == HKDFGUARD_ERR_KEK_ACCESS_DENIED) {
                Printf(stderr, "hint: run it from an elevated prompt\n");
            }
            if (e.code() == HKDFGUARD_ERR_KEK_INVALID) {
                Printf(stderr,
                       "hint: something is already at ProgramData\\HkdfGuard or its TpmKeys folder that this "
                       "account didn't create with the store's access list - possibly created by another user to "
                       "block provisioning. Investigate it, remove it, and run prepare-store again.\n");
            }
            return 1;
        }
    }

    Printf(stderr, "error: unknown subcommand \"%s\": expected %s\n", command.c_str(), kSubcommandList);
    PrintUsage();
    return 2;
}
