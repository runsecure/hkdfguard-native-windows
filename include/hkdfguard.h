// #ifndef / #define / #endif below is an "include guard": if this header
// gets #include'd more than once while compiling a single .cpp file (which
// happens easily once several of your own headers include each other), the
// guard makes every #include after the first one expand to nothing, so the
// compiler never sees the declarations twice.
#ifndef HKDFGUARD_H
#define HKDFGUARD_H

// stdint.h (the C header; <cstdint> is the C++-flavored equivalent) gives us
// uint8_t (unsigned, exactly 8 bits) for byte buffers. Lengths, status codes
// and flags are plain `int` / `unsigned int`, the same as the Linux and
// macOS headers, so one caller's code compiles against all three; `int` is
// 32 bits on every platform this ABI targets (Windows x64/ARM64, Linux,
// macOS), so bindings declare them as 32-bit integers. Windows' own type
// names (BYTE, DWORD, ...) intentionally do NOT appear anywhere in this file -
// the whole point of this header is to be usable from C, C#, Python, Java,
// Go, etc., none of which know what a DWORD is.
#include <stdint.h>

// __declspec(dllexport) / __declspec(dllimport) are MSVC-specific keywords
// that control whether a function's symbol is written into (export) or read
// from (import) a DLL's symbol table. The convention used here - define
// HKDFGUARD_API to dllexport while *building* the DLL, and to dllimport for
// anyone who *consumes* it - is the standard Windows way to share one header
// between the library's own .cpp files and its callers. HKDFGUARD_EXPORTS is
// defined only by this project's own build (see CMakeLists.txt); nobody
// #include-ing this header from outside the project defines it, so they
// automatically get the "import" branch.
#if defined(_WIN32)
#  if defined(HKDFGUARD_EXPORTS)
#    define HKDFGUARD_API __declspec(dllexport)
#  else
#    define HKDFGUARD_API __declspec(dllimport)
#  endif
#else
// Non-Windows platforms don't have dllexport/dllimport at all, so the macro
// just disappears (this branch exists only so the header doesn't hard-fail
// if some tool ever parses it on another OS; the library itself is
// Windows-only, see CMakeLists.txt).
#  define HKDFGUARD_API
#endif

// extern "C" tells the C++ compiler: "compile everything inside these braces
// using C linkage rules, not C++ ones." Without it, C++ would "mangle" the
// function names (encoding parameter types into the symbol name, e.g.
// hkdfguard_wrap_dek becomes something like ?hkdfguard_wrap_dek@@YAHPEBEH...)
// so that overloaded functions can coexist. A mangled name is compiler- and
// version-specific, so no other language's FFI (C#'s P/Invoke, Python's
// ctypes, Go's cgo, ...) could reliably call it. extern "C" pins the name to
// the plain, predictable string "hkdfguard_wrap_dek", which is what makes
// this a *stable C ABI*. __cplusplus is only defined when a C++ compiler is
// processing the file, so a plain C compiler (which has no notion of linkage
// specifications) skips this block entirely and just sees ordinary
// declarations.
#ifdef __cplusplus
extern "C" {
#endif

/*
 * hkdfguard-native-windows - Windows-native DEK wrapper.
 *
 * Wraps and unwraps a 32-byte Data Encryption Key (DEK) using a persistent,
 * machine-wide-scoped, non-exportable P-256 Key Encryption Key (KEK) held by
 * the Microsoft Platform Crypto Provider (TPM/vTPM) when available, or the
 * Microsoft Software Key Storage Provider otherwise. All Windows-specific
 * details (CNG/NCrypt handles, COM, provider selection) are fully contained
 * behind this ABI. No exception ever crosses this boundary; every function
 * returns one of the HKDFGUARD_* status codes below.
 */

// #define here creates a plain, untyped preprocessor macro: every later
// occurrence of the name HKDFGUARD_DEK_LEN in this file (and any file that
// #includes it) is textually replaced with 32 before the compiler proper
// ever runs. This is the traditional C way of naming a constant so it can
// also be used where the language requires a compile-time literal.
#define HKDFGUARD_DEK_LEN     32
/* Largest wrapped payload hkdfguard_wrap_dek / hkdfguard_generate_and_wrap_dek
 * can produce - the same name as on Linux and macOS, so a buffer of this size
 * never needs a retry on any of them. On Windows every payload is exactly this
 * size (a WrappedDekV1 payload, incl. 32-byte salt and 32-byte KEK
 * fingerprint); the Linux and macOS values differ, since a payload is only
 * ever unwrapped on the host that wrapped it. */
#define HKDFGUARD_WRAPPED_MAX_LEN 132

// Status codes. HKDFGUARD_OK is 0 (following the common C convention that
// "0 means success"); every failure is a distinct *negative* number, so a
// caller can cheaply test "did this fail?" with `if (rc < 0)` without having
// to know the individual codes, while still being able to branch on the
// exact one if they care. The parentheses around the negative numbers, e.g.
// (-1), are just defensive style: they stop the macro from being
// misinterpreted if it's ever substituted next to another operator in a
// caller's expression, e.g. `x - HKDFGUARD_ERR_INVALID_ARGUMENT` — with no
// parens that would textually become `x - -1`.
//
// This table is shared, number for number, by all three implementations of
// this C ABI (hkdfguard-native-windows, -linux and -macos), so a caller - or
// a managed wrapper sitting above all three - can interpret a status code
// the same way on every platform. Every code is #define'd here, including
// ones only another platform returns (marked "not returned on Windows"), so
// portable code can name them without #ifdef'ing per platform. The numbers
// are grouped into bands, with gaps left reserved so each band can grow
// without renumbering anything:
//
//     0           success
//    -1 ..  -7    general: argument, buffer, provider, crypto, internal
//    -8 ..  -9    service name and machine policy
//   -10 .. -15    wrapped payload (malformed / auth failed / unsupported)
//   -16 .. -31    KEK (fingerprint, existence, access, integrity) and
//                 process hardening
//   -32 .. -63    hkdfguard_open_file's key-file checks, then reserved for
//                 future common codes
//   -64 .. -79    Windows-specific
//   -80 .. -95    Linux-specific (none defined yet)
//   -96 .. -111   macOS-specific
//
// A code in a platform band is always a more precise *refinement* of one of
// the common codes above it (each one's comment names which). A caller that
// only wants portable handling may treat any code in a platform band exactly
// as the common code it refines - e.g. HKDFGUARD_ERR_WIN_GROUP_INVALID as
// HKDFGUARD_ERR_POLICY_INVALID.
#define HKDFGUARD_OK                              0
// ---- General (-1..-7) ----
#define HKDFGUARD_ERR_INVALID_ARGUMENT           (-1) /* null pointer, wrong dek length, bad path argument, etc. */
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL           (-2) /* *out_len on input is too small for the result */
#define HKDFGUARD_ERR_PROVIDER_UNAVAILABLE       (-3) /* no key storage provider could be used at all; not returned on Windows (a KSP failure is HKDFGUARD_ERR_PROVIDER_ERROR) */
#define HKDFGUARD_ERR_PROVIDER_ERROR             (-4) /* KEK provider/key open or create failed */
#define HKDFGUARD_ERR_CRYPTO_ERROR               (-5) /* ECDH/HKDF/AES/RNG operation failed (not an authentication failure) */
#define HKDFGUARD_ERR_INTERNAL_ERROR             (-6) /* unexpected internal failure */
/* -7 reserved */
// ---- Service name and policy (-8..-9) ----
#define HKDFGUARD_ERR_INVALID_SERVICE_NAME       (-8) /* service is null, empty, too long, not valid UTF-8, or contains a disallowed character */
#define HKDFGUARD_ERR_POLICY_INVALID             (-9) /* a machine policy value (HKLM\Software\Policies\HkdfGuard) is invalid */
// ---- Wrapped payload (-10..-15) ----
#define HKDFGUARD_ERR_PAYLOAD_MALFORMED         (-10) /* wrapped payload is not a valid WrappedDekV1: wrong length, nonzero reserved bytes, or unknown provider type or key id */
#define HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED       (-11) /* AES-GCM authentication tag verification failed */
#define HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED       (-12) /* wrapped payload's version (or suite) is not one this build understands */
/* -13..-15 reserved */
// ---- KEK and process (-16..-31) ----
#define HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH  (-16) /* payload's KEK fingerprint does not match the KEK it routes to */
#define HKDFGUARD_ERR_KEK_NOT_FOUND             (-17) /* no KEK is provisioned for this service (call hkdfguard_create_kek first) */
#define HKDFGUARD_ERR_KEK_ACCESS_DENIED         (-18) /* this KEK exists, but the calling account is not authorized to use it (or, for a new KEK, the process is not elevated) */
#define HKDFGUARD_ERR_KEK_INVALID               (-19) /* an existing KEK is unusable as found: on Windows, its ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal */
#define HKDFGUARD_ERR_PROCESS_HARDENING_FAILED  (-20) /* hkdfguard_harden_process(_with_flags): a hardening step failed (steps already applied stay applied), or (with HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) the process could not be closed to its own user */
/* -21..-31 reserved */
// ---- Key file, hkdfguard_open_file (-32..-39) ----
#define HKDFGUARD_ERR_FILE_NOT_FOUND            (-32) /* hkdfguard_open_file: the file (or a folder in its path) does not exist */
#define HKDFGUARD_ERR_FILE_ACCESS_DENIED        (-33) /* hkdfguard_open_file: the calling account may not read the file */
#define HKDFGUARD_ERR_FILE_IO                   (-34) /* hkdfguard_open_file: not a regular file, in use by a writer, or a read failed */
#define HKDFGUARD_ERR_FILE_TOO_SHORT            (-35) /* hkdfguard_open_file: file is shorter than HKDFGUARD_WRAPPED_MAX_LEN */
#define HKDFGUARD_ERR_FILE_TOO_LONG             (-36) /* hkdfguard_open_file: file is longer than HKDFGUARD_WRAPPED_MAX_LEN */
#define HKDFGUARD_ERR_FILE_PLAINTEXT_KEY        (-37) /* hkdfguard_open_file: file holds what looks like an unwrapped key - HKDFGUARD_DEK_LEN raw bytes, or its hex or base64 */
#define HKDFGUARD_ERR_FILE_MALFORMED            (-38) /* hkdfguard_open_file: file is the right size but its contents are not a valid WrappedDekV1 payload (including an unknown version) */
#define HKDFGUARD_ERR_FILE_UNTRUSTED            (-39) /* hkdfguard_open_file: path is, or passes through, a symbolic link, junction or other reparse point, uses an 8.3 short name, or is not on a local drive (UNC, mapped or SUBST drive, device); or the file or a folder above it is owned by, or lets, an account other than SYSTEM, Administrators, TrustedInstaller or the caller write or replace it */
/* -40..-63 reserved for future common codes */
// ---- Windows-specific (-64..-79) ----
#define HKDFGUARD_ERR_WIN_GROUP_INVALID         (-64) /* refines HKDFGUARD_ERR_POLICY_INVALID: a KeyUseGroups policy entry is unresolvable, not a group, not host-local, or over-broad */
// ---- Linux-specific (-80..-95): none defined yet ----
// ---- macOS-specific (-96..-111); each refines HKDFGUARD_ERR_PROVIDER_ERROR, none returned on Windows ----
#define HKDFGUARD_ERR_MAC_ACCESS_CONTROL_CREATION_FAILED  (-96) /* macOS: creating the KEK's keychain access-control object failed; not returned on Windows */
#define HKDFGUARD_ERR_MAC_KEY_GENERATION_FAILED           (-97) /* macOS: generating the KEK failed; not returned on Windows */
#define HKDFGUARD_ERR_MAC_KEYCHAIN_WRITE_FAILED           (-98) /* macOS: storing the KEK in the keychain failed; not returned on Windows */
#define HKDFGUARD_ERR_MAC_KEK_VERIFICATION_FAILED         (-99) /* macOS: verifying an existing KEK's properties failed; not returned on Windows */
#define HKDFGUARD_ERR_MAC_KEYCHAIN_READ_FAILED           (-100) /* macOS: reading the KEK from the keychain failed; not returned on Windows */

/*
 * Reports whether a persistent KEK already exists for `service`, without
 * creating or modifying anything. Subject to the same setup latency floor
 * and serialization as hkdfguard_create_kek below; "exists" and "doesn't
 * exist" take the same time.
 *
 * service     - see hkdfguard_wrap_dek.
 * out_exists  - caller-owned output. On success, set to 1 if the KEK exists,
 *               0 otherwise.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * including HKDFGUARD_ERR_KEK_ACCESS_DENIED if a KEK is present but the
 * calling account cannot even open it to confirm that (existence could not
 * be determined, as opposed to *out_exists being a reliable 0).
 * *out_exists is left untouched on failure.
 */
HKDFGUARD_API int hkdfguard_kek_exists(
    const char* service,
    int* out_exists);

/* Length of a KEK fingerprint, as written by hkdfguard_kek_fingerprint. */
#define HKDFGUARD_KEK_FINGERPRINT_LEN 32

/*
 * Writes the fingerprint of the KEK `service` currently resolves to under
 * the KeyStoragePolicy - the KEK hkdfguard_wrap_dek would use - to `out`:
 * SHA-256 of its public key's raw X || Y coordinates (64 bytes, no 0x04
 * prefix), the same value embedded in every payload wrapped under it (bytes
 * 100..131). Public-key material, not a secret. Lets an operator record which
 * KEK a service uses after provisioning, and confirm it before retiring it
 * (hkdfguard.exe retire). Never creates a KEK, and is not slowed by the setup
 * floor: it opens the KEK exactly as hkdfguard_wrap_dek does.
 *
 * Shared with the macOS build (same name and signature; on Windows the
 * buffer contract is the one every function here follows); not in the Linux
 * build. Each platform hashes its own public-key encoding, so the values are
 * only ever compared on the host that produced them.
 *
 * service - see hkdfguard_wrap_dek.
 * out     - caller-owned output buffer. May be NULL only if *out_len is 0, to
 *           probe the required size.
 * out_len - in: capacity of out, in bytes (negative returns
 *           HKDFGUARD_ERR_INVALID_ARGUMENT). out: on success
 *           HKDFGUARD_KEK_FINGERPRINT_LEN. On HKDFGUARD_ERR_BUFFER_TOO_SMALL,
 *           the required capacity (HKDFGUARD_KEK_FINGERPRINT_LEN), reported
 *           after the service name is checked, without reaching a provider.
 *           Left unchanged on every other failure.
 *
 * Returns HKDFGUARD_OK, or a negative HKDFGUARD_ERR_* code - notably
 * HKDFGUARD_ERR_KEK_NOT_FOUND if no KEK is provisioned for the service,
 * HKDFGUARD_ERR_KEK_ACCESS_DENIED if the calling account may not open it, and
 * HKDFGUARD_ERR_PROVIDER_ERROR if a key exists under the service's name but
 * fails the same property checks hkdfguard_wrap_dek applies (not a
 * non-exportable P-256 ECDH key with the expected usage).
 */
HKDFGUARD_API int hkdfguard_kek_fingerprint(
    const char* service,
    uint8_t* out, int* out_len);

/*
 * Creates the persistent KEK for `service` if it does not already exist, or
 * verifies its properties if it does. Safe to call more than once for the
 * same service.
 *
 * Deliberately slow: this and hkdfguard_kek_exists are setup calls, meant
 * to run once per application startup. Each takes at least one second of
 * wall-clock time, whatever its outcome, and they run one at a time across
 * threads. The floor is the REG_DWORD value
 *
 *     HKLM\Software\Policies\HkdfGuard\SetupMinDelayMs
 *
 * in milliseconds: 1000 when absent, 0 disables it, at most 60000. A value
 * of the wrong type or above 60000 keeps the 1000 ms default. Do not call
 * them per request; call once at startup and then use hkdfguard_wrap_dek /
 * hkdfguard_unwrap_dek, which are not slowed. Argument errors (null
 * pointer, invalid service name) return immediately. After more than 10
 * setup calls in one process, event 2007 is logged once. This matches the
 * Linux build's startup_behavior.setup_min_delay_ms.
 *
 * Which principals may use (unwrap with) the KEK is machine policy, not a
 * caller choice. SYSTEM and BUILTIN\Administrators always receive full
 * control. Two optional local groups are honored if they exist - as groups
 * in this machine's own SAM - at the moment the KEK is created:
 * HkdfGuardAdmins receives full control and HkdfGuardUsers receives
 * key-use access. The MSI creates HkdfGuardUsers; HkdfGuardAdmins exists
 * only if an administrator creates it. In addition, every entry of the
 * REG_MULTI_SZ registry value
 *
 *     HKLM\Software\Policies\HkdfGuard\KeyUseGroups
 *
 * is granted key-use access when the KEK is created. An entry is either a
 * group name (e.g. "MYDOMAIN\KeyUsers", "Cryptographic Operators") or a SID
 * string (e.g. "S-1-5-21-...-1234"); surrounding whitespace is ignored.
 * Each entry must resolve to a group - a user or computer account is
 * rejected - and must not be an over-broad principal: Everyone,
 * Authenticated Users, Users, Guests, Anonymous, NULL SID, Local account,
 * This Organization, ALL SERVICES, LOCAL, CONSOLE LOGON, or the logon-type
 * groups INTERACTIVE, NETWORK, BATCH, SERVICE and REMOTE INTERACTIVE LOGON.
 * It must also be host-local: a group in this machine's own SAM, or a
 * BUILTIN, NT AUTHORITY or NT SERVICE principal. This protection is host-specific, so domain
 * groups are rejected even on a domain-joined machine, whether written
 * domain-qualified or not. Any entry failing these checks fails the whole
 * call with HKDFGUARD_ERR_WIN_GROUP_INVALID before any key is created. A
 * missing or empty value grants no additional principals.
 *
 * The ACL is applied only when the KEK is first created. Changing the
 * policy afterwards does not alter an existing KEK's ACL; a later call for
 * an already-provisioned service verifies the key and returns HKDFGUARD_OK
 * without modifying access. That verification does check the existing ACL
 * against invariants that hold for every KEK this library creates,
 * independent of policy: it must be a real (non-NULL) DACL, it must include
 * SYSTEM and BUILTIN\Administrators, and it must grant nothing to an
 * over-broad principal (the same list rejected above). A key failing any of
 * these - most plausibly one pre-planted under this service's name, or one
 * whose ACL was later widened - fails the call with
 * HKDFGUARD_ERR_KEK_INVALID and is left exactly as found; it is never
 * modified, replaced or deleted.
 *
 * service - see hkdfguard_wrap_dek.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * notably HKDFGUARD_ERR_KEK_ACCESS_DENIED, which covers two distinct cases: the
 * service's KEK already exists but the calling account cannot even open it
 * to verify it, or the KEK does not exist yet and this process is not
 * elevated (creating a *new* machine-scoped KEK requires an elevated
 * process - opening/using an existing one does not; see the "Deployment
 * model" note in README.md).
 */
HKDFGUARD_API int hkdfguard_create_kek(
    const char* service);

/*
 * Wraps a 32-byte DEK into a self-contained, versioned payload.
 *
 * The wrapping key is derived from ECDH between the KEK's *private* key and
 * a point hashed from a random per-payload salt, so only an account
 * authorized to use the KEK can create a payload that hkdfguard_unwrap_dek
 * accepts - knowing the KEK's public key is not enough. For a TPM-backed KEK
 * that makes every wrap a TPM operation (around 10 ms).
 *
 * service   - null-terminated UTF-8 string identifying which persistent KEK
 *             to use (e.g. an application or tenant name). Different service
 *             names get independent, non-interoperable KEKs. The same
 *             service name must be passed to hkdfguard_unwrap_dek to unwrap
 *             a payload produced with it; the service name itself is not
 *             recorded in the wrapped payload. Must be non-null, non-empty,
 *             and at most 128 bytes (excluding the null terminator), and may
 *             only contain ASCII letters, digits, and '.', may not start with
 *             '.' and may not contain ".."; anything else
 *             (including NULL) fails with HKDFGUARD_ERR_INVALID_SERVICE_NAME,
 *             on this and every other function taking `service`.
 *             Case-insensitive: normalized to lowercase internally, so
 *             "MyApp" and "myapp" identify the same KEK and may
 *             be used interchangeably across hkdfguard_create_kek/
 *             hkdfguard_kek_exists/hkdfguard_wrap_dek/
 *             hkdfguard_unwrap_dek calls for the same logical service.
 *             hkdfguard_create_kek must have already provisioned this
 *             service's KEK; this function never creates one.
 * dek       - pointer to exactly HKDFGUARD_DEK_LEN bytes of plaintext DEK.
 * dek_len   - must equal HKDFGUARD_DEK_LEN.
 * out       - caller-owned output buffer. May be NULL only if *out_len is
 *             0, to probe the required size; a NULL `out` with a positive
 *             *out_len returns HKDFGUARD_ERR_INVALID_ARGUMENT.
 * out_len   - in: capacity of out, in bytes. Negative returns
 *             HKDFGUARD_ERR_INVALID_ARGUMENT.
 *             out: on success, the number of bytes written (always
 *             HKDFGUARD_WRAPPED_MAX_LEN). On HKDFGUARD_ERR_BUFFER_TOO_SMALL,
 *             the required capacity (HKDFGUARD_WRAPPED_MAX_LEN), answered
 *             at once without reaching a provider - after the service name
 *             is checked, so an invalid one is reported first. Left
 *             unchanged on every other failure. The same contract as the
 *             Linux and macOS builds.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * notably HKDFGUARD_ERR_KEK_NOT_FOUND if hkdfguard_create_kek has not yet
 * provisioned this service's KEK, or HKDFGUARD_ERR_KEK_ACCESS_DENIED if it has
 * but the calling account is not authorized to use it (see
 * hkdfguard_create_kek's KeyUseGroups policy). On failure, no partial
 * output is left in the caller's buffer.
*/

HKDFGUARD_API int hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int dek_len,
    uint8_t* out, int* out_len);

/*
 * Unwraps a payload produced by hkdfguard_wrap_dek back into a 32-byte DEK.
 *
 * service     - must be the same service name passed to hkdfguard_wrap_dek
 *               when this payload was produced; see hkdfguard_wrap_dek.
 * wrapped     - pointer to the wrapped payload.
 * wrapped_len - length of the wrapped payload in bytes.
 * out         - caller-owned output buffer. May be NULL only if *out_len
 *               is 0, to probe the required size.
 * out_len     - in: capacity of out, in bytes (must be >= HKDFGUARD_DEK_LEN;
 *               negative returns HKDFGUARD_ERR_INVALID_ARGUMENT).
 *               out: on success, the number of plaintext bytes written
 *               (always HKDFGUARD_DEK_LEN). On
 *               HKDFGUARD_ERR_BUFFER_TOO_SMALL, the required capacity
 *               (HKDFGUARD_DEK_LEN), reported after the service name is
 *               checked but before the payload is even parsed - no
 *               provider is reached. Left unchanged on every other failure.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * HKDFGUARD_ERR_INVALID_ARGUMENT for a null `wrapped` or `out_len`, or a
 * negative `wrapped_len`.
 * HKDFGUARD_ERR_PAYLOAD_MALFORMED means a structurally invalid payload
 * (wrong length, nonzero reserved bytes, unknown provider type or KeyId).
 * The salt has no structure: a changed salt yields a different wrapping
 * key, so it surfaces as HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED.
 * HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED means the payload's version byte is not
 * one this build understands. HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH
 * means the payload is well-formed but was wrapped under a different KEK
 * than the one this service currently routes to (its embedded KEK
 * fingerprint doesn't match) - detected before any ECDH or decryption is
 * attempted, and distinct from HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED, which now
 * indicates tampering with a payload that *does* belong to this KEK.
 * HKDFGUARD_ERR_KEK_NOT_FOUND and HKDFGUARD_ERR_KEK_ACCESS_DENIED are as
 * described on hkdfguard_wrap_dek.
 * On any failure (including authentication failure), the output buffer is
 * zeroed before returning; no plaintext is left behind.
 */
HKDFGUARD_API int hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int wrapped_len,
    uint8_t* out, int* out_len);

/*
 * Generates a fresh random 32-byte DEK and wraps it, in one call; the
 * plaintext DEK never leaves the library. `service`, `out` and `out_len`
 * behave exactly as on hkdfguard_wrap_dek, including the required capacity
 * reported on HKDFGUARD_ERR_BUFFER_TOO_SMALL.
 */
HKDFGUARD_API int hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out, int* out_len);

/*
 * Reads a wrapped-key file (e.g. one written by hkdfguard.exe
 * wrap) and returns its WRAPPED DEK bytes in `out`, exactly as stored on
 * disk. Reads exactly HKDFGUARD_WRAPPED_MAX_LEN bytes and checks they are a
 * well-formed WrappedDekV1 payload. This call never unwraps: nothing is
 * decrypted, no KEK is opened, and the calling account needs no access to
 * any KEK - only read access to the file. Unwrapping is a separate, later
 * step (hkdfguard_unwrap_dek on the returned bytes), typically by other
 * code.
 *
 * path    - null-terminated UTF-8 path to the file: absolute, or relative to
 *           the process's current directory. The same rules as the CLI's
 *           --key-file-path apply, and fail with
 *           HKDFGUARD_ERR_FILE_UNTRUSTED: it must be a real file on a
 *           local drive ("C:\..."), reached through real directories. A
 *           symbolic link, junction, volume mount point or other reparse
 *           point at the path or anywhere above it is refused, never
 *           followed - so a link planted in the key folder cannot redirect
 *           a privileged reader to some other file. A path that spells any
 *           folder or the file with its 8.3 short name ("PROGRA~1") is
 *           refused too, rather than expanded; a genuine long name that
 *           merely contains "~" is fine. (Files on volumes with
 *           Data Deduplication enabled, and cloud placeholder files, are
 *           reparse points too and are refused for the same reason.) UNC
 *           paths, mapped and SUBST drives, and device paths (\\.\pipe\...,
 *           NUL) are refused before anything is opened, so this process
 *           never connects or authenticates to a server named in a path.
 *           Must also name a regular file: directories are refused. Opened
 *           read-only, sharing read access only, so a file that another
 *           process has open for writing is refused rather than read
 *           mid-write.
 *           The file, and every folder above it up to the drive root,
 *           must be owned by SYSTEM, BUILTIN\Administrators,
 *           TrustedInstaller or the account this process runs as, and
 *           must grant no other account the right to change it: on the
 *           file, write, append, write attributes or extended attributes,
 *           delete, change permissions or take ownership; on a folder,
 *           delete entries in it, delete the folder itself, change its
 *           permissions or take ownership. (Creating new entries in a
 *           folder is fine - C:\ProgramData lets Users do that.)
 *           Otherwise HKDFGUARD_ERR_FILE_UNTRUSTED: reading a wrapped DEK
 *           gains nothing, but anyone able to replace it, and to wrap
 *           under the service's KEK, could plant a DEK they know. A folder
 *           created directly under C:\ inherits "Authenticated Users:
 *           Modify" and fails this until its permissions are narrowed.
 *           Read access for other accounts is never a reason to refuse:
 *           the file is ciphertext.
 * out     - caller-owned output buffer. May be NULL only if *out_len is
 *           0, to probe the required size.
 * out_len - in: capacity of out, in bytes (must be >= HKDFGUARD_WRAPPED_MAX_LEN;
 *           negative returns HKDFGUARD_ERR_INVALID_ARGUMENT).
 *           out: on success, the number of bytes read (always
 *           HKDFGUARD_WRAPPED_MAX_LEN). On HKDFGUARD_ERR_BUFFER_TOO_SMALL, the
 *           required capacity (HKDFGUARD_WRAPPED_MAX_LEN), answered after
 *           `path` is checked but without opening the file. Left unchanged
 *           on every other failure - the same contract as
 *           hkdfguard_wrap_dek and hkdfguard_unwrap_dek, and as the Linux
 *           and macOS builds.
 *
 * The file's size is checked before any of it is read:
 *   HKDFGUARD_ERR_FILE_PLAINTEXT_KEY - exactly HKDFGUARD_DEK_LEN (32) bytes:
 *       the size of an *unwrapped* DEK, so most likely a plaintext key
 *       written to disk by mistake. Treat it as a key exposure. The file's
 *       contents are never read, so the possible key never enters this
 *       process. Also returned for a DEK written as text: 64 hex digits
 *       (either case) or base64 (standard or URL-safe, with or without its
 *       '=' padding), with any leading or trailing whitespace. To tell, a
 *       file of 96 bytes or fewer is read into a buffer that is wiped
 *       afterwards; none of it is returned.
 *   HKDFGUARD_ERR_FILE_TOO_SHORT - any other size below HKDFGUARD_WRAPPED_MAX_LEN,
 *       including an empty file.
 *   HKDFGUARD_ERR_FILE_TOO_LONG - more than HKDFGUARD_WRAPPED_MAX_LEN bytes.
 * A file of exactly HKDFGUARD_WRAPPED_MAX_LEN bytes is then read and validated
 * as hkdfguard_unwrap_dek would before touching a KEK - version, provider
 * type, reserved bytes and KeyId (the salt has no structure to check) -
 * failing with HKDFGUARD_ERR_FILE_MALFORMED otherwise. That includes an
 * unrecognized version: this call reports the *file* as malformed rather
 * than returning the payload codes (HKDFGUARD_ERR_PAYLOAD_MALFORMED /
 * _UNSUPPORTED) hkdfguard_unwrap_dek would, matching the Linux and macOS
 * builds. HKDFGUARD_ERR_FILE_NOT_FOUND, HKDFGUARD_ERR_FILE_ACCESS_DENIED
 * and HKDFGUARD_ERR_FILE_IO report why the file couldn't be opened or read.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * HKDFGUARD_ERR_INVALID_ARGUMENT for a null `path` or `out_len`, a negative
 * capacity, a NULL `out` with a positive capacity, or a path that is
 * empty, not valid UTF-8, or longer than Windows allows (32,767
 * characters). On any failure, the output buffer is zeroed before
 * returning (unless `out_len` is NULL: then nothing is written).
 */
HKDFGUARD_API int hkdfguard_open_file(
    const char* path,
    uint8_t* out, int* out_len);

/*
 * Hardens the calling process against disclosure of its memory - where DEKs
 * and wrapping keys live while a call is in progress. The Windows
 * counterpart of the Linux build's function of the same name (which turns
 * off core dumps and ptrace attach). Opt-in: the library never calls this
 * itself, since it changes process-wide state the host owns. Call it once,
 * early - before handling any key material, and ideally before starting
 * worker threads (see below).
 *
 * It does three things:
 *   1. Windows Error Reporting leaves the heap out of any crash report it
 *      collects for this process (WerSetFlags NOHEAP).
 *   2. The process object's DACL is replaced: only SYSTEM may read or write
 *      its memory, inject threads, duplicate its handles, or change its
 *      security. The account it runs as - from any of its processes - keeps
 *      only query, synchronize and terminate access, so tools can still list
 *      it, wait on it and stop it, but cannot dump it (Task Manager's "Create
 *      dump file", procdump, MiniDumpWriteDump) or attach a debugger.
 *   3. Every thread that exists at the time of the call is restricted the
 *      same way, so its registers can't be read or its execution redirected.
 *
 * Limits - this is a same-user barrier, not a boundary against
 * administrators:
 *   - Administrators holding SeDebugPrivilege, SYSTEM, and kernel code
 *     bypass a DACL entirely.
 *   - Threads created after the call keep the default thread DACL; their
 *     registers stay readable, and their execution redirectable, by the
 *     same user (the process's memory does not). Call again after starting
 *     threads to cover them, or pass
 *     HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE (below), which covers
 *     them for good.
 *   - Handles to the process or its threads opened *before* the call keep
 *     the access they were opened with.
 *   - Memory paged to the page file, or written to hiberfil.sys, is outside
 *     the process's control; so are full dumps configured machine-wide by an
 *     administrator (WER LocalDumps, kernel dumps).
 *
 *   - A GUI process can still have code injected by a same-user process
 *     on the same desktop through window hooks (SetWindowsHookEx); no
 *     process or thread DACL covers that. Host key-handling code in a
 *     process without windows (a service or console process).
 *
 * Idempotent: safe to call more than once.
 *
 * Same as hkdfguard_harden_process_with_flags(0).
 *
 * Returns HKDFGUARD_OK, or HKDFGUARD_ERR_PROCESS_HARDENING_FAILED if any
 * step failed. Steps applied before the failure stay applied - there is no
 * rollback.
 */
HKDFGUARD_API int hkdfguard_harden_process(void);

/*
 * Flags for hkdfguard_harden_process_with_flags. Shared by every platform:
 * a flag has the same bit everywhere, and every platform accepts every
 * flag defined here.
 *
 * HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: fail with
 *     HKDFGUARD_ERR_PROCESS_HARDENING_FAILED unless no other process of the
 *     same user can attach a debugger to, or inject code into, this
 *     process.
 *       macOS: that depends on the host executable's code signature, which
 *         the library can only check.
 *       Linux: PR_SET_DUMPABLE already guarantees it; no further check.
 *       Windows: the three steps above leave threads created after the
 *         call open (see "Limits"), so this flag adds two more, applied
 *         first:
 *           4. The process token's default DACL - which every unnamed
 *              object the process creates from then on receives, threads
 *              included - is replaced: SYSTEM keeps every right, and the
 *              account only SYNCHRONIZE and READ_CONTROL. Later threads
 *              are then as closed as existing ones.
 *           5. The process token's own DACL is replaced so the account may
 *              only query and duplicate it (the TPM key store duplicates its
 *              own token) - otherwise a same-user process could open the
 *              token and put the old default DACL back.
 *         The cost is the reason it's a flag: everything the process
 *         creates afterwards without an explicit security descriptor -
 *         child processes, named pipes, named events and other named
 *         objects - is closed to its own user too. A same-user client can't
 *         connect to a pipe it created with a NULL security descriptor, and
 *         a child process can't be stopped by Task Manager (its creator's
 *         handle still works). Use it in a service or console process that
 *         doesn't share objects with other processes by name. Window
 *         hooks into a GUI process stay outside it (see "Limits").
 */
#define HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE 0x1u

/*
 * hkdfguard_harden_process, with `flags` - a bitwise OR of
 * HKDFGUARD_HARDEN_* flags, or 0 - choosing how strict it is. Idempotent
 * in either mode, and a call without the flag after one with it leaves the
 * stricter state in place.
 *
 * Returns HKDFGUARD_OK; HKDFGUARD_ERR_INVALID_ARGUMENT if `flags` has a
 * bit this library doesn't know (checked before anything is changed, so a
 * newer flag is never silently ignored); or
 * HKDFGUARD_ERR_PROCESS_HARDENING_FAILED.
 */
HKDFGUARD_API int hkdfguard_harden_process_with_flags(unsigned int flags);

// Closes the extern "C" block opened above.
#ifdef __cplusplus
}
#endif

// Closes the include guard opened at the top of the file.
#endif /* HKDFGUARD_H */
