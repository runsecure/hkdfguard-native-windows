// #ifndef / #define / #endif below is an "include guard": if this header
// gets #include'd more than once while compiling a single .cpp file (which
// happens easily once several of your own headers include each other), the
// guard makes every #include after the first one expand to nothing, so the
// compiler never sees the declarations twice.
#ifndef HKDFGUARD_H
#define HKDFGUARD_H

// stdint.h (the C header; <cstdint> is the C++-flavored equivalent) gives us
// fixed-width integer types like uint8_t (unsigned, exactly 8 bits) and
// int32_t (signed, exactly 32 bits). Windows' own type names (BYTE, DWORD,
// ...) intentionally do NOT appear anywhere in this file - the whole point
// of this header is to be usable from C, C#, Python, Java, Go, etc., none of
// which know what a DWORD is.
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
#define HKDFGUARD_WRAPPED_LEN 164 /* fixed size of a WrappedDekV1 payload (incl. 32-byte KEK fingerprint) */

// Status codes. HKDFGUARD_OK is 0 (following the common C convention that
// "0 means success"); every failure is a distinct *negative* number, so a
// caller can cheaply test "did this fail?" with `if (rc < 0)` without having
// to know the individual codes, while still being able to branch on the
// exact one if they care. The parentheses around the negative numbers, e.g.
// (-1), are just defensive style: they stop the macro from being
// misinterpreted if it's ever substituted next to another operator in a
// caller's expression, e.g. `x - HKDFGUARD_ERR_INVALID_ARG` — with no
// parens that would textually become `x - -1`.
#define HKDFGUARD_OK                    0
#define HKDFGUARD_ERR_INVALID_ARG      (-1) /* null pointer, wrong dek length, bad service, etc. */
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL (-2) /* *out_len on input is too small for the result */
#define HKDFGUARD_ERR_PROVIDER         (-3) /* KEK provider/key open or create failed */
#define HKDFGUARD_ERR_CRYPTO           (-4) /* ECDH/HKDF/AES operation failed (non-auth) */
#define HKDFGUARD_ERR_AUTH_FAILED      (-5) /* AES-GCM authentication tag verification failed */
#define HKDFGUARD_ERR_MALFORMED        (-6) /* wrapped payload is not a valid WrappedDekV1 */
#define HKDFGUARD_ERR_INTERNAL         (-7) /* unexpected internal failure */
#define HKDFGUARD_ERR_SERVICE_NAME_INVALID (-8) /* Service Name is malformed or invalid */
#define HKDFGUARD_ERR_INVALID_POLICY   (-9) /* Invalid Key Storage Policy Flag */
#define HKDFGUARD_ERR_GROUP_INVALID   (-10) /* KeyUseGroups policy entry is unresolvable, not a group, or over-broad */
#define HKDFGUARD_ERR_KEK_MISMATCH    (-11) /* payload's KEK fingerprint does not match the KEK it routes to */
#define HKDFGUARD_ERR_KEK_NOT_FOUND   (-12) /* no KEK is provisioned for this service (call hkdfguard_create_kek first) */
#define HKDFGUARD_ERR_ACCESS_DENIED   (-13) /* this KEK exists, but the calling account is not authorized to use it */
#define HKDFGUARD_ERR_KEK_ACL_INVALID (-14) /* an existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal */

/*
 * Reports whether a persistent KEK already exists for `service`, without
 * creating or modifying anything.
 *
 * service     - see hkdfguard_wrap_dek.
 * out_exists  - caller-owned output. On success, set to 1 if the KEK exists,
 *               0 otherwise.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * including HKDFGUARD_ERR_ACCESS_DENIED if a KEK is present but the
 * calling account cannot even open it to confirm that (existence could not
 * be determined, as opposed to *out_exists being a reliable 0).
 * *out_exists is left untouched on failure.
 */
HKDFGUARD_API int32_t hkdfguard_kek_exists(
    const char* service,
    int32_t* out_exists);

/*
 * Creates the persistent KEK for `service` if it does not already exist, or
 * verifies its properties if it does. Safe to call more than once for the
 * same service.
 *
 * Which principals may use (unwrap with) the KEK is machine policy, not a
 * caller choice. SYSTEM and BUILTIN\Administrators always receive full
 * control. In addition, every entry of the REG_MULTI_SZ registry value
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
 * call with HKDFGUARD_ERR_GROUP_INVALID before any key is created. A
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
 * HKDFGUARD_ERR_KEK_ACL_INVALID and is left exactly as found; it is never
 * modified, replaced or deleted.
 *
 * service - see hkdfguard_wrap_dek.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * notably HKDFGUARD_ERR_ACCESS_DENIED, which covers two distinct cases: the
 * service's KEK already exists but the calling account cannot even open it
 * to verify it, or the KEK does not exist yet and this process is not
 * elevated (creating a *new* machine-scoped KEK requires an elevated
 * process - opening/using an existing one does not; see the "Deployment
 * model" note in README.md).
 */
HKDFGUARD_API int32_t hkdfguard_create_kek(
    const char* service);

/*
 * Wraps a 32-byte DEK into a self-contained, versioned payload.
 *
 * service   - null-terminated UTF-8 string identifying which persistent KEK
 *             to use (e.g. an application or tenant name). Different service
 *             names get independent, non-interoperable KEKs. The same
 *             service name must be passed to hkdfguard_unwrap_dek to unwrap
 *             a payload produced with it; the service name itself is not
 *             recorded in the wrapped payload. Must be non-null, non-empty,
 *             and at most 128 bytes (excluding the null terminator), and may
 *             only contain ASCII letters, digits, and '.'. Case-insensitive:
 *             normalized to lowercase internally, so "MyApp" and "myapp"
 *             identify the same KEK and may be used interchangeably across
 *             hkdfguard_create_kek/hkdfguard_kek_exists/hkdfguard_wrap_dek/
 *             hkdfguard_unwrap_dek calls for the same logical service.
 *             hkdfguard_create_kek must have already provisioned this
 *             service's KEK; this function never creates one.
 * dek       - pointer to exactly HKDFGUARD_DEK_LEN bytes of plaintext DEK.
 * dek_len   - must equal HKDFGUARD_DEK_LEN.
 * out       - caller-owned output buffer.
 * out_len   - in: capacity of out, in bytes.
 *             out: on success, the number of bytes written (always
 *             HKDFGUARD_WRAPPED_LEN). On HKDFGUARD_ERR_BUFFER_TOO_SMALL,
 *             the required capacity (HKDFGUARD_WRAPPED_LEN). Left
 *             unchanged on every other failure.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code -
 * notably HKDFGUARD_ERR_KEK_NOT_FOUND if hkdfguard_create_kek has not yet
 * provisioned this service's KEK, or HKDFGUARD_ERR_ACCESS_DENIED if it has
 * but the calling account is not authorized to use it (see
 * hkdfguard_create_kek's KeyUseGroups policy). On failure, no partial
 * output is left in the caller's buffer.
*/

HKDFGUARD_API int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int32_t dek_len,
    uint8_t* out, int32_t* out_len);

/*
 * Unwraps a payload produced by hkdfguard_wrap_dek back into a 32-byte DEK.
 *
 * service     - must be the same service name passed to hkdfguard_wrap_dek
 *               when this payload was produced; see hkdfguard_wrap_dek.
 * wrapped     - pointer to the wrapped payload.
 * wrapped_len - length of the wrapped payload in bytes.
 * out         - caller-owned output buffer.
 * out_len     - in: capacity of out, in bytes (must be >= HKDFGUARD_DEK_LEN).
 *               out: on success, the number of plaintext bytes written
 *               (always HKDFGUARD_DEK_LEN). On
 *               HKDFGUARD_ERR_BUFFER_TOO_SMALL, the required capacity
 *               (HKDFGUARD_DEK_LEN). Left unchanged on every other failure.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 * HKDFGUARD_ERR_MALFORMED covers both a structurally invalid payload and a
 * payload whose embedded ephemeral public key is not a valid P-256 point
 * (rejected before it ever reaches the KEK). HKDFGUARD_ERR_KEK_MISMATCH
 * means the payload is well-formed but was wrapped under a different KEK
 * than the one this service currently routes to (its embedded KEK
 * fingerprint doesn't match) - detected before any ECDH or decryption is
 * attempted, and distinct from HKDFGUARD_ERR_AUTH_FAILED, which now
 * indicates tampering with a payload that *does* belong to this KEK.
 * HKDFGUARD_ERR_KEK_NOT_FOUND and HKDFGUARD_ERR_ACCESS_DENIED are as
 * described on hkdfguard_wrap_dek.
 * On any failure (including authentication failure), the output buffer is
 * zeroed before returning; no plaintext is left behind.
 */
HKDFGUARD_API int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int32_t wrapped_len,
    uint8_t* out, int32_t* out_len);

/*
 * Generates a fresh random 32-byte DEK and wraps it, in one call; the
 * plaintext DEK never leaves the library. `service`, `out` and `out_len`
 * behave exactly as on hkdfguard_wrap_dek, including the required capacity
 * reported on HKDFGUARD_ERR_BUFFER_TOO_SMALL.
 */
HKDFGUARD_API int32_t hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out, int32_t* out_len);

// Closes the extern "C" block opened above.
#ifdef __cplusplus
}
#endif

// Closes the include guard opened at the top of the file.
#endif /* HKDFGUARD_H */
