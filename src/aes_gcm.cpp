#include "aes_gcm.h"
#include "errors.h"
#include "handle_traits.h" // ScopedBCryptAlg, ScopedBCryptKey - see that file for the RAII pattern
#include <windows.h>
#include <bcrypt.h>

// STATUS_AUTH_TAG_MISMATCH is the specific NTSTATUS code CNG returns when
// AES-GCM decryption's authentication check fails (i.e. someone tampered
// with the ciphertext or tag, or the wrong key was used). It's normally
// declared in ntstatus.h, which this project doesn't otherwise need and
// which has known conflicts with other Windows headers if included
// carelessly - so `#ifndef` here only supplies our own definition of the
// constant if nothing else already provided one, avoiding a "redefinition"
// compiler error while still guaranteeing the symbol exists.
#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace hkdfguard {
    // An anonymous `namespace { ... }` (as opposed to the named `namespace
    // hkdfguard { ... }` wrapping the whole file) gives everything inside it
    // *internal linkage*: OpenAesKey is only visible/callable from within this
    // one .cpp file, even though other .cpp files in the project also define a
    // function or two of their own also named things privately. It's the C++
    // equivalent of C's `static` on a file-scope function, and is how this
    // project keeps each file's private helper functions out of each other's
    // way without having to invent ever-more-unique names.
    namespace {
        // Builds a CNG AES-GCM key object from 32 raw key bytes. Returns a
        // ScopedBCryptKey (see handle_traits.h) so the caller doesn't have to
        // remember to destroy it - it's destroyed automatically wherever the
        // returned object's scope ends.
        //
        // `alg` is taken by reference (`ScopedBCryptAlg&`) rather than by value
        // because ScopedBCryptAlg's copy constructor is deleted (see
        // handle_traits.h) - a reference lets this function use the caller's
        // existing algorithm-provider handle in place, without needing to copy or
        // move ownership of it.
        ScopedBCryptKey OpenAesKey(ScopedBCryptAlg &alg, const uint8_t key[32]) {
            // BCryptOpenAlgorithmProvider asks Windows for a handle to its AES
            // implementation. `alg.put()` (see handle_traits.h) hands the API the
            // address it needs to write the resulting handle into, and afterward
            // `alg` owns whatever handle was written there.
            NTSTATUS status = BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_AES_ALGORITHM, nullptr, 0);
            // NTSTATUS is Windows' native "did this succeed" result type for
            // low-level APIs (0 and small positive values mean success; the
            // top bits distinguish errors); BCRYPT_SUCCESS(status) is the standard
            // macro that checks it correctly (don't just compare `status == 0`,
            // some non-zero values are still "successful" informational codes).
            if (!BCRYPT_SUCCESS(status)) {
                // Throwing here means `alg` (already own a valid provider handle or
                // not) gets cleaned up correctly by its own destructor as this
                // exception unwinds - no manual cleanup needed on this error path.
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptOpenAlgorithmProvider(AES) failed");
            }

            // AES defaults to ECB mode in CNG unless told otherwise; this call
            // switches the algorithm provider to GCM (Galois/Counter Mode), the
            // authenticated encryption mode this whole library relies on for both
            // confidentiality and tamper-detection.
            status = BCryptSetProperty(
                alg.get(), BCRYPT_CHAINING_MODE,
                // BCRYPT_CHAIN_MODE_GCM is itself a wide-string constant (L"..."),
                // and BCryptSetProperty's generic `PUCHAR` (pointer-to-bytes)
                // parameter type doesn't know that - so the value has to be
                // explicitly reinterpreted as raw bytes, and because that value is
                // a `const wchar_t*` while the API wants a non-const `PUCHAR`, the
                // `const_cast` first strips the const-ness (safe here: CNG only
                // *reads* this value, it never writes through the pointer) before
                // `reinterpret_cast` reinterprets the pointer's type without
                // changing the bits it points to.
                reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptSetProperty(GCM) failed");
            }

            // Turns the raw 32 key bytes into an actual CNG key object CNG can
            // encrypt/decrypt with. This is the one place the 32-byte wrapping key
            // gets copied into memory this code doesn't directly control (CNG's own
            // internal key-object representation) - unavoidable, since that's the
            // API's contract, but it's exactly why `aes_key` below is wrapped in
            // ScopedBCryptKey: BCryptDestroyKey (CNG's own documented cleanup for a
            // key object) runs automatically the moment this key is no longer
            // needed, via the RAII pattern.
            ScopedBCryptKey aes_key;
            status = BCryptGenerateSymmetricKey(
                alg.get(), aes_key.put(), nullptr, 0,
                const_cast<PUCHAR>(key), 32, 0);
            if (!BCRYPT_SUCCESS(status)) {
                throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptGenerateSymmetricKey failed");
            }
            // Returned by value; see handle_traits.h's note on ScopedHandle's move
            // constructor for why this doesn't copy the underlying handle.
            return aes_key;
        }
    } // namespace

    void AesGcmEncrypt(
        const uint8_t key[32],
        const uint8_t *plaintext, unsigned long plaintext_len,
        const uint8_t *aad, unsigned long aad_len,
        uint8_t nonce_out[kNonceLen],
        uint8_t *ciphertext_out,
        uint8_t tag_out[kTagLen]) {
        // `alg` must stay alive for as long as `aes_key` is in use (the key
        // object is logically tied to the algorithm provider it was created
        // from), so both are declared here in AesGcmEncrypt's own scope, with
        // `alg` constructed first (and therefore destroyed last, since C++
        // destroys local objects in the reverse of their construction order).
        ScopedBCryptAlg alg;
        ScopedBCryptKey aes_key = OpenAesKey(alg, key);

        // BCryptGenRandom fills nonce_out with cryptographically secure random
        // bytes - the AES-GCM nonce (a.k.a. IV) must be unique for every
        // encryption performed under the same key, and using the OS's CSPRNG is
        // the standard way to get that with overwhelming probability.
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG tells CNG to use its default/best
        // available random number generator rather than a specific named one.
        NTSTATUS status = BCryptGenRandom(
            nullptr, nonce_out, static_cast<ULONG>(kNonceLen), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptGenRandom(nonce) failed");
        }

        // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO is the struct CNG uses to pass
        // the extra parameters authenticated modes like GCM need beyond a plain
        // cipher (the nonce and where to put/read the authentication tag).
        // It's declared here as a plain local variable (uninitialized at this
        // point - its fields are garbage until the next lines fill them in).
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        // BCRYPT_INIT_AUTH_MODE_INFO is a macro (not a function) provided by
        // bcrypt.h that expands to a few lines zeroing `auth_info` and setting
        // its `cbSize`/`dwInfoVersion` header fields to the values CNG expects
        // to see before it will trust the rest of the struct's contents.
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        // Tell CNG where the nonce is and how long it is...
        auth_info.pbNonce = nonce_out;
        auth_info.cbNonce = static_cast<ULONG>(kNonceLen);
        // ...and where it should write the resulting 16-byte authentication tag
        // once encryption finishes.
        auth_info.pbTag = tag_out;
        auth_info.cbTag = static_cast<ULONG>(kTagLen);
        // ...and the additional authenticated data (the caller's `service`
        // string, per hkdfguard.cpp's call site) to bind into the tag without
        // encrypting it. CNG accepts null/0 here for "no AAD" just as readily
        // as a real buffer.
        auth_info.pbAuthData = const_cast<PUCHAR>(aad);
        auth_info.cbAuthData = aad_len;

        // `result_len` is another in/out-style parameter: BCryptEncrypt writes
        // the actual number of bytes it produced into it, which we then check
        // against what we expected.
        ULONG result_len = 0;
        status = BCryptEncrypt(
            aes_key.get(), const_cast<PUCHAR>(plaintext), plaintext_len, &auth_info,
            // The two `nullptr, 0` arguments here are BCryptEncrypt's `pbIV`/
            // `cbIV` parameters - unused because the nonce/IV was already
            // supplied through `auth_info.pbNonce` above, which is how GCM mode
            // specifically expects to receive it.
            nullptr, 0, ciphertext_out, plaintext_len, &result_len, 0);
        if (!BCRYPT_SUCCESS(status) || result_len != plaintext_len) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptEncrypt failed");
        }
        // Nothing further to clean up by hand here: `aes_key` and `alg` both
        // wipe/close themselves automatically via their destructors as this
        // function returns (see handle_traits.h). Note the plaintext (`dek` in
        // hkdfguard.cpp's caller) was read directly from the caller's pointer
        // above and never copied into a local buffer in this function at all -
        // the shortest possible in-memory lifetime for that secret is "however
        // long the caller who owns it already keeps it alive," which this
        // function adds nothing to.
    }

    void AesGcmDecrypt(
        const uint8_t key[32],
        const uint8_t nonce[kNonceLen],
        const uint8_t *ciphertext, unsigned long ciphertext_len,
        const uint8_t *aad, unsigned long aad_len,
        const uint8_t tag[kTagLen],
        uint8_t *plaintext_out) {
        ScopedBCryptAlg alg;
        ScopedBCryptKey aes_key = OpenAesKey(alg, key);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        // On the decrypt side, the nonce, tag, and AAD are *inputs* CNG reads
        // (the ones that were produced by AesGcmEncrypt and travelled along
        // with the ciphertext in the wrapped payload, or supplied fresh by the
        // caller for AAD) rather than outputs it writes, so `const_cast`
        // strips the const-ness here purely because
        // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO's fields are typed as
        // non-const `PUCHAR` even when used for input-only data - CNG itself
        // does not write through these three pointers during a decrypt.
        auth_info.pbNonce = const_cast<PUCHAR>(nonce);
        auth_info.cbNonce = static_cast<ULONG>(kNonceLen);
        auth_info.pbTag = const_cast<PUCHAR>(tag);
        auth_info.cbTag = static_cast<ULONG>(kTagLen);
        // Must match the AAD used in AesGcmEncrypt, or CNG reports an
        // authentication failure below (STATUS_AUTH_TAG_MISMATCH), same as any
        // other tamper.
        auth_info.pbAuthData = const_cast<PUCHAR>(aad);
        auth_info.cbAuthData = aad_len;

        ULONG result_len = 0;
        NTSTATUS status = BCryptDecrypt(
            aes_key.get(), const_cast<PUCHAR>(ciphertext), ciphertext_len, &auth_info,
            nullptr, 0, plaintext_out, ciphertext_len, &result_len, 0);

        // BCryptDecrypt in GCM mode can still write unauthenticated plaintext
        // into plaintext_out even when it reports a tag mismatch; callers must
        // not trust plaintext_out unless this function returns normally, and
        // the ABI layer zeroes the caller's output buffer on any failure.
        if (status == STATUS_AUTH_TAG_MISMATCH) {
            // A tag mismatch is reported as its own distinct, more specific
            // error code (HKDFGUARD_ERR_AUTH_FAILED) rather than the generic
            // HKDFGUARD_ERR_CRYPTO below, so a caller can tell "this was
            // tampered with / the wrong key was used" apart from "something
            // about the crypto machinery itself broke."
            throw HkdfGuardError(HKDFGUARD_ERR_AUTH_FAILED, "AES-GCM authentication failed");
        }
        if (!BCRYPT_SUCCESS(status) || result_len != ciphertext_len) {
            throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptDecrypt failed");
        }
        // On success, the plaintext DEK now lives in `plaintext_out`, which -
        // all the way back up the call chain - is the caller-owned buffer
        // passed into the public hkdfguard_unwrap_dek. This function never
        // copies it anywhere else.
    }
} // namespace hkdfguard
