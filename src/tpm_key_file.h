#pragma once

#include "tpm2_marshal.h" // Bytes, PublicArea
#include <windows.h>         // PACL, ACCESS_MASK (CheckKeyStoreDacl)
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// The version 2 TPM KEK's key file (docs/adr/0001-post-quantum-payload-version-2.md,
// section 3): the TPM2_Create output that, loaded under the storage root
// key, is the service's HMAC-SHA-256 KEK. The TPM checks nothing about who
// loads a key, so whoever can read this file can use the KEK: **the file's
// ACL is the KEK's access control**, and the file and every folder above it
// are checked on every open, as a KSP checks a key's ACL.
//
// Layout (big-endian, like the TPM structures it carries):
//
//   offset  size  field
//   0       4     magic "HKGT"
//   4       2     format version (1)
//   6       2     reserved (0)
//   8       2+n   service name (u16 length, 1..128 bytes)
//   ...     4     parent handle (the storage root key, 0x81xxxxxx)
//   ...     2+34  parent Name (u16 length, SHA-256 Name: 0x000B || digest)
//   ...     2+n   the key's TPM2B_PUBLIC, as TPM2_Create returned it
//   ...     2+n   the key's TPM2B_PRIVATE, as TPM2_Create returned it
//
// Every field must be present and the file consumed exactly. The parent's
// Name pins the storage root key: a key file is used only under the key it
// was created under. The public area must be exactly the template
// provisioning uses (see CheckTpmKekPublicArea) - in particular
// TPM-generated (sensitiveDataOrigin), so nobody can plant a key whose
// value they chose.
//
// Store: <ProgramData>\HkdfGuard\TpmKeys\<file name>, ProgramData located
// through the known-folder API, not the environment. Those two folders and
// the file may be owned, and written, only by SYSTEM, Administrators or
// HkdfGuardAdmins (key_acl.h's IsKekAdministrator); the folders above them
// also by TrustedInstaller, and may let others create entries (as
// C:\ProgramData does) but never delete, rename or take over anything. Key
// use groups get read access to the file and the right to pass through its
// folders, nothing more - not even to list them.
//
// Every failure is an HkdfGuardError: HKDFGUARD_ERR_KEK_NOT_FOUND for a key
// file (or store folder) that doesn't exist; HKDFGUARD_ERR_KEK_ACCESS_DENIED
// when the caller may not read it, or - writing or deleting - isn't elevated;
// HKDFGUARD_ERR_KEK_INVALID for anything about the file or its folders that
// fails a check - thrown as errors.h's KekAccessControlError when the
// failure is the owner or DACL of the file or of a folder, which fixing the
// ACL repairs; HKDFGUARD_ERR_PROVIDER_ERROR for an I/O failure.
namespace hkdfguard {
    using tpm2::Bytes;

    // The attributes a version 2 TPM KEK has, exactly: TPM-generated, bound
    // to this TPM and to its parent, sign-only (HMAC), usable with its empty
    // authValue, and exempt from dictionary-attack lockout.
    constexpr uint32_t kTpmKekAttributes = tpm2::kObjFixedTpm | tpm2::kObjFixedParent | tpm2::kObjSensitiveDataOrigin |
                                           tpm2::kObjUserWithAuth | tpm2::kObjNoDa | tpm2::kObjSign;

    // The TPM2_Create template for a version 2 TPM KEK: a keyed-hash
    // HMAC-SHA-256 object with kTpmKekAttributes, nameAlg SHA-256, no
    // authPolicy.
    Bytes TpmKekTemplate();

    // Throws HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID) unless `area` is
    // exactly what TpmKekTemplate creates: keyed-hash, nameAlg SHA-256,
    // kTpmKekAttributes and no other attribute, an empty authPolicy, the
    // HMAC(SHA-256) scheme and a 32-byte unique digest.
    void CheckTpmKekPublicArea(const tpm2::PublicArea &area);

    struct TpmKeyFile {
        std::string service;     // the normalized service name it belongs to
        uint32_t parent_handle = 0;
        Bytes parent_name;       // 34 bytes
        Bytes public_blob;       // TPM2B_PUBLIC, size prefix included
        Bytes private_blob;      // TPM2B_PRIVATE, size prefix included
    };

    constexpr size_t kMaxTpmKeyFileLen = 4096;

    // The file's bytes. Throws HkdfGuardError(HKDFGUARD_ERR_INTERNAL_ERROR)
    // for a TpmKeyFile that ParseTpmKeyFile would refuse.
    Bytes SerializeTpmKeyFile(const TpmKeyFile &file);

    // Parses and checks a key file's bytes: layout, every length, the public
    // area (CheckTpmKekPublicArea). Throws
    // HkdfGuardError(HKDFGUARD_ERR_KEK_INVALID) on any failure. Doesn't
    // compare the service name with anything; ReadTpmKeyFile does.
    TpmKeyFile ParseTpmKeyFile(const uint8_t *data, size_t len);

    // The file name for a service's KEK: "hkdfguardwin_<service>_v<key_id>.tpmkey",
    // `service` being the normalized name (letters, digits and '.').
    std::wstring TpmKeyFileName(const std::wstring &service, uint32_t key_id);

    // Where the store lives: the folder holding "HkdfGuard\TpmKeys" -
    // ProgramData for the real store. Tests use their own folder.
    struct TpmKeyStore {
        std::wstring parent;
    };

    // The real store, under ProgramData (SHGetKnownFolderPath). Throws
    // HkdfGuardError(HKDFGUARD_ERR_PROVIDER_ERROR) if it can't be located.
    TpmKeyStore DefaultTpmKeyStore();

    // Reads, checks and parses `file_name` in `store`, which must belong to
    // `service`. See the header comment for every check and code.
    TpmKeyFile ReadTpmKeyFile(const TpmKeyStore &store, const std::wstring &file_name, const std::string &service);

    // Whether `file_name` exists in `store`: ReadTpmKeyFile's result, false
    // only for HKDFGUARD_ERR_KEK_NOT_FOUND; any other failure is thrown, so
    // an invalid file is never reported as absent.
    bool TpmKeyFileExists(const TpmKeyStore &store, const std::wstring &file_name, const std::string &service);

    // Creates `file_name` in `store` with `file`'s contents and the KEK file
    // ACL (key_acl.h's BuildKekFileSecurityDescriptor with
    // `additional_groups`), creating the store's folders first if they don't
    // exist - each with an ACL of its own - and checking them if they do. The
    // file is written under a temporary name, created delete-on-close so a
    // process that dies before the rename leaves nothing behind, flushed,
    // renamed into place without replacing anything, kept (delete-on-close
    // cleared), and read back through ReadTpmKeyFile.
    // Returns false, writing nothing, if `file_name` already exists. Needs an
    // elevated caller: HKDFGUARD_ERR_KEK_ACCESS_DENIED otherwise, checked
    // before anything is created.
    bool WriteTpmKeyFile(const TpmKeyStore &store, const std::wstring &file_name, const TpmKeyFile &file,
                         const std::vector<std::wstring> &additional_groups);

    // The DACL rule every object of the store is held to, on a DACL in hand
    // (the store applies it to each folder's and the file's live security,
    // after checking the owner): a DACL present, and no allow ACE granting
    // any right in `forbidden` to an account other than the KEK
    // administrators (key_acl.h's IsKekAdministrator) - or, with
    // `installer_ok`, TrustedInstaller. Inherit-only and deny ACEs are
    // skipped; an allow ACE of any type other than plain or callback is
    // refused. Throws errors.h's KekAccessControlError naming `what`.
    // Public so it can be fuzzed (tests/fuzz/fuzz_kek_dacl.cpp).
    void CheckKeyStoreDacl(PACL dacl, ACCESS_MASK forbidden, bool installer_ok, const std::string &what);

    // Creates the store's folders (HkdfGuard, then TpmKeys) if they don't
    // exist, each with the store folder ACL, and checks them - and every
    // folder above them - exactly as a write does; returns the TpmKeys
    // folder's path. For the installer, which runs it as SYSTEM before any
    // user can create HkdfGuard under ProgramData (C:\ProgramData lets
    // Users create folders) and so block provisioning. Walks without
    // following links, so a folder planted in the way - or a junction in
    // its place - is refused, never followed or re-ACL'd:
    // HKDFGUARD_ERR_KEK_INVALID (as KekAccessControlError for a folder that
    // someone else owns or may write). Idempotent. Needs an elevated
    // caller.
    std::wstring PrepareTpmKeyStore(const TpmKeyStore &store);

    // Checks that the existing `file_name` in `store` grants every principal
    // a KEK this library creates now would: SYSTEM, Administrators and
    // HkdfGuardAdmins, and HkdfGuardUsers, HkdfGuardDeployers and
    // `additional_groups` (the KeyUseGroups and DeployerGroups policy) -
    // key_acl.h's VerifyKekDaclGrants, after the same folder checks as a
    // read. For provisioning, which verifies an existing KEK against the
    // current policy as version 1 does (VerifyKeyAcl): a group the policy
    // names but the file doesn't grant is HKDFGUARD_ERR_PROVIDER_ERROR, and
    // the file is left untouched. A grant the policy no longer names isn't
    // detected here, as for version 1.
    void VerifyTpmKeyFileGrants(const TpmKeyStore &store, const std::wstring &file_name,
                                const std::vector<std::wstring> &additional_groups);

    // Deletes `file_name` from `store` after the same folder checks as a
    // read. Returns false if there is no such file. Needs an elevated caller.
    bool DeleteTpmKeyFile(const TpmKeyStore &store, const std::wstring &file_name);
} // namespace hkdfguard
