"""Writes the seed corpora for the libFuzzer targets in this folder.

    python tests/fuzz/make_seeds.py

Each seed is a well-formed input for its target, so fuzzing starts from
realistic structure: a key file as provisioning writes it, Windows' storage
root key, a TPM2_HMAC response in a salted session, a KEK's DACL, a pair of
KDF inputs. The seeds are checked in under tests/fuzz/corpus/<target>/;
rerun this after changing a format. Nothing here is secret: every key, nonce
and HMAC is a fixed placeholder.
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def u16(v):
    return struct.pack('>H', v)


def u32(v):
    return struct.pack('>I', v)


def tpm2b(b):
    return u16(len(b)) + b


def write(target, name, data):
    folder = os.path.join(HERE, 'corpus', target)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), 'wb') as f:
        f.write(data)


ALG_RSA, ALG_HMAC, ALG_AES, ALG_KEYEDHASH, ALG_SHA256, ALG_NULL, ALG_ECC, ALG_CFB = (
    0x0001, 0x0005, 0x0006, 0x0008, 0x000B, 0x0010, 0x0023, 0x0043)

# The version 2 TPM KEK's public area (tpm_key_file.h, kTpmKekAttributes:
# fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | sign).
KEK_ATTRS = 0x2 | 0x10 | 0x20 | 0x40 | 0x400 | 0x40000
KEK_PUBLIC = (u16(ALG_KEYEDHASH) + u16(ALG_SHA256) + u32(KEK_ATTRS) + tpm2b(b'') +
              u16(ALG_HMAC) + u16(ALG_SHA256) + tpm2b(bytes(range(32))))

# Windows' storage root keys, as probed (attributes 0x00030472).
SRK_ATTRS = 0x00030472
SRK_RSA = (u16(ALG_RSA) + u16(ALG_SHA256) + u32(SRK_ATTRS) + tpm2b(b'') +
           u16(ALG_AES) + u16(128) + u16(ALG_CFB) + u16(ALG_NULL) + u16(2048) + u32(0) +
           tpm2b(bytes([0xC5]) * 256))
SRK_ECC = (u16(ALG_ECC) + u16(ALG_SHA256) + u32(SRK_ATTRS) + tpm2b(b'') +
           u16(ALG_AES) + u16(128) + u16(ALG_CFB) + u16(ALG_NULL) + u16(0x0003) + u16(ALG_NULL) +
           tpm2b(bytes([0x11]) * 32) + tpm2b(bytes([0x22]) * 32))

# ---- fuzz_tpm_key_file: a key file as WriteTpmKeyFile lays it out ----
key_file = (b'HKGT' + u16(1) + u16(0) + tpm2b(b'myapp.v2') + u32(0x81000001) +
            tpm2b(u16(ALG_SHA256) + bytes([0xAB]) * 32) + tpm2b(KEK_PUBLIC) +
            tpm2b(tpm2b(bytes([0x5A]) * 32) + bytes([0x6B]) * 96))
write('fuzz_tpm_key_file', 'valid_key_file', key_file)
write('fuzz_tpm_key_file', 'short_service', key_file.replace(tpm2b(b'myapp.v2'), tpm2b(b'a')))

# ---- fuzz_srk_rule: public areas ----
write('fuzz_srk_rule', 'windows_rsa_srk', SRK_RSA)
write('fuzz_srk_rule', 'ecc_p256_srk', SRK_ECC)
write('fuzz_srk_rule', 'kek_keyed_hash', KEK_PUBLIC)

# ---- fuzz_tpm2_session: mode byte, then a TPM2_HMAC response ----
params = tpm2b(bytes([0x3C]) * 32)
for mode, attrs, name in ((0x01, 0x40, 'signed_closes'), (0x03, 0x41, 'signed_continues'),
                          (0x00, 0x41, 'unsigned'), (0x02, 0x40, 'unsigned_asked_continue')):
    auth = tpm2b(bytes([0x07]) * 32) + bytes([attrs]) + tpm2b(bytes([0x0E]) * 32)
    body = u32(len(params)) + params + auth
    response = u16(0x8002) + u32(10 + len(body)) + u32(0) + body
    write('fuzz_tpm2_session', name, bytes([mode]) + response)
write('fuzz_tpm2_session', 'error_response', bytes([0x01]) + u16(0x8001) + u32(10) + u32(0x00000101))

# ---- fuzz_kek_dacl: mode byte, then a KEK's DACL (little-endian) ----
def sid(*parts):
    authority, subs = parts[0], parts[1:]
    return bytes([1, len(subs)]) + authority.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


def ace(ace_type, flags, mask, sid_bytes):
    return struct.pack('<BBHI', ace_type, flags, 8 + len(sid_bytes), mask) + sid_bytes


def acl(*aces):
    body = b''.join(aces)
    return struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body


SYSTEM, ADMINS, USERS, EVERYONE = sid(5, 18), sid(5, 32, 544), sid(5, 32, 545), sid(1, 0)
GENERIC_ALL, GENERIC_READ, FILE_WRITE_DATA = 0x10000000, 0x80000000, 0x2
kek_dacl = acl(ace(0, 0, GENERIC_ALL, SYSTEM), ace(0, 0, GENERIC_ALL, ADMINS), ace(0, 0, GENERIC_READ, sid(5, 32, 555)))
write('fuzz_kek_dacl', 'kek_dacl', bytes([0x00]) + kek_dacl)
write('fuzz_kek_dacl', 'store_folder_dacl', bytes([0x04]) + acl(
    ace(0, 0, 0x1F01FF, SYSTEM), ace(0, 0, 0x1F01FF, ADMINS), ace(0, 0, 0x1200A0, USERS)))
write('fuzz_kek_dacl', 'everyone_read', bytes([0x00]) + acl(
    ace(0, 0, GENERIC_ALL, SYSTEM), ace(0, 0, GENERIC_ALL, ADMINS), ace(0, 0, GENERIC_READ, EVERYONE)))
write('fuzz_kek_dacl', 'others_write_inherit_only', bytes([0x03]) + acl(
    ace(0, 0, GENERIC_ALL, SYSTEM), ace(0, 0x08, FILE_WRITE_DATA, USERS), ace(1, 0, FILE_WRITE_DATA, USERS)))

# ---- fuzz_v2_kdf: two (service, header) pairs, then a CMAC key and message ----
header = bytes([2, 1, 0, 0, 1, 0, 0, 0]) + bytes(range(32))
pair_a = bytes([8]) + b'myapp.v2' + header
pair_b = bytes([9]) + b'myapp.v2x' + header
cmac = bytes(range(32)) + bytes(range(64))
write('fuzz_v2_kdf', 'two_services', pair_a + pair_b + cmac)
write('fuzz_v2_kdf', 'same_pair', pair_a + pair_a + cmac[:32])
write('fuzz_v2_kdf', 'length_boundary', bytes([1]) + b'a' + header + bytes([2]) + b'a' + header[:1] + header + cmac)

# ---- fuzz_tpm2_marshal: selector byte, then a response ----
read_public = u16(0x8001) + u32(10 + 2 + len(SRK_RSA) + 2 + 34 + 2 + 34) + u32(0) + tpm2b(SRK_RSA) + \
    tpm2b(u16(ALG_SHA256) + bytes(32)) + tpm2b(u16(ALG_SHA256) + bytes(32))
write('fuzz_tpm2_marshal', 'read_public_rsa_srk', bytes([0]) + read_public)
write('fuzz_tpm2_marshal', 'bare_header', bytes([8]) + u16(0x8001) + u32(10) + u32(0))

print('seeds written to', os.path.join(HERE, 'corpus'))
