"""Writes the seed corpora for the libFuzzer targets in this folder.

    python tests/fuzz/make_seeds.py

Each seed is a well-formed input for its target, so fuzzing starts from
realistic structure: a KEK's DACL, a pair of KDF inputs. The seeds are
checked in under tests/fuzz/corpus/<target>/; rerun this after changing a
format. Nothing here is secret.
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def write(target, name, data):
    folder = os.path.join(HERE, 'corpus', target)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), 'wb') as f:
        f.write(data)


# ---- fuzz_kek_dacl: an unused byte, then a KEK's DACL (little-endian) ----
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
write('fuzz_kek_dacl', 'everyone_read', bytes([0x00]) + acl(
    ace(0, 0, GENERIC_ALL, SYSTEM), ace(0, 0, GENERIC_ALL, ADMINS), ace(0, 0, GENERIC_READ, EVERYONE)))
write('fuzz_kek_dacl', 'others_write_inherit_only', bytes([0x03]) + acl(
    ace(0, 0, GENERIC_ALL, SYSTEM), ace(0, 0x08, FILE_WRITE_DATA, USERS), ace(1, 0, FILE_WRITE_DATA, USERS)))

# ---- fuzz_v2_kdf: two (service, header) pairs ----
header = bytes([2, 1, 0, 0, 1, 0, 0, 0]) + bytes(range(32))
pair_a = bytes([8]) + b'myapp.v2' + header
pair_b = bytes([9]) + b'myapp.v2x' + header
write('fuzz_v2_kdf', 'two_services', pair_a + pair_b)
write('fuzz_v2_kdf', 'same_pair', pair_a + pair_a)
write('fuzz_v2_kdf', 'length_boundary', bytes([1]) + b'a' + header + bytes([2]) + b'a' + header[:1] + header)

print('seeds written to', os.path.join(HERE, 'corpus'))
