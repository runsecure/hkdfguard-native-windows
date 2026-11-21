# Fuzzing the C ABI

Coverage-guided fuzzing (libFuzzer, MSVC, with AddressSanitizer) of the
library's C ABI and two of its internal parsers. Nothing here is part of the
build that ships: the harnesses are built only with
`-DHKDFGUARD_BUILD_FUZZERS=ON`, and the C ABI targets link the library's own
sources - not `HkdfGuard.dll` - compiled with policy.h's test seams
(`HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE`) and a stub event log
(`event_log_stub.cpp`).

The C ABI targets are the Windows counterpart of
`hkdfguard-native-linux/fuzz`, target for target and seed for seed where the
two libraries have the same surface.

## Targets

| Target | What it drives | What it checks beyond "no crash" |
|---|---|---|
| `fuzz_unwrap_dek` | `hkdfguard_unwrap_dek` on arbitrary bytes and on bit-flipped, truncated and extended copies of a genuine payload; every shape of service string (valid, other case, unknown, arbitrary bytes, NULL) and of output buffer (any capacity, negative included; NULL `out`; NULL `out_len`) | only the genuine payload unwraps, only under its own service, only to its DEK; every failure zeroes the caller's buffer; the argument checks answer in the documented order; `BUFFER_TOO_SMALL` reports 32; a misshapen payload gets its documented refusal; never `INTERNAL_ERROR` |
| `fuzz_wrap_round_trip` | `hkdfguard_wrap_dek` (any DEK length, NULL), `hkdfguard_generate_and_wrap_dek`, `hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`, `hkdfguard_security_model`, `hkdfguard_key_file_principal_trusted` | what wrap produces parses, carries the KEK's fingerprint and unwraps to the same DEK under either spelling of the service; two wraps never give the same payload; a failed wrap leaves the buffer untouched; a wrong-length DEK is refused without being read; `kek_exists` answers for exactly the created KEK; SYSTEM, Administrators and this account are trusted principals, Everyone is not |
| `fuzz_open_file` | `hkdfguard_open_file` on arbitrary file contents under eight file ACLs, and on arbitrary paths | the plaintext-key detector, an independent restatement of the payload's shape and `open_file` agree on what a key file is; a file another account may change is refused whatever it holds; every failure zeroes the buffer; a refused file's length never comes back through `BUFFER_TOO_SMALL`; no arbitrary path opens as a key file |
| `fuzz_string_bounds` | every C string the ABI takes - the service (through each of the six functions that take one), a key file path, a principal - with no terminator, at the longest length allowed, one byte over, and with a NUL before more bytes | an unterminated or over-long string gets its documented refusal; the longest valid service name is not refused for its length; bytes after the first NUL change neither the status nor the output; the genuine string still works |
| `fuzz_api_threads` | up to four threads at once, each a sequence of create_kek, kek_exists, kek_fingerprint, wrap, unwrap (genuine and corrupted payloads, short buffers), generate, open_file | every thread gets the answer the call gets alone: its own DEK back and never another thread's, a fingerprint that doesn't change, no KEK appearing for a service without one |
| `fuzz_kek_dacl` | the two DACL walks that decide whether a KEK's access control is acceptable | no ACL Windows accepts crashes them or makes them read past an ACE; they refuse only with their documented codes |
| `fuzz_v2_kdf` | payload version 2's SP 800-108 framing | two different (service, header) pairs never give the same block |

## How a memory error is caught

Every buffer and string a C ABI target hands the library ends against an
inaccessible page (`fuzz_abi.h`'s `Exact`). A read or write one byte past it
is an access violation at the instruction that does it - in any build, and
whoever does it. That last part matters: the library zeroes with
`SecureZeroMemory`, and Windows (`BCryptDecrypt`, `ReadFile`) writes results
straight into the caller's buffer, and AddressSanitizer sees none of those
writes. The buffers are freed when the call returns, so a pointer the
library kept is a use after free on the next call. AddressSanitizer covers
the library's own heap and stack.

## The KEK, and elevation

A KEK can only be created elevated. Elevated (as in CI), a target's setup
creates a throwaway Software KSP KEK per payload version, wraps a known DEK
under each ("the genuine payload"), and deletes them at exit. Not elevated,
there is normally no KEK: every buffer, string, length and path attack still
runs, and everything that needs the KEK must fail cleanly. The line each
target prints at startup says whether it found a KEK.

A run that is killed (a timeout, Ctrl+C) can't delete its KEKs, named
`hkdfguardwin.fuzz.<target>`. They are harmless and the target's next
elevated run removes them; until then a run that isn't elevated, by an
account allowed to use them, finds them and runs with them.

Policy is pinned inside the process (Software KSP only, the developer
security model, no floor on setup calls); the registry is never written.

## Running

```powershell
cmake -S . -B build-analysis -G Ninja -DCMAKE_BUILD_TYPE=Debug -DHKDFGUARD_BUILD_FUZZERS=ON -DHKDFGUARD_ENABLE_ASAN=ON
cmake --build build-analysis
ctest --test-dir build-analysis -R fuzz_      # every seed once, then a few thousand inputs each
```

(`scripts\Build-Analysis.ps1` does all of that, with clang-tidy.)

A ctest run of a C ABI target starts from a fresh corpus every time
(`RunSmoke.cmake`): every seed once, then a few thousand inputs or four
minutes, whichever comes first. With a KEK it is much slower per input than
without: each wrap or unwrap is a key storage provider round trip.

For a real campaign, run a target directly, from any shell:

```powershell
cd build-analysis\tests
mkdir my-corpus\fuzz_unwrap_dek
.\fuzz_unwrap_dek.exe -max_total_time=900 -timeout=60 -artifact_prefix=fuzz-crashes/fuzz_unwrap_dek/ my-corpus\fuzz_unwrap_dek fuzz-seeds\fuzz_unwrap_dek
```

libFuzzer reads both folders and writes new inputs only to the first. Keep a
campaign's corpus in a folder of your own, as above: `fuzz-found\` belongs
to the ctest runs, which empty it. An
input that fails is saved under `fuzz-crashes\<target>\`; pass that file as
the only argument to replay it.

## Seeds: the memory attacks, written down

`Make-AbiSeeds.ps1` writes about 2,500 inputs for the C ABI targets, each
named for what it tries. The build runs it (into `tests\fuzz-seeds` in the
build tree); the script is their source, so they are not checked in. It
needs only the Windows PowerShell every Windows machine has.

- **output buffers**: a capacity that fits exactly, one byte short, one
  over, zero, one, negative, the most negative and the largest; `out` NULL,
  `out_len` NULL, both;
- **payloads and key files**: cut off at every field boundary; each header
  byte - version, provider, reserved, key id, salt - and each later field's
  first and last byte flipped to its extremes; trailing bytes; a second
  payload appended; raw blocks of zeros and `0xFF`; every wrong version,
  provider and key id;
- **plaintext keys**: 32 raw bytes with and without a line ending; hex in
  either case; base64, standard and URL-safe, padded and not, non-canonical,
  wrapped, with a BOM, as UTF-16;
- **strings**: an early NUL (before, inside and after the genuine name), no
  terminator, the longest valid length and one more, format strings, path
  traversal, device and stream names, control and non-UTF-8 bytes;
- **lengths that lie**: DEKs of every length round 32, NULL with a non-zero
  length;
- **paths**: devices (`NUL`, `\\.\PhysicalDrive0`, pipes), `\\?\` and
  `\??\` prefixes, UNC and WebDAV, alternate data streams, 8.3 short names,
  drive-relative and root-relative paths, trailing dots and spaces,
  components of 255 and 256 characters, invalid UTF-8;
- **SIDs**: well-known ones, SDDL aliases, overflowing authorities and
  sub-authorities, 15 and 16 sub-authorities, 255 and 256 bytes;
- **threads**: every call on four threads at once, `create_kek` racing wrap,
  distinct DEKs per thread.

A seed is the encoding of its target's input (`fuzz_abi.h`'s `In`): when an
input changes shape, its builder in `Make-AbiSeeds.ps1` changes with it. Add
a seed for every finding, named for it.

`Make-Seeds.ps1` writes the few checked-in seeds of `fuzz_kek_dacl` and
`fuzz_v2_kdf` (`corpus\`).

## What this does not cover yet

Compared with `hkdfguard-native-linux/fuzz`:

- **The command-line tool.** Linux fuzzes `hkdfguard`'s argument, base64 and
  stdin parsing in-process (`cli_args`) and the real binary black-box
  (`cli_blackbox.py`). Windows has neither; `hkdfguard.exe` is covered only
  by the example-based tests `test_cli.ps1` and `test_cli_v2.ps1`.
- **The folder walk.** Linux's `path_walk` builds random trees of
  directories and symlinks and compares the library's walk with the
  kernel's. Windows has no equivalent for `no_follow_open.h` over random
  trees of folders and junctions.
- **TPM KEKs.** The targets use the Software KSP; `test_v2_kek` and the
  role tests cover the Platform Crypto Provider.

`unwrap_secret`, `wrap_secret_round_trip`, `open_secret_file`, `policy` and
`tpm_key_file` have no Windows counterpart: this library has no secrets API,
no policy file and no TPM key file.
