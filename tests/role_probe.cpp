// role_probe: the library's public ABI, called as whichever account runs this
// process. test_roles.ps1 starts it as throwaway local accounts - a deployer
// and an application runner - to check what each role can and can't do
// under the production security model. Public ABI only (plus plain Win32
// file calls for the "plant" and "overwrite" commands), like the CLI.
//
// Each command prints one line of key=value results and exits 0 if it ran,
// 2 on a usage error:
//
//   model                    model=<0|1> may_write=<0|1> rc=<status>
//   open <path>              open=<status>
//   unwrap <service> <path>  open=<status> unwrap=<status>
//   ephemeral <service>      generate=<status> unwrap=<status> wrap=<status> unwrap2=<status>
//   plant <src> <dir> <name> mkdir=<win32> write=<win32> - copies the key file
//                            <src> into <dir>\<name>, creating <dir>, as
//                            this account: a key file it persisted itself
//   overwrite <path>         write=<win32> - opens an existing file for writing
//   inspect <path>           inspect=<win32> owner=<sid> sha256=<hex> - the
//                            file's owner and content hash, as this account
//                            (a key file's DACL may not admit the test's admin)
#include "hkdfguard.h"

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {
    int OpenFile(const char *path, std::vector<uint8_t> &payload) {
        payload.assign(HKDFGUARD_WRAPPED_MAX_LEN, 0);
        int len = static_cast<int>(payload.size());
        int rc = hkdfguard_open_file(path, payload.data(), &len);
        payload.resize(rc == HKDFGUARD_OK ? static_cast<size_t>(len) : 0);
        return rc;
    }

    int Unwrap(const char *service, const std::vector<uint8_t> &payload) {
        uint8_t dek[HKDFGUARD_DEK_LEN] = {};
        int len = sizeof(dek);
        int rc = hkdfguard_unwrap_dek(service, payload.data(), static_cast<int>(payload.size()), dek, &len);
        SecureZeroMemory(dek, sizeof(dek));
        return rc;
    }

    DWORD CopyAsThisAccount(const char *src, const std::string &dst) {
        HANDLE in = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (in == INVALID_HANDLE_VALUE) return GetLastError();
        std::vector<char> bytes(4096);
        DWORD got = 0;
        BOOL ok = ReadFile(in, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr);
        CloseHandle(in);
        if (!ok) return GetLastError();
        HANDLE out = CreateFileA(dst.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out == INVALID_HANDLE_VALUE) return GetLastError();
        DWORD put = 0;
        ok = WriteFile(out, bytes.data(), got, &put, nullptr);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(out);
        return err;
    }

    DWORD Inspect(const char *path, std::string &owner, std::string &sha256) {
        HANDLE h = CreateFileA(path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return GetLastError();
        PSID ownerSid = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        DWORD err = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &ownerSid, nullptr, nullptr, nullptr, &sd);
        if (err == ERROR_SUCCESS) {
            char *text = nullptr;
            if (ConvertSidToStringSidA(ownerSid, &text)) {
                owner = text;
                LocalFree(text);
            } else {
                err = GetLastError();
            }
            LocalFree(sd);
        }
        std::vector<uint8_t> bytes;
        uint8_t chunk[4096];
        DWORD got = 0;
        while (err == ERROR_SUCCESS) {
            if (!ReadFile(h, chunk, sizeof(chunk), &got, nullptr)) {
                err = GetLastError();
            } else if (got == 0) {
                break;
            } else {
                bytes.insert(bytes.end(), chunk, chunk + got);
            }
        }
        CloseHandle(h);
        if (err != ERROR_SUCCESS) return err;
        uint8_t digest[32] = {};
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, bytes.data(), static_cast<ULONG>(bytes.size()), digest,
                       sizeof(digest)) != 0) {
            return ERROR_INVALID_DATA;
        }
        static const char hex[] = "0123456789abcdef";
        for (uint8_t b : digest) {
            sha256 += hex[b >> 4];
            sha256 += hex[b & 0xf];
        }
        return ERROR_SUCCESS;
    }
} // namespace

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: role_probe model | open <path> | unwrap <service> <path> | ephemeral <service> | "
                             "plant <src> <dir> <name> | overwrite <path> | inspect <path>\n");
        return 2;
    }
    const std::string command = argv[1];

    if (command == "model" && argc == 2) {
        int model = -1, may_write = -1;
        int rc = hkdfguard_security_model(&model, &may_write);
        std::printf("model=%d may_write=%d rc=%d\n", model, may_write, rc);
        return 0;
    }
    if (command == "open" && argc == 3) {
        std::vector<uint8_t> payload;
        std::printf("open=%d\n", OpenFile(argv[2], payload));
        return 0;
    }
    if (command == "unwrap" && argc == 4) {
        std::vector<uint8_t> payload;
        int open = OpenFile(argv[3], payload);
        int unwrap = open == HKDFGUARD_OK ? Unwrap(argv[2], payload) : open;
        std::printf("open=%d unwrap=%d\n", open, unwrap);
        return 0;
    }
    if (command == "ephemeral" && argc == 3) {
        // An ephemeral key, in memory only: generated and wrapped, then
        // unwrapped; and a caller-supplied DEK wrapped and unwrapped.
        std::vector<uint8_t> payload(HKDFGUARD_WRAPPED_MAX_LEN);
        int len = static_cast<int>(payload.size());
        int generate = hkdfguard_generate_and_wrap_dek(argv[2], payload.data(), &len);
        payload.resize(generate == HKDFGUARD_OK ? static_cast<size_t>(len) : 0);
        int unwrap = generate == HKDFGUARD_OK ? Unwrap(argv[2], payload) : generate;

        uint8_t dek[HKDFGUARD_DEK_LEN] = {};
        BCryptGenRandom(nullptr, dek, sizeof(dek), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_MAX_LEN);
        int wrapped_len = static_cast<int>(wrapped.size());
        int wrap = hkdfguard_wrap_dek(argv[2], dek, sizeof(dek), wrapped.data(), &wrapped_len);
        SecureZeroMemory(dek, sizeof(dek));
        wrapped.resize(wrap == HKDFGUARD_OK ? static_cast<size_t>(wrapped_len) : 0);
        int unwrap2 = wrap == HKDFGUARD_OK ? Unwrap(argv[2], wrapped) : wrap;
        std::printf("generate=%d unwrap=%d wrap=%d unwrap2=%d\n", generate, unwrap, wrap, unwrap2);
        return 0;
    }
    if (command == "plant" && argc == 5) {
        DWORD mkdir = CreateDirectoryA(argv[3], nullptr) ? ERROR_SUCCESS : GetLastError();
        DWORD write = CopyAsThisAccount(argv[2], std::string(argv[3]) + "\\" + argv[4]);
        std::printf("mkdir=%lu write=%lu\n", mkdir, write);
        return 0;
    }
    if (command == "overwrite" && argc == 3) {
        HANDLE h = CreateFileA(argv[2], GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        DWORD err = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        std::printf("write=%lu\n", err);
        return 0;
    }
    if (command == "inspect" && argc == 3) {
        std::string owner, sha256;
        DWORD err = Inspect(argv[2], owner, sha256);
        std::printf("inspect=%lu owner=%s sha256=%s\n", err, owner.c_str(), sha256.c_str());
        return 0;
    }
    std::fprintf(stderr, "role_probe: unknown command or wrong argument count\n");
    return 2;
}
