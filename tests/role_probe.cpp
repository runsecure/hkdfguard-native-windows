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
#include "hkdfguard.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <string>
#include <vector>

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
} // namespace

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: role_probe model | open <path> | unwrap <service> <path> | ephemeral <service> | "
                             "plant <src> <dir> <name> | overwrite <path>\n");
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
    std::fprintf(stderr, "role_probe: unknown command or wrong argument count\n");
    return 2;
}
