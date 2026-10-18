// Tests hkdfguard_harden_process from the outside, the only place its
// effect is visible: a process always has full access to itself through
// GetCurrentProcess(), whatever its DACL says. So this .exe runs twice:
//
//   test_harden_process.exe              - the parent: starts a copy of
//                                          itself as the child, probes it,
//                                          then does the same in strict mode
//   test_harden_process.exe child        - the child: starts a worker
//                                          thread, hardens itself, checks
//                                          what it can check from the
//                                          inside, and reports
//   test_harden_process.exe child-strict - the same, hardening with
//                                          HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE
//
// The child reports one line on stdout - "READY <main tid> <worker tid>
// <late tid> <mid tid>" (mid is 0 outside strict mode) or "FAIL <reason>" -
// then waits for its stdin to close before exiting, so it stays alive while
// the parent probes it.
//
// Same hand-rolled PASS/FAIL style as test_roundtrip.cpp. Exits 0 when every
// check passes, 1 otherwise, and 77 (ctest's SKIP_RETURN_CODE, see
// tests/CMakeLists.txt) when run as SYSTEM, which the hardened DACL grants
// everything by design.
#include "hkdfguard.h"

#include <windows.h>
#include <dbghelp.h> // MiniDumpWriteDump
#include <werapi.h>  // WerGetFlags

#include <cstdio>
#include <cstring>
#include <string>

namespace {

int g_failures = 0;

void Check(bool condition, const char *what) {
    if (condition) {
        std::printf("[PASS] %s\n", what);
    } else {
        std::printf("[FAIL] %s\n", what);
        ++g_failures;
    }
}

constexpr int kSkip = 77;

// ---- Child -------------------------------------------------------------

HANDLE g_release = nullptr; // set by the child when its stdin closes; ends the threads below

DWORD WINAPI Park(LPVOID) {
    WaitForSingleObject(g_release, INFINITE);
    return 0;
}

int ChildFail(const char *reason) {
    std::printf("FAIL %s\n", reason);
    std::fflush(stdout);
    return 1;
}

int RunChild(bool strict) {
    g_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD workerId = 0;
    HANDLE worker = CreateThread(nullptr, 0, Park, nullptr, 0, &workerId);
    if (g_release == nullptr || worker == nullptr) {
        return ChildFail("could not start the worker thread");
    }

    // Unknown flag bits are refused before anything is changed, so a flag a
    // newer caller relies on is never silently ignored: WER's NOHEAP, the
    // first step, must still be off afterwards.
    if (hkdfguard_harden_process_with_flags(~HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) !=
            HKDFGUARD_ERR_INVALID_ARGUMENT ||
        hkdfguard_harden_process_with_flags(0x80000000u) != HKDFGUARD_ERR_INVALID_ARGUMENT) {
        return ChildFail("unknown flag bits did not return HKDFGUARD_ERR_INVALID_ARGUMENT");
    }
    DWORD before = 0;
    if (SUCCEEDED(WerGetFlags(GetCurrentProcess(), &before)) && (before & WER_FAULT_REPORTING_FLAG_NOHEAP) != 0) {
        return ChildFail("a call refused for unknown flag bits still changed the process");
    }

    DWORD midId = 0;
    HANDLE mid = nullptr;
    if (!strict) {
        if (hkdfguard_harden_process() != HKDFGUARD_OK) {
            return ChildFail("hkdfguard_harden_process did not return HKDFGUARD_OK");
        }
        // Idempotency: a second call finds its own DACLs already in place.
        if (hkdfguard_harden_process() != HKDFGUARD_OK) {
            return ChildFail("a second hkdfguard_harden_process call did not return HKDFGUARD_OK");
        }
    } else {
        if (hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) != HKDFGUARD_OK) {
            return ChildFail("strict hardening did not return HKDFGUARD_OK");
        }
        // A thread started between calls is created under the strict
        // default DACL; repeat calls, strict or not, must accept it (it
        // denies them WRITE_DAC) and the already-locked token.
        mid = CreateThread(nullptr, 0, Park, nullptr, 0, &midId);
        if (mid == nullptr) {
            return ChildFail("could not start a thread between strict hardening calls");
        }
        if (hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) != HKDFGUARD_OK) {
            return ChildFail("a second strict hardening call did not return HKDFGUARD_OK");
        }
        if (hkdfguard_harden_process() != HKDFGUARD_OK) {
            return ChildFail("hkdfguard_harden_process after strict hardening did not return HKDFGUARD_OK");
        }
    }

    DWORD flags = 0;
    if (FAILED(WerGetFlags(GetCurrentProcess(), &flags)) || (flags & WER_FAULT_REPORTING_FLAG_NOHEAP) == 0) {
        return ChildFail("WER_FAULT_REPORTING_FLAG_NOHEAP is not set");
    }

    // The hardened process still works normally from the inside: it can
    // start threads and use the library (which opens a key storage provider).
    DWORD lateId = 0;
    HANDLE late = CreateThread(nullptr, 0, Park, nullptr, 0, &lateId);
    if (late == nullptr) {
        return ChildFail("could not start a thread after hardening");
    }
    int32_t exists = -1;
    int32_t kek_rc = hkdfguard_kek_exists("hkdfguard.hardentest.absent", &exists);
    if (kek_rc != HKDFGUARD_OK || exists != 0) {
        return ChildFail(("hkdfguard_kek_exists failed after hardening (rc " + std::to_string(kek_rc) + ")").c_str());
    }

    std::printf("READY %lu %lu %lu %lu\n", GetCurrentThreadId(), workerId, lateId, midId);
    std::fflush(stdout);

    // Block until the parent closes our stdin.
    char buf[16];
    DWORD read = 0;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof(buf), &read, nullptr) && read != 0) {
    }
    SetEvent(g_release);
    HANDLE threads[] = {worker, late, mid};
    WaitForMultipleObjects(mid != nullptr ? 3 : 2, threads, TRUE, 5000);
    return 0;
}

// ---- Parent ------------------------------------------------------------

bool RunningAsSystem() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    BYTE buffer[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)];
    DWORD needed = 0;
    bool system = GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &needed) &&
                  IsWellKnownSid(reinterpret_cast<TOKEN_USER *>(buffer)->User.Sid, WinLocalSystemSid);
    CloseHandle(token);
    return system;
}

// An enabled SeDebugPrivilege bypasses a process's DACL entirely (the
// documented limit). Elevated tokens hold it disabled, but a token inherits
// its parent's enabled state, so a harness that enabled it would make every
// "denied" check below pass access instead. Disable it for this process.
void DisableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        return;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = 0; // disabled
        AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    }
    CloseHandle(token);
}

// Opens the child with exactly `access`; true if that succeeded.
bool CanOpenProcess(DWORD pid, DWORD access) {
    HANDLE h = OpenProcess(access, FALSE, pid);
    if (h == nullptr) {
        return false;
    }
    CloseHandle(h);
    return true;
}

// True only if the open failed *because access was denied*, not for some
// unrelated reason such as the child having exited.
bool OpenProcessDenied(DWORD pid, DWORD access) {
    HANDLE h = OpenProcess(access, FALSE, pid);
    if (h != nullptr) {
        CloseHandle(h);
        return false;
    }
    return GetLastError() == ERROR_ACCESS_DENIED;
}

bool CanOpenThread(DWORD tid, DWORD access) {
    HANDLE h = OpenThread(access, FALSE, tid);
    if (h == nullptr) {
        return false;
    }
    CloseHandle(h);
    return true;
}

bool OpenThreadDenied(DWORD tid, DWORD access) {
    HANDLE h = OpenThread(access, FALSE, tid);
    if (h != nullptr) {
        CloseHandle(h);
        return false;
    }
    return GetLastError() == ERROR_ACCESS_DENIED;
}

void CheckThreadHardened(DWORD tid, const char *name) {
    std::string prefix = std::string(name) + " thread: ";
    Check(OpenThreadDenied(tid, THREAD_GET_CONTEXT), (prefix + "THREAD_GET_CONTEXT denied").c_str());
    Check(OpenThreadDenied(tid, THREAD_SET_CONTEXT), (prefix + "THREAD_SET_CONTEXT denied").c_str());
    Check(OpenThreadDenied(tid, THREAD_SUSPEND_RESUME), (prefix + "THREAD_SUSPEND_RESUME denied").c_str());
    Check(OpenThreadDenied(tid, THREAD_TERMINATE), (prefix + "THREAD_TERMINATE denied").c_str());
    Check(OpenThreadDenied(tid, WRITE_DAC), (prefix + "WRITE_DAC denied").c_str());
    Check(OpenThreadDenied(tid, WRITE_OWNER), (prefix + "WRITE_OWNER denied").c_str());
    Check(CanOpenThread(tid, THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
          (prefix + "THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE still allowed").c_str());
}

// A thread created under the strict default DACL: the account keeps only
// SYNCHRONIZE (and READ_CONTROL) - not even query.
void CheckThreadStrict(DWORD tid, const char *name) {
    std::string prefix = std::string(name) + " thread: ";
    Check(OpenThreadDenied(tid, THREAD_GET_CONTEXT), (prefix + "THREAD_GET_CONTEXT denied").c_str());
    Check(OpenThreadDenied(tid, THREAD_SET_CONTEXT), (prefix + "THREAD_SET_CONTEXT denied (no execution redirect)").c_str());
    Check(OpenThreadDenied(tid, THREAD_SUSPEND_RESUME), (prefix + "THREAD_SUSPEND_RESUME denied").c_str());
    Check(OpenThreadDenied(tid, THREAD_TERMINATE), (prefix + "THREAD_TERMINATE denied").c_str());
    Check(OpenThreadDenied(tid, WRITE_DAC), (prefix + "WRITE_DAC denied").c_str());
    Check(OpenThreadDenied(tid, WRITE_OWNER), (prefix + "WRITE_OWNER denied").c_str());
    Check(OpenThreadDenied(tid, THREAD_QUERY_LIMITED_INFORMATION), (prefix + "THREAD_QUERY_LIMITED_INFORMATION denied").c_str());
    Check(CanOpenThread(tid, SYNCHRONIZE), (prefix + "SYNCHRONIZE still allowed").c_str());
}

// Opens the child's primary token with `access`: true if allowed, and sets
// `denied` if it failed because access was denied (not for another reason).
bool OpenChildToken(DWORD pid, DWORD access, bool &denied) {
    denied = false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) {
        return false;
    }
    HANDLE token = nullptr;
    bool ok = OpenProcessToken(process, access, &token) != FALSE;
    denied = !ok && GetLastError() == ERROR_ACCESS_DENIED;
    if (ok) {
        CloseHandle(token);
    }
    CloseHandle(process);
    return ok;
}

void ProbeChild(bool strict, DWORD pid, DWORD mainTid, DWORD workerTid, DWORD lateTid, DWORD midTid) {
    // The process: memory, threads, handles and security all denied...
    Check(OpenProcessDenied(pid, PROCESS_VM_READ), "process: PROCESS_VM_READ denied");
    Check(OpenProcessDenied(pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION), "process: PROCESS_VM_WRITE | PROCESS_VM_OPERATION denied");
    Check(OpenProcessDenied(pid, PROCESS_CREATE_THREAD), "process: PROCESS_CREATE_THREAD denied");
    Check(OpenProcessDenied(pid, PROCESS_DUP_HANDLE), "process: PROCESS_DUP_HANDLE denied");
    Check(OpenProcessDenied(pid, PROCESS_SET_INFORMATION), "process: PROCESS_SET_INFORMATION denied");
    Check(OpenProcessDenied(pid, PROCESS_SUSPEND_RESUME), "process: PROCESS_SUSPEND_RESUME denied");
    Check(OpenProcessDenied(pid, READ_CONTROL), "process: READ_CONTROL denied");
    Check(OpenProcessDenied(pid, WRITE_DAC), "process: WRITE_DAC denied (the old DACL cannot be put back)");
    Check(OpenProcessDenied(pid, WRITE_OWNER), "process: WRITE_OWNER denied");
    Check(OpenProcessDenied(pid, PROCESS_ALL_ACCESS), "process: PROCESS_ALL_ACCESS denied");

    // ...while listing, waiting on and stopping it still work.
    Check(CanOpenProcess(pid, PROCESS_QUERY_LIMITED_INFORMATION), "process: PROCESS_QUERY_LIMITED_INFORMATION still allowed");
    Check(CanOpenProcess(pid, PROCESS_QUERY_INFORMATION), "process: PROCESS_QUERY_INFORMATION still allowed");
    Check(CanOpenProcess(pid, SYNCHRONIZE), "process: SYNCHRONIZE still allowed");
    Check(CanOpenProcess(pid, PROCESS_TERMINATE), "process: PROCESS_TERMINATE still allowed");

    // What a dump tool would do, with the most a same-user process can get.
    HANDLE query = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    wchar_t tempDir[MAX_PATH + 1];
    wchar_t dumpPath[MAX_PATH + 1];
    bool dumped = true;
    if (query != nullptr && GetTempPathW(MAX_PATH + 1, tempDir) != 0 &&
        GetTempFileNameW(tempDir, L"hgd", 0, dumpPath) != 0) {
        HANDLE file = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            dumped = MiniDumpWriteDump(query, pid, file, MiniDumpWithFullMemory, nullptr, nullptr, nullptr) != FALSE;
            CloseHandle(file);
        }
        DeleteFileW(dumpPath);
    }
    if (query != nullptr) {
        CloseHandle(query);
    }
    Check(!dumped, "process: MiniDumpWriteDump fails");

    // Threads existing at hardening time - including one that isn't the
    // thread which made the call.
    CheckThreadHardened(mainTid, "main");
    CheckThreadHardened(workerTid, "worker");

    bool denied = false;
    if (!strict) {
        // The documented limit: a thread started after the call keeps the
        // token's default DACL. Pinned here so a change in that behavior - in
        // either direction - is noticed and the documentation updated.
        Check(CanOpenThread(lateTid, THREAD_GET_CONTEXT),
              "late thread (started after hardening) keeps the default DACL, as documented");
        // And the token is left alone outside strict mode.
        Check(OpenChildToken(pid, TOKEN_ADJUST_DEFAULT, denied),
              "token: TOKEN_ADJUST_DEFAULT still allowed without the strict flag, as documented");
        return;
    }

    // Strict: threads started after the call - between two strict calls,
    // and after all of them - are closed too.
    CheckThreadStrict(midTid, "strict mid (started between calls)");
    CheckThreadStrict(lateTid, "strict late (started after hardening)");

    // The token can't be used to undo it.
    Check(!OpenChildToken(pid, TOKEN_ADJUST_DEFAULT, denied) && denied,
          "strict token: TOKEN_ADJUST_DEFAULT denied (the old default DACL cannot be put back)");
    Check(!OpenChildToken(pid, WRITE_DAC, denied) && denied, "strict token: WRITE_DAC denied");
    Check(!OpenChildToken(pid, WRITE_OWNER, denied) && denied, "strict token: WRITE_OWNER denied");
    Check(!OpenChildToken(pid, TOKEN_ADJUST_PRIVILEGES, denied) && denied, "strict token: TOKEN_ADJUST_PRIVILEGES denied");
    Check(OpenChildToken(pid, TOKEN_QUERY, denied), "strict token: TOKEN_QUERY still allowed");
    // The TPM key store duplicates its own process token on every key open
    // (NTE_PERM without it), so this stays - see HardenToken.
    Check(OpenChildToken(pid, TOKEN_DUPLICATE, denied), "strict token: TOKEN_DUPLICATE still allowed (the TPM key store needs it)");
}

// Starts the child in one mode, probes it, and collects its exit code.
void RunChildAndProbe(bool strict) {
    std::printf("\n--- %s ---\n", strict ? "strict (HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE)" : "default");
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    HANDLE childStdinRead = nullptr, childStdinWrite = nullptr;
    HANDLE childStdoutRead = nullptr, childStdoutWrite = nullptr;
    if (!CreatePipe(&childStdinRead, &childStdinWrite, &inherit, 0) ||
        !CreatePipe(&childStdoutRead, &childStdoutWrite, &inherit, 0)) {
        Check(false, "CreatePipe");
        return;
    }
    // Our own ends must not be inherited, or the child's stdin never closes.
    SetHandleInformation(childStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(childStdoutRead, HANDLE_FLAG_INHERIT, 0);

    wchar_t self[MAX_PATH];
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        Check(false, "GetModuleFileName");
        return;
    }
    std::wstring commandLine = L"\"" + std::wstring(self) + (strict ? L"\" child-strict" : L"\" child");

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = childStdinRead;
    si.hStdOutput = childStdoutWrite;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(self, commandLine.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        std::printf("[FAIL] could not start the child (error %lu)\n", GetLastError());
        ++g_failures;
        return;
    }
    CloseHandle(childStdinRead);
    CloseHandle(childStdoutWrite);

    // Read the child's one report line.
    std::string line;
    char c = 0;
    DWORD got = 0;
    while (line.size() < 256 && ReadFile(childStdoutRead, &c, 1, &got, nullptr) && got == 1 && c != '\n') {
        line += c;
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }

    unsigned long mainTid = 0, workerTid = 0, lateTid = 0, midTid = 0;
    bool ready = std::sscanf(line.c_str(), "READY %lu %lu %lu %lu", &mainTid, &workerTid, &lateTid, &midTid) == 4;
    Check(ready, ("child refused unknown flags, hardened itself repeatedly, has WER NOHEAP set and still works (\"" +
                  line + "\")").c_str());
    if (ready) {
        // pi.hProcess / pi.hThread were opened before hardening and keep
        // full access (another documented limit) - every probe opens anew.
        ProbeChild(strict, pi.dwProcessId, mainTid, workerTid, lateTid, midTid);
    }

    // Release the child and collect its exit code.
    CloseHandle(childStdinWrite);
    DWORD exitCode = 1;
    if (WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    GetExitCodeProcess(pi.hProcess, &exitCode);
    Check(exitCode == 0, "child exited cleanly");
    CloseHandle(childStdoutRead);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

int RunParent() {
    if (RunningAsSystem()) {
        std::printf("[SKIP] running as SYSTEM, which the hardened DACL grants full access by design\n");
        return kSkip;
    }
    DisableDebugPrivilege();

    RunChildAndProbe(false);
    RunChildAndProbe(true);

    std::printf("\n%d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "child") == 0) {
        return RunChild(false);
    }
    if (argc == 2 && std::strcmp(argv[1], "child-strict") == 0) {
        return RunChild(true);
    }
    return RunParent();
}
