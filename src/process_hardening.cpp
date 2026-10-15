#include "process_hardening.h"
#include "../include/hkdfguard.h"
#include "errors.h"

#include <windows.h>
#include <aclapi.h>   // SetSecurityInfo
#include <sddl.h>     // ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertSidToStringSidW
#include <tlhelp32.h> // CreateToolhelp32Snapshot - enumerating this process's threads
#include <werapi.h>   // WerSetFlags

#include <string>
#include <vector>

namespace hkdfguard {
    namespace {
        [[noreturn]] void Fail(const char *what) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROCESS_HARDENING_FAILED, what);
        }

        // Owns a security descriptor allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW.
        class LocalSecurityDescriptor {
        public:
            explicit LocalSecurityDescriptor(const std::wstring &sddl) {
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.c_str(), SDDL_REVISION_1, &sd_, nullptr)) {
                    Fail("ConvertStringSecurityDescriptorToSecurityDescriptor failed");
                }
            }
            ~LocalSecurityDescriptor() { LocalFree(sd_); }
            LocalSecurityDescriptor(const LocalSecurityDescriptor &) = delete;
            LocalSecurityDescriptor &operator=(const LocalSecurityDescriptor &) = delete;

            PACL Dacl() const {
                BOOL present = FALSE, defaulted = FALSE;
                PACL dacl = nullptr;
                if (!GetSecurityDescriptorDacl(sd_, &present, &dacl, &defaulted) || !present || dacl == nullptr) {
                    Fail("security descriptor has no DACL");
                }
                return dacl;
            }

        private:
            PSECURITY_DESCRIPTOR sd_ = nullptr;
        };

        // The SID of the account this process runs as, in string form.
        std::wstring CurrentUserSidString() {
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
                Fail("OpenProcessToken failed");
            }
            DWORD needed = 0;
            GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
            std::vector<BYTE> buffer(needed);
            bool ok = needed != 0 && GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed);
            CloseHandle(token);
            if (!ok) {
                Fail("GetTokenInformation(TokenUser) failed");
            }
            LPWSTR sid = nullptr;
            if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &sid)) {
                Fail("ConvertSidToStringSid failed");
            }
            std::wstring result(sid);
            LocalFree(sid);
            return result;
        }

        // A protected DACL (inherits nothing) granting SYSTEM `all` and
        // `limited` to both OWNER RIGHTS (S-1-3-4, "OW") and the account
        // itself. The OWNER RIGHTS ACE is what makes the restriction stick:
        // an object's owner is otherwise implicitly allowed READ_CONTROL and
        // WRITE_DAC, so a same-user process could rewrite the DACL; with this
        // ACE present the owner gets exactly `limited` instead.
        //
        // `all` is the object type's own all-access mask rather than generic
        // GA: the kernel maps a generic right to specific ones when it stores
        // a DACL, so a GA ACE would never compare equal to what
        // AlreadyHardened reads back.
        std::wstring RestrictedDacl(DWORD all, DWORD limited, const std::wstring &user) {
            wchar_t full[16], rights[16];
            swprintf_s(full, L"0x%lx", all);
            swprintf_s(rights, L"0x%lx", limited);
            return std::wstring(L"D:P(A;;") + full + L";;;SY)(A;;" + rights + L";;;OW)(A;;" + rights + L";;;" + user +
                   L")";
        }

        // Whether thread `id` already has exactly `expected` as a protected
        // DACL - i.e. an earlier call hardened it.
        bool AlreadyHardened(DWORD id, PACL expected) {
            HANDLE thread = OpenThread(READ_CONTROL, FALSE, id);
            if (thread == nullptr) {
                return false;
            }
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            DWORD rc = GetSecurityInfo(thread, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
                                       nullptr, &sd);
            CloseHandle(thread);
            SECURITY_DESCRIPTOR_CONTROL control = 0;
            DWORD revision = 0;
            bool same = rc == ERROR_SUCCESS && dacl != nullptr &&
                        GetSecurityDescriptorControl(sd, &control, &revision) && (control & SE_DACL_PROTECTED) != 0 &&
                        dacl->AceCount == expected->AceCount;
            // ACE by ACE: the stored ACL's allocated size (AclSize) needn't
            // match the one built here, but its entries must.
            for (WORD i = 0; same && i < expected->AceCount; ++i) {
                void *got = nullptr, *want = nullptr;
                same = GetAce(dacl, i, &got) && GetAce(expected, i, &want) &&
                       static_cast<ACE_HEADER *>(got)->AceSize == static_cast<ACE_HEADER *>(want)->AceSize &&
                       memcmp(got, want, static_cast<ACE_HEADER *>(want)->AceSize) == 0;
            }
            LocalFree(sd);
            return same;
        }

        void Apply(HANDLE object, PACL dacl, const char *what) {
            DWORD rc = SetSecurityInfo(object, SE_KERNEL_OBJECT,
                                       DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, dacl, nullptr);
            if (rc != ERROR_SUCCESS) {
                Fail(what);
            }
        }
    } // namespace

    void HardenProcess() {
        // 1. Crash reports: no heap. Per process, no elevation needed.
        if (FAILED(WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP))) {
            Fail("WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) failed");
        }

        const std::wstring user = CurrentUserSidString();

        // 2. The process. Kept: terminate (as on Linux, the same user can
        // still kill a hardened process), query (plain and limited - tools
        // and runtimes that open their own process by ID for information
        // keep working) and synchronize (waiting for exit). Gone: VM read,
        // write and operation, create thread, duplicate handle, set
        // information, suspend/resume, READ_CONTROL and WRITE_DAC.
        constexpr DWORD kProcessLimited =
                PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
        LocalSecurityDescriptor processSd(RestrictedDacl(PROCESS_ALL_ACCESS, kProcessLimited, user));
        Apply(GetCurrentProcess(), processSd.Dacl(), "SetSecurityInfo on the process failed");

        // 3. Every thread that exists now. Kept: query and synchronize. Gone:
        // get/set context, suspend/resume, impersonate, terminate,
        // READ_CONTROL and WRITE_DAC. Threads created after this call get
        // the token's default DACL, which this deliberately leaves alone: it
        // is also the DACL of every other unnamed object the host creates,
        // whose access rights mean something different per object type.
        // READ_CONTROL (reading the DACL) is kept so a repeat call can
        // recognize a thread it already hardened - see below.
        constexpr DWORD kThreadLimited =
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | READ_CONTROL;
        LocalSecurityDescriptor threadSd(RestrictedDacl(THREAD_ALL_ACCESS, kThreadLimited, user));
        PACL threadDacl = threadSd.Dacl();

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            Fail("CreateToolhelp32Snapshot failed");
        }
        const DWORD pid = GetCurrentProcessId();
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        bool failed = false;
        for (BOOL more = Thread32First(snapshot, &entry); more; more = Thread32Next(snapshot, &entry)) {
            if (entry.th32OwnerProcessID != pid) {
                continue;
            }
            HANDLE thread = OpenThread(WRITE_DAC, FALSE, entry.th32ThreadID);
            if (thread == nullptr) {
                DWORD error = GetLastError();
                // A thread that exited since the snapshot is fine. Access
                // denied is expected on a repeat call - a hardened thread
                // denies WRITE_DAC to everyone but SYSTEM - and is fine
                // exactly when the thread already carries this DACL. Any
                // other failure means a thread was left unprotected.
                if (error == ERROR_ACCESS_DENIED) {
                    failed = failed || !AlreadyHardened(entry.th32ThreadID, threadDacl);
                } else if (error != ERROR_INVALID_PARAMETER) {
                    failed = true;
                }
                continue;
            }
            if (SetSecurityInfo(thread, SE_KERNEL_OBJECT,
                                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, threadDacl, nullptr) != ERROR_SUCCESS) {
                failed = true;
            }
            CloseHandle(thread);
        }
        CloseHandle(snapshot);
        if (failed) {
            Fail("could not restrict every thread of the process");
        }
    }
} // namespace hkdfguard
