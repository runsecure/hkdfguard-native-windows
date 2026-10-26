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

        // Whether `dacl` holds exactly `expected`'s ACEs, in order. The stored
        // ACL's allocated size (AclSize) needn't match the one built here,
        // but its entries must.
        bool SameAces(PACL dacl, PACL expected) {
            if (dacl == nullptr || dacl->AceCount != expected->AceCount) {
                return false;
            }
            for (WORD i = 0; i < expected->AceCount; ++i) {
                void *got = nullptr, *want = nullptr;
                if (!GetAce(dacl, i, &got) || !GetAce(expected, i, &want) ||
                    static_cast<ACE_HEADER *>(got)->AceSize != static_cast<ACE_HEADER *>(want)->AceSize ||
                    memcmp(got, want, static_cast<ACE_HEADER *>(want)->AceSize) != 0) {
                    return false;
                }
            }
            return true;
        }

        // Whether `object` (opened with READ_CONTROL) carries exactly
        // `expected` as its DACL - protected from inheritance, if
        // `require_protected`.
        bool HasDacl(HANDLE object, PACL expected, bool require_protected) {
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (GetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
                                nullptr, &sd) != ERROR_SUCCESS) {
                return false;
            }
            SECURITY_DESCRIPTOR_CONTROL control = 0;
            DWORD revision = 0;
            bool same = GetSecurityDescriptorControl(sd, &control, &revision) &&
                        (!require_protected || (control & SE_DACL_PROTECTED) != 0) && SameAces(dacl, expected);
            LocalFree(sd);
            return same;
        }

        // Whether thread `id` was already hardened: by an earlier call
        // (`hardened`, protected), or by having been created under the
        // strict default DACL (`strict_default`, copied from the token, so
        // not protected). Either way it denies WRITE_DAC to this account,
        // so it can't be redone - and both are what it should be.
        bool AlreadyHardened(DWORD id, PACL hardened, PACL strict_default) {
            HANDLE thread = OpenThread(READ_CONTROL, FALSE, id);
            if (thread == nullptr) {
                return false;
            }
            bool done = HasDacl(thread, hardened, true) || HasDacl(thread, strict_default, false);
            CloseHandle(thread);
            return done;
        }

        void Apply(HANDLE object, PACL dacl, const char *what) {
            DWORD rc = SetSecurityInfo(object, SE_KERNEL_OBJECT,
                                       DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, dacl, nullptr);
            if (rc != ERROR_SUCCESS) {
                Fail(what);
            }
        }
        // The default DACL strict mode gives the process token: every unnamed
        // object created from then on - threads and child processes
        // included - gets it. SYSTEM gets every specific and standard right
        // (0x1FFFFF, the all-access mask of any object type); the account
        // and OWNER RIGHTS only SYNCHRONIZE and READ_CONTROL (0x120000).
        // Only standard rights for the account, never specific ones: a
        // specific bit means something different for every object type
        // (0x40 is a thread's QUERY_INFORMATION but a process's DUP_HANDLE).
        std::wstring StrictDefaultDacl(const std::wstring &user) {
            return L"D:(A;;0x1fffff;;;SY)(A;;0x120000;;;OW)(A;;0x120000;;;" + user + L")";
        }

        // Steps 4 and 5 (see process_hardening.h): the token's default DACL,
        // then the token's own DACL - in that order, since the second takes
        // away the access the first needs. On a repeat call the token can no
        // longer be opened to change either, so both are verified instead.
        //
        // The account keeps query and TOKEN_DUPLICATE on the token. The
        // Platform Crypto Provider (the TPM key store) duplicates its own
        // process token on every key open, and fails with NTE_PERM without
        // it. Duplicating gains a same-user process nothing: the copy is a
        // separate token, and changing its default DACL changes nothing here.
        // What would undo step 4 - TOKEN_ADJUST_DEFAULT, WRITE_DAC,
        // WRITE_OWNER - stays SYSTEM's alone.
        void HardenToken(const std::wstring &user, PACL default_dacl) {
            LocalSecurityDescriptor tokenSd(RestrictedDacl(
                    TOKEN_ALL_ACCESS, TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | READ_CONTROL, user));
            PACL tokenDacl = tokenSd.Dacl();

            HANDLE token = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | WRITE_DAC, &token)) {
                TOKEN_DEFAULT_DACL value{default_dacl};
                bool ok = SetTokenInformation(token, TokenDefaultDacl, &value, sizeof(value)) != FALSE &&
                          SetSecurityInfo(token, SE_KERNEL_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                          nullptr, tokenDacl, nullptr) == ERROR_SUCCESS;
                CloseHandle(token);
                if (!ok) {
                    Fail("could not restrict the process token's default DACL and its own DACL");
                }
                return;
            }
            if (GetLastError() != ERROR_ACCESS_DENIED ||
                !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &token)) {
                Fail("OpenProcessToken failed");
            }
            bool done = HasDacl(token, tokenDacl, true);
            DWORD needed = 0;
            GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &needed);
            std::vector<BYTE> buffer(needed);
            done = done && needed != 0 &&
                   GetTokenInformation(token, TokenDefaultDacl, buffer.data(), needed, &needed) &&
                   SameAces(reinterpret_cast<TOKEN_DEFAULT_DACL *>(buffer.data())->DefaultDacl, default_dacl);
            CloseHandle(token);
            if (!done) {
                Fail("the process token can't be changed, and isn't already hardened");
            }
        }
    } // namespace

    void HardenProcess(bool strict) {
        // 1. Crash reports: no heap. Per process, no elevation needed.
        if (FAILED(WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP))) {
            Fail("WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) failed");
        }

        const std::wstring user = CurrentUserSidString();
        LocalSecurityDescriptor strictDefaultSd(StrictDefaultDacl(user));
        PACL strictDefault = strictDefaultSd.Dacl();

        // 4 and 5 (strict only), before anything else: a thread started from
        // here on is created under the strict default DACL.
        if (strict) {
            HardenToken(user, strictDefault);
        }

        // 2. The process. Kept: terminate (the same user can still kill a
        // hardened process), query (plain and limited - tools
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
        // the token's default DACL, which this leaves alone unless `strict`
        // (step 4): it is also the DACL of every other unnamed object the
        // host creates, so changing it is the caller's choice.
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
                // denies WRITE_DAC to everyone but SYSTEM, as does one
                // created under the strict default DACL - and is fine
                // exactly when the thread carries one of those two. Any
                // other failure means a thread was left unprotected.
                if (error == ERROR_ACCESS_DENIED) {
                    failed = failed || !AlreadyHardened(entry.th32ThreadID, threadDacl, strictDefault);
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
