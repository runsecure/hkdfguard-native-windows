#pragma once

namespace hkdfguard {
    // Hardens the calling process against memory disclosure - the Windows
    // counterpart of the Linux build's RLIMIT_CORE / PR_SET_DUMPABLE (see
    // hkdfguard_harden_process in hkdfguard.h for the contract):
    //
    //   1. WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP): Windows Error
    //      Reporting leaves the heap out of crash data it collects for this
    //      process - where DEKs and wrapping keys live during a call.
    //   2. The process object's DACL is replaced so that only SYSTEM may read
    //      or write its memory, create threads in it, duplicate its handles
    //      or change its security. The account it runs as keeps query,
    //      synchronize and terminate rights only. An OWNER RIGHTS ACE takes
    //      away the owner's implicit right to rewrite the DACL - without it,
    //      a same-user process could simply put the old DACL back.
    //   3. Every thread existing at the time gets the same treatment (only
    //      SYSTEM may get or set a thread's context, suspend it or change its
    //      security): otherwise a same-user process could read a thread's
    //      registers, or redirect its execution, with the process locked.
    //
    // Idempotent. Throws HkdfGuardError(HKDFGUARD_ERR_PROCESS_HARDENING_FAILED)
    // if any step fails; steps already applied stay applied.
    void HardenProcess();
} // namespace hkdfguard
