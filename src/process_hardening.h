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
    // With `strict` (HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE), two
    // more steps close what the three above leave open to a same-user
    // process, applied first so threads started while this runs are
    // covered too:
    //
    //   4. The process token's default DACL - the DACL every unnamed object
    //      it creates from then on gets, threads included - is set so only
    //      SYSTEM has any specific right; the account and OWNER RIGHTS keep
    //      only SYNCHRONIZE and READ_CONTROL. Threads started later are
    //      then as closed as the ones step 3 covers.
    //   5. The process token's own DACL is replaced so the account may only
    //      query and duplicate it (the TPM key store duplicates its own
    //      token): without this, a same-user process could open the token
    //      and put the old default DACL back.
    //
    // Idempotent, in either mode and in any order. Throws
    // HkdfGuardError(HKDFGUARD_ERR_PROCESS_HARDENING_FAILED) if any step
    // fails; steps already applied stay applied.
    void HardenProcess(bool strict);
} // namespace hkdfguard
