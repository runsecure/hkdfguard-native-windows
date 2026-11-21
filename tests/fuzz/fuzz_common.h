#pragma once

// Shared by the libFuzzer targets in this folder. A property a target
// checks that fails is a finding: FUZZ_REQUIRE reports it and aborts, which
// libFuzzer records as a crash with the input that caused it.

#include <cstdio>
#include <cstdlib>

// Ends the process the way libFuzzer records as a crash - at once: without
// the C runtime's abort message or Windows Error Reporting, either of which
// can hold a failing run for a minute and turn a finding into a "timeout".
[[noreturn]] inline void FuzzAbort() {
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    std::abort();
}

#define FUZZ_REQUIRE(condition, what)                                                   \
    do {                                                                                \
        if (!static_cast<bool>(condition)) {                                            \
            std::fprintf(stderr, "fuzz property violated: %s (%s:%d)\n", what, __FILE__, \
                         __LINE__);                                                     \
            FuzzAbort();                                                                \
        }                                                                               \
    } while (0)
