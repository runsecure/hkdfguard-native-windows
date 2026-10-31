#pragma once

// Shared by the libFuzzer targets in this folder. A property a target
// checks that fails is a finding: FUZZ_REQUIRE reports it and aborts, which
// libFuzzer records as a crash with the input that caused it.

#include <cstdio>
#include <cstdlib>

#define FUZZ_REQUIRE(condition, what)                                                   \
    do {                                                                                \
        if (!(condition)) {                                                             \
            std::fprintf(stderr, "fuzz property violated: %s (%s:%d)\n", what, __FILE__, \
                         __LINE__);                                                     \
            std::abort();                                                               \
        }                                                                               \
    } while (0)
