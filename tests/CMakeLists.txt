# The tests compile copies of src/ files that HkdfGuard.dll's build already
# runs clang-tidy on (HKDFGUARD_CLANG_TIDY); linting each copy again would
# only repeat the same findings. Source properties are per directory, so
# this affects only the targets defined here.
file(GLOB HKDFGUARD_SRC_COPIES ${CMAKE_CURRENT_SOURCE_DIR}/../src/*.cpp)
set_source_files_properties(${HKDFGUARD_SRC_COPIES} PROPERTIES SKIP_LINTING ON)

# test_roundtrip exercises the public DLL ABI (HkdfGuard.dll) for wrap/unwrap,
# and also compiles some of src/ directly so it can call internal helpers
# such as DeleteKek() to remove the KEKs it creates. Those sources are
# compiled into the DLL too; each copy lives in a separate binary, so there
# is no linker conflict.
add_executable(test_roundtrip
    test_roundtrip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
    # ecdh_hkdf.cpp + hash_to_curve.cpp: so the test can call
    # IsValidP256Point, HashToCurveP256 and PayloadEcdhPoint directly
    # (hand-built points and RFC 9380's hash-to-curve vectors) without a KEK, and DeriveWrappingKey
    # with the test-only provider fault enabled.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdh_hkdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hash_to_curve.cpp
    # event_log.cpp: the test's copy of kek_store.cpp logs KEK creation.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/event_log.cpp
    # key_file.cpp: so the test can call ReadWrappedKeyFile (hkdfguard_open_file's
    # implementation) directly.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_file.cpp
)
# The DLL's import library for the public ABI calls, plus the Windows
# libraries the directly compiled src/ files call into.
target_link_libraries(test_roundtrip PRIVATE hkdfguard ncrypt.lib bcrypt.lib ntdll.lib netapi32.lib)
target_include_directories(test_roundtrip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
# Enables policy.h's SetTestPolicyOverride seam in this target's copy of
# policy.cpp only. The DLL target never defines this macro, so the seam does
# not exist in shipped code.
target_compile_definitions(test_roundtrip PRIVATE HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
hkdfguard_apply_warnings(test_roundtrip)

add_test(NAME roundtrip COMMAND test_roundtrip)
# HkdfGuard.dll's output directory goes on the front of PATH for each test
# process so the loader finds the DLL.
#
# ENVIRONMENT is a CMake list, so every unescaped ';' starts a new entry.
# PATH is itself ';'-separated; spliced in raw, the test's PATH would be the
# DLL directory alone - no System32, not even cmd.exe. Escaping each ';'
# keeps the whole value as one PATH entry.
string(REPLACE ";" "\\;" HKDFGUARD_TEST_PATH "$ENV{PATH}")
set_tests_properties(roundtrip PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
)

# test_v2_kek checks payload version 2 end to end: the SP 800-108
# construction against the Linux library's known answers, the Software KSP's
# SP 800-108 derivation against it, the ClassicalMode rule, and - elevated -
# the DLL's TPM and software version 2 KEKs (create, wrap, unwrap,
# tampering, relabeling) and provider choice. It
# compiles its own copies of the version 2 sources, with the test seams
# enabled, for the provider-choice checks; everything else goes through
# HkdfGuard.dll.
add_executable(test_v2_kek
    test_v2_kek.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_v2.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sp800_108.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/event_log.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
)
target_include_directories(test_v2_kek PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_compile_definitions(test_v2_kek PRIVATE HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE UNICODE _UNICODE)
target_link_libraries(test_v2_kek PRIVATE hkdfguard ncrypt.lib bcrypt.lib advapi32.lib netapi32.lib ntdll.lib)
hkdfguard_apply_warnings(test_v2_kek)
add_test(NAME v2_kek COMMAND test_v2_kek)
set_tests_properties(v2_kek PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
)

# v2_provider_probe checks the providers' own behavior that version 2
# relies on - the Software KSP's SP 800-108 key and the PCP's HMAC key -
# straight through NCrypt, without HkdfGuard.dll or src/, so it is
# independent evidence for a new TPM or Windows build (SecurityAssumptions.md
# section 17). Not a ctest test: it is run by scripts/hardware-tests, on the
# machine being qualified, elevated.
add_executable(v2_provider_probe v2_provider_probe.cpp)
target_compile_definitions(v2_provider_probe PRIVATE UNICODE _UNICODE)
target_link_libraries(v2_provider_probe PRIVATE ncrypt.lib bcrypt.lib advapi32.lib)
hkdfguard_apply_warnings(v2_provider_probe)

# The same parsers under libFuzzer and AddressSanitizer, built only on
# request: cmake -DHKDFGUARD_BUILD_FUZZERS=ON. Registered as a short ctest
# smoke run (a fixed number of inputs); run the executable directly, with a
# corpus folder, for a real fuzzing session.
option(HKDFGUARD_BUILD_FUZZERS "Build the libFuzzer targets (MSVC, with AddressSanitizer)" OFF)
if(HKDFGUARD_BUILD_FUZZERS AND MSVC)
    # One libFuzzer target: its .cpp in fuzz/, the src/ files it needs, and
    # the system libraries those use. Each is registered as a ctest smoke
    # run over its seed corpus (fuzz/corpus/<target>, read only: new inputs
    # libFuzzer finds go to a scratch folder in the build tree).
    # A fuzzer always links AddressSanitizer, whose runtime DLL must be the
    # one from the toolset that built it: another Visual Studio's copy on
    # PATH fails at load ("entry point __asan_... could not be located").
    # Each fuzzer gets the matching DLL beside it, so it runs from any shell.
    get_filename_component(_hkdfguard_fuzz_asan_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(HKDFGUARD_FUZZ_ASAN_RUNTIME "${_hkdfguard_fuzz_asan_dir}/clang_rt.asan_dynamic-x86_64.dll")
    if(NOT EXISTS "${HKDFGUARD_FUZZ_ASAN_RUNTIME}")
        message(FATAL_ERROR "ASan runtime not found at ${HKDFGUARD_FUZZ_ASAN_RUNTIME}")
    endif()
    function(hkdfguard_stage_asan_runtime target)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${HKDFGUARD_FUZZ_ASAN_RUNTIME}" "$<TARGET_FILE_DIR:${target}>"
            VERBATIM)
    endfunction()

    function(hkdfguard_add_fuzzer name runs max_len)
        cmake_parse_arguments(FUZZ "" "" "SOURCES;LIBS" ${ARGN})
        set(sources fuzz/${name}.cpp)
        foreach(src IN LISTS FUZZ_SOURCES)
            list(APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/../src/${src})
        endforeach()
        add_executable(${name} ${sources})
        hkdfguard_stage_asan_runtime(${name})
        target_include_directories(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/../include
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
            ${CMAKE_CURRENT_SOURCE_DIR}/fuzz
        )
        target_compile_definitions(${name} PRIVATE UNICODE _UNICODE)
        target_compile_options(${name} PRIVATE /fsanitize=fuzzer /fsanitize=address /Zi)
        target_link_options(${name} PRIVATE /INCREMENTAL:NO)
        hkdfguard_apply_warnings(${name})
        if(FUZZ_LIBS)
            target_link_libraries(${name} PRIVATE ${FUZZ_LIBS})
        endif()
        set(found ${CMAKE_CURRENT_BINARY_DIR}/fuzz-found/${name})
        # An input that fails is saved here, apart from the corpus.
        set(crashes ${CMAKE_CURRENT_BINARY_DIR}/fuzz-crashes/${name})
        file(MAKE_DIRECTORY ${found} ${crashes})
        add_test(NAME ${name}
                 COMMAND ${name} -runs=${runs} -max_len=${max_len} -artifact_prefix=${crashes}/ ${found}
                         ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/${name})
    endfunction()

    set(HKDFGUARD_FUZZ_WIN_LIBS bcrypt.lib ncrypt.lib advapi32.lib netapi32.lib ntdll.lib)

    # The DACL walks behind "access list invalid" and the provisioning
    # grant check.
    hkdfguard_add_fuzzer(fuzz_kek_dacl 20000 1025
        SOURCES key_acl.cpp
        LIBS ${HKDFGUARD_FUZZ_WIN_LIBS})
    # The SP 800-108 framing's injectivity.
    hkdfguard_add_fuzzer(fuzz_v2_kdf 100000 1025
        SOURCES sp800_108.cpp)

    # ---- The C ABI under attack (fuzz/fuzz_abi.h) ----
    #
    # Five targets that call the exported functions the way a hostile or
    # careless caller does: wrong capacities, NULLs, truncated and corrupted
    # payloads, unterminated strings, four threads at once. They link the
    # library's own sources, compiled once here with libFuzzer's coverage
    # and AddressSanitizer - not HkdfGuard.dll - so the fuzzer sees into the
    # code and every out-of-bounds access is a finding. Two differences from
    # the DLL, neither in shipped code: policy.h's test seams are compiled in
    # (HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE), and the event log is a stub
    # (fuzz/event_log_stub.cpp) so millions of refused calls aren't logged.
    add_library(hkdfguard_fuzz_abi STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/hkdfguard.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdh_hkdf.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/aes_gcm.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_file.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/hash_to_curve.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/process_hardening.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_v2.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/sp800_108.cpp
        fuzz/event_log_stub.cpp
    )
    target_include_directories(hkdfguard_fuzz_abi PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/fuzz
    )
    # HKDFGUARD_EXPORTS: the functions are defined in this binary, not
    # imported from the DLL.
    target_compile_definitions(hkdfguard_fuzz_abi PUBLIC
        HKDFGUARD_EXPORTS HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE UNICODE _UNICODE)
    target_compile_options(hkdfguard_fuzz_abi PUBLIC /fsanitize=fuzzer /fsanitize=address /Zi)
    target_link_libraries(hkdfguard_fuzz_abi PUBLIC ${HKDFGUARD_FUZZ_WIN_LIBS} wer.lib)
    hkdfguard_apply_warnings(hkdfguard_fuzz_abi)

    # The seeds - the memory attacks a caller tries first, written down - are
    # generated, not checked in: fuzz/Make-AbiSeeds.ps1 is their source. It
    # runs under the Windows PowerShell every Windows machine has.
    set(HKDFGUARD_FUZZ_SEEDS ${CMAKE_CURRENT_BINARY_DIR}/fuzz-seeds)
    find_program(HKDFGUARD_POWERSHELL NAMES powershell pwsh REQUIRED)
    execute_process(
        COMMAND ${HKDFGUARD_POWERSHELL} -NoProfile -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/Make-AbiSeeds.ps1 -OutDir ${HKDFGUARD_FUZZ_SEEDS}
        RESULT_VARIABLE HKDFGUARD_FUZZ_SEEDS_RESULT)
    if(NOT HKDFGUARD_FUZZ_SEEDS_RESULT EQUAL 0)
        message(FATAL_ERROR "tests/fuzz/Make-AbiSeeds.ps1 failed")
    endif()
    # Reconfigure, and so regenerate the seeds, when the script changes.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/Make-AbiSeeds.ps1)

    # One C ABI target. Its ctest run replays every seed once, then fuzzes
    # for `runs` more inputs.
    function(hkdfguard_add_abi_fuzzer name runs)
        add_executable(${name} fuzz/${name}.cpp)
        hkdfguard_stage_asan_runtime(${name})
        target_link_libraries(${name} PRIVATE hkdfguard_fuzz_abi)
        target_link_options(${name} PRIVATE /INCREMENTAL:NO)
        hkdfguard_apply_warnings(${name})
        set(found ${CMAKE_CURRENT_BINARY_DIR}/fuzz-found/${name})
        set(crashes ${CMAKE_CURRENT_BINARY_DIR}/fuzz-crashes/${name})
        file(MAKE_DIRECTORY ${found} ${crashes} ${HKDFGUARD_FUZZ_SEEDS}/${name})
        add_test(NAME ${name}
                 COMMAND ${name} -runs=${runs} -max_len=4096 -timeout=60 -artifact_prefix=${crashes}/
                         ${found} ${HKDFGUARD_FUZZ_SEEDS}/${name})
        set_tests_properties(${name} PROPERTIES TIMEOUT 900)
    endfunction()

    hkdfguard_add_abi_fuzzer(fuzz_unwrap_dek 5000)
    hkdfguard_add_abi_fuzzer(fuzz_wrap_round_trip 3000)
    hkdfguard_add_abi_fuzzer(fuzz_open_file 3000)
    hkdfguard_add_abi_fuzzer(fuzz_string_bounds 2000)
    hkdfguard_add_abi_fuzzer(fuzz_api_threads 300)
endif()

# bench_hkdfguard: latency and throughput benchmarks, built only on request:
# cmake -DHKDFGUARD_BUILD_BENCHMARKS=ON (use a Release build for real
# numbers). It times the CPU-only internals through its own copy of src/,
# hkdfguard_open_file, and - elevated - wrap/unwrap through HkdfGuard.dll for
# payload versions 1 and 2 on the Software KSP and the TPM, using throwaway
# KEKs it deletes afterwards. See the comment at the top of the .cpp for its
# options. Built with the DLL's hardening flags so its copy of src/ costs
# what the DLL's does. Registered as a ctest smoke run (--quick), which only
# fails if an operation errors; timings are never a pass/fail criterion.
option(HKDFGUARD_BUILD_BENCHMARKS "Build the bench_hkdfguard benchmark executable" OFF)
if(HKDFGUARD_BUILD_BENCHMARKS)
    add_executable(bench_hkdfguard
        bench_hkdfguard.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/aes_gcm.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdh_hkdf.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/event_log.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/hash_to_curve.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_v2.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/sp800_108.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
    )
    target_include_directories(bench_hkdfguard PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
    )
    target_compile_definitions(bench_hkdfguard PRIVATE UNICODE _UNICODE NOMINMAX)
    target_link_libraries(bench_hkdfguard PRIVATE hkdfguard ncrypt.lib bcrypt.lib advapi32.lib netapi32.lib ntdll.lib)
    hkdfguard_apply_hardening(bench_hkdfguard)
    add_test(NAME bench_smoke COMMAND bench_hkdfguard --quick)
    # Elevated, it sets machine policy values and creates KEKs, like
    # roundtrip and v2_kek, so it shares their lock.
    set_tests_properties(bench_smoke PROPERTIES
        ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
        RESOURCE_LOCK HkdfGuardMachineState
    )
endif()

# test_cli.ps1 exercises hkdfguard.exe's argument parsing, validation and
# file handling, which test_roundtrip (DLL calls only) doesn't cover. It
# gets the built CLI's path as -CliExePath and the same PATH as roundtrip.
add_test(
    NAME cli
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/test_cli.ps1"
            -CliExePath "$<TARGET_FILE:hkdfguard-cli>"
)
set_tests_properties(cli PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
)

# test_cli_v2.ps1: the CLI's provision, status and retire for payload
# version 2 KEKs, on the software key store and the TPM, including a
# corrupted TPM key file and a version 1 KEK beside them. test_cli.ps1 keeps
# testing everything else under version 1. Needs elevation; skipped
# otherwise.
add_test(
    NAME cli_v2
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/test_cli_v2.ps1"
            -CliExePath "$<TARGET_FILE:hkdfguard-cli>"
)
set_tests_properties(cli_v2 PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
)

# test_harden_process checks hkdfguard_harden_process from outside the
# hardened process - the only vantage point where a process DACL is visible
# - by starting a copy of itself as a child and probing it (see the comment
# at the top of the .cpp). Public ABI only, so no src/ files are compiled
# in. dbghelp.lib: MiniDumpWriteDump; wer.lib: WerGetFlags. Exit code 77
# means it ran as SYSTEM, which the hardened DACL deliberately lets through,
# so there is nothing to test.
add_executable(test_harden_process test_harden_process.cpp)
target_link_libraries(test_harden_process PRIVATE hkdfguard dbghelp.lib wer.lib)
hkdfguard_apply_warnings(test_harden_process)
add_test(NAME harden_process COMMAND test_harden_process)
set_tests_properties(harden_process PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
    SKIP_RETURN_CODE 77
)

# test_roles.ps1 checks the production security model with real, separate
# accounts: it creates a throwaway deployer and application account, then
# runs the CLI and role_probe.exe (the public ABI, nothing more) as each of
# them. Needs elevation; skipped otherwise. role_probe links only the
# hkdfguard import library, like the CLI.
add_executable(role_probe role_probe.cpp)
target_link_libraries(role_probe PRIVATE hkdfguard bcrypt.lib)
hkdfguard_apply_warnings(role_probe)
add_test(
    NAME roles
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/test_roles.ps1"
            -CliExePath "$<TARGET_FILE:hkdfguard-cli>"
            -ProbeExePath "$<TARGET_FILE:role_probe>"
            -DllPath "$<TARGET_FILE:hkdfguard>"
)
set_tests_properties(roles PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
    # A backstop over test_roles.ps1's own per-process timeout: ctest has no
    # default, and this test starts processes as other accounts, where a
    # stuck one would otherwise hang the CI job until GitHub cancels it.
    TIMEOUT 1200
)

# roundtrip, cli and roles each change machine-wide state while they run -
# KEKs, local accounts and groups, and the SecurityModel policy value, which
# roundtrip and cli set and then restore. Run concurrently (ctest -j), one
# could save the other's temporary value and "restore" it, leaving the
# machine in the developer model. A shared lock makes ctest run them one at
# a time, whatever -j says; harden_process touches none of it.
set_tests_properties(roundtrip cli cli_v2 roles v2_kek PROPERTIES RESOURCE_LOCK HkdfGuardMachineState)
