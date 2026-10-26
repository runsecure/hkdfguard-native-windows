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

# test_harden_process checks hkdfguard_harden_process from outside the
# hardened process - the only vantage point where a process DACL is visible
# - by starting a copy of itself as a child and probing it (see the comment
# at the top of the .cpp). Public ABI only, so no src/ files are compiled
# in. dbghelp.lib: MiniDumpWriteDump; wer.lib: WerGetFlags. Exit code 77
# means it ran as SYSTEM, which the hardened DACL deliberately lets through,
# so there is nothing to test.
add_executable(test_harden_process test_harden_process.cpp)
target_link_libraries(test_harden_process PRIVATE hkdfguard dbghelp.lib wer.lib)
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
)

# roundtrip, cli and roles each change machine-wide state while they run -
# KEKs, local accounts and groups, and the SecurityModel policy value, which
# roundtrip and cli set and then restore. Run concurrently (ctest -j), one
# could save the other's temporary value and "restore" it, leaving the
# machine in the developer model. A shared lock makes ctest run them one at
# a time, whatever -j says; harden_process touches none of it.
set_tests_properties(roundtrip cli roles PROPERTIES RESOURCE_LOCK HkdfGuardMachineState)
