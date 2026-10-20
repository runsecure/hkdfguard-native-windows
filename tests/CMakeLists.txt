# test_roundtrip exercises the public DLL ABI (HkdfGuard.dll) for wrap/unwrap,
# and additionally compiles kek_store.cpp/wire_format.cpp directly so it can
# call the internal DeleteKek() helper to remove any KEKs it creates once the
# test finishes - those helpers are not part of the public C ABI.
#
# Compiling kek_store.cpp/wire_format.cpp a second time here (they're also
# compiled once already as part of the hkdfguard DLL target in the parent
# CMakeLists.txt) is intentional and harmless: each ends up in a separate
# binary (HkdfGuard.dll vs. test_roundtrip.exe), so there's no linker
# conflict from the same function existing in both.
add_executable(test_roundtrip
    test_roundtrip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
    # ecdh_hkdf.cpp + hash_to_curve.cpp: so the test can call
    # IsValidP256Point and PayloadEcdhPoint directly (hand-built points, and
    # the Linux implementation's hash-to-curve vectors) without a KEK, and
    # DeriveWrappingKey with the test-only provider fault enabled.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdh_hkdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/hash_to_curve.cpp
    # event_log.cpp: kek_store.cpp's CreateKek logs KEK creation, so this
    # test's own compiled copy of kek_store.cpp needs it too.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/event_log.cpp
    # key_file.cpp: so the test can call ReadWrappedKeyFile (hkdfguard_open_file's
    # implementation) directly.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_file.cpp
)
# Links against hkdfguard (the DLL's import library, for the public ABI
# calls) plus the two raw Windows crypto libraries directly (needed because
# this executable now also compiles kek_store.cpp itself, which calls
# NCrypt*/BCrypt* functions of its own).
target_link_libraries(test_roundtrip PRIVATE hkdfguard ncrypt.lib bcrypt.lib ntdll.lib netapi32.lib)
target_include_directories(test_roundtrip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
# Enables policy.h/.cpp's SetTestPolicyOverride seam (see policy.h) in this
# target's own compiled copy of policy.cpp only. The hkdfguard DLL target in
# the parent CMakeLists.txt never defines this macro, so its own separate
# compiled copy of policy.cpp has no such function, and no override state,
# at all - the seam does not exist in shipped release code.
target_compile_definitions(test_roundtrip PRIVATE HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)

# Registers test_roundtrip.exe as a CTest test named "roundtrip" - what
# `ctest` (see README.md) actually runs.
add_test(NAME roundtrip COMMAND test_roundtrip)
# Windows only searches a fixed set of locations for a DLL an .exe depends
# on, and the directory containing HkdfGuard.dll (the build output directory
# for that target) isn't necessarily one of them when ctest launches
# test_roundtrip.exe directly. This prepends that directory onto PATH for
# just this one test's process, so the OS loader can find HkdfGuard.dll at
# startup. $<TARGET_FILE_DIR:hkdfguard> is a CMake "generator expression" -
# evaluated at build-configuration time to the real output path, whatever it
# ends up being for the chosen build type/generator.
#
# ENVIRONMENT is a CMake *list*, so every unescaped ';' in its value starts
# a new list entry. Windows PATH is itself ';'-separated, so splicing
# $ENV{PATH} in raw would leave the test with PATH set to the DLL directory
# alone (everything after the first ';' becoming bogus separate entries) -
# no System32, so the CLI test could not even find cmd.exe. Escaping each
# ';' keeps the whole value as one PATH entry.
string(REPLACE ";" "\\;" HKDFGUARD_TEST_PATH "$ENV{PATH}")
set_tests_properties(roundtrip PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>\\;${HKDFGUARD_TEST_PATH}"
)

# test_cli.ps1 exercises hkdfguard.exe's own argument parsing,
# validation, and file-handling behavior - none of which test_roundtrip
# covers, since that only calls into HkdfGuard.dll directly and never spawns
# the CLI. Registered as an ordinary ctest test whose "command" happens to be
# powershell.exe running a script, the same way any other test executable
# would be; $<TARGET_FILE:hkdfguard-cli> resolves to the CLI's real
# built path (whatever it ends up being for the chosen generator/config),
# passed as that script's -CliExePath argument. hkdfguard.exe
# needs HkdfGuard.dll to be findable too (same reason as roundtrip/
# direct_aead above), so this test gets the identical PATH treatment.
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
