# test_roundtrip exercises the public DLL ABI (hkdfguard.dll) for wrap/unwrap,
# and additionally compiles kek_store.cpp/wire_format.cpp directly so it can
# call the internal DeleteKek() helper to remove any KEKs it creates once the
# test finishes - those helpers are not part of the public C ABI.
#
# Compiling kek_store.cpp/wire_format.cpp a second time here (they're also
# compiled once already as part of the hkdfguard DLL target in the parent
# CMakeLists.txt) is intentional and harmless: each ends up in a separate
# binary (hkdfguard.dll vs. test_roundtrip.exe), so there's no linker
# conflict from the same function existing in both.
add_executable(test_roundtrip
    test_roundtrip.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_store.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
    # ecdh_hkdf.cpp: so the test can call ValidateEphemeralPublicKey (the
    # unwrap-side point-validation gate) directly, with hand-built valid and
    # invalid points, without needing a provisioned KEK or elevation.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdh_hkdf.cpp
    # event_log.cpp: kek_store.cpp's CreateKek logs KEK creation, so this
    # test's own compiled copy of kek_store.cpp needs it too.
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/event_log.cpp
)
# Links against hkdfguard (the DLL's import library, for the public ABI
# calls) plus the two raw Windows crypto libraries directly (needed because
# this executable now also compiles kek_store.cpp itself, which calls
# NCrypt*/BCrypt* functions of its own).
target_link_libraries(test_roundtrip PRIVATE hkdfguard ncrypt.lib bcrypt.lib)
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
# on, and the directory containing hkdfguard.dll (the build output directory
# for that target) isn't necessarily one of them when ctest launches
# test_roundtrip.exe directly. This prepends that directory onto PATH for
# just this one test's process, so the OS loader can find hkdfguard.dll at
# startup. $<TARGET_FILE_DIR:hkdfguard> is a CMake "generator expression" -
# evaluated at build-configuration time to the real output path, whatever it
# ends up being for the chosen build type/generator.
set_tests_properties(roundtrip PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>;$ENV{PATH}"
)

# test_cli.ps1 exercises hkdfguard-v1-initialize.exe's own argument parsing,
# validation, and file-handling behavior - none of which test_roundtrip
# covers, since that only calls into hkdfguard.dll directly and never spawns
# the CLI. Registered as an ordinary ctest test whose "command" happens to be
# powershell.exe running a script, the same way any other test executable
# would be; $<TARGET_FILE:hkdfguard-v1-initialize> resolves to the CLI's real
# built path (whatever it ends up being for the chosen generator/config),
# passed as that script's -CliExePath argument. hkdfguard-v1-initialize.exe
# needs hkdfguard.dll to be findable too (same reason as roundtrip/
# direct_aead above), so this test gets the identical PATH treatment.
add_test(
    NAME cli
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/test_cli.ps1"
            -CliExePath "$<TARGET_FILE:hkdfguard-v1-initialize>"
)
set_tests_properties(cli PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:hkdfguard>;$ENV{PATH}"
)
