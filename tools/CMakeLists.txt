# hkdfguard-cli (built as hkdfguard.exe): the command-line tool that
# provisions KEKs, wraps a caller-supplied DEK and writes it to a file, and
# inspects and retires KEKs. Provisioning and wrapping go through
# HkdfGuard.dll's public C ABI (include/hkdfguard.h) only. The hkdfguard
# target supplies include/.
#
# retire and status need more than the ABI: one provider's key, and a
# delete, which the DLL deliberately doesn't offer. For a payload version 1
# KEK the tool opens the persisted key with NCrypt itself. A payload version
# 2 KEK has no public key - its fingerprint is a PRF output of the KEK,
# an HMAC computed by the TPM or the Software KSP - so for it the tool
# compiles the library's own version 2 key code
# (kek_v2.cpp and what it uses) rather than a second copy of it. Nothing else
# from src/ is compiled in; and none of this is in the DLL that
# applications load, so the library itself still can't delete a key.
add_executable(hkdfguard-cli
    hkdfguard_cli.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/kek_v2.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sp800_108.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/key_acl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/policy.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/event_log.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/wire_format.cpp
)
target_link_libraries(hkdfguard-cli PRIVATE hkdfguard bcrypt.lib ncrypt.lib advapi32.lib ntdll.lib
    netapi32.lib)
# src/ for no_follow_open.h - header-only and exception-free, the path walk
# that never follows a link, which the wrapped-key and --dek-file paths must
# use exactly as hkdfguard_open_file does - and for the version 2 key code's
# headers.
target_include_directories(hkdfguard-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
# The version 2 sources expect the wide (UTF-16) Windows APIs, as the DLL
# builds them.
target_compile_definitions(hkdfguard-cli PRIVATE UNICODE _UNICODE)

# The executable is hkdfguard.exe. The CMake *target* can't share that name:
# "hkdfguard" is already the DLL's target (output HkdfGuard.dll), so the
# target is hkdfguard-cli and only its output file is renamed.
set_target_properties(hkdfguard-cli PROPERTIES OUTPUT_NAME "hkdfguard")

# The same version resource as the DLL (see the root CMakeLists.txt).
hkdfguard_add_version_resource(hkdfguard-cli "HkdfGuard provisioning tool" "hkdfguard.exe" VFT_APP)

# Same hardening as the DLL (see hkdfguard_apply_hardening in the root
# CMakeLists.txt): this tool runs elevated and handles the plaintext DEK.
hkdfguard_apply_hardening(hkdfguard-cli)
