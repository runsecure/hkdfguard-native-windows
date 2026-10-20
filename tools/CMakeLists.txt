# hkdfguard-cli (built as hkdfguard.exe): a standalone command-line utility that wraps a
# caller-supplied DEK and writes it to a file, using HkdfGuard.dll purely
# through its public C ABI (include/hkdfguard.h) - deliberately not linked
# against anything in src/, matching this project's macOS and Linux
# equivalents (which also only ever go through their platform's public C
# ABI, never an internal shortcut).
#
# Linking against the "hkdfguard" CMake target (not its renamed output
# file - see the root CMakeLists.txt's OUTPUT_NAME comment) transitively
# brings along its PUBLIC include/ directory, so no separate
# target_include_directories call is needed here for hkdfguard.h.
add_executable(hkdfguard-cli hkdfguard_cli.cpp)
target_link_libraries(hkdfguard-cli PRIVATE hkdfguard bcrypt.lib ncrypt.lib advapi32.lib ntdll.lib)
# The one header shared from src/: no_follow_open.h, header-only and
# exception-free - the path walk that never follows a link, which the
# wrapped-key and --dek-file paths must use exactly as hkdfguard_open_file
# does. Nothing from src/ is compiled or linked into this tool.
target_include_directories(hkdfguard-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

# The executable is hkdfguard.exe. The CMake *target* can't share that name:
# "hkdfguard" is already the DLL's target (output HkdfGuard.dll), so the
# target is hkdfguard-cli and only its output file is renamed.
set_target_properties(hkdfguard-cli PROPERTIES OUTPUT_NAME "hkdfguard")

# Same hardening as the DLL (see hkdfguard_apply_hardening in the root
# CMakeLists.txt): this tool runs elevated and handles the plaintext DEK.
hkdfguard_apply_hardening(hkdfguard-cli)
