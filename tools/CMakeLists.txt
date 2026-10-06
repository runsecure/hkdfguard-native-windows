# hkdfguard-v1-initialize: a standalone command-line utility that wraps a
# caller-supplied DEK and writes it to a file, using hkdfguard.dll purely
# through its public C ABI (include/hkdfguard.h) - deliberately not linked
# against anything in src/, matching this project's macOS and Linux
# equivalents (which also only ever go through their platform's public C
# ABI, never an internal shortcut).
#
# Linking against the "hkdfguard" CMake target (not its renamed output
# file - see the root CMakeLists.txt's OUTPUT_NAME comment) transitively
# brings along its PUBLIC include/ directory, so no separate
# target_include_directories call is needed here for hkdfguard.h.
add_executable(hkdfguard-v1-initialize hkdfguard-v1-initialize.cpp)
target_link_libraries(hkdfguard-v1-initialize PRIVATE hkdfguard bcrypt.lib crypt32.lib advapi32.lib)

# Same hardening as the DLL (see the root CMakeLists.txt): this tool runs
# elevated and handles the plaintext DEK, so it gets stack cookies and
# Control Flow Guard too, not just the warning level.
if(MSVC)
    target_compile_options(hkdfguard-v1-initialize PRIVATE /W4 /guard:cf /GS)
    target_link_options(hkdfguard-v1-initialize PRIVATE /GUARD:CF)
endif()
