# Minimum CMake version this project's syntax requires.
cmake_minimum_required(VERSION 3.20)
# Declares the project name and that it's a C++ project (as opposed to C,
# which CMake also supports enabling separately).
project(HkdfGuardWin CXX)

# This library depends on Windows-only APIs (CNG/NCrypt), so fail loudly and
# immediately rather than producing confusing compiler errors later if
# someone tries to configure it on Linux/macOS.
if(NOT WIN32)
    message(FATAL_ERROR "HkdfGuardWin is Windows-only (requires CNG/NCrypt).")
endif()

# Require C++17 (the language standard used throughout src/, e.g. inline
# variables, structured bindings availability, etc.) and refuse to silently
# fall back to an older standard if the compiler doesn't support it.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Only the two functions explicitly marked HKDFGUARD_API (dllexport) in
# hkdfguard.h should be exported from the DLL - this turns off CMake's
# option to auto-export every symbol, which would defeat the point of
# hand-picking a minimal, stable ABI surface.
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

# Statically link the MSVC/UCRT runtime (/MT, /MTd for Debug) into every
# binary this project produces, instead of the CMake/MSVC default of
# dynamically linking it (/MD, /MDd). Without this, hkdfguard.dll and
# hkdfguard-v1-initialize.exe depend on MSVCP140.dll/VCRUNTIME140*.dll/the
# api-ms-win-crt-*.dll forwarders at load time, none of which ship with a
# bare Windows install - a machine without the Visual C++ Redistributable
# (or Visual Studio itself) installed fails to load them. Statically linking
# instead makes both fully self-contained: nothing beyond the OS itself is
# required on a target machine. Must be set before any target is declared
# below (it configures a global default new targets pick up); relies on
# CMake policy CMP0091 defaulting to NEW, which it does automatically here
# since cmake_minimum_required's version (3.20) is well past 3.15, the
# version that introduced it.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Declares the "hkdfguard" build target: a SHARED library (a .dll on
# Windows, plus a companion .lib "import library" other code links against
# to call into it), built from exactly these five .cpp files. Each .cpp's
# own #include of its matching .h pulls the rest of the source tree in as
# needed - CMake itself doesn't need to know about the .h files here.
add_library(hkdfguard SHARED
    src/hkdfguard.cpp
    src/wire_format.cpp
    src/kek_store.cpp
    src/ecdh_hkdf.cpp
    src/aes_gcm.cpp
    src/policy.cpp
    src/key_acl.cpp
    src/event_log.cpp
)

# Event log message table: mc.exe (Windows SDK) compiles
# src/event_messages.mc into a resource script, which is linked into the
# DLL so the DLL itself can be registered (by the MSI) as the
# "HkdfGuard.Kms.Windows.v1" event source's EventMessageFile. Without a
# message table Event Viewer still records every event, but renders it with
# a "description cannot be found" preamble. MSVC builds only - other
# toolchains (e.g. a MinGW dev build) simply skip the resource; the logging
# code itself doesn't depend on it.
if(MSVC)
    enable_language(RC)
    find_program(HKDFGUARD_MC_EXE NAMES mc REQUIRED)
    set(HKDFGUARD_MC_OUT ${CMAKE_CURRENT_BINARY_DIR}/event_messages)
    add_custom_command(
        OUTPUT ${HKDFGUARD_MC_OUT}/event_messages.rc ${HKDFGUARD_MC_OUT}/event_messages.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${HKDFGUARD_MC_OUT}
        COMMAND ${HKDFGUARD_MC_EXE} -h ${HKDFGUARD_MC_OUT} -r ${HKDFGUARD_MC_OUT}
                ${CMAKE_CURRENT_SOURCE_DIR}/src/event_messages.mc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/event_messages.mc
        COMMENT "Compiling event log message table"
        VERBATIM)
    target_sources(hkdfguard PRIVATE ${HKDFGUARD_MC_OUT}/event_messages.rc)
    # The generated .rc references MSG00409.bin by bare name; this lets the
    # resource compiler find it in the mc output directory.
    target_include_directories(hkdfguard PRIVATE ${HKDFGUARD_MC_OUT})
endif()

# Names the actual output files (the .dll and its companion .lib import
# library) after this platform and the wire-format/wrap-protocol version
# they implement, matching the same HkdfGuard.Kms.<platform>.v1 naming
# convention this project's macOS and Linux build outputs use. Only
# changes what lands on disk - the CMake target itself is still named
# "hkdfguard" everywhere else in this file and in tests/CMakeLists.txt
# (e.g. target_link_libraries, $<TARGET_FILE_DIR:hkdfguard>), so nothing
# else needs to change when this name does.
set_target_properties(hkdfguard PROPERTIES OUTPUT_NAME "HkdfGuard.Kms.Windows.v1")

# PRIVATE compile definitions apply only while compiling hkdfguard's own
# .cpp files, not to anything that later links against it. HKDFGUARD_EXPORTS
# is exactly the macro hkdfguard.h checks to choose dllexport over
# dllimport (see that file's comment) - this is the one and only place it
# gets defined. UNICODE/_UNICODE steer the small number of Windows headers
# that have separate ANSI/wide-character APIs toward their wide (UTF-16)
# versions, matching the std::wstring-based key names used in kek_store.cpp.
target_compile_definitions(hkdfguard PRIVATE HKDFGUARD_EXPORTS UNICODE _UNICODE)
# PUBLIC include dirs are inherited by anything that links against this
# target (like the test_roundtrip executable in tests/) - here, that's
# include/, so consumers can #include "hkdfguard.h". PRIVATE include dirs
# (src/) are only visible while building hkdfguard.dll's own sources, kept
# private since e.g. wire_format.h's byte-offset constants are internal
# implementation detail, not part of the public ABI contract.
target_include_directories(hkdfguard
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
# The two Windows system libraries providing every NCrypt*/BCrypt* function
# called throughout src/.
target_link_libraries(hkdfguard PRIVATE ncrypt.lib bcrypt.lib)

# MSVC-specific hardening flags, applied only when compiling with MSVC (as
# opposed to some other compiler CMake might be configured to use).
if(MSVC)
    # /W4: enable a high warning level (catches many real bugs, like
    # accidentally comparing signed and unsigned values). /guard:cf and
    # /GUARD:CF (compile-time and link-time halves of the same feature):
    # enable Control Flow Guard, a Windows exploit-mitigation feature that
    # restricts indirect function calls to a validated set of targets. /GS:
    # enables stack-buffer-overrun detection ("stack cookies").
    target_compile_options(hkdfguard PRIVATE /W4 /guard:cf /GS)
    target_link_options(hkdfguard PRIVATE /GUARD:CF)
endif()

# tools/CMakeLists.txt declares hkdfguard-v1-initialize, the standalone CLI
# utility that wraps a DEK and writes it to a file - see that file for why
# it's a separate add_subdirectory rather than folded into this one.
add_subdirectory(tools)

# Turns on CTest support (the `ctest` command used in README.md) and pulls
# in tests/CMakeLists.txt, which declares the test_roundtrip executable and
# registers it as a test.
enable_testing()
add_subdirectory(tests)
