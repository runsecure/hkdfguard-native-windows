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
# opposed to some other compiler CMake might be configured to use). Defined
# once as a function so the DLL and the CLI (tools/CMakeLists.txt) always get
# the identical set. The linker's own defaults (/DYNAMICBASE,
# /HIGHENTROPYVA, /NXCOMPAT - ASLR and DEP) are left on and not repeated.
#
#   /W4               High warning level (catches e.g. signed/unsigned mixups).
#   /guard:cf         Control Flow Guard (compile and /GUARD:CF link halves):
#                     indirect calls may only target validated functions.
#   /GS               Stack-buffer-overrun detection (stack cookies).
#   /sdl              Additional security checks: wider /GS coverage, security
#                     warnings (uninitialized use, unsafe CRT calls) as
#                     errors, pointer sanitization after delete, and
#                     zero-initialized class members on new.
#   /Qspectre         Speculation barriers (LFENCE on x64, CSDB on ARM64) where
#                     the compiler sees a Spectre variant 1 bounds-check
#                     pattern. The wrapping key and raw ECDH secret live in
#                     this process. Because the runtime is linked statically
#                     (/MT, above), the runtime itself is only mitigated if
#                     the Spectre-mitigated libraries are linked too - see
#                     below.
#   /guard:ehcont     (x64) EH continuation metadata, compile and link: a
#                     corrupted exception context cannot resume at an
#                     arbitrary address. The library throws C++ exceptions
#                     internally, so this applies directly.
#   /CETCOMPAT        (x64) Marks the image compatible with CET hardware
#                     shadow stacks, which catch overwritten return
#                     addresses. Lets a host process that runs in strict
#                     shadow-stack mode load the DLL at all.
#
# /guard:ehcont and /CETCOMPAT are applied to x64 only: CET shadow stacks are
# an x64 hardware feature, and EH continuation metadata is only applied where
# its toolset support is documented. ARM64 binaries get everything else.
if(MSVC)
    # The Spectre-mitigated runtime libraries are a separate Visual Studio
    # component ("MSVC ... Spectre-mitigated libs (Latest)"), installed per
    # architecture under the toolset's lib\spectre\<arch> directory. When
    # present, that directory is searched first so the static runtime that
    # gets linked is the mitigated one. When absent, the build still works -
    # /Qspectre still covers this project's own code - but says so.
    #
    # HKDFGUARD_REQUIRE_SPECTRE_LIBS turns the "absent" case from a warning
    # into a configure failure. Off by default so a developer machine without
    # the component can still build; the release workflow turns it on (via
    # the environment variable of the same name, which seeds the option's
    # default) so a release can never quietly ship an unmitigated runtime.
    if("$ENV{HKDFGUARD_REQUIRE_SPECTRE_LIBS}" STREQUAL "1")
        set(_hkdfguard_require_spectre_default ON)
    else()
        set(_hkdfguard_require_spectre_default OFF)
    endif()
    option(HKDFGUARD_REQUIRE_SPECTRE_LIBS
        "Fail configuration if the Spectre-mitigated runtime libraries are not installed"
        ${_hkdfguard_require_spectre_default})

    get_filename_component(_hkdfguard_cl_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(_hkdfguard_msvc_root "${_hkdfguard_cl_dir}/../../.." ABSOLUTE)
    string(TOLOWER "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}" _hkdfguard_arch)
    set(HKDFGUARD_SPECTRE_LIB_DIR "${_hkdfguard_msvc_root}/lib/spectre/${_hkdfguard_arch}")
    if(EXISTS "${HKDFGUARD_SPECTRE_LIB_DIR}/libcmt.lib")
        message(STATUS "Linking the Spectre-mitigated runtime from ${HKDFGUARD_SPECTRE_LIB_DIR}")
        set(HKDFGUARD_HAVE_SPECTRE_LIBS TRUE)
    elseif(HKDFGUARD_REQUIRE_SPECTRE_LIBS)
        message(FATAL_ERROR
            "Spectre-mitigated runtime libraries not found at ${HKDFGUARD_SPECTRE_LIB_DIR}, and "
            "HKDFGUARD_REQUIRE_SPECTRE_LIBS is on. Install the Visual Studio component "
            "\"MSVC Spectre-mitigated libs (Latest)\" for ${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}.")
    else()
        message(WARNING
            "Spectre-mitigated runtime libraries not found at ${HKDFGUARD_SPECTRE_LIB_DIR}. "
            "/Qspectre still mitigates this project's own code, but the statically linked "
            "runtime will be the unmitigated one. Install the Visual Studio component "
            "\"MSVC Spectre-mitigated libs (Latest)\" for ${CMAKE_CXX_COMPILER_ARCHITECTURE_ID} "
            "to fix this.")
        set(HKDFGUARD_HAVE_SPECTRE_LIBS FALSE)
    endif()
endif()

function(hkdfguard_apply_hardening target)
    if(NOT MSVC)
        return()
    endif()
    target_compile_options(${target} PRIVATE /W4 /guard:cf /GS /sdl /Qspectre)
    target_link_options(${target} PRIVATE /GUARD:CF)
    if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "x64")
        target_compile_options(${target} PRIVATE /guard:ehcont)
        target_link_options(${target} PRIVATE /guard:ehcont /CETCOMPAT)
    endif()
    if(HKDFGUARD_HAVE_SPECTRE_LIBS)
        target_link_directories(${target} PRIVATE "${HKDFGUARD_SPECTRE_LIB_DIR}")
    endif()
endfunction()

hkdfguard_apply_hardening(hkdfguard)

# tools/CMakeLists.txt declares hkdfguard-v1-initialize, the standalone CLI
# utility that wraps a DEK and writes it to a file - see that file for why
# it's a separate add_subdirectory rather than folded into this one.
add_subdirectory(tools)

# Turns on CTest support (the `ctest` command used in README.md) and pulls
# in tests/CMakeLists.txt, which declares the test_roundtrip executable and
# registers it as a test.
enable_testing()
add_subdirectory(tests)
