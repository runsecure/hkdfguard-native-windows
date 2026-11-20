cmake_minimum_required(VERSION 3.20)
# VERSION is the single source of the release version: it is stamped into
# HkdfGuard.dll's and hkdfguard.exe's version resources (src/version.rc.in),
# Build-Msi.ps1 reads it as the MSI's default ProductVersion, and the release
# workflow refuses a tag that doesn't match it. Bump it for every release.
project(hkdfguard-native-windows VERSION 0.9.2 LANGUAGES CXX)

# The ProductName and CompanyName in both binaries' version resources.
set(HKDFGUARD_PRODUCT_NAME "HkdfGuard for Windows")
set(HKDFGUARD_COMPANY_NAME "HkdfGuard")

# The library depends on Windows-only APIs (CNG/NCrypt); fail at configure
# time rather than with confusing compiler errors.
if(NOT WIN32)
    message(FATAL_ERROR "hkdfguard-native-windows is Windows-only (requires CNG/NCrypt).")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Only the functions marked HKDFGUARD_API (dllexport) in hkdfguard.h are
# exported, keeping the ABI surface minimal and deliberate.
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)

# Statically link the MSVC/UCRT runtime (/MT, /MTd for Debug) instead of the
# default /MD. Dynamically linked, both binaries would need MSVCP140.dll,
# VCRUNTIME140*.dll and the api-ms-win-crt-*.dll forwarders, which a bare
# Windows install lacks without the Visual C++ Redistributable; statically
# linked they need nothing beyond the OS. Must be set before any target is
# declared; relies on policy CMP0091 being NEW (implied by the 3.20
# minimum).
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# AddressSanitizer test builds: cmake -DHKDFGUARD_ENABLE_ASAN=ON. Every target
# (the DLL, the CLI and the tests) is instrumented, so ctest checks every
# memory access the tests drive for out-of-bounds, use-after-free and
# similar errors. For testing only - never ship these binaries: they need
# the ASan runtime DLL (copied next to HkdfGuard.dll below) and are slower.
# MSVC ships the ASan runtime for x86 and x64 only, so not for ARM64.
option(HKDFGUARD_ENABLE_ASAN "Instrument every target with AddressSanitizer (test builds only, x64)" OFF)
if(HKDFGUARD_ENABLE_ASAN)
    if(NOT MSVC OR NOT CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "x64")
        message(FATAL_ERROR "HKDFGUARD_ENABLE_ASAN needs MSVC targeting x64 (MSVC has no ARM64 ASan runtime).")
    endif()
    # /RTC (CMake's Debug default) cannot be combined with /fsanitize=address.
    foreach(_flags_var CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_DEBUG)
        string(REGEX REPLACE "/RTC[1csu]+" "" ${_flags_var} "${${_flags_var}}")
    endforeach()
    add_compile_options(/fsanitize=address /Zi)
    # Incremental linking is incompatible with ASan; /DEBUG keeps symbols for
    # ASan's stack traces in every configuration.
    add_link_options(/INCREMENTAL:NO /DEBUG)
endif()

# clang-tidy, run on every C++ source as it compiles: cmake
# -DHKDFGUARD_CLANG_TIDY=ON. The checks live in .clang-tidy at the repo
# root, where every finding is an error. CMake runs clang-tidy only with the
# Ninja and Makefile generators (the scripts in scripts/ use Ninja). The
# clang-tidy that ships with Visual Studio's C++ Clang tools is used unless
# HKDFGUARD_CLANG_TIDY_EXE points at another.
option(HKDFGUARD_CLANG_TIDY "Run clang-tidy (.clang-tidy) on every source while building" OFF)
if(HKDFGUARD_CLANG_TIDY)
    if(CMAKE_GENERATOR MATCHES "Visual Studio")
        message(FATAL_ERROR "HKDFGUARD_CLANG_TIDY needs the Ninja or a Makefile generator; "
                            "CMake does not run clang-tidy under ${CMAKE_GENERATOR}.")
    endif()
    get_filename_component(_hkdfguard_cl_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
    find_program(HKDFGUARD_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED
        HINTS "${_hkdfguard_cl_bin}/../../../../../Llvm/x64/bin"
              "${_hkdfguard_cl_bin}/../../../../../Llvm/ARM64/bin"
              "${_hkdfguard_cl_bin}/../../../../../Llvm/bin")
    message(STATUS "clang-tidy: ${HKDFGUARD_CLANG_TIDY_EXE}")
    # clang-tidy parses the cl.exe command line in clang-cl mode, which
    # ignores (and warns about) the MSVC-only flags it does not implement,
    # such as /analyze, /Qspectre and /guard:ehcont; those warnings are
    # about the command line, not the code. /EHsc is repeated as an extra
    # argument because clang-tidy 19, run with checks enabled from a Visual
    # Studio developer environment, otherwise parses with C++ exceptions
    # disabled and rejects every throw and try.
    set(CMAKE_CXX_CLANG_TIDY "${HKDFGUARD_CLANG_TIDY_EXE}"
        "--extra-arg=/EHsc"
        "--extra-arg=-Wno-unused-command-line-argument"
        "--extra-arg=-Wno-unknown-argument")
endif()

# The library: HkdfGuard.dll plus its HkdfGuard.lib import library.
add_library(hkdfguard SHARED
    src/hkdfguard.cpp
    src/wire_format.cpp
    src/kek_store.cpp
    src/ecdh_hkdf.cpp
    src/aes_gcm.cpp
    src/policy.cpp
    src/key_acl.cpp
    src/event_log.cpp
    src/key_file.cpp
    src/hash_to_curve.cpp
    src/process_hardening.cpp
    # Payload version 2 (docs/adr/0001-post-quantum-payload-version-2.md):
    # the KEK store (NCrypt HMAC keys in the TPM and the Software KSP) and
    # its SP 800-108 derivation.
    src/kek_v2.cpp
    src/sp800_108.cpp
)

# Event log message table: mc.exe (Windows SDK) compiles
# src/event_messages.mc into a resource linked into the DLL, so the MSI can
# register the DLL as the "hkdfguard-native-windows" event source's
# EventMessageFile. Without it Event Viewer still records every event, but
# with a "description cannot be found" preamble. MSVC builds only; other
# toolchains skip the resource, and the logging code doesn't depend on it.
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

# Adds a version resource (src/version.rc.in) to target: the project()
# version as its file and product version, HKDFGUARD_PRODUCT_NAME, and the
# given description, original file name and file type (VFT_DLL / VFT_APP).
# MSVC builds only, like the message table above. Defined here so
# tools/CMakeLists.txt can use it for hkdfguard.exe.
function(hkdfguard_add_version_resource target description original_filename file_type)
    if(NOT MSVC)
        return()
    endif()
    set(HKDFGUARD_FILE_DESCRIPTION "${description}")
    set(HKDFGUARD_ORIGINAL_FILENAME "${original_filename}")
    set(HKDFGUARD_FILE_TYPE "${file_type}")
    configure_file(${PROJECT_SOURCE_DIR}/src/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/${target}_version.rc @ONLY)
    target_sources(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${target}_version.rc)
endfunction()

hkdfguard_add_version_resource(hkdfguard "HkdfGuard native KMS library" "HkdfGuard.dll" VFT_DLL)

# Output files are HkdfGuard.dll / HkdfGuard.lib, with no version in the
# name: the wrap format is identified by the payload's version byte, not by
# the library. (The event log source and the MSI's product name,
# hkdfguard-native-windows, are separate identifiers - see installer/.) The
# CMake target itself stays "hkdfguard".
set_target_properties(hkdfguard PROPERTIES OUTPUT_NAME "HkdfGuard")

# HKDFGUARD_EXPORTS makes hkdfguard.h choose dllexport over dllimport; this
# is the only place it is defined. UNICODE/_UNICODE select the wide (UTF-16)
# Windows APIs, matching the std::wstring key names in kek_store.cpp.
target_compile_definitions(hkdfguard PRIVATE HKDFGUARD_EXPORTS UNICODE _UNICODE)
# include/ (the public header) is inherited by consumers such as the tests;
# src/ stays private, since its headers are implementation detail, not ABI.
target_include_directories(hkdfguard
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
# Windows system libraries: NCrypt/BCrypt for the cryptography, wer.lib for
# process_hardening.cpp's WerSetFlags, plus ntdll and netapi32.
target_link_libraries(hkdfguard PRIVATE ncrypt.lib bcrypt.lib wer.lib ntdll.lib netapi32.lib)

# MSVC hardening flags, defined once as a function so the DLL and the CLI
# (tools/CMakeLists.txt) always get the identical set. The linker's own defaults (/DYNAMICBASE,
# /HIGHENTROPYVA, /NXCOMPAT - ASLR and DEP) are left on and not repeated.
#
#   (warnings)        hkdfguard_apply_warnings, below.
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
    # the component can still build; CI and release builds turn it on (via
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

# The project's warning flags, applied to every target it builds - the
# shipped binaries (through hkdfguard_apply_hardening below) and every test,
# probe, benchmark and fuzzer - so no code is compiled to a lower standard.
#
#   /W4               High warning level (catches e.g. signed/unsigned mixups).
#   /permissive-      Standards conformance: rejects MSVC's non-standard
#                     extensions, as other compilers would.
#   /WX               Warnings are errors, so none accumulate.
#   /analyze          The compiler's static analysis (C6xxx/C26xxx warnings:
#                     null dereferences, buffer overruns, uninitialized
#                     memory, SAL annotation violations), as errors too.
#   /external:anglebrackets /external:W0 /analyze:external-
#                     Headers included with <...> (the Windows SDK and the
#                     standard library) are not this project's code: no
#                     warnings, and no analysis, from them.
function(hkdfguard_apply_warnings target)
    if(NOT MSVC)
        return()
    endif()
    target_compile_options(${target} PRIVATE
        /W4 /permissive- /WX /analyze
        /external:anglebrackets /external:W0 /analyze:external-)
endfunction()

function(hkdfguard_apply_hardening target)
    if(NOT MSVC)
        return()
    endif()
    hkdfguard_apply_warnings(${target})
    target_compile_options(${target} PRIVATE /guard:cf /GS /sdl /Qspectre)
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

# An ASan build's binaries load the ASan runtime DLL from the toolset. It is
# copied next to HkdfGuard.dll, whose folder every test puts on PATH, so the
# tests and the CLI find it without the developer environment.
if(HKDFGUARD_ENABLE_ASAN)
    get_filename_component(_hkdfguard_asan_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(HKDFGUARD_ASAN_RUNTIME "${_hkdfguard_asan_dir}/clang_rt.asan_dynamic-x86_64.dll")
    if(NOT EXISTS "${HKDFGUARD_ASAN_RUNTIME}")
        message(FATAL_ERROR "ASan runtime not found at ${HKDFGUARD_ASAN_RUNTIME}")
    endif()
    add_custom_command(TARGET hkdfguard POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${HKDFGUARD_ASAN_RUNTIME}" "$<TARGET_FILE_DIR:hkdfguard>"
        VERBATIM)
endif()

# tools/: hkdfguard-cli (hkdfguard.exe), the command-line tool.
add_subdirectory(tools)

# tests/: the test_roundtrip executable and the CTest registrations.
enable_testing()
add_subdirectory(tests)
