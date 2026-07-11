cmake_minimum_required(VERSION 3.22)
project(alps LANGUAGES CXX VERSION 0.1.0)

# Language.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The JNI .so target needs PIC; setting globally keeps things uniform.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make configure/build failures loud.
set(CMAKE_MESSAGE_LOG_LEVEL STATUS)

# Build options.
option(ALPS_BUILD_CLI       "Build the alps CLI executable"                ON)
option(ALPS_BUILD_JNI       "Build the JNI .so (Android only)"             OFF)
option(ALPS_BUILD_TESTS     "Build smoke tests"                            ON)
option(ALPS_STRICT          "Treat warnings as errors on our code"         ON)
option(ALPS_WITH_YARA       "Enable YARA binary verify"                    OFF)
# Collector and TUI are on-device / POSIX components: automatically off
# on native Windows host builds, on everywhere else. Override with
# -DALPS_BUILD_COLLECTOR=OFF for a stripped runner-only build.
if(WIN32 AND NOT ANDROID)
    set(_alps_posix_default OFF)
else()
    set(_alps_posix_default ON)
endif()
option(ALPS_BUILD_COLLECTOR "Build the on-device fact collector"           ${_alps_posix_default})
option(ALPS_BUILD_TUI       "Build the interactive terminal browser"       ${_alps_posix_default})

# JNI target only makes sense under the Android NDK.
if(NOT ANDROID AND ALPS_BUILD_JNI)
    message(WARNING "ALPS_BUILD_JNI requested but this is not an Android toolchain; disabling.")
    set(ALPS_BUILD_JNI OFF)
endif()

# Warnings applied to ALPS-owned targets only.
if(MSVC)
    set(ALPS_WARN_FLAGS /W4)
    if(ALPS_STRICT)
        list(APPEND ALPS_WARN_FLAGS /WX)
    endif()
else()
    set(ALPS_WARN_FLAGS -Wall -Wextra -Wpedantic)
    if(ALPS_STRICT)
        list(APPEND ALPS_WARN_FLAGS -Werror)
    endif()
endif()

# Small helper so every ALPS target gets the same discipline.
function(alps_target_defaults tgt)
    target_compile_options(${tgt} PRIVATE ${ALPS_WARN_FLAGS})
    target_compile_features(${tgt} PUBLIC cxx_std_20)
    if(MSVC)
        # `getenv`, `gmtime` etc. are portable C; MSVC's "unsafe" C4996
        # deprecation isn't a real concern for our uses.
        target_compile_definitions(${tgt} PRIVATE
            _CRT_SECURE_NO_WARNINGS
            _CRT_NONSTDC_NO_DEPRECATE
            NOMINMAX
        )
    endif()
endfunction()

# Third-party dependencies (all MIT / BSD / Apache).
include(cmake/FetchDeps.cmake)

# Static libraries.
add_subdirectory(src/core)
add_subdirectory(src/engine)
add_subdirectory(src/report)
add_subdirectory(src/osv)
add_subdirectory(src/exploit)
if(ALPS_BUILD_COLLECTOR)
    add_subdirectory(src/collector)
endif()
if(ALPS_BUILD_TUI)
    add_subdirectory(src/tui)
endif()

if(ALPS_BUILD_CLI)
    add_subdirectory(src/cli)
endif()

if(ALPS_BUILD_JNI)
    add_subdirectory(src/jni)
endif()

if(ALPS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Configuration echo.
message(STATUS "ALPS configuration:")
message(STATUS "  CMake version    : ${CMAKE_VERSION}")
message(STATUS "  Compiler         : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Build type       : ${CMAKE_BUILD_TYPE}")
message(STATUS "  ANDROID          : ${ANDROID}")
if(ANDROID)
    message(STATUS "  ANDROID_ABI      : ${ANDROID_ABI}")
    message(STATUS "  ANDROID_PLATFORM : ${ANDROID_PLATFORM}")
    message(STATUS "  ANDROID_STL      : ${ANDROID_STL}")
endif()
message(STATUS "  ALPS_BUILD_CLI       : ${ALPS_BUILD_CLI}")
message(STATUS "  ALPS_BUILD_JNI       : ${ALPS_BUILD_JNI}")
message(STATUS "  ALPS_BUILD_COLLECTOR : ${ALPS_BUILD_COLLECTOR}")
message(STATUS "  ALPS_BUILD_TUI       : ${ALPS_BUILD_TUI}")
message(STATUS "  ALPS_BUILD_TESTS     : ${ALPS_BUILD_TESTS}")
message(STATUS "  ALPS_STRICT          : ${ALPS_STRICT}")
