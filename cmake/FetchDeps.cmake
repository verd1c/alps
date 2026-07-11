# Third-party dependency wiring. All deps are permissively licensed:
#   nlohmann/json  - MIT   (header-only)
#   yaml-cpp       - MIT
#   CLI11          - BSD-3-Clause (header-only)
#
# libyara (BSD-3-Clause) is optionally enabled via ALPS_WITH_YARA.

include(FetchContent)

# nlohmann/json.
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
set(JSON_BuildTests OFF CACHE INTERNAL "")

# yaml-cpp.
FetchContent_Declare(
    yaml_cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        0.8.0
    GIT_SHALLOW    TRUE
)
set(YAML_CPP_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB  OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL        OFF CACHE BOOL "" FORCE)
set(YAML_CPP_FORMAT_SOURCE  OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)

# CLI11.
FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2
    GIT_SHALLOW    TRUE
)
set(CLI11_BUILD_TESTS    OFF CACHE INTERNAL "")
set(CLI11_BUILD_EXAMPLES OFF CACHE INTERNAL "")

FetchContent_MakeAvailable(nlohmann_json yaml_cpp CLI11)

# Treat dependency headers as SYSTEM so ALPS_STRICT (-Werror on our code)
# does not fail on unrelated warnings from library headers we don't control.
function(_alps_mark_system tgt)
    if(NOT TARGET ${tgt})
        return()
    endif()
    get_target_property(inc ${tgt} INTERFACE_INCLUDE_DIRECTORIES)
    if(inc)
        set_target_properties(${tgt} PROPERTIES
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${inc}")
    endif()
endfunction()

foreach(dep_target IN ITEMS nlohmann_json yaml-cpp CLI11)
    _alps_mark_system(${dep_target})
endforeach()
