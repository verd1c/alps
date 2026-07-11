# Embed rules/*.yaml into a generated .cpp at build time. Any change to any
# rule file (or GenerateBuiltinRules.cmake itself) re-triggers the codegen.
file(GLOB ALPS_BUILTIN_RULE_FILES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/rules/*.yaml"
    "${CMAKE_SOURCE_DIR}/rules/*.yml"
)
set(ALPS_GENERATED_RULES "${CMAKE_CURRENT_BINARY_DIR}/generated_rules.cpp")
add_custom_command(
    OUTPUT  "${ALPS_GENERATED_RULES}"
    COMMAND "${CMAKE_COMMAND}"
            "-DRULES_DIR=${CMAKE_SOURCE_DIR}/rules"
            "-DOUT_FILE=${ALPS_GENERATED_RULES}"
            -P "${CMAKE_SOURCE_DIR}/cmake/GenerateBuiltinRules.cmake"
    DEPENDS ${ALPS_BUILTIN_RULE_FILES}
            "${CMAKE_SOURCE_DIR}/cmake/GenerateBuiltinRules.cmake"
    COMMENT "Embedding rule KB (${CMAKE_SOURCE_DIR}/rules) into alps_core"
    VERBATIM
)

add_library(alps_core STATIC
    src/device_facts.cpp
    src/rule.cpp
    src/finding.cpp
    src/builtin_rules.cpp
    "${ALPS_GENERATED_RULES}"
)

target_include_directories(alps_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(alps_core
    PUBLIC
        nlohmann_json::nlohmann_json
        yaml-cpp::yaml-cpp
)

alps_target_defaults(alps_core)
