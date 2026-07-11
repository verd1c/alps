add_library(alps_collector STATIC
    src/shell.cpp
    src/getprop_parse.cpp
    src/mali_version.cpp
    src/adreno_version.cpp
    src/root_detection.cpp
    src/collect.cpp
)

target_include_directories(alps_collector
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(alps_collector
    PUBLIC
        alps_core
)

alps_target_defaults(alps_collector)
