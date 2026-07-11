add_library(alps_osv STATIC
    src/import.cpp
)

target_include_directories(alps_osv
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(alps_osv
    PUBLIC
        alps_core
)

alps_target_defaults(alps_osv)
