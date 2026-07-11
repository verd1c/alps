add_library(alps_report STATIC
    src/terminal.cpp
    src/markdown.cpp
    src/json_report.cpp
)

target_include_directories(alps_report
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(alps_report
    PUBLIC
        alps_core
        alps_engine
)

alps_target_defaults(alps_report)
