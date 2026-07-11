add_library(alps_tui STATIC
    src/terminal.cpp
    src/browser.cpp
    src/runner_view.cpp
)

target_include_directories(alps_tui
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(alps_tui
    PUBLIC
        alps_core
        alps_report
        alps_exploit
)

alps_target_defaults(alps_tui)
