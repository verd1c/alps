set(_alps_cli_srcs
    src/main.cpp
    src/cmd_match.cpp
    src/cmd_report.cpp
    src/cmd_rules.cpp
    src/cmd_update.cpp
    src/cmd_exploit.cpp
)
set(_alps_cli_libs
    alps_core
    alps_engine
    alps_report
    alps_osv
    alps_exploit
    CLI11::CLI11
)
if(ALPS_BUILD_COLLECTOR)
    list(APPEND _alps_cli_srcs src/cmd_scan.cpp src/cmd_collect.cpp)
    list(APPEND _alps_cli_libs alps_collector)
endif()
if(ALPS_BUILD_TUI)
    list(APPEND _alps_cli_srcs src/cmd_ui.cpp)
    list(APPEND _alps_cli_libs alps_tui)
endif()

add_executable(alps ${_alps_cli_srcs})

target_link_libraries(alps PRIVATE ${_alps_cli_libs})

if(ALPS_BUILD_COLLECTOR)
    target_compile_definitions(alps PRIVATE ALPS_HAVE_COLLECTOR=1)
endif()
if(ALPS_BUILD_TUI)
    target_compile_definitions(alps PRIVATE ALPS_HAVE_TUI=1)
endif()

alps_target_defaults(alps)
