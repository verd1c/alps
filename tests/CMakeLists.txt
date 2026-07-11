add_executable(alps_core_smoke smoke_core.cpp)
target_link_libraries(alps_core_smoke PRIVATE alps_core)
alps_target_defaults(alps_core_smoke)

# Bake the source-tree location in so a host `ctest` invocation Just Works.
# On-device runs pass the pushed root as argv[1] instead.
target_compile_definitions(alps_core_smoke PRIVATE
    ALPS_DEFAULT_ROOT="${CMAKE_SOURCE_DIR}"
)

add_executable(alps_engine_tests engine_tests.cpp)
target_link_libraries(alps_engine_tests PRIVATE alps_engine)
alps_target_defaults(alps_engine_tests)

add_executable(alps_predicate_tests predicate_tests.cpp)
target_link_libraries(alps_predicate_tests PRIVATE alps_engine)
alps_target_defaults(alps_predicate_tests)

add_executable(alps_matcher_tests matcher_tests.cpp)
target_link_libraries(alps_matcher_tests PRIVATE alps_engine)
alps_target_defaults(alps_matcher_tests)

if(ALPS_BUILD_COLLECTOR)
    add_executable(alps_collector_tests collector_tests.cpp)
    target_link_libraries(alps_collector_tests PRIVATE alps_collector)
    # The collector unit tests reach into internal headers (getprop_parse.hpp,
    # mali_version.hpp) that are not on the public include path.
    target_include_directories(alps_collector_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/src/collector/src
    )
    alps_target_defaults(alps_collector_tests)

    add_executable(alps_collector_smoke collector_smoke.cpp)
    target_link_libraries(alps_collector_smoke PRIVATE alps_collector)
    alps_target_defaults(alps_collector_smoke)
endif()

add_executable(alps_osv_tests osv_tests.cpp)
target_link_libraries(alps_osv_tests PRIVATE alps_osv)
alps_target_defaults(alps_osv_tests)

if(NOT CMAKE_CROSSCOMPILING)
    add_test(NAME alps_core_smoke        COMMAND alps_core_smoke)
    add_test(NAME alps_engine_tests      COMMAND alps_engine_tests)
    add_test(NAME alps_predicate_tests   COMMAND alps_predicate_tests
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME alps_matcher_tests     COMMAND alps_matcher_tests ${CMAKE_SOURCE_DIR})
    if(ALPS_BUILD_COLLECTOR)
        add_test(NAME alps_collector_tests COMMAND alps_collector_tests)
    endif()
    add_test(NAME alps_osv_tests         COMMAND alps_osv_tests)
endif()
