set(ALPS_ENGINE_SOURCES
    src/comparators.cpp
    src/timeline.cpp
    src/predicate.cpp
    src/downgrade.cpp
    src/matcher.cpp
)

if(ALPS_WITH_YARA)
    # Reserved for future FetchContent(libyara) + verify_yara.cpp wiring.
    # Until enabled, the stub is authoritative.
    list(APPEND ALPS_ENGINE_SOURCES src/verify_stub.cpp)
    target_compile_definitions(alps_engine PRIVATE ALPS_WITH_YARA=1)
else()
    list(APPEND ALPS_ENGINE_SOURCES src/verify_stub.cpp)
endif()

add_library(alps_engine STATIC ${ALPS_ENGINE_SOURCES})

target_include_directories(alps_engine
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(alps_engine
    PUBLIC
        alps_core
)

alps_target_defaults(alps_engine)
