# liballps.so: JNI shim for the Android app. Built only when
# ALPS_BUILD_JNI is enabled and the toolchain is Android. The public JNI
# ABI marshals arguments and results as JSON strings.

add_library(alps_jni SHARED
    src/alps_jni.cpp
)

set_target_properties(alps_jni PROPERTIES
    OUTPUT_NAME "alps"      # produces liballps.so
    POSITION_INDEPENDENT_CODE ON
)

target_link_libraries(alps_jni
    PRIVATE
        alps_core
        alps_engine
        alps_collector
        log                 # Android's liblog (auto-provided by the NDK)
)

# Size discipline for the .so: the goal is a small per-ABI blob in
# the APK, not the CLI binary's flexibility.
target_compile_options(alps_jni PRIVATE
    -Oz
    -fvisibility=hidden
    -fdata-sections
    -ffunction-sections
)
target_link_options(alps_jni PRIVATE
    -Wl,--gc-sections
    -Wl,--exclude-libs,ALL
    -Wl,-s
)

alps_target_defaults(alps_jni)
