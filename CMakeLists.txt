cmake_minimum_required(VERSION 3.16)

project(AssetVeil
    VERSION 0.1.0
    DESCRIPTION "Fast lightweight asset obfuscation and packing library"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(assetveil
    src/assetveil.cpp
)

target_include_directories(assetveil
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

add_executable(assetveil_cli
    cli/main.cpp
)

target_link_libraries(assetveil_cli PRIVATE assetveil)
set_target_properties(assetveil_cli PROPERTIES OUTPUT_NAME assetveil)

enable_testing()

add_executable(assetveil_roundtrip_test
    tests/roundtrip.cpp
)

target_link_libraries(assetveil_roundtrip_test PRIVATE assetveil)

add_test(NAME assetveil_roundtrip COMMAND assetveil_roundtrip_test)
