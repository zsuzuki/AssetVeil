cmake_minimum_required(VERSION 3.16)

project(AssetVeil
    VERSION 0.2.0
    DESCRIPTION "Authenticated game asset encryption and packing library"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium>=1.0.12)
endif()
if(TARGET PkgConfig::SODIUM)
    set(ASSETVEIL_SODIUM_TARGET PkgConfig::SODIUM)
else()
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "AssetVeil requires libsodium >= 1.0.12. Install it or set CMAKE_PREFIX_PATH.")
    endif()
    add_library(assetveil_sodium UNKNOWN IMPORTED)
    set_target_properties(assetveil_sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
    set(ASSETVEIL_SODIUM_TARGET assetveil_sodium)
endif()

add_library(assetveil
    src/assetveil.cpp
)
target_compile_features(assetveil PUBLIC cxx_std_17)
target_link_libraries(assetveil PRIVATE ${ASSETVEIL_SODIUM_TARGET})
option(ASSETVEIL_SODIUM_STATIC "Define SODIUM_STATIC when linking a static libsodium on Windows" OFF)
if(WIN32 AND ASSETVEIL_SODIUM_STATIC)
    target_compile_definitions(assetveil PRIVATE SODIUM_STATIC)
endif()

target_include_directories(assetveil
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

set(ASSETVEIL_STANDALONE OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(ASSETVEIL_STANDALONE ON)
endif()
option(ASSETVEIL_BUILD_CLI "Build development encode/decode/extraction tools" ${ASSETVEIL_STANDALONE})
option(ASSETVEIL_BUILD_TESTS "Build AssetVeil regression tests" ${ASSETVEIL_STANDALONE})

if(ASSETVEIL_BUILD_CLI)
    add_executable(assetveil_cli cli/main.cpp)
    target_link_libraries(assetveil_cli PRIVATE assetveil)
    set_target_properties(assetveil_cli PROPERTIES OUTPUT_NAME assetveil)
endif()

if(ASSETVEIL_BUILD_TESTS)
    enable_testing()
    add_executable(assetveil_roundtrip_test tests/roundtrip.cpp)
    target_link_libraries(assetveil_roundtrip_test PRIVATE assetveil)
    add_test(NAME assetveil_roundtrip COMMAND assetveil_roundtrip_test)
    add_executable(assetveil_security_test tests/security.cpp)
    target_link_libraries(assetveil_security_test PRIVATE assetveil ${ASSETVEIL_SODIUM_TARGET})
    if(WIN32 AND ASSETVEIL_SODIUM_STATIC)
        target_compile_definitions(assetveil_security_test PRIVATE SODIUM_STATIC)
    endif()
    add_test(NAME assetveil_security COMMAND assetveil_security_test)
    if(ASSETVEIL_BUILD_CLI)
        find_package(Python3 QUIET COMPONENTS Interpreter)
        if(Python3_Interpreter_FOUND)
            add_test(NAME assetveil_known_plaintext
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/known_plaintext.py $<TARGET_FILE:assetveil_cli>)
            add_test(NAME assetveil_cli_security
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_security.py $<TARGET_FILE:assetveil_cli>)
        endif()
    endif()
endif()
