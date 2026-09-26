cmake_minimum_required(VERSION 3.24)

project(sb_easy_c VERSION 1.0.0 LANGUAGES C)

include(FetchContent)
include(CTest)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

option(SB_EASY_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(SB_EASY_STATIC "Build fully static Linux executables" OFF)
option(SB_EASY_EMBED_SINGBOX "Link the sing-box engine into the service" OFF)
# Semicolon-separated regexes of src/*.c files to leave out of sb_core, e.g.
# -DSB_EASY_EXCLUDE_SOURCES="http_routes_admin;wireguard". Only meant for
# local work on a subset of modules; release builds use every source.
set(SB_EASY_EXCLUDE_SOURCES "" CACHE STRING "Regexes of core sources to exclude")
set(SB_EASY_SINGBOX_BRIDGE_LIBRARY "" CACHE FILEPATH "Path to the sing-box Go c-archive")
set(SB_EASY_SINGBOX_BRIDGE_INCLUDE_DIR "" CACHE PATH "Directory containing libsb_easy_singbox.h")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(SB_EASY_STATIC)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    add_link_options(-static)
endif()

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAML REQUIRED IMPORTED_TARGET yaml-0.1)

# ---- third-party C sources (pinned, same versions as the C++ build) ----
FetchContent_Declare(qrcodegen
    GIT_REPOSITORY https://github.com/nayuki/QR-Code-generator.git
    GIT_TAG v1.8.0 GIT_SHALLOW TRUE)
FetchContent_Declare(argon2_source
    URL https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz
    URL_HASH SHA256=daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(civetweb
    GIT_REPOSITORY https://github.com/civetweb/civetweb.git
    GIT_TAG v1.16 GIT_SHALLOW TRUE)
set(QJS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_LIBC OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_WERROR OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(quickjs_ng
    GIT_REPOSITORY https://github.com/quickjs-ng/quickjs.git
    GIT_TAG v0.15.1 GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL)

# Only populate civetweb/qrcodegen/argon2 (we compile their sources ourselves).
FetchContent_GetProperties(qrcodegen)
if(NOT qrcodegen_POPULATED)
    FetchContent_Populate(qrcodegen)
endif()
FetchContent_GetProperties(argon2_source)
if(NOT argon2_source_POPULATED)
    FetchContent_Populate(argon2_source)
endif()
FetchContent_GetProperties(civetweb)
if(NOT civetweb_POPULATED)
    FetchContent_Populate(civetweb)
endif()
FetchContent_MakeAvailable(quickjs_ng)

add_library(sb_qrcodegen STATIC ${qrcodegen_SOURCE_DIR}/c/qrcodegen.c)
target_include_directories(sb_qrcodegen PUBLIC ${qrcodegen_SOURCE_DIR}/c)

add_library(sb_argon2 STATIC
    ${argon2_source_SOURCE_DIR}/src/argon2.c
    ${argon2_source_SOURCE_DIR}/src/blake2/blake2b.c
    ${argon2_source_SOURCE_DIR}/src/core.c
    ${argon2_source_SOURCE_DIR}/src/encoding.c
    ${argon2_source_SOURCE_DIR}/src/ref.c
    ${argon2_source_SOURCE_DIR}/src/thread.c)
target_include_directories(sb_argon2
    PUBLIC ${argon2_source_SOURCE_DIR}/include
    PRIVATE ${argon2_source_SOURCE_DIR}/src)
target_link_libraries(sb_argon2 PRIVATE Threads::Threads)

# civetweb: plain HTTP + WebSocket (TLS terminates at the reverse proxy, as
# with the Drogon build). Compiled as a static library from its single source.
add_library(sb_civetweb STATIC ${civetweb_SOURCE_DIR}/src/civetweb.c)
target_include_directories(sb_civetweb PUBLIC ${civetweb_SOURCE_DIR}/include)
target_compile_definitions(sb_civetweb PUBLIC
    NO_SSL USE_WEBSOCKET USE_IPV6 NO_CGI NO_FILES_SIZE_LIMIT MG_EXPERIMENTAL_INTERFACES
    PRIVATE NDEBUG)
target_compile_options(sb_civetweb PRIVATE -w)
target_link_libraries(sb_civetweb PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

# ---- sing-box bridge (optional) ----
if(SB_EASY_EMBED_SINGBOX)
    add_library(sb_singbox_bridge STATIC IMPORTED GLOBAL)
    set_target_properties(sb_singbox_bridge PROPERTIES
        IMPORTED_LOCATION "${SB_EASY_SINGBOX_BRIDGE_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SB_EASY_SINGBOX_BRIDGE_INCLUDE_DIR}")
    target_link_libraries(sb_singbox_bridge INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m resolv)
endif()

# ---- sb-easy core library ----
# Every src/*.c except the program entry points (src/main_*.c) and the
# supervisor variant not selected for this build is part of the core library.
file(GLOB SB_CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
list(FILTER SB_CORE_SOURCES EXCLUDE REGEX ".*/main_[^/]*\\.c$")
foreach(pattern ${SB_EASY_EXCLUDE_SOURCES})
    list(FILTER SB_CORE_SOURCES EXCLUDE REGEX "/${pattern}[^/]*\\.c$")
endforeach()
if(SB_EASY_EMBED_SINGBOX)
    list(FILTER SB_CORE_SOURCES EXCLUDE REGEX ".*/singbox_supervisor_child\\.c$")
else()
    list(FILTER SB_CORE_SOURCES EXCLUDE REGEX ".*/singbox_supervisor_embedded\\.c$")
endif()

add_library(sb_core STATIC ${SB_CORE_SOURCES})
target_include_directories(sb_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(sb_core PUBLIC _GNU_SOURCE
    SB_EASY_VERSION="${PROJECT_VERSION}")
target_compile_options(sb_core PRIVATE -Wall -Wextra -Wshadow -Wno-unused-parameter)
if(SB_EASY_WARNINGS_AS_ERRORS)
    target_compile_options(sb_core PRIVATE -Werror)
endif()
target_link_libraries(sb_core PUBLIC
    OpenSSL::Crypto OpenSSL::SSL SQLite::SQLite3 CURL::libcurl PkgConfig::YAML
    qjs sb_argon2 sb_qrcodegen sb_civetweb Threads::Threads m)
if(SB_EASY_EMBED_SINGBOX)
    target_link_libraries(sb_core PUBLIC sb_singbox_bridge)
    target_compile_definitions(sb_core PUBLIC SB_EASY_EMBED_SINGBOX=1)
endif()

# ---- programs ----
# src/main_<name>.c -> executable sb-easy-c-<name> (e.g. main_server.c ->
# sb-easy-c-server). main_unified.c is the single-binary entry (sb-easy).
file(GLOB SB_MAINS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/main_*.c)
foreach(main ${SB_MAINS})
    get_filename_component(stem ${main} NAME_WE)
    string(REPLACE "main_" "" name ${stem})
    if(name STREQUAL "unified")
        set(target sb-easy)
    else()
        set(target sb-easy-c-${name})
    endif()
    add_executable(${target} ${main})
    target_link_libraries(${target} PRIVATE sb_core)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-unused-parameter)
endforeach()

# ---- tests ----
# tests/<name>_test.c -> executable + ctest entry. Tests run from the repo
# root so they can reach ../migrations and fixtures.
if(BUILD_TESTING)
    file(GLOB SB_TESTS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*_test.c)
    if(SB_EASY_EMBED_SINGBOX)
        # The supervisor test drives fake sing-box executables, which only the
        # child-process supervisor runs.
        list(FILTER SB_TESTS EXCLUDE REGEX ".*/singbox_supervisor_test\\.c$")
    endif()
    foreach(test_source ${SB_TESTS})
        get_filename_component(name ${test_source} NAME_WE)
        add_executable(${name} ${test_source})
        target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        target_link_libraries(${name} PRIVATE sb_core)
        target_compile_options(${name} PRIVATE -Wall -Wno-unused-parameter)
        add_test(NAME ${name} COMMAND ${name}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
        set_tests_properties(${name} PROPERTIES
            ENVIRONMENT "SB_EASY_MIGRATIONS=${CMAKE_CURRENT_SOURCE_DIR}/../migrations")
    endforeach()
endif()

# Starts, reloads and stops the in-process engine; run by the unified image
# build to prove the Go bridge links and works.
if(SB_EASY_EMBED_SINGBOX)
    add_executable(sb-easy-singbox-embedded-smoke tests/singbox_embedded_smoke.c)
    target_link_libraries(sb-easy-singbox-embedded-smoke PRIVATE sb_core)
    target_compile_options(sb-easy-singbox-embedded-smoke PRIVATE -Wall -Wextra)
endif()
