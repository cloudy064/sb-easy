cmake_minimum_required(VERSION 3.24)

project(sb_easy_cpp VERSION 0.1.0 LANGUAGES C CXX)

include(FetchContent)
include(CTest)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
if(TARGET SQLite3::SQLite3)
    set(SB_EASY_SQLITE_TARGET SQLite3::SQLite3)
else()
    set(SB_EASY_SQLITE_TARGET SQLite::SQLite3)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SB_EASY_WARNINGS_AS_ERRORS "Treat sb-easy C++ warnings as errors" OFF)
option(SB_EASY_BUILD_HTTP "Build the Drogon HTTP server" ON)

function(sb_easy_enable_warnings target)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
    )
    if(SB_EASY_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang>:-Werror>
        )
    endif()
endfunction()

FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(QJS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_LIBC OFF CACHE BOOL "" FORCE)
set(QJS_BUILD_WERROR OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    quickjs_ng
    GIT_REPOSITORY https://github.com/quickjs-ng/quickjs.git
    GIT_TAG v0.15.1
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(quickjs_ng)

if(SB_EASY_BUILD_HTTP)
    set(SB_EASY_PROJECT_BUILD_TESTING ${BUILD_TESTING})
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(BUILD_CTL OFF CACHE BOOL "" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_ORM OFF CACHE BOOL "" FORCE)
    set(BUILD_BROTLI OFF CACHE BOOL "" FORCE)
    set(BUILD_C-ARES OFF CACHE BOOL "" FORCE)
    set(BUILD_YAML_CONFIG OFF CACHE BOOL "" FORCE)
    set(USE_SUBMODULE ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        drogon
        GIT_REPOSITORY https://github.com/drogonframework/drogon.git
        GIT_TAG v1.9.13
        GIT_SHALLOW TRUE
        GIT_SUBMODULES_RECURSE TRUE
    )
    FetchContent_MakeAvailable(drogon)
    set(BUILD_TESTING ${SB_EASY_PROJECT_BUILD_TESTING} CACHE BOOL "" FORCE)
endif()

add_library(sb_easy_core
    src/atomic_file.cpp
    src/config_etag.cpp
    src/config_renderer.cpp
    src/database.cpp
    src/script_engine.cpp
    src/store.cpp
)
add_library(sb-easy::core ALIAS sb_easy_core)

target_include_directories(sb_easy_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(sb_easy_core
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE
        OpenSSL::Crypto
        ${SB_EASY_SQLITE_TARGET}
        qjs
)
sb_easy_enable_warnings(sb_easy_core)

add_executable(sb-easy-cpp src/main.cpp)
target_link_libraries(sb-easy-cpp PRIVATE sb-easy::core)
sb_easy_enable_warnings(sb-easy-cpp)

if(SB_EASY_BUILD_HTTP)
    add_library(sb_easy_http src/http_server.cpp)
    add_library(sb-easy::http ALIAS sb_easy_http)
    target_include_directories(sb_easy_http
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_link_libraries(sb_easy_http
        PUBLIC sb-easy::core
        PRIVATE drogon
    )
    sb_easy_enable_warnings(sb_easy_http)

    add_executable(sb-easy-cpp-server src/server_main.cpp)
    target_link_libraries(sb-easy-cpp-server PRIVATE sb-easy::http)
    sb_easy_enable_warnings(sb-easy-cpp-server)

    add_library(sb_easy_agent src/agent_client.cpp)
    add_library(sb-easy::agent ALIAS sb_easy_agent)
    target_include_directories(sb_easy_agent
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_link_libraries(sb_easy_agent
        PUBLIC sb-easy::core
        PRIVATE drogon
    )
    sb_easy_enable_warnings(sb_easy_agent)

    add_executable(sb-easy-cpp-agent src/agent_main.cpp)
    target_link_libraries(sb-easy-cpp-agent PRIVATE sb-easy::agent)
    sb_easy_enable_warnings(sb-easy-cpp-agent)
endif()

if(BUILD_TESTING)
    add_executable(sb-easy-core-tests
        tests/agent_core_test.cpp
        tests/config_renderer_test.cpp
        tests/script_engine_test.cpp
        tests/store_test.cpp
        tests/test_main.cpp
    )
    target_link_libraries(sb-easy-core-tests PRIVATE sb-easy::core)
    target_compile_definitions(sb-easy-core-tests PRIVATE
        SB_EASY_MIGRATIONS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../migrations"
    )
    sb_easy_enable_warnings(sb-easy-core-tests)
    add_test(NAME sb-easy-core-tests COMMAND sb-easy-core-tests)
    set_tests_properties(sb-easy-core-tests PROPERTIES TIMEOUT 15)

    if(SB_EASY_BUILD_HTTP)
        add_executable(sb-easy-http-tests tests/http_server_test.cpp)
        target_link_libraries(sb-easy-http-tests PRIVATE sb-easy::http drogon)
        target_compile_definitions(sb-easy-http-tests PRIVATE
            SB_EASY_MIGRATIONS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../migrations"
        )
        sb_easy_enable_warnings(sb-easy-http-tests)
        add_test(NAME sb-easy-http-tests COMMAND sb-easy-http-tests)
        set_tests_properties(sb-easy-http-tests PROPERTIES TIMEOUT 15)

        add_executable(sb-easy-agent-tests tests/agent_client_test.cpp)
        target_link_libraries(sb-easy-agent-tests
            PRIVATE sb-easy::agent sb-easy::http drogon
        )
        target_compile_definitions(sb-easy-agent-tests PRIVATE
            SB_EASY_MIGRATIONS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../migrations"
        )
        sb_easy_enable_warnings(sb-easy-agent-tests)
        add_test(NAME sb-easy-agent-tests COMMAND sb-easy-agent-tests)
        set_tests_properties(sb-easy-agent-tests PROPERTIES TIMEOUT 15)
    endif()
endif()
