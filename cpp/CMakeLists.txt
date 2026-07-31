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

add_library(sb_easy_core
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
target_compile_options(sb_easy_core PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)
if(SB_EASY_WARNINGS_AS_ERRORS)
    target_compile_options(sb_easy_core PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Werror>
    )
endif()
add_executable(sb-easy-cpp src/main.cpp)
target_link_libraries(sb-easy-cpp PRIVATE sb-easy::core)

if(BUILD_TESTING)
    add_executable(sb-easy-core-tests
        tests/config_renderer_test.cpp
        tests/script_engine_test.cpp
        tests/store_test.cpp
        tests/test_main.cpp
    )
    target_link_libraries(sb-easy-core-tests PRIVATE sb-easy::core)
    target_compile_definitions(sb-easy-core-tests PRIVATE
        SB_EASY_MIGRATIONS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../migrations"
    )
    add_test(NAME sb-easy-core-tests COMMAND sb-easy-core-tests)
    set_tests_properties(sb-easy-core-tests PROPERTIES TIMEOUT 15)
endif()
