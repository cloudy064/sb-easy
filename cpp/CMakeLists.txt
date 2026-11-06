cmake_minimum_required(VERSION 3.24)

project(sb_easy_cpp VERSION 1.0.0 LANGUAGES C CXX)

include(FetchContent)
include(CTest)
# yaml-cpp 0.8.0 still declares compatibility with pre-3.5 CMake. CMake 4
# requires consumers to state the oldest policy set they permit for subprojects.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SB_EASY_WARNINGS_AS_ERRORS "Treat sb-easy C++ warnings as errors" OFF)
option(SB_EASY_BUILD_HTTP "Build the Drogon HTTP server" ON)
option(SB_EASY_PORTABLE_ONLY
       "Build only the platform-neutral agent runtime and its tests" OFF)
option(SB_EASY_BUILD_WINDOWS_CLIENT
       "Build the native Windows Service client" ${WIN32})
option(SB_EASY_BUILD_WINDOWS_UI
       "Build the Win32/WebView2 desktop shell" ${WIN32})
option(SB_EASY_WINDOWS_ONLY
       "Build the Windows client without POSIX server targets" ${WIN32})
option(SB_EASY_WINDOWS_INTEGRATION_TESTS
       "Run integration tests against prepared sing-box/Wintun artifacts" OFF)
option(SB_EASY_BUILD_WINDOWS_INSTALLER
       "Build the WiX MSI and bootstrapper after the Windows payload" OFF)

if(WIN32 AND NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type for single-config Windows generators" FORCE)
endif()

function(sb_easy_enable_warnings target)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/permissive-;/utf-8>
    )
    if(SB_EASY_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang>:-Werror>
            $<$<CXX_COMPILER_ID:MSVC>:/WX>
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
find_package(Threads REQUIRED)

add_library(sb_easy_agent_runtime
    src/agent_config.cpp
    src/agent_runtime.cpp
)
add_library(sb-easy::agent-runtime ALIAS sb_easy_agent_runtime)
target_include_directories(sb_easy_agent_runtime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(sb_easy_agent_runtime
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE Threads::Threads
)
sb_easy_enable_warnings(sb_easy_agent_runtime)

if(BUILD_TESTING)
    add_executable(sb-easy-agent-runtime-tests
        tests/agent_runtime_test.cpp
        tests/test_main.cpp
    )
    target_link_libraries(sb-easy-agent-runtime-tests
        PRIVATE sb-easy::agent-runtime
    )
    sb_easy_enable_warnings(sb-easy-agent-runtime-tests)
    add_test(NAME sb-easy-agent-runtime-tests
             COMMAND sb-easy-agent-runtime-tests)
    set_tests_properties(sb-easy-agent-runtime-tests PROPERTIES TIMEOUT 15)
endif()

if(WIN32 AND SB_EASY_BUILD_WINDOWS_CLIENT)
    if(NOT MSVC)
        message(FATAL_ERROR
            "The sb-easy Windows client is supported only with the MSVC toolchain")
    endif()
    enable_language(RC)
    set(SB_EASY_WINDOWS_RUNTIME_STAGING
        "${CMAKE_BINARY_DIR}/windows-runtime")
    set(SB_EASY_SING_BOX_RUNTIME
        "${SB_EASY_WINDOWS_RUNTIME_STAGING}/sing-box.exe")
    set(SB_EASY_WINTUN_RUNTIME
        "${SB_EASY_WINDOWS_RUNTIME_STAGING}/wintun.dll")
    set(SB_EASY_WINDOWS_RUNTIME_METADATA
        "${SB_EASY_WINDOWS_RUNTIME_STAGING}/windows-runtime.json")
    set(SB_EASY_WINDOWS_RUNTIME_STAMP
        "${SB_EASY_WINDOWS_RUNTIME_STAGING}/prepared.stamp")
    add_custom_command(
        OUTPUT "${SB_EASY_WINDOWS_RUNTIME_STAMP}"
        BYPRODUCTS
            "${SB_EASY_SING_BOX_RUNTIME}"
            "${SB_EASY_WINTUN_RUNTIME}"
            "${SB_EASY_WINDOWS_RUNTIME_METADATA}"
        COMMAND pwsh -NoProfile -File
            "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/prepare-windows-runtime.ps1"
            -Destination "${SB_EASY_WINDOWS_RUNTIME_STAGING}"
        COMMAND "${CMAKE_COMMAND}" -E touch
            "${SB_EASY_WINDOWS_RUNTIME_STAMP}"
        DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/prepare-windows-runtime.ps1"
        COMMENT "Downloading and verifying pinned Windows runtime resources"
        VERBATIM
    )
    add_custom_target(sb-easy-windows-runtime-files
        DEPENDS "${SB_EASY_WINDOWS_RUNTIME_STAMP}"
    )
    set(SB_EASY_SING_BOX_RESOURCE_PATH "${SB_EASY_SING_BOX_RUNTIME}")
    set(SB_EASY_WINTUN_RESOURCE_PATH "${SB_EASY_WINTUN_RUNTIME}")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/windows/service_runtime.rc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/service_runtime.rc"
        @ONLY
    )
    set_source_files_properties(
        "${CMAKE_CURRENT_BINARY_DIR}/service_runtime.rc"
        PROPERTIES OBJECT_DEPENDS
            "${SB_EASY_SING_BOX_RUNTIME};${SB_EASY_WINTUN_RUNTIME}"
    )

    FetchContent_Declare(
        sqlite_amalgamation_windows
        URL https://sqlite.org/2025/sqlite-amalgamation-3500100.zip
        URL_HASH SHA3_256=65e5176c171aff92ff31f3ab4d431a879d648de93f139816f9331a7074859092
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(sqlite_amalgamation_windows)
    add_library(sb_easy_windows_sqlite STATIC
        ${sqlite_amalgamation_windows_SOURCE_DIR}/sqlite3.c)
    target_include_directories(sb_easy_windows_sqlite PUBLIC
        ${sqlite_amalgamation_windows_SOURCE_DIR})
    target_compile_definitions(sb_easy_windows_sqlite PRIVATE
        SQLITE_THREADSAFE=1
        SQLITE_DQS=0
        SQLITE_OMIT_LOAD_EXTENSION
    )
    if(MSVC)
        target_compile_options(sb_easy_windows_sqlite PRIVATE /W0 /utf-8)
        set_property(TARGET sb_easy_windows_sqlite PROPERTY MSVC_RUNTIME_LIBRARY
            "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

    add_library(sb_easy_windows_platform
        src/windows/embedded_runtime.cpp
        src/windows/enrollment.cpp
        src/windows/http.cpp
        src/windows/ipc.cpp
        src/windows/log.cpp
        src/windows/pipe_client.cpp
        src/windows/platform.cpp
        src/windows/route_stats.cpp
        src/windows/singbox.cpp
    )
    add_library(sb-easy::windows-platform ALIAS sb_easy_windows_platform)
    target_include_directories(sb_easy_windows_platform
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_compile_definitions(sb_easy_windows_platform
        PUBLIC
            UNICODE
            _UNICODE
            _WIN32_WINNT=0x0A00
            WINVER=0x0A00
    )
    target_link_libraries(sb_easy_windows_platform
        PUBLIC sb-easy::agent-runtime
        PRIVATE Advapi32 Bcrypt Crypt32 Shell32 Winhttp Ws2_32
                sb_easy_windows_sqlite
    )
    sb_easy_enable_warnings(sb_easy_windows_platform)
    if(MSVC)
        foreach(target sb_easy_agent_runtime sb_easy_windows_platform)
            set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY
                "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endforeach()
        if(TARGET sb-easy-agent-runtime-tests)
            set_property(TARGET sb-easy-agent-runtime-tests
                PROPERTY MSVC_RUNTIME_LIBRARY
                "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
    endif()

    add_executable(sb-easy-service
        src/windows/service_main.cpp
        "${CMAKE_CURRENT_BINARY_DIR}/service_runtime.rc"
    )
    add_dependencies(sb-easy-service sb-easy-windows-runtime-files)
    target_include_directories(sb-easy-service PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/windows")
    target_link_libraries(sb-easy-service
        PRIVATE sb-easy::windows-platform Advapi32 Iphlpapi Ws2_32
    )
    sb_easy_enable_warnings(sb-easy-service)
    if(MSVC)
        set_property(TARGET sb-easy-service PROPERTY MSVC_RUNTIME_LIBRARY
            "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

    add_executable(sb-easy-setup WIN32 src/windows/setup_main.cpp)
    target_link_libraries(sb-easy-setup PRIVATE Shell32 Ole32 User32)
    sb_easy_enable_warnings(sb-easy-setup)
    if(MSVC)
        set_property(TARGET sb-easy-setup PROPERTY MSVC_RUNTIME_LIBRARY
            "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

    add_custom_target(sb-easy-prepare-windows-runtime
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${SB_EASY_SING_BOX_RUNTIME}"
            "$<TARGET_FILE_DIR:sb-easy-service>/sing-box.exe"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${SB_EASY_WINTUN_RUNTIME}"
            "$<TARGET_FILE_DIR:sb-easy-service>/wintun.dll"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${SB_EASY_WINDOWS_RUNTIME_METADATA}"
            "$<TARGET_FILE_DIR:sb-easy-service>/windows-runtime.json"
        DEPENDS sb-easy-service sb-easy-windows-runtime-files
        VERBATIM
    )

    if(SB_EASY_BUILD_WINDOWS_UI)
        FetchContent_Declare(
            webview2_sdk
            URL https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/1.0.4078.44/microsoft.web.webview2.1.0.4078.44.nupkg
            URL_HASH SHA512=307eca883211dd75cf6c90887482bfa7385ce4351df20b0905b172b0815591a9120421068e2b39fd4b720aa9558906c2d45b574d887f94b64deaf1c93721a8dd
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_MakeAvailable(webview2_sdk)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(SB_EASY_WEBVIEW2_ARCH x64)
        else()
            set(SB_EASY_WEBVIEW2_ARCH x86)
        endif()
        add_library(sb_easy_webview2_loader STATIC IMPORTED GLOBAL)
        set_target_properties(sb_easy_webview2_loader PROPERTIES
            IMPORTED_LOCATION
                "${webview2_sdk_SOURCE_DIR}/build/native/${SB_EASY_WEBVIEW2_ARCH}/WebView2LoaderStatic.lib"
            INTERFACE_INCLUDE_DIRECTORIES
                "${webview2_sdk_SOURCE_DIR}/build/native/include"
        )
        add_executable(sb-easy WIN32
            src/windows/ui_main.cpp
            src/windows/ui_preferences.cpp
            src/windows/webview_host.cpp
            src/windows/sb-easy.manifest
        )
        set_source_files_properties(src/windows/sb-easy.manifest PROPERTIES
            HEADER_FILE_ONLY TRUE)
        set_property(TARGET sb-easy APPEND PROPERTY LINK_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/src/windows/sb-easy.manifest")
        target_link_libraries(sb-easy
            PRIVATE
                sb-easy::windows-platform
                sb_easy_webview2_loader
                Comctl32 Ole32 Shell32 User32
        )
        sb_easy_enable_warnings(sb-easy)
        if(MSVC)
            target_link_options(sb-easy PRIVATE
                "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/src/windows/sb-easy.manifest")
            set_property(TARGET sb-easy PROPERTY MSVC_RUNTIME_LIBRARY
                "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()

        find_program(SB_EASY_NPM_EXECUTABLE NAMES npm.cmd npm REQUIRED)
        set(SB_EASY_WINDOWS_UI_ROOT
            "${CMAKE_CURRENT_SOURCE_DIR}/../windows/ui")
        file(GLOB_RECURSE SB_EASY_WINDOWS_UI_SOURCES CONFIGURE_DEPENDS
            "${SB_EASY_WINDOWS_UI_ROOT}/src/*.ts"
            "${SB_EASY_WINDOWS_UI_ROOT}/src/*.vue"
            "${SB_EASY_WINDOWS_UI_ROOT}/src/*.css")
        add_custom_command(
            OUTPUT "${SB_EASY_WINDOWS_UI_ROOT}/dist/index.html"
            COMMAND "${SB_EASY_NPM_EXECUTABLE}" ci --ignore-scripts
            COMMAND "${SB_EASY_NPM_EXECUTABLE}" run build
            WORKING_DIRECTORY "${SB_EASY_WINDOWS_UI_ROOT}"
            DEPENDS
                "${SB_EASY_WINDOWS_UI_ROOT}/package.json"
                "${SB_EASY_WINDOWS_UI_ROOT}/package-lock.json"
                "${SB_EASY_WINDOWS_UI_ROOT}/tsconfig.json"
                "${SB_EASY_WINDOWS_UI_ROOT}/vite.config.ts"
                "${SB_EASY_WINDOWS_UI_ROOT}/index.html"
                ${SB_EASY_WINDOWS_UI_SOURCES}
            COMMENT "Building the packaged Windows Vue UI"
            VERBATIM
        )
        add_custom_target(sb-easy-windows-ui-assets
            DEPENDS "${SB_EASY_WINDOWS_UI_ROOT}/dist/index.html")
        add_dependencies(sb-easy sb-easy-windows-ui-assets)
        add_custom_target(sb-easy-stage-windows-ui ALL
            COMMAND "${CMAKE_COMMAND}" -E remove_directory
                "$<TARGET_FILE_DIR:sb-easy>/ui"
            COMMAND "${CMAKE_COMMAND}" -E copy_directory
                "${SB_EASY_WINDOWS_UI_ROOT}/dist"
                "$<TARGET_FILE_DIR:sb-easy>/ui"
            DEPENDS sb-easy sb-easy-windows-ui-assets
            COMMENT "Staging packaged Windows UI beside sb-easy.exe"
            VERBATIM
        )
    endif()

    if(SB_EASY_BUILD_WINDOWS_INSTALLER)
        if(NOT SB_EASY_BUILD_WINDOWS_UI)
            message(FATAL_ERROR
                "SB_EASY_BUILD_WINDOWS_INSTALLER requires SB_EASY_BUILD_WINDOWS_UI")
        endif()
        add_custom_target(sb-easy-windows-installer
            COMMAND pwsh -NoProfile -File
                "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/build-windows-installer.ps1"
                -RuntimeDirectory "$<TARGET_FILE_DIR:sb-easy>"
                -LauncherPath "$<TARGET_FILE:sb-easy-setup>"
                -DependencyDirectory "${CMAKE_BINARY_DIR}/_deps"
                -OutputDirectory "${CMAKE_BINARY_DIR}/windows-release"
                -ProductVersion "${PROJECT_VERSION}"
            DEPENDS
                sb-easy-prepare-windows-runtime
                sb-easy-stage-windows-ui
                sb-easy-setup
            COMMENT "Building and statically validating the Windows MSI and bootstrapper"
            VERBATIM
        )
    endif()

    if(BUILD_TESTING)
        add_test(NAME sb-easy-windows-setup-tests
            COMMAND pwsh -NoProfile -File
                "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/test-windows-setup-launcher.ps1"
                -LauncherPath "$<TARGET_FILE:sb-easy-setup>")
        set_tests_properties(sb-easy-windows-setup-tests PROPERTIES TIMEOUT 30)

        add_executable(sb-easy-windows-tests
            tests/windows_platform_test.cpp
            tests/test_main.cpp
        )
        add_dependencies(sb-easy-windows-tests sb-easy-setup)
        target_link_libraries(sb-easy-windows-tests
            PRIVATE sb-easy::windows-platform
        )
        sb_easy_enable_warnings(sb-easy-windows-tests)
        if(MSVC)
            set_property(TARGET sb-easy-windows-tests PROPERTY MSVC_RUNTIME_LIBRARY
                "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        endif()
        add_test(NAME sb-easy-windows-tests COMMAND sb-easy-windows-tests)
        set_tests_properties(sb-easy-windows-tests PROPERTIES TIMEOUT 30)

        if(SB_EASY_WINDOWS_INTEGRATION_TESTS)
            add_executable(sb-easy-windows-singbox-integration-tests
                tests/windows_singbox_integration_test.cpp
                tests/test_main.cpp
            )
            add_dependencies(sb-easy-windows-singbox-integration-tests
                sb-easy-prepare-windows-runtime)
            target_link_libraries(sb-easy-windows-singbox-integration-tests
                PRIVATE sb-easy::windows-platform
            )
            sb_easy_enable_warnings(sb-easy-windows-singbox-integration-tests)
            if(MSVC)
                set_property(TARGET sb-easy-windows-singbox-integration-tests
                    PROPERTY MSVC_RUNTIME_LIBRARY
                    "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            endif()
            add_test(NAME sb-easy-windows-singbox-integration-tests
                     COMMAND sb-easy-windows-singbox-integration-tests)
            set_tests_properties(sb-easy-windows-singbox-integration-tests
                                 PROPERTIES TIMEOUT 45)
        endif()
    endif()
endif()

if(SB_EASY_PORTABLE_ONLY)
    return()
endif()

if(WIN32 AND SB_EASY_WINDOWS_ONLY)
    return()
endif()

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
if(TARGET SQLite3::SQLite3)
    set(SB_EASY_SQLITE_TARGET SQLite3::SQLite3)
else()
    set(SB_EASY_SQLITE_TARGET SQLite::SQLite3)
endif()

FetchContent_Declare(
    qrcodegen
    GIT_REPOSITORY https://github.com/nayuki/QR-Code-generator.git
    GIT_TAG v1.8.0
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(qrcodegen)
add_library(sb_easy_qrcode STATIC
    ${qrcodegen_SOURCE_DIR}/cpp/qrcodegen.cpp
)
target_include_directories(sb_easy_qrcode
    PUBLIC ${qrcodegen_SOURCE_DIR}/cpp
)

FetchContent_Declare(
    argon2_source
    URL https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz
    URL_HASH SHA256=daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(argon2_source)
add_library(sb_easy_argon2 STATIC
    ${argon2_source_SOURCE_DIR}/src/argon2.c
    ${argon2_source_SOURCE_DIR}/src/blake2/blake2b.c
    ${argon2_source_SOURCE_DIR}/src/core.c
    ${argon2_source_SOURCE_DIR}/src/encoding.c
    ${argon2_source_SOURCE_DIR}/src/ref.c
    ${argon2_source_SOURCE_DIR}/src/thread.c
)
target_include_directories(sb_easy_argon2
    PUBLIC ${argon2_source_SOURCE_DIR}/include
    PRIVATE ${argon2_source_SOURCE_DIR}/src
)
target_link_libraries(sb_easy_argon2 PRIVATE Threads::Threads)

set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    yaml_cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG 0.8.0
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(yaml_cpp)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # yaml-cpp 0.8.0's emitter uses uint16_t without including <cstdint>.
    # Newer compilers no longer receive that typedef transitively.
    target_compile_options(yaml-cpp PRIVATE -include cstdint)
endif()

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
    src/auth.cpp
    src/config_etag.cpp
    src/config_renderer.cpp
    src/database.cpp
    src/proxy_parser.cpp
    src/script_engine.cpp
    src/singbox_supervisor.cpp
    src/store.cpp
    src/wireguard.cpp
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
        sb_easy_argon2
        sb_easy_qrcode
        yaml-cpp::yaml-cpp
)
sb_easy_enable_warnings(sb_easy_core)

add_executable(sb-easy-cpp src/main.cpp)
target_link_libraries(sb-easy-cpp PRIVATE sb-easy::core)
sb_easy_enable_warnings(sb-easy-cpp)

if(SB_EASY_BUILD_HTTP)
    add_library(sb_easy_clash src/clash_client.cpp)
    add_library(sb-easy::clash ALIAS sb_easy_clash)
    target_include_directories(sb_easy_clash
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_link_libraries(sb_easy_clash
        PUBLIC nlohmann_json::nlohmann_json
        PRIVATE drogon
    )
    sb_easy_enable_warnings(sb_easy_clash)

    add_library(sb_easy_http
        src/clash_websocket.cpp
        src/http_server.cpp
        src/subscription_fetcher.cpp
    )
    add_library(sb-easy::http ALIAS sb_easy_http)
    target_include_directories(sb_easy_http
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_link_libraries(sb_easy_http
        PUBLIC sb-easy::core
        PRIVATE drogon sb-easy::clash
    )
    sb_easy_enable_warnings(sb_easy_http)

    add_executable(sb-easy-cpp-server src/server_main.cpp)
    target_link_libraries(sb-easy-cpp-server PRIVATE sb-easy::http)
    sb_easy_enable_warnings(sb-easy-cpp-server)

    add_library(sb_easy_agent
        src/agent_clash.cpp
        src/agent_client.cpp
        src/agent_config_storage.cpp
        src/agent_ui.cpp
        src/platform/posix_metadata.cpp
        src/platform/posix_process.cpp
        src/platform/posix_storage.cpp
        src/platform/system_clock.cpp
    )
    add_library(sb-easy::agent ALIAS sb_easy_agent)
    target_include_directories(sb_easy_agent
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_link_libraries(sb_easy_agent
        PUBLIC sb-easy::agent-runtime sb-easy::core
        PRIVATE drogon sb-easy::clash OpenSSL::Crypto
    )
    sb_easy_enable_warnings(sb_easy_agent)

    add_executable(sb-easy-cpp-agent src/agent_main.cpp)
    target_link_libraries(sb-easy-cpp-agent PRIVATE sb-easy::agent)
    sb_easy_enable_warnings(sb-easy-cpp-agent)
endif()

if(BUILD_TESTING)
    add_executable(sb-easy-core-tests
        tests/agent_core_test.cpp
        tests/auth_test.cpp
        tests/config_renderer_test.cpp
        tests/proxy_parser_test.cpp
        tests/script_engine_test.cpp
        tests/singbox_supervisor_test.cpp
        tests/store_test.cpp
        tests/test_main.cpp
        tests/wireguard_test.cpp
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

        add_executable(sb-easy-agent-ui-tests tests/agent_ui_test.cpp)
        target_link_libraries(sb-easy-agent-ui-tests
            PRIVATE sb-easy::agent drogon
        )
        sb_easy_enable_warnings(sb-easy-agent-ui-tests)
        add_test(NAME sb-easy-agent-ui-tests COMMAND sb-easy-agent-ui-tests)
        set_tests_properties(sb-easy-agent-ui-tests PROPERTIES TIMEOUT 15)
    endif()
endif()
