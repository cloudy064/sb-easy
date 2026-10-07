cmake_minimum_required(VERSION 3.24)
project(sb_easy_windows VERSION 0.3.0 LANGUAGES C)

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "The Windows preview requires MSVC targeting x64")
endif()
# Ninja matches the compiler's raw /showIncludes bytes. CMake's automatic
# console-code-page conversion can corrupt that prefix on localized MSVC with
# UTF-8 terminal output, silently omitting header dependencies. Probe without
# transcoding, including when an existing build cache contains a stale prefix.
if(CMAKE_GENERATOR MATCHES "Ninja")
    set(include_probe "${CMAKE_BINARY_DIR}/CMakeFiles/sb-show-includes")
    file(MAKE_DIRECTORY "${include_probe}")
    file(WRITE "${include_probe}/included.h" "\n")
    file(WRITE "${include_probe}/probe.c" "#include \"included.h\"\nint main(void) { return 0; }\n")
    execute_process(COMMAND "${CMAKE_C_COMPILER}" /nologo /showIncludes /c probe.c
        WORKING_DIRECTORY "${include_probe}" OUTPUT_VARIABLE include_output
        ERROR_VARIABLE include_error RESULT_VARIABLE include_result ENCODING NONE)
    if(include_result EQUAL 0 AND include_output MATCHES "(^|\n)([^:\n]+:[^:\n]+:[ \t]+)([A-Za-z]:[/\\\\])")
        set(CMAKE_CL_SHOWINCLUDES_PREFIX "${CMAKE_MATCH_2}")
    else()
        message(FATAL_ERROR "Cannot determine MSVC include prefix; header dependency tracking would be unreliable")
    endif()
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(SB_EASY_BUILD_DESKTOP "Build the WebView2 desktop shell" ON)
option(SB_EASY_WARNINGS_AS_ERRORS "Treat project warnings as errors" ON)
include(CTest)

function(sb_windows_target target)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
        _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS SB_EASY_VERSION="${PROJECT_VERSION}-dev")
    target_compile_options(${target} PRIVATE /W4 /utf-8)
    if(SB_EASY_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE /WX)
    endif()
endfunction()

add_library(sb_windows_common STATIC common.c ../c/src/json.c)
target_include_directories(sb_windows_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/../c/include")
sb_windows_target(sb_windows_common)

add_library(sb_windows_runtime STATIC runtime/state.c)
target_include_directories(sb_windows_runtime PUBLIC runtime)
sb_windows_target(sb_windows_runtime)

add_library(sb_windows_control_plane STATIC service/control_plane.c)
target_include_directories(sb_windows_control_plane PUBLIC service)
target_link_libraries(sb_windows_control_plane PUBLIC sb_windows_common winhttp ws2_32)
sb_windows_target(sb_windows_control_plane)

add_library(sb_windows_controller STATIC service/controller.c service/secure_store.c service/core_process.c service/runtime_config.c service/dashboard.c)
target_include_directories(sb_windows_controller PUBLIC service)
target_link_libraries(sb_windows_controller PUBLIC sb_windows_runtime sb_windows_control_plane
    sb_windows_common crypt32 bcrypt advapi32 shell32 ole32 iphlpapi)
sb_windows_target(sb_windows_controller)

add_library(sb_windows_protocol STATIC service/protocol.c)
target_include_directories(sb_windows_protocol PUBLIC service)
target_link_libraries(sb_windows_protocol PUBLIC sb_windows_controller)
sb_windows_target(sb_windows_protocol)

add_library(sb_windows_pipe STATIC service/pipe_server.c)
target_link_libraries(sb_windows_pipe PUBLIC sb_windows_protocol advapi32)
sb_windows_target(sb_windows_pipe)

add_executable(sb-easy-service service/service_main.c)
target_link_libraries(sb-easy-service PRIVATE sb_windows_pipe)
sb_windows_target(sb-easy-service)

if(SB_EASY_BUILD_DESKTOP)
    # NuGet SDK only: the separately installed Evergreen Runtime remains updateable.
    set(webview_version "1.0.4258.31")
    set(webview_archive "${CMAKE_BINARY_DIR}/_deps/webview2-${webview_version}.zip")
    set(webview_root "${CMAKE_BINARY_DIR}/_deps/webview2-${webview_version}")
    file(DOWNLOAD
        "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/${webview_version}/microsoft.web.webview2.${webview_version}.nupkg"
        "${webview_archive}"
        EXPECTED_HASH SHA256=56f7f4b8bf9aee4b8efefbbdd4f67d5f74ebd1b100ed0806da71bf76af481aa9
        TLS_VERIFY ON)
    if(NOT EXISTS "${webview_root}/build/native/include/WebView2.h")
        file(ARCHIVE_EXTRACT INPUT "${webview_archive}" DESTINATION "${webview_root}")
    endif()
    add_library(sb_webview2 INTERFACE)
    target_include_directories(sb_webview2 SYSTEM INTERFACE "${webview_root}/build/native/include")
    target_link_libraries(sb_webview2 INTERFACE "${webview_root}/build/native/x64/WebView2Loader.dll.lib")

    add_executable(sb-easy WIN32 ui-host/main.c ui-host/pipe_client.c ui-host/server_identity.c ui-host/service_start.c ui-host/webview_guids.c ui-host/app.manifest)
    target_link_libraries(sb-easy PRIVATE sb_webview2 sb_windows_common
        user32 shell32 ole32 shlwapi version advapi32 uuid)
    sb_windows_target(sb-easy)
    # Refresh packaged assets on every build, including UI-only changes.
    add_custom_target(sb_windows_ui_assets ALL
        COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/ui/dist" "$<TARGET_FILE_DIR:sb-easy>/ui"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:sb-easy>/licenses"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/licenses/sbj-grisu2-MIT.txt" "$<TARGET_FILE_DIR:sb-easy>/licenses/sbj-grisu2-MIT.txt"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${webview_root}/build/native/x64/WebView2Loader.dll" "$<TARGET_FILE_DIR:sb-easy>/WebView2Loader.dll"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${webview_root}/LICENSE.txt" "$<TARGET_FILE_DIR:sb-easy>/licenses/webview2.txt"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${webview_root}/NOTICE.txt" "$<TARGET_FILE_DIR:sb-easy>/licenses/webview2-notice.txt"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/ui/node_modules/vue/LICENSE" "$<TARGET_FILE_DIR:sb-easy>/licenses/vue.txt"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/README.md" "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md" "$<TARGET_FILE_DIR:sb-easy>"
        COMMENT "Copying packaged desktop UI (run npm ci && npm run build in windows/ui first)")
    add_dependencies(sb-easy sb_windows_ui_assets)
endif()

if(BUILD_TESTING)
    add_executable(windows_dashboard_test tests/dashboard_test.c)
    target_link_libraries(windows_dashboard_test PRIVATE sb_windows_controller)
    sb_windows_target(windows_dashboard_test)
    add_test(NAME windows_dashboard COMMAND windows_dashboard_test)
    add_executable(windows_connection_fixture tests/connection_fixture.c)
    target_link_libraries(windows_connection_fixture PRIVATE sb_windows_common ws2_32)
    sb_windows_target(windows_connection_fixture)
    add_executable(windows_connection_test tests/connection_test.c)
    target_link_libraries(windows_connection_test PRIVATE sb_windows_protocol)
    sb_windows_target(windows_connection_test)
    add_dependencies(windows_connection_test windows_connection_fixture)
    add_test(NAME windows_connection COMMAND windows_connection_test $<TARGET_FILE:windows_connection_fixture>)
    set_tests_properties(windows_connection PROPERTIES TIMEOUT 60)
    add_executable(windows_runtime_config_test tests/runtime_config_test.c)
    target_link_libraries(windows_runtime_config_test PRIVATE sb_windows_controller)
    sb_windows_target(windows_runtime_config_test)
    add_test(NAME windows_runtime_config COMMAND windows_runtime_config_test)
    set_tests_properties(windows_runtime_config PROPERTIES TIMEOUT 30)
    add_executable(windows_core_fixture tests/core_fixture.c)
    target_link_libraries(windows_core_fixture PRIVATE sb_windows_common)
    sb_windows_target(windows_core_fixture)
    add_executable(windows_core_process_test tests/core_process_test.c)
    target_link_libraries(windows_core_process_test PRIVATE sb_windows_controller)
    sb_windows_target(windows_core_process_test)
    add_dependencies(windows_core_process_test windows_core_fixture)
    add_test(NAME windows_core_process COMMAND windows_core_process_test $<TARGET_FILE:windows_core_fixture>)
    set_tests_properties(windows_core_process PROPERTIES TIMEOUT 30)

    add_executable(windows_control_plane_test tests/control_plane_test.c)
    target_link_libraries(windows_control_plane_test PRIVATE sb_windows_control_plane ws2_32)
    sb_windows_target(windows_control_plane_test)
    add_test(NAME windows_control_plane COMMAND windows_control_plane_test)

    add_executable(windows_controller_test tests/controller_test.c)
    target_link_libraries(windows_controller_test PRIVATE sb_windows_protocol)
    sb_windows_target(windows_controller_test)
    add_dependencies(windows_controller_test windows_core_fixture)
    add_test(NAME windows_controller COMMAND windows_controller_test $<TARGET_FILE:windows_core_fixture>)

    add_executable(windows_secure_store_test tests/secure_store_test.c)
    target_link_libraries(windows_secure_store_test PRIVATE sb_windows_controller)
    sb_windows_target(windows_secure_store_test)
    add_test(NAME windows_secure_store COMMAND windows_secure_store_test)
    set_tests_properties(windows_control_plane windows_controller windows_secure_store PROPERTIES TIMEOUT 60)
    add_executable(windows_identity_test ui-host/server_identity_test.c ui-host/server_identity.c)
    target_link_libraries(windows_identity_test PRIVATE sb_windows_common advapi32)
    sb_windows_target(windows_identity_test)
    add_test(NAME windows_identity COMMAND windows_identity_test)
    set_tests_properties(windows_identity PROPERTIES TIMEOUT 10)
    add_executable(windows_service_start_test tests/service_start_test.c ui-host/service_start.c ui-host/server_identity.c ui-host/pipe_client.c)
    target_link_libraries(windows_service_start_test PRIVATE sb_windows_common advapi32 shell32)
    sb_windows_target(windows_service_start_test)
    add_dependencies(windows_service_start_test sb-easy-service)
    add_test(NAME windows_service_start COMMAND windows_service_start_test $<TARGET_FILE:sb-easy-service>)
    set_tests_properties(windows_service_start PROPERTIES TIMEOUT 30)
    add_executable(windows_state_test tests/state_test.c)
    target_link_libraries(windows_state_test PRIVATE sb_windows_runtime)
    sb_windows_target(windows_state_test)
    add_test(NAME windows_state COMMAND windows_state_test)

    add_executable(windows_protocol_test tests/protocol_test.c)
    target_link_libraries(windows_protocol_test PRIVATE sb_windows_protocol)
    sb_windows_target(windows_protocol_test)
    add_test(NAME windows_protocol COMMAND windows_protocol_test)

    add_executable(windows_pipe_test tests/pipe_integration_test.c)
    target_link_libraries(windows_pipe_test PRIVATE sb_windows_pipe)
    sb_windows_target(windows_pipe_test)
    add_test(NAME windows_pipe COMMAND windows_pipe_test)
    set_tests_properties(windows_state windows_protocol windows_pipe PROPERTIES TIMEOUT 30)
endif()
