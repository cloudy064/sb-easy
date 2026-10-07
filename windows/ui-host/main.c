#define CINTERFACE
#define COBJMACROS
#define CONST_VTABLE
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <WebView2.h>
#include <process.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../common.h"
#include "pipe_client.h"
#include "server_identity.h"
#include "service_start.h"

static const wchar_t app_uri[] = L"https://sbeasy.local/index.html";
static const wchar_t default_pipe[] = L"\\\\.\\pipe\\sb-easy-control-v1";
enum { TRAY_MESSAGE = WM_APP + 1, REPLY_MESSAGE = WM_APP + 2,
       COMMAND_OPEN = 100, COMMAND_EXIT = 101, SMOKE_TIMER = 1 };
typedef struct message { char *text; struct message *next; } message;
typedef struct desktop {
    LONG refs, alive;
    HWND window;
    HANDLE cancel, workers[2];
    CRITICAL_SECTION mutex;
    CONDITION_VARIABLE ready;
    message *requests, *requests_tail, *responses, *responses_tail;
    unsigned request_count;
    bool stopping, tray_added, smoke_busy, capturing;
    bool expect_disconnected, expect_enrolled, smoke_refresh, smoke_validate, validation_requested, smoke_connect;
    bool expect_running, view_requested, sample_requested;
    bool auto_service, smoke_start_service;
    int width, exit_code;
    unsigned smoke_step, connection_step;
    wchar_t last_smoke_state[64];
    ULONGLONG smoke_deadline;
    wchar_t *pipe, *service_data, *screenshot, *smoke_control_plane, *smoke_page, *smoke_theme, *assets, *profile;
    ICoreWebView2Controller *controller;
    ICoreWebView2 *webview;
} desktop;
static desktop *current_desktop;
static UINT taskbar_created;

static wchar_t *wide_copy(const wchar_t *text) {
    size_t size = (wcslen(text) + 1) * sizeof(wchar_t);
    wchar_t *copy = sb_xmalloc(size); memcpy(copy, text, size); return copy;
}
static void queue_push(message **head, message **tail, char *text) {
    message *item = sb_xcalloc(1, sizeof(*item)); item->text = text;
    if (*tail) (*tail)->next = item; else *head = item;
    *tail = item;
}
static char *queue_pop(message **head, message **tail) {
    message *item = *head; char *text;
    if (!item) return NULL;
    *head = item->next; if (!*head) *tail = NULL;
    text = item->text; free(item); return text;
}
static void app_addref(desktop *app) { InterlockedIncrement(&app->refs); }
static void app_release(desktop *app) {
    char *text;
    if (InterlockedDecrement(&app->refs)) return;
    while ((text = queue_pop(&app->requests, &app->requests_tail)) != NULL) sbw_secret_free(text);
    while ((text = queue_pop(&app->responses, &app->responses_tail)) != NULL) free(text);
    if (app->cancel) CloseHandle(app->cancel);
    DeleteCriticalSection(&app->mutex);
    free(app->pipe); free(app->service_data); free(app->screenshot); free(app->smoke_control_plane); free(app->smoke_page); free(app->smoke_theme); free(app->assets); free(app->profile); free(app);
}
static bool app_alive(desktop *app) { return InterlockedCompareExchange(&app->alive, 0, 0) != 0; }
static void app_shutdown(desktop *app) {
    InterlockedExchange(&app->alive, 0);
    if (app->cancel) SetEvent(app->cancel);
    EnterCriticalSection(&app->mutex); app->stopping = true; LeaveCriticalSection(&app->mutex);
    WakeAllConditionVariable(&app->ready);
}
static void fatal(desktop *app, const wchar_t *text) {
    app->exit_code = 1;
    if (!app->screenshot) MessageBoxW(app->window, text, L"sb-easy", MB_OK | MB_ICONERROR);
    DestroyWindow(app->window);
}
static void resize(desktop *app) {
    RECT bounds;
    if (app->controller && GetClientRect(app->window, &bounds)) ICoreWebView2Controller_put_Bounds(app->controller, bounds);
}
static sbj *failure(const sbj *id, const char *code, const char *text) {
    sbj *result = sbj_object(), *error = sbj_object();
    sbj_set(result, "id", id ? sbj_clone(id) : sbj_null());
    sbj_set_int(result, "version", 1); sbj_set_bool(result, "ok", false);
    sbj_set_str(error, "code", code); sbj_set_str(error, "message", text); sbj_set(result, "error", error);
    return result;
}
static void send_json(desktop *app, const sbj *value) {
    sbw_error error = {0}; char *json = sbj_dump(value, -1); wchar_t *wide = sbw_wide(json, &error);
    if (wide && app->webview && app_alive(app)) ICoreWebView2_PostWebMessageAsJson(app->webview, wide);
    free(wide); free(json);
}
static void send_failure(desktop *app, const sbj *id, const char *code, const char *text) {
    sbj *value = failure(id, code, text); send_json(app, value); sbj_free(value);
}
static void receive(desktop *app, ICoreWebView2WebMessageReceivedEventArgs *args) {
    LPWSTR source = NULL, raw = NULL;
    sbw_error error = {0};
    char *utf8 = NULL, *serialized = NULL;
    sbj *request = NULL;
    const sbj *id = NULL, *version, *method;
    bool allowed = false, queued = false;
    static const char *methods[] = {"protocol.hello", "status.get", "enrollment.status", "enrollment.apply",
                                   "enrollment.forget", "config.summary", "config.refresh", "config.validate",
                                   "connection.start", "connection.stop", "config.inspect", "runtime.snapshot"};
    if (FAILED(ICoreWebView2WebMessageReceivedEventArgs_get_Source(args, &source))) return;
    allowed = source && wcscmp(source, app_uri) == 0; CoTaskMemFree(source);
    if (!allowed) return;
    if (FAILED(ICoreWebView2WebMessageReceivedEventArgs_get_WebMessageAsJson(args, &raw)) || !raw) return;
    if (wcslen(raw) > 1024U * 1024U) goto done;
    utf8 = sbw_utf8(raw, &error);
    if (!utf8) goto invalid;
    request = sbw_json_parse(utf8, strlen(utf8), 32, &error);
    if (!request) goto invalid;
    if (sbw_json_string(sbj_get(request, "id"), 128, false)) id = sbj_get(request, "id");
    version = sbj_get(request, "version"); method = sbj_get(request, "method");
    if (!sbj_is_object(request) || !id || !sbj_is_integer(version) || sbj_as_int(version, 0) != 1 ||
        !sbw_json_string(method, 128, false) || !sbj_is_object(sbj_get(request, "params"))) goto invalid;
    allowed = false;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i)
        if (sbj_string_is(method, methods[i])) allowed = true;
    if (!allowed) { send_failure(app, id, "NOT_IMPLEMENTED", "This operation is not available in this preview"); goto done; }
    serialized = sbj_dump(request, -1);
    if (strlen(serialized) > 1024U * 1024U) goto invalid;
    EnterCriticalSection(&app->mutex);
    if (!app->stopping && app->request_count < 8) {
        queue_push(&app->requests, &app->requests_tail, serialized); serialized = NULL;
        ++app->request_count; queued = true;
    }
    LeaveCriticalSection(&app->mutex);
    if (queued) WakeConditionVariable(&app->ready);
    else send_failure(app, id, "BUSY", "Too many pending requests");
    goto done;
invalid:
    send_failure(app, id, "INVALID_REQUEST", "Invalid desktop request");
done:
    if (raw) { SecureZeroMemory(raw, wcslen(raw) * sizeof(wchar_t)); CoTaskMemFree(raw); }
    sbw_secret_free(utf8); sbw_secret_free(serialized); sbj_free(request);
}
static unsigned __stdcall work(void *context) {
    desktop *app = context;
    for (;;) {
        char *request, *response = NULL;
        sbj *parsed_request, *parsed_response = NULL;
        const sbj *id;
        sbw_error error = {0};
        bool valid = false;
        EnterCriticalSection(&app->mutex);
        while (!app->stopping && !app->requests) SleepConditionVariableCS(&app->ready, &app->mutex, INFINITE);
        if (app->stopping) { LeaveCriticalSection(&app->mutex); break; }
        request = queue_pop(&app->requests, &app->requests_tail); --app->request_count;
        LeaveCriticalSection(&app->mutex);
        parsed_request = sbw_json_parse(request, strlen(request), 32, &error);
        id = sbj_get(parsed_request, "id");
        int ready = 0;
        if (parsed_request && app->auto_service && sbj_string_is(sbj_get(parsed_request, "method"), "protocol.hello")) {
            wchar_t *binary = sbw_expected_service_binary();
            sbw_service_start_options options = {app->pipe, binary, app->service_data, wcscmp(app->pipe, default_pipe) == 0};
            ready = sbw_service_ensure(&options, app->cancel, 12000, NULL, &error);
            free(binary);
        }
        if (parsed_request && !ready && !sbw_pipe_request(app->pipe, request, app->cancel, 35000, &response, &error)) {
            parsed_response = sbw_json_parse(response, strlen(response), 32, &error);
            valid = sbj_is_object(parsed_response) && sbj_equal(sbj_get(parsed_response, "id"), id) &&
                sbj_is_integer(sbj_get(parsed_response, "version")) && sbj_get_int(parsed_response, "version", 0) == 1 &&
                sbj_is_bool(sbj_get(parsed_response, "ok"));
            if (!valid) sbw_fail(&error, "INVALID_RESPONSE", "Invalid service response");
        }
        if (!valid) {
            sbj *failed = failure(id, *error.code ? error.code : "SERVICE_UNAVAILABLE", *error.message ? error.message : "Invalid service response");
            free(response); response = sbj_dump(failed, -1); sbj_free(failed);
        }
        sbj_free(parsed_request); sbj_free(parsed_response); sbw_secret_free(request);
        EnterCriticalSection(&app->mutex);
        if (app->stopping) { LeaveCriticalSection(&app->mutex); free(response); break; }
        queue_push(&app->responses, &app->responses_tail, response);
        LeaveCriticalSection(&app->mutex);
        PostMessageW(app->window, REPLY_MESSAGE, 0, 0);
    }
    app_release(app); return 0;
}
static void deliver(desktop *app) {
    for (;;) {
        char *text; wchar_t *wide; sbw_error error = {0};
        EnterCriticalSection(&app->mutex); text = queue_pop(&app->responses, &app->responses_tail); LeaveCriticalSection(&app->mutex);
        if (!text) return;
        wide = sbw_wide(text, &error);
        if (wide && app_alive(app) && app->webview) ICoreWebView2_PostWebMessageAsJson(app->webview, wide);
        free(wide); free(text);
    }
}

/* Each concrete COM handler has its own vtable and reference count. Its desktop
 * reference outlives shutdown, so late callbacks can safely check alive. */
#define DECLARE_CALLBACK(Name, Interface, Arguments) \
    typedef struct Name { Interface iface; LONG refs; desktop *app; IStream *stream; bool block_all; } Name; \
    static HRESULT STDMETHODCALLTYPE Name##_invoke Arguments; \
    static HRESULT STDMETHODCALLTYPE Name##_query(Interface *self, REFIID iid, void **out) { \
        if (!out) return E_POINTER; *out = NULL; \
        if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_##Interface)) return E_NOINTERFACE; \
        *out = self; InterlockedIncrement(&((Name *)self)->refs); return S_OK; } \
    static ULONG STDMETHODCALLTYPE Name##_addref(Interface *self) { return (ULONG)InterlockedIncrement(&((Name *)self)->refs); } \
    static ULONG STDMETHODCALLTYPE Name##_release(Interface *self) { \
        Name *handler = (Name *)self; ULONG count = (ULONG)InterlockedDecrement(&handler->refs); \
        if (!count) { if (handler->stream) IStream_Release(handler->stream); app_release(handler->app); free(handler); } return count; } \
    static const Interface##Vtbl Name##_vtable = {Name##_query, Name##_addref, Name##_release, Name##_invoke}; \
    static Name *Name##_new(desktop *app) { Name *h = sb_xcalloc(1, sizeof(*h)); h->iface.lpVtbl = &Name##_vtable; \
        h->refs = 1; h->app = app; app_addref(app); return h; }

DECLARE_CALLBACK(environment_handler, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
    (ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *self, HRESULT result, ICoreWebView2Environment *environment))
DECLARE_CALLBACK(controller_handler, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
    (ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *self, HRESULT result, ICoreWebView2Controller *controller))
DECLARE_CALLBACK(navigation_handler, ICoreWebView2NavigationStartingEventHandler,
    (ICoreWebView2NavigationStartingEventHandler *self, ICoreWebView2 *sender, ICoreWebView2NavigationStartingEventArgs *args))
DECLARE_CALLBACK(window_handler, ICoreWebView2NewWindowRequestedEventHandler,
    (ICoreWebView2NewWindowRequestedEventHandler *self, ICoreWebView2 *sender, ICoreWebView2NewWindowRequestedEventArgs *args))
DECLARE_CALLBACK(permission_handler, ICoreWebView2PermissionRequestedEventHandler,
    (ICoreWebView2PermissionRequestedEventHandler *self, ICoreWebView2 *sender, ICoreWebView2PermissionRequestedEventArgs *args))
DECLARE_CALLBACK(message_handler, ICoreWebView2WebMessageReceivedEventHandler,
    (ICoreWebView2WebMessageReceivedEventHandler *self, ICoreWebView2 *sender, ICoreWebView2WebMessageReceivedEventArgs *args))
DECLARE_CALLBACK(script_handler, ICoreWebView2ExecuteScriptCompletedHandler,
    (ICoreWebView2ExecuteScriptCompletedHandler *self, HRESULT result, LPCWSTR value))
DECLARE_CALLBACK(capture_handler, ICoreWebView2CapturePreviewCompletedHandler,
    (ICoreWebView2CapturePreviewCompletedHandler *self, HRESULT result))

static HRESULT STDMETHODCALLTYPE navigation_handler_invoke(ICoreWebView2NavigationStartingEventHandler *self,
    ICoreWebView2 *sender, ICoreWebView2NavigationStartingEventArgs *args) {
    navigation_handler *handler = (navigation_handler *)self; LPWSTR uri = NULL; (void)sender;
    ICoreWebView2NavigationStartingEventArgs_get_Uri(args, &uri);
    ICoreWebView2NavigationStartingEventArgs_put_Cancel(args, handler->block_all || !uri || wcscmp(uri, app_uri) != 0);
    CoTaskMemFree(uri); return S_OK;
}
static HRESULT STDMETHODCALLTYPE window_handler_invoke(ICoreWebView2NewWindowRequestedEventHandler *self,
    ICoreWebView2 *sender, ICoreWebView2NewWindowRequestedEventArgs *args) {
    (void)self; (void)sender; ICoreWebView2NewWindowRequestedEventArgs_put_Handled(args, TRUE); return S_OK;
}
static HRESULT STDMETHODCALLTYPE permission_handler_invoke(ICoreWebView2PermissionRequestedEventHandler *self,
    ICoreWebView2 *sender, ICoreWebView2PermissionRequestedEventArgs *args) {
    (void)self; (void)sender; ICoreWebView2PermissionRequestedEventArgs_put_State(args, COREWEBVIEW2_PERMISSION_STATE_DENY); return S_OK;
}
static HRESULT STDMETHODCALLTYPE message_handler_invoke(ICoreWebView2WebMessageReceivedEventHandler *self,
    ICoreWebView2 *sender, ICoreWebView2WebMessageReceivedEventArgs *args) {
    desktop *app = ((message_handler *)self)->app; (void)sender;
    if (app_alive(app)) receive(app, args); return S_OK;
}
static void configure(desktop *app) {
    ICoreWebView2Settings *settings = NULL;
    ICoreWebView2_3 *resources = NULL;
    EventRegistrationToken token;
    HRESULT hr;
    navigation_handler *nav, *frame;
    window_handler *window;
    permission_handler *permission;
    message_handler *message_cb;
    hr = ICoreWebView2_get_Settings(app->webview, &settings);
    if (FAILED(hr) || !settings) { fatal(app, L"无法配置 WebView2。"); return; }
    hr = ICoreWebView2Settings_put_AreDevToolsEnabled(settings, FALSE);
    if (SUCCEEDED(hr)) hr = ICoreWebView2Settings_put_AreDefaultContextMenusEnabled(settings, FALSE);
    if (SUCCEEDED(hr)) hr = ICoreWebView2Settings_put_AreHostObjectsAllowed(settings, FALSE);
    if (SUCCEEDED(hr)) hr = ICoreWebView2Settings_put_AreDefaultScriptDialogsEnabled(settings, FALSE);
    ICoreWebView2Settings_Release(settings);
    if (FAILED(hr)) { fatal(app, L"无法配置 WebView2 安全选项。"); return; }
    hr = ICoreWebView2_QueryInterface(app->webview, &IID_ICoreWebView2_3, (void **)&resources);
    if (SUCCEEDED(hr)) hr = ICoreWebView2_3_SetVirtualHostNameToFolderMapping(resources, L"sbeasy.local", app->assets, COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY);
    if (resources) ICoreWebView2_3_Release(resources);
    if (FAILED(hr)) { fatal(app, L"WebView2 Runtime 不支持本地资源映射。"); return; }
    nav = navigation_handler_new(app);
    hr = ICoreWebView2_add_NavigationStarting(app->webview, &nav->iface, &token); navigation_handler_release(&nav->iface);
    frame = navigation_handler_new(app); frame->block_all = true;
    if (SUCCEEDED(hr)) hr = ICoreWebView2_add_FrameNavigationStarting(app->webview, &frame->iface, &token);
    navigation_handler_release(&frame->iface);
    window = window_handler_new(app);
    if (SUCCEEDED(hr)) hr = ICoreWebView2_add_NewWindowRequested(app->webview, &window->iface, &token);
    window_handler_release(&window->iface);
    permission = permission_handler_new(app);
    if (SUCCEEDED(hr)) hr = ICoreWebView2_add_PermissionRequested(app->webview, &permission->iface, &token);
    permission_handler_release(&permission->iface);
    message_cb = message_handler_new(app);
    if (SUCCEEDED(hr)) hr = ICoreWebView2_add_WebMessageReceived(app->webview, &message_cb->iface, &token);
    message_handler_release(&message_cb->iface);
    if (FAILED(hr)) { fatal(app, L"无法初始化受保护的界面消息桥。"); return; }
    resize(app); ICoreWebView2Controller_put_IsVisible(app->controller, TRUE);
    if (FAILED(ICoreWebView2_Navigate(app->webview, app_uri))) fatal(app, L"无法加载客户端界面。");
}
static HRESULT STDMETHODCALLTYPE controller_handler_invoke(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *self,
    HRESULT result, ICoreWebView2Controller *controller) {
    desktop *app = ((controller_handler *)self)->app;
    if (!app_alive(app)) { if (controller) ICoreWebView2Controller_Close(controller); return S_OK; }
    if (FAILED(result) || !controller) { fatal(app, L"无法创建客户端窗口。"); return S_OK; }
    app->controller = controller; ICoreWebView2Controller_AddRef(controller);
    if (FAILED(ICoreWebView2Controller_get_CoreWebView2(controller, &app->webview)) || !app->webview)
        fatal(app, L"WebView2 初始化失败。");
    else configure(app);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE environment_handler_invoke(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *self,
    HRESULT result, ICoreWebView2Environment *environment) {
    desktop *app = ((environment_handler *)self)->app; controller_handler *handler; HRESULT hr;
    if (!app_alive(app)) return S_OK;
    if (FAILED(result) || !environment) { fatal(app, L"无法启动 WebView2 Runtime。"); return S_OK; }
    handler = controller_handler_new(app);
    hr = ICoreWebView2Environment_CreateCoreWebView2Controller(environment, app->window, &handler->iface);
    controller_handler_release(&handler->iface);
    if (FAILED(hr)) fatal(app, L"无法创建 WebView2 控制器。");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE capture_handler_invoke(ICoreWebView2CapturePreviewCompletedHandler *self, HRESULT result) {
    capture_handler *handler = (capture_handler *)self; desktop *app = handler->app;
    if (app_alive(app)) {
        app->exit_code = SUCCEEDED(result) && SUCCEEDED(IStream_Commit(handler->stream, STGC_DEFAULT)) ? 0 : 4;
        DestroyWindow(app->window);
    }
    return S_OK;
}
static void smoke_click_connection(desktop *app, bool starting) {
    wchar_t script[512]; script_handler *handler = script_handler_new(app);
    (void)swprintf_s(script, 512,
        L"(()=>{const button=document.querySelector('[data-testid=connection-%ls]');"
        L"if(!button||button.disabled)return 'button-pending';button.click();return '%ls-clicked'})()",
        starting ? L"start" : L"stop", starting ? L"start" : L"stop");
    app->smoke_busy = true;
    HRESULT result = ICoreWebView2_ExecuteScript(app->webview, script, &handler->iface);
    script_handler_release(&handler->iface);
    if (FAILED(result)) app->smoke_busy = false;
}
static HRESULT STDMETHODCALLTYPE script_handler_invoke(ICoreWebView2ExecuteScriptCompletedHandler *self, HRESULT result, LPCWSTR value) {
    desktop *app = ((script_handler *)self)->app;
    const wchar_t *expected;
    IStream *stream = NULL;
    capture_handler *capture;
    HRESULT hr;
    if (!app_alive(app)) return S_OK;
    app->smoke_busy = false;
    /* Test diagnostics contain only fixed state labels, never DOM text, form
     * inputs, registration links or IPC payloads. Normal launches write none. */
    if (SUCCEEDED(result) && value && wcscmp(app->last_smoke_state, value)) {
        static const wchar_t *states[] = {L"\"loading\"", L"\"overflow\"", L"\"connected\"", L"\"disconnected\"",
            L"\"unenrolled\"", L"\"no-candidate\"", L"\"validation-pending\"", L"\"connection-pending\"",
            L"\"stop-pending\"", L"\"stopped\"", L"\"running\"", L"\"sampling\"", L"\"telemetry-pending\"",
            L"\"view-pending\"", L"\"theme-pending\"", L"\"button-pending\"", L"\"start-clicked\"", L"\"stop-clicked\""};
        for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i) if (!wcscmp(value, states[i])) {
            size_t length = wcslen(app->screenshot) + 16;
            wchar_t *path = sb_xcalloc(length, sizeof(wchar_t)); FILE *log = NULL;
            (void)swprintf_s(path, length, L"%ls.state", app->screenshot);
            if (!_wfopen_s(&log, path, L"ab") && log) {
                fprintf(log, "%llu step=%u connection=%u state=%ls\n", (unsigned long long)GetTickCount64(), app->smoke_step, app->connection_step, value);
                fclose(log);
            }
            wcscpy_s(app->last_smoke_state, 64, value); free(path); break;
        }
    }
    if (app->expect_running && SUCCEEDED(result) && value && !wcscmp(value, L"\"sampling\"") && !app->sample_requested) {
        app->sample_requested = true;
        ICoreWebView2_ExecuteScript(app->webview,
            L"(()=>{const timer=setInterval(()=>{const app=document.querySelector('[data-testid=desktop-app]');if(Number(app?.dataset.samples)>=2){clearInterval(timer);return}document.querySelector('[data-testid=status-refresh]')?.click()},1000)})()", NULL); return S_OK;
    }
    if (SUCCEEDED(result) && value && app->smoke_control_plane) {
        if (!wcscmp(value, L"\"unenrolled\"") && app->smoke_step == 0) {
            sbw_error error = {0}; char *server = sbw_utf8(app->smoke_control_plane, &error);
            sbj *server_value = sbj_str(server); char *quoted = sbj_dump(server_value, -1);
            char *script = sb_asprintf("(() => { const input = document.querySelector('[data-testid=enrollment-uri]');"
                "if(!input) return; input.value = 'sbeasy://enroll?server=' + encodeURIComponent(%s) + '&code=' + 'a'.repeat(64);"
                "input.dispatchEvent(new Event('input', {bubbles:true}));"
                "setTimeout(() => document.querySelector('[data-testid=enrollment-submit]')?.click(), 0); })()", quoted);
            wchar_t *wide = sbw_wide(script, &error);
            app->smoke_step = 1;
            if (wide) ICoreWebView2_ExecuteScript(app->webview, wide, NULL);
            free(wide); free(script); free(quoted); sbj_free(server_value); free(server); return S_OK;
        }
        if (!wcscmp(value, L"\"no-candidate\"") && app->smoke_step <= 1) {
            app->smoke_step = 2;
            ICoreWebView2_ExecuteScript(app->webview, L"document.querySelector('[data-testid=config-refresh]')?.click()", NULL); return S_OK;
        }
    }
    if (SUCCEEDED(result) && value && app->smoke_connect) {
        if (!app->connection_step && !wcscmp(value, L"\"start-clicked\"")) { app->connection_step = 1; return S_OK; }
        if (app->connection_step == 1 && !wcscmp(value, L"\"stop-clicked\"")) { app->connection_step = 2; return S_OK; }
        if (app->connection_step == 1 && !wcscmp(value, L"\"running\"")) {
            smoke_click_connection(app, false); return S_OK;
        }
        if (app->connection_step == 2 && !wcscmp(value, L"\"stopped\"")) app->connection_step = 3;
    }
    expected = app->connection_step == 3 ? L"\"stopped\"" : app->expect_disconnected ? L"\"disconnected\"" : L"\"connected\"";
    if (FAILED(result) || !value || wcscmp(value, expected)) return S_OK;
    if (app->smoke_refresh && !app->smoke_step) {
        app->smoke_step = 3;
        ICoreWebView2_ExecuteScript(app->webview, L"document.querySelector('[data-testid=config-refresh]')?.click()", NULL); return S_OK;
    }
    if (app->smoke_validate && !app->validation_requested) {
        app->validation_requested = true;
        ICoreWebView2_ExecuteScript(app->webview, L"document.querySelector('[data-testid=config-validate]')?.click()", NULL); return S_OK;
    }
    if (app->smoke_connect && !app->connection_step) {
        smoke_click_connection(app, true); return S_OK;
    }
    if ((app->smoke_page || app->smoke_theme) && !app->view_requested) {
        const wchar_t *page = app->smoke_page ? app->smoke_page : L"overview";
        wchar_t script[1024]; app->view_requested = true;
        if (app->smoke_theme) (void)swprintf_s(script, 1024,
            L"document.querySelector('[data-testid=nav-settings]')?.click();setTimeout(()=>{document.querySelector('[data-testid=theme-%ls]')?.click();document.querySelector('[data-testid=nav-%ls]')?.click();scrollTo(0,0)},50)", app->smoke_theme, page);
        else (void)swprintf_s(script, 1024, L"document.querySelector('[data-testid=nav-%ls]')?.click();scrollTo(0,0)", page);
        ICoreWebView2_ExecuteScript(app->webview, script, NULL); return S_OK;
    }
    app->capturing = true;
    if (FAILED(SHCreateStreamOnFileEx(app->screenshot, STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE,
        FILE_ATTRIBUTE_NORMAL, TRUE, NULL, &stream))) { app->exit_code = 3; DestroyWindow(app->window); return S_OK; }
    capture = capture_handler_new(app); capture->stream = stream;
    hr = ICoreWebView2_CapturePreview(app->webview, COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG, stream, &capture->iface);
    capture_handler_release(&capture->iface);
    if (FAILED(hr)) { app->exit_code = 4; DestroyWindow(app->window); }
    return S_OK;
}
static void smoke_tick(desktop *app) {
    const wchar_t *base = L"(() => { const app = document.querySelector('[data-testid=desktop-app]');"
        L"if (!app) return 'loading'; if (document.documentElement.scrollWidth > innerWidth) return 'overflow';"
        L"if (app.getAttribute('data-busy') === 'true') return 'loading'; const state = app.getAttribute('data-service-state');";
    const wchar_t *extra = app->smoke_control_plane || app->expect_enrolled ?
        L"if (state !== 'connected') return state; if (app.getAttribute('data-enrolled') !== 'true') return 'unenrolled';"
        L"if (app.getAttribute('data-candidate') !== 'true') return 'no-candidate';"
        L"" : L"";
    const wchar_t *end = L"return state; })()";
    const wchar_t *validated = app->validation_requested ?
        L"if (app.getAttribute('data-validation') !== 'valid') return 'validation-pending';" : L"";
    const wchar_t *connection = app->connection_step == 1 ?
        L"document.querySelector('[data-testid=connection-summary]')?.scrollIntoView({block:'start'});"
        L"return app.getAttribute('data-phase') === 'RUNNING' && app.getAttribute('data-core-running') === 'true' && app.getAttribute('data-active-etag') ? 'running' : 'connection-pending';" :
        app->connection_step >= 2 ?
        L"document.querySelector('[data-testid=connection-summary]')?.scrollIntoView({block:'start'});"
        L"return app.getAttribute('data-phase') === 'STOPPED' && app.getAttribute('data-core-running') === 'false' && app.getAttribute('data-active-etag') === '' ? 'stopped' : 'stop-pending';" : L"";
    wchar_t view[512] = L"", observing[256] = L"";
    if (app->view_requested) {
        (void)swprintf_s(view, 512, L"if(app.getAttribute('data-page')!=='%ls')return 'view-pending';", app->smoke_page ? app->smoke_page : L"overview");
        if (app->smoke_theme) {
            wchar_t theme[160]; (void)swprintf_s(theme, 160, L"if(document.documentElement.dataset.theme!=='%ls')return 'theme-pending';", app->smoke_theme);
            wcscat_s(view, 512, theme);
        }
    }
    if (app->expect_running) wcscpy_s(observing, 256, L"if(app.dataset.coreRunning!=='true'||app.dataset.telemetry!=='ready')return 'telemetry-pending';if(Number(app.dataset.samples)<2)return 'sampling';");
    wchar_t *script; size_t length; script_handler *handler; HRESULT hr;
    if (GetTickCount64() > app->smoke_deadline) { app->exit_code = 2; DestroyWindow(app->window); return; }
    if (!app->webview || app->smoke_busy || app->capturing) return;
    app->smoke_busy = true;
    length = wcslen(base) + wcslen(extra) + wcslen(validated) + wcslen(connection) + wcslen(view) + wcslen(observing) + wcslen(end) + 1;
    script = sb_xcalloc(length, sizeof(wchar_t)); wcscpy_s(script, length, base); wcscat_s(script, length, extra);
    wcscat_s(script, length, validated); wcscat_s(script, length, connection); wcscat_s(script, length, view); wcscat_s(script, length, observing); wcscat_s(script, length, end);
    handler = script_handler_new(app);
    hr = ICoreWebView2_ExecuteScript(app->webview, script, &handler->iface);
    script_handler_release(&handler->iface); free(script);
    if (FAILED(hr)) app->smoke_busy = false;
}
static void add_tray(desktop *app) {
    NOTIFYICONDATAW icon = {0}; icon.cbSize = sizeof(icon); icon.hWnd = app->window; icon.uID = 1;
    icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP; icon.uCallbackMessage = TRAY_MESSAGE;
    icon.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wcscpy_s(icon.szTip, sizeof(icon.szTip) / sizeof(icon.szTip[0]), L"sb-easy · Windows 开发预览");
    app->tray_added = Shell_NotifyIconW(NIM_ADD, &icon) != FALSE;
    icon.uVersion = NOTIFYICON_VERSION_4; if (app->tray_added) Shell_NotifyIconW(NIM_SETVERSION, &icon);
}
static void remove_tray(desktop *app) {
    NOTIFYICONDATAW icon = {0}; if (!app->tray_added) return;
    icon.cbSize = sizeof(icon); icon.hWnd = app->window; icon.uID = 1; Shell_NotifyIconW(NIM_DELETE, &icon); app->tray_added = false;
}
static void show(desktop *app) { ShowWindow(app->window, SW_RESTORE); SetForegroundWindow(app->window); }
static void tray_action(desktop *app, LPARAM action) {
    if (LOWORD(action) == WM_LBUTTONUP || LOWORD(action) == NIN_SELECT || LOWORD(action) == NIN_KEYSELECT) show(app);
    if (LOWORD(action) == WM_RBUTTONUP || LOWORD(action) == WM_CONTEXTMENU) {
        POINT point; HMENU menu; UINT choice; GetCursorPos(&point); menu = CreatePopupMenu(); if (!menu) return;
        AppendMenuW(menu, MF_STRING, COMMAND_OPEN, L"打开 sb-easy"); AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(menu, MF_STRING, COMMAND_EXIT, L"退出界面"); SetForegroundWindow(app->window);
        choice = (UINT)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, app->window, NULL);
        DestroyMenu(menu); if (choice == COMMAND_OPEN) show(app); if (choice == COMMAND_EXIT) DestroyWindow(app->window);
    }
}
static wchar_t *parent_path(const wchar_t *path) {
    wchar_t *copy = wide_copy(path); wchar_t *slash = wcsrchr(copy, L'\\');
    if (slash == copy + 2 && copy[1] == L':') slash[1] = L'\0';
    else if (slash) *slash = L'\0';
    else *copy = L'\0';
    return copy;
}
static void start(desktop *app) {
    sbw_error error = {0}; wchar_t *directory, *index; PWSTR local = NULL;
    environment_handler *handler; HRESULT hr;
    /* One long mutation must leave room for a bounded status request. The
     * service still serializes mutations and both workers share cancellation. */
    for (size_t i = 0; i < sizeof(app->workers) / sizeof(app->workers[0]); ++i) {
        app_addref(app);
        app->workers[i] = (HANDLE)_beginthreadex(NULL, 0, work, app, 0, NULL);
        if (!app->workers[i]) { app_release(app); fatal(app, L"无法创建服务通信线程。"); return; }
    }
    if (!app->screenshot) add_tray(app);
    directory = sbw_executable_directory(&error);
    app->assets = directory ? sbw_path_join(directory, L"ui") : NULL; free(directory);
    index = app->assets ? sbw_path_join(app->assets, L"index.html") : NULL;
    if (!index || GetFileAttributesW(index) == INVALID_FILE_ATTRIBUTES || (GetFileAttributesW(index) & FILE_ATTRIBUTE_DIRECTORY)) {
        free(index); fatal(app, L"找不到界面资源，请重新运行 Windows 构建脚本。"); return;
    }
    free(index);
    if (app->screenshot) { directory = parent_path(app->screenshot); app->profile = sbw_path_join(directory, L"webview2-smoke-profile"); free(directory); }
    else {
        if (FAILED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &local))) { fatal(app, L"无法访问本地应用数据目录。"); return; }
        app->profile = sbw_path_join(local, L"sb-easy\\WebView2"); CoTaskMemFree(local);
    }
    handler = environment_handler_new(app);
    hr = CreateCoreWebView2EnvironmentWithOptions(NULL, app->profile, NULL, &handler->iface);
    environment_handler_release(&handler->iface);
    if (FAILED(hr)) { fatal(app, L"无法启动 WebView2，请安装 Microsoft Edge WebView2 Runtime。"); return; }
    if (app->screenshot) { app->smoke_deadline = GetTickCount64() + (app->smoke_connect ? 120000 : 60000); SetTimer(app->window, SMOKE_TIMER, 250, NULL); }
}
static LRESULT CALLBACK window_proc(HWND window, UINT message_id, WPARAM wparam, LPARAM lparam) {
    desktop *app = current_desktop;
    if (!app) return DefWindowProcW(window, message_id, wparam, lparam);
    if (taskbar_created && message_id == taskbar_created && !app->screenshot) { add_tray(app); return 0; }
    switch (message_id) {
    case WM_SIZE: resize(app); return 0;
    case WM_DPICHANGED: {
        const RECT *rect = (const RECT *)lparam;
        SetWindowPos(window, NULL, rect->left, rect->top, rect->right - rect->left, rect->bottom - rect->top, SWP_NOZORDER | SWP_NOACTIVATE); return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *bounds = (MINMAXINFO *)lparam; UINT dpi = GetDpiForWindow(window);
        bounds->ptMinTrackSize.x = MulDiv(760, (int)dpi, 96); bounds->ptMinTrackSize.y = MulDiv(560, (int)dpi, 96); return 0;
    }
    case WM_CLOSE: if (app->tray_added && !app->screenshot) ShowWindow(window, SW_HIDE); else DestroyWindow(window); return 0;
    case WM_DESTROY: app_shutdown(app); PostQuitMessage(app->exit_code); return 0;
    case TRAY_MESSAGE: tray_action(app, lparam); return 0;
    case REPLY_MESSAGE: deliver(app); return 0;
    case WM_TIMER: if (wparam == SMOKE_TIMER) smoke_tick(app); return 0;
    default: return DefWindowProcW(window, message_id, wparam, lparam);
    }
}
static bool parse_arguments(desktop *app) {
    int count = 0; LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &count); bool ok = false;
    if (!args) return false;
    for (int i = 1; i < count; ++i) {
        const wchar_t *arg = args[i];
        if (!wcscmp(arg, L"--pipe-name") && i + 1 < count) { free(app->pipe); app->pipe = wide_copy(args[++i]); }
        else if (!wcscmp(arg, L"--smoke-test") && i + 1 < count) {
            wchar_t absolute[32768]; DWORD length = GetFullPathNameW(args[++i], 32768, absolute, NULL);
            if (!length || length >= 32768) goto done;
            free(app->screenshot); app->screenshot = wide_copy(absolute);
        } else if (!wcscmp(arg, L"--expect-disconnected")) app->expect_disconnected = true;
        else if (!wcscmp(arg, L"--expect-enrolled")) app->expect_enrolled = true;
        else if (!wcscmp(arg, L"--expect-running")) app->expect_running = true;
        else if (!wcscmp(arg, L"--smoke-page") && i + 1 < count) {
            const wchar_t *page = args[++i];
            if (wcscmp(page, L"overview") && wcscmp(page, L"proxies") && wcscmp(page, L"connections") && wcscmp(page, L"profiles") && wcscmp(page, L"rules") && wcscmp(page, L"activity") && wcscmp(page, L"settings")) goto done;
            free(app->smoke_page); app->smoke_page = wide_copy(page);
        }
        else if (!wcscmp(arg, L"--smoke-theme") && i + 1 < count) {
            const wchar_t *theme = args[++i];
            if (wcscmp(theme, L"system") && wcscmp(theme, L"light") && wcscmp(theme, L"dark")) goto done;
            free(app->smoke_theme); app->smoke_theme = wide_copy(theme);
        }
        else if (!wcscmp(arg, L"--smoke-refresh")) app->smoke_refresh = true;
        else if (!wcscmp(arg, L"--smoke-validate")) app->smoke_validate = true;
        else if (!wcscmp(arg, L"--smoke-connect")) app->smoke_connect = true;
        else if (!wcscmp(arg, L"--smoke-start-service")) app->smoke_start_service = true;
        else if (!wcscmp(arg, L"--smoke-service-data") && i + 1 < count) {
            wchar_t absolute[32768]; DWORD length = GetFullPathNameW(args[++i], 32768, absolute, NULL);
            if (!length || length >= 32768) goto done;
            free(app->service_data); app->service_data = wide_copy(absolute);
        }
        else if (!wcscmp(arg, L"--smoke-control-plane") && i + 1 < count) { free(app->smoke_control_plane); app->smoke_control_plane = wide_copy(args[++i]); }
        else if (!wcscmp(arg, L"--smoke-width") && i + 1 < count) {
            wchar_t *end; long value = wcstol(args[++i], &end, 10); if (*end || value < 760 || value > 1920) goto done; app->width = (int)value;
        } else goto done;
    }
    if ((app->expect_disconnected || app->expect_enrolled || app->smoke_refresh || app->smoke_validate || app->smoke_connect || app->smoke_control_plane || app->width != 1120) && !app->screenshot) goto done;
    if ((app->expect_running || app->smoke_page || app->smoke_theme) && !app->screenshot) goto done;
    if (app->smoke_start_service || app->service_data) {
        if (!app->screenshot || !app->smoke_start_service || !app->service_data || app->expect_disconnected || !wcscmp(app->pipe, default_pipe)) goto done;
    }
    app->auto_service = app->smoke_start_service || (!app->screenshot && !wcscmp(app->pipe, default_pipe));
    if (app->expect_running && (app->smoke_connect || app->expect_disconnected || !app->expect_enrolled)) goto done;
    if (app->smoke_validate && !app->smoke_control_plane && !app->expect_enrolled) goto done;
    if (app->smoke_connect && ((!app->smoke_control_plane && !app->expect_enrolled) || app->expect_disconnected)) goto done;
    if (app->smoke_control_plane) {
        const wchar_t *prefix = L"http://127.0.0.1:"; const wchar_t *port; const wchar_t *slash; wchar_t *end; unsigned long value;
        if (wcsncmp(app->smoke_control_plane, prefix, wcslen(prefix))) goto done;
        port = app->smoke_control_plane + wcslen(prefix); slash = wcschr(port, L'/');
        if (!slash || slash == port || slash - port > 5 || wcscmp(slash, L"/test")) goto done;
        for (const wchar_t *c = port; c < slash; ++c) if (*c < L'0' || *c > L'9') goto done;
        value = wcstoul(port, &end, 10); if (end != slash || value < 1 || value > 65535) goto done;
    }
    if (wcsncmp(app->pipe, L"\\\\.\\pipe\\", 9) || wcslen(app->pipe) <= 9 || wcslen(app->pipe) > 240 || wcspbrk(app->pipe + 9, L"\\/")) goto done;
    if (app->screenshot) {
        wchar_t *directory = parent_path(app->screenshot); int result = SHCreateDirectoryExW(NULL, directory, NULL); free(directory);
        if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS) goto done;
    }
    ok = true;
done:
    LocalFree(args); return ok;
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show_command) {
    desktop *app; WNDCLASSW window_class = {0}; MSG message_value; int result = 1; BOOL next;
    (void)previous; (void)command_line;
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
    app = sb_xcalloc(1, sizeof(*app)); app->refs = 1; app->alive = 1; app->width = 1120;
    InitializeCriticalSection(&app->mutex); InitializeConditionVariable(&app->ready);
    app->cancel = CreateEventW(NULL, TRUE, FALSE, NULL); app->pipe = wide_copy(default_pipe);
    if (!app->cancel || !parse_arguments(app)) goto cleanup;
    current_desktop = app; taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    window_class.lpfnWndProc = window_proc; window_class.hInstance = instance; window_class.lpszClassName = L"SbEasyDesktopWindow";
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW); window_class.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); RegisterClassW(&window_class);
    app->window = CreateWindowExW(0, window_class.lpszClassName, L"sb-easy · Windows 开发预览", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, app->width, 780, NULL, NULL, instance, NULL);
    if (!app->window) goto cleanup;
    ShowWindow(app->window, app->screenshot ? SW_HIDE : show_command); start(app);
    while ((next = GetMessageW(&message_value, NULL, 0, 0)) > 0) { TranslateMessage(&message_value); DispatchMessageW(&message_value); }
    result = next < 0 ? 1 : app->exit_code;
cleanup:
    app_shutdown(app); current_desktop = NULL;
    for (size_t i = 0; i < sizeof(app->workers) / sizeof(app->workers[0]); ++i)
        if (app->workers[i]) { WaitForSingleObject(app->workers[i], INFINITE); CloseHandle(app->workers[i]); app->workers[i] = NULL; }
    if (app->controller) ICoreWebView2Controller_Close(app->controller);
    if (app->webview) { ICoreWebView2_Release(app->webview); app->webview = NULL; }
    if (app->controller) { ICoreWebView2Controller_Release(app->controller); app->controller = NULL; }
    remove_tray(app); app_release(app); CoUninitialize(); return result;
}
