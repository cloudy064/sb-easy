#include "resource.h"
#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <objbase.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../common.h"
#include "local_web.h"
#include "pipe_client.h"
#include "server_identity.h"
#include "service_start.h"
#include "tray_bridge.h"
#include "tray_smoke.h"

static const wchar_t default_pipe[] = L"\\\\.\\pipe\\sb-easy-control-v1";
enum { TRAY_MESSAGE = WM_APP + 1, OPEN_MESSAGE, UPDATE_CLOSE_MESSAGE,
    COMMAND_OPEN = 100, COMMAND_EXPORT, COMMAND_EXIT, UPDATE_TIMER = 1 };
typedef struct desktop {
    HWND window;
    HANDLE cancel;
    sbw_local_web *web;
    wchar_t *url, *pipe, *receipt;
    bool tray_added, background, offline;
} desktop;
static desktop *current;
static UINT taskbar_created;


static wchar_t *wide_copy(const wchar_t *text) {
    size_t size = (wcslen(text) + 1) * sizeof(wchar_t);
    wchar_t *copy = sb_xmalloc(size); memcpy(copy, text, size); return copy;
}

static sbj *failure(const sbj *id, const char *code, const char *text) {
    sbj *result = sbj_object(), *error = sbj_object();
    sbj_set(result, "id", id ? sbj_clone(id) : sbj_null());
    sbj_set_int(result, "version", 1); sbj_set_bool(result, "ok", false);
    sbj_set_str(error, "code", code); sbj_set_str(error, "message", text); sbj_set(result, "error", error);
    return result;
}

static bool httpdebug_local(desktop *app,sbj *request,char **response,sbw_error *error) {
    const char *method=sbj_get_str(request,"method","");bool export_har=sb_streq(method,"httpdebug.export"),open=sb_streq(method,"httpdebug.open")||export_har,remove=sb_streq(method,"httpdebug.untrust");
    sbj *query=sbj_clone(request);sbj_set_str(query,"method",open?"httpdebug.snapshot":"httpdebug.certificate");char *raw=sbj_dump(query,-1),*answer=NULL;sbj_free(query);
    int failed=sbw_pipe_request(app->pipe,raw,app->cancel,10000,&answer,error);free(raw);if(failed)return false;
    sbj *reply=sbw_json_parse(answer,strlen(answer),32,error);free(answer);bool ok=sbj_get_bool(reply,"ok",false);const sbj *result=sbj_get(reply,"result");
    if(!ok){sbw_fail(error,"HTTP_DEBUG_ERROR",sbj_get_str(sbj_get(reply,"error"),"message","Start HTTP debugging first."));sbj_free(reply);return false;}
    if(open) {
        const char *url=sbj_get_str(result,"url","");const char *prefix="http://127.0.0.1:17991/?token=";size_t n=strlen(prefix);
        ok=strlen(url)==n+64&&!strncmp(url,prefix,n)&&strspn(url+n,"0123456789abcdef")==64;
        if(ok){char destination[160];sprintf_s(destination,sizeof destination,"http://127.0.0.1:17991/%s?token=%s",export_har?"sbeasy.har":"",url+n);wchar_t *wide=sbw_wide(destination,error);ok=wide&&(INT_PTR)ShellExecuteW(NULL,L"open",wide,NULL,NULL,SW_SHOWNORMAL)>32;free(wide);}
    }else {
        const char *hex=sbj_get_str(result,"der","");DWORD size=0;ok=*hex&&strlen(hex)<32768&&CryptStringToBinaryA(hex,0,CRYPT_STRING_HEXRAW,NULL,&size,NULL,NULL);
        BYTE *bytes=ok?sb_xmalloc(size):NULL;PCCERT_CONTEXT cert=NULL;HCERTSTORE store=NULL;
        if(ok)ok=CryptStringToBinaryA(hex,0,CRYPT_STRING_HEXRAW,bytes,&size,NULL,NULL);
        if(ok){cert=CertCreateCertificateContext(X509_ASN_ENCODING,bytes,size);ok=cert!=NULL;}
        if(ok){store=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_CURRENT_USER,L"ROOT");ok=store!=NULL;}
        if(ok&&remove){PCCERT_CONTEXT found=CertFindCertificateInStore(store,X509_ASN_ENCODING,0,CERT_FIND_EXISTING,cert,NULL);ok=!found||CertDeleteCertificateFromStore(found);}
        else if(ok)ok=CertAddCertificateContextToStore(store,cert,CERT_STORE_ADD_USE_EXISTING,NULL);
        if (store) CertCloseStore(store, 0);
        if (cert) CertFreeCertificateContext(cert);
        free(bytes);
    }
    if(ok){sbj *body=sbj_object();sbj_set_bool(body,"ready",true);sbj_set(reply,"result",body);*response=sbj_dump(reply,-1);}
    else sbw_fail(error,"HTTP_DEBUG_ERROR",open?"Could not open the local capture window.":"Could not update this user's capture certificate.");
    sbj_free(reply);return ok;
}


static char *response_json(sbj *value) { char *text = sbj_dump(value, -1); sbj_free(value); return text; }
static char *ready_reply(const sbj *id) {
    sbj *result = sbj_object(), *detail = sbj_object();
    sbj_set(result, "id", sbj_clone(id)); sbj_set_int(result, "version", 1);
    sbj_set_bool(result, "ok", true); sbj_set_bool(detail, "ready", true); sbj_set(result, "result", detail);
    return response_json(result);
}
/* HTTP authentication and service process verification are separate checks. */
static char *request_service(const char *body, size_t length, void *user) {
    desktop *app = user; sbw_error error = {0};
    sbj *request = sbw_tray_request(body, length, &error);
    if (!request) return response_json(failure(NULL, error.code, error.message));
    const sbj *id = sbj_get(request, "id"); const char *method = sbj_get_str(request, "method", "");
    char *response = NULL;
    bool local = sb_streq(method, "service.start");
    bool debug = sb_streq(method, "httpdebug.open") || sb_streq(method, "httpdebug.export") ||
        sb_streq(method, "httpdebug.trust") || sb_streq(method, "httpdebug.untrust");
    if (local) {
        if (app->receipt || wcscmp(app->pipe, default_pipe) || sbj_obj_len(sbj_get(request, "params")))
            sbw_fail(&error, "INVALID_REQUEST", "Expected an installed service and empty params.");
        else if (!sbw_service_elevate(app->window, app->cancel, &error)) response = ready_reply(id);
    } else if (debug) {
        if (sbj_obj_len(sbj_get(request, "params"))) sbw_fail(&error, "INVALID_REQUEST", "Expected empty params.");
        else {
            HRESULT com = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
            (void)httpdebug_local(app, request, &response, &error);
            if (SUCCEEDED(com)) CoUninitialize();
        }
    } else {
        int unavailable = 0;
        if (!app->receipt && sb_streq(method, "protocol.hello")) {
            wchar_t *binary = sbw_expected_service_binary();
            sbw_service_start_options options = {app->pipe, binary, NULL, true};
            unavailable = sbw_service_ensure(&options, app->cancel, 12000, NULL, &error); free(binary);
        }
        DWORD timeout = app->receipt ? 3000 : (sb_streq(method, "connection.start") || sb_streq(method, "updates.install") ? 90000 : 35000);
        char *serialized = sbj_dump(request, -1);
        if (!unavailable && !sbw_pipe_request(app->pipe, serialized, app->cancel, timeout, &response, &error)) {
            sbj *answer = sbw_json_parse(response, strlen(response), 32, &error);
            bool valid = sbj_is_object(answer) && sbj_equal(sbj_get(answer, "id"), id) &&
                sbj_is_integer(sbj_get(answer, "version")) && sbj_get_int(answer, "version", 0) == 1 && sbj_is_bool(sbj_get(answer, "ok"));
            if (!valid) { sbw_secret_free(response); response = NULL; sbw_fail(&error, "INVALID_RESPONSE", "Invalid service response."); }
            else if (sb_streq(method, "updates.install") && sbj_get_bool(answer, "ok", false) &&
                sbj_string_is(sbj_get(sbj_get(answer, "result"), "phase"), "installing"))
                PostMessageW(app->window, UPDATE_CLOSE_MESSAGE, 0, 0);
            sbj_free(answer);
        }
        sbw_secret_free(serialized);
    }
    if (!response) response = response_json(failure(id, *error.code ? error.code : "SERVICE_UNAVAILABLE",
        *error.message ? error.message : "Local service is unavailable."));
    sbj_free(request); return response;
}
static void open_web(desktop *app) {
    if (app->url && (INT_PTR)ShellExecuteW(app->window, L"open", app->url, NULL, NULL, SW_SHOWNORMAL) <= 32)
        MessageBoxW(app->window, L"无法打开默认浏览器，请检查浏览器设置。", L"sb-easy", MB_OK | MB_ICONERROR);
}
static void add_tray(desktop *app) {
    NOTIFYICONDATAW icon = {0}; icon.cbSize = sizeof icon; icon.hWnd = app->window; icon.uID = 1;
    icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP; icon.uCallbackMessage = TRAY_MESSAGE;
    icon.hIcon = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_SB_EASY), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED);
    wcscpy_s(icon.szTip, sizeof icon.szTip / sizeof *icon.szTip, L"sb-easy · 本地网页管理");
    app->tray_added = Shell_NotifyIconW(NIM_ADD, &icon) != FALSE; icon.uVersion = NOTIFYICON_VERSION_4;
    if (app->tray_added) Shell_NotifyIconW(NIM_SETVERSION, &icon);
}
static void remove_tray(desktop *app) {
    if (!app->tray_added) return;
    NOTIFYICONDATAW icon = {0}; icon.cbSize = sizeof icon; icon.hWnd = app->window; icon.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &icon); app->tray_added = false;
}
static void tray_action(desktop *app, LPARAM action) {
    if (LOWORD(action) == WM_LBUTTONUP || LOWORD(action) == NIN_SELECT || LOWORD(action) == NIN_KEYSELECT) open_web(app);
    if (LOWORD(action) == WM_RBUTTONUP || LOWORD(action) == WM_CONTEXTMENU) {
        POINT point; GetCursorPos(&point); HMENU menu = CreatePopupMenu(); if (!menu) return;
        AppendMenuW(menu, MF_STRING, COMMAND_OPEN, L"打开网页"); AppendMenuW(menu, MF_STRING, COMMAND_EXPORT, L"导出诊断");
        AppendMenuW(menu, MF_SEPARATOR, 0, NULL); AppendMenuW(menu, MF_STRING, COMMAND_EXIT, L"退出托盘（保留后台服务）");
        SetForegroundWindow(app->window);
        UINT choice = (UINT)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, app->window, NULL);
        DestroyMenu(menu); PostMessageW(app->window, WM_NULL, 0, 0);
        if (choice == COMMAND_OPEN) open_web(app);
        else if (choice == COMMAND_EXIT) DestroyWindow(app->window);
        else if (choice == COMMAND_EXPORT) {
            sbw_error error = {0}; wchar_t *dir = sbw_executable_directory(&error);
            wchar_t *path = dir ? sbw_path_join(dir, L"Export-Diagnostics.cmd") : NULL;
            if (path) ShellExecuteW(app->window, L"open", path, NULL, dir, SW_HIDE);
            free(path); free(dir);
        }
    }
}
static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    desktop *app = current; if (!app) return DefWindowProcW(window, message, wparam, lparam);
    if (taskbar_created && message == taskbar_created) { add_tray(app); return 0; }
    switch (message) {
    case OPEN_MESSAGE: open_web(app); return 0;
    case TRAY_MESSAGE: tray_action(app, lparam); return 0;
    case WM_QUERYENDSESSION: return TRUE;
    case WM_ENDSESSION: if (wparam) DestroyWindow(window); return 0;
    case WM_CLOSE: DestroyWindow(window); return 0;
    case WM_DESTROY: SetEvent(app->cancel); remove_tray(app); PostQuitMessage(0); return 0;
    case UPDATE_CLOSE_MESSAGE: SetTimer(window, UPDATE_TIMER, 700, NULL); return 0;
    case WM_TIMER: if (wparam == UPDATE_TIMER) DestroyWindow(window); return 0;
    default: return DefWindowProcW(window, message, wparam, lparam);
    }
}
static wchar_t *user_sid(void) {
    HANDLE token = NULL; DWORD size = 0; wchar_t *sid = NULL, *result = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = size && size <= 65536 ? sb_xmalloc(size) : NULL;
    if (user && GetTokenInformation(token, TokenUser, user, size, &size) && ConvertSidToStringSidW(user->User.Sid, &sid)) {
        result = wide_copy(sid); LocalFree(sid);
    }
    free(user); CloseHandle(token); return result;
}
static bool arguments(desktop *app) {
    int count = 0; wchar_t **args = CommandLineToArgvW(GetCommandLineW(), &count); bool ok = args != NULL;
    if (args && sbw_tray_arguments(count, (const wchar_t *const *)args, &app->background)) {
        LocalFree(args); return true;
    }
    for (int i = 1; args && i < count && ok; ++i) {
        if (!wcscmp(args[i], L"--background")) app->background = true;
        else if (!wcscmp(args[i], L"--open")) app->background = false;
        else if (!wcscmp(args[i], L"--expect-disconnected")) app->offline = true;
        else if (!wcscmp(args[i], L"--pipe-name") && i + 1 < count) { free(app->pipe); app->pipe = wide_copy(args[++i]); }
        else if (!wcscmp(args[i], L"--smoke-test") && i + 1 < count) { free(app->receipt); app->receipt = wide_copy(args[++i]); }
        else ok = false;
    }
    if (args) LocalFree(args);
    if (!app->receipt) ok = false;
    if ((wcscmp(app->pipe, default_pipe) != 0) != (app->receipt != NULL) || (app->offline && !app->receipt)) ok = false;
    if (wcsncmp(app->pipe, L"\\\\.\\pipe\\", 9) || wcslen(app->pipe) <= 9 ||
        wcslen(app->pipe) > 240 || wcspbrk(app->pipe + 9, L"\\/")) ok = false;
    return ok;
}
static bool unelevated(void) {
    HANDLE token = NULL; TOKEN_ELEVATION elevation = {0}; DWORD bytes = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &bytes) && !elevation.TokenIsElevated;
    CloseHandle(token); return ok;
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show_command) {
    (void)previous; (void)command_line; (void)show_command;
    int helper = sbw_service_start_helper(); if (helper >= 0) return helper;
    desktop app = {0}; app.pipe = wide_copy(default_pipe);
    if (!arguments(&app)) { free(app.pipe); free(app.receipt); return ERROR_INVALID_PARAMETER; }
    /* Headless smoke uses only its explicitly isolated pipe and never opens a
     * browser. This permits CI fixtures; normal HTTP sessions stay unelevated. */
    if (!app.receipt && !unelevated()) {
        MessageBoxW(NULL, L"请以普通用户权限启动 sb-easy 托盘。后台服务会继续运行。", L"sb-easy", MB_OK | MB_ICONERROR);
        free(app.pipe); return ERROR_ELEVATION_REQUIRED;
    }
    wchar_t *sid = user_sid(); if (!sid) { free(app.pipe); free(app.receipt); return ERROR_ACCESS_DENIED; }
    wchar_t mutex_name[256], class_name[256];
    (void)swprintf_s(class_name, 256, L"SbEasyTrayWindow-%ls-%lu", sid, app.receipt ? GetCurrentProcessId() : 0);
    (void)swprintf_s(mutex_name, 256, L"Local\\%ls", class_name); free(sid);
    HANDLE singleton = CreateMutexW(NULL, FALSE, mutex_name);
    if (!singleton) { free(app.pipe); free(app.receipt); return ERROR_ACCESS_DENIED; }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (!app.background) for (unsigned i = 0; i < 20; ++i) {
            HWND existing = FindWindowW(class_name, NULL); if (existing) { PostMessageW(existing, OPEN_MESSAGE, 0, 0); break; } Sleep(50);
        }
        CloseHandle(singleton); free(app.pipe); free(app.receipt); return 0;
    }
    HRESULT com = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED); int result = 1;
    wchar_t *directory = NULL, *assets = NULL; sbw_error error = {0};
    app.cancel = CreateEventW(NULL, TRUE, FALSE, NULL); current = &app; if (!app.cancel) goto done;
    WNDCLASSEXW cls = {0}; cls.cbSize = sizeof cls; cls.lpfnWndProc = window_proc; cls.hInstance = instance; cls.lpszClassName = class_name;
    if (!RegisterClassExW(&cls)) goto done;
    taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    /* Hidden top-level window only, for Explorer restart and session messages. */
    app.window = CreateWindowExW(WS_EX_TOOLWINDOW, class_name, L"sb-easy 托盘", WS_OVERLAPPED, 0, 0, 0, 0, NULL, NULL, instance, NULL);
    if (!app.window) goto done;
    directory = sbw_executable_directory(&error); assets = directory ? sbw_path_join(directory, L"ui") : NULL;
    if (!assets) goto done;
    app.web = sbw_local_web_start(assets, request_service, &app, &error);
    if (!app.web) { if (!app.receipt) MessageBoxW(NULL, L"无法启动本地网页，请检查安装文件和本机网络设置。", L"sb-easy", MB_OK | MB_ICONERROR); goto done; }
    if (app.receipt) { result = sbw_tray_smoke(app.web, app.receipt, app.offline); goto done; }
    app.url = sbw_tray_browser_url(sbw_local_web_port(app.web), sbw_local_web_token(app.web), &error); if (!app.url) goto done;
    add_tray(&app);
    if (!app.tray_added) { MessageBoxW(NULL, L"无法添加系统托盘图标，请重启资源管理器后重试。", L"sb-easy", MB_OK | MB_ICONERROR); goto done; }
    if (!app.background) open_web(&app);
    MSG message; BOOL next;
    while ((next = GetMessageW(&message, NULL, 0, 0)) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
    result = next < 0 ? 1 : 0;
done:
    if (app.cancel) SetEvent(app.cancel);
    if (app.web) sbw_local_web_stop(app.web);
    remove_tray(&app); if (app.window && IsWindow(app.window)) DestroyWindow(app.window);
    if (app.url) { SecureZeroMemory(app.url, wcslen(app.url) * sizeof *app.url); free(app.url); }
    if (app.cancel) CloseHandle(app.cancel);
    free(directory); free(assets); free(app.pipe); free(app.receipt); current = NULL;
    if (SUCCEEDED(com)) CoUninitialize();
    CloseHandle(singleton); return result;
}
