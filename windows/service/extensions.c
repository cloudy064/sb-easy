#include "extensions.h"
#include "extension_store.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

wchar_t *sbw_extension_path(const wchar_t *relative) {
    wchar_t *base=sbw_executable_directory(NULL),*path=base?sbw_path_join(base,relative):NULL;free(base);return path;
}

static wchar_t *location(const char *id,const wchar_t *suffix,bool ui) {
    if(!sbw_extension_release_find(id))return NULL;
    wchar_t relative[256];swprintf_s(relative,256,L"%sextensions\\%S%s",ui?L"ui\\":L"",id,suffix);
    return sbw_extension_path(relative);
}
static bool exists(const wchar_t *path) {
    DWORD a=path?GetFileAttributesW(path):INVALID_FILE_ATTRIBUTES;
    return a!=INVALID_FILE_ATTRIBUTES&&!(a&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT));
}
bool sbw_extension_installed(const char *id) {
    const sbw_extension_release *release=sbw_extension_release_find(id);if(!release)return false;
    wchar_t *path=location(id,L"\\extension.json",false);
    HANDLE f=path?CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL):INVALID_HANDLE_VALUE;free(path);
    if(f==INVALID_HANDLE_VALUE)return false;
    char data[2049];DWORD n=0;LARGE_INTEGER size;FILE_ATTRIBUTE_TAG_INFO info;
    bool ok=GetFileSizeEx(f,&size)&&size.QuadPart>0&&size.QuadPart<=2048&&GetFileInformationByHandleEx(f,FileAttributeTagInfo,&info,sizeof info)&&!(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)&&ReadFile(f,data,2048,&n,NULL);CloseHandle(f);
    sbj *manifest=ok?sbw_json_parse(data,n,8,NULL):NULL;
    ok=sbj_string_is(sbj_get(manifest,"id"),id)&&sbj_get_int(manifest,"api_version",0)==1&&sbj_string_is(sbj_get(manifest,"version"),"1.0.0");sbj_free(manifest);
    for(size_t i=0;ok&&i<release->file_count;++i){bool ui=!wcsncmp(release->files[i],L"view",4);path=location(id,release->files[i]+(ui?4:9),ui);ok=exists(path);free(path);}
    return ok;
}
bool sbw_extension_is_enabled(const char *id) {wchar_t *p=location(id,L"\\enabled",false);bool ok=sbw_extension_installed(id)&&exists(p);free(p);return ok;}
bool sbw_extension_enabled(void){return sbw_extension_is_enabled("capture");}
sbj *sbw_extensions_snapshot(sbw_capture *capture,bool statistics_running,bool statistics_failed) {
    sbj *result=sbj_object(),*list=sbj_array();size_t count;const sbw_extension_release *releases=sbw_extension_releases(&count);
    for(size_t i=0;i<count;++i){const char *id=releases[i].id;sbj *item=sbj_object();bool present=sbw_extension_installed(id),enabled=sbw_extension_is_enabled(id);
        bool running=sb_streq(id,"capture")?sbw_capture_worker_running(capture):sb_streq(id,"statistics")?statistics_running:false;
        bool failed=sb_streq(id,"capture")?(capture&&!running):sb_streq(id,"statistics")?statistics_failed:false;
        sbj_set_str(item,"id",id);sbj_set_str(item,"name",releases[i].name);sbj_set_str(item,"version",present?"1.0.0":"");
        sbj_set_bool(item,"installed",present);sbj_set_bool(item,"enabled",enabled);sbj_set_bool(item,"running",running);sbj_set_bool(item,"failed",enabled&&failed);sbj_arr_push(list,item);
    }sbj_set(result,"extensions",list);return result;
}
int sbw_extension_change(const char *id,const char *action,sbw_error *error) {
    if(!sbw_extension_installed(id))return sbw_fail(error,"EXTENSION_MISSING","Install the compatible official extension first.");
    wchar_t *marker=location(id,L"\\enabled",false);int result=0;
    if(sb_streq(action,"enable")) {HANDLE f=CreateFileW(marker,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);if(f==INVALID_HANDLE_VALUE)result=-1;else CloseHandle(f);}
    else if(!DeleteFileW(marker)&&GetLastError()!=ERROR_FILE_NOT_FOUND)result=-1;
    free(marker);if(result)return sbw_fail(error,"EXTENSION_STORAGE","Could not save extension state.");
    if(sb_streq(action,"remove")) {
        wchar_t suffix[128];swprintf_s(suffix,128,L"-removed-%llu",GetTickCount64());
        wchar_t *from=location(id,L"",false),*to=location(id,suffix,false),*ui=location(id,L"",true),*ui_to=location(id,suffix,true);
        /* Roll back the first rename if the second one fails. Data is retained. */
        if(!MoveFileW(ui,ui_to))result=-1;
        else if(!MoveFileW(from,to)){MoveFileW(ui_to,ui);result=-1;}
        free(from);free(to);free(ui);free(ui_to);
        if(result)return sbw_fail(error,"EXTENSION_STORAGE","Extension is disabled; retiring its files failed. Close its page and retry.");
    }return 0;
}
