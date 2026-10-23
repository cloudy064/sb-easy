#include "extension_store.h"
#include "extensions.h"
#include "store_catalog.h"
#include "plugin_storage.h"
#include "plugin_catalog.h"
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The catalog and release digest ship with the trusted client. Neither RPC nor
 * the download server can nominate executable code, paths or a new digest. */
static SRWLOCK lock=SRWLOCK_INIT;
static SRWLOCK storage_lock=SRWLOCK_INIT;
static sbj *download_release;
static unsigned char *pending_bytes;
static size_t pending_length;
static HANDLE thread;
static LONG stopping;
static bool busy;
static const char *phase="idle";
static size_t received;
static sbw_error failure;
static const sbw_extension_release *active_release;
const sbw_extension_release *sbw_extension_releases(size_t *count){*count=sizeof(releases)/sizeof(releases[0]);return releases;}
const sbw_extension_release *sbw_extension_release_find(const char *id){for(size_t i=0;i<sizeof(releases)/sizeof(releases[0]);++i)if(sb_streq(id,releases[i].id))return &releases[i];return NULL;}
static const wchar_t *dirs[]={L"extension",L"extension\\capture",L"extension\\licenses",L"view"};
static void progress(const char *value,size_t bytes) {
    AcquireSRWLockExclusive(&lock);phase=value;received=bytes;ReleaseSRWLockExclusive(&lock);
}
bool sbw_store_busy(void) {AcquireSRWLockShared(&lock);bool value=busy;ReleaseSRWLockShared(&lock);return value;}
sbj *sbw_store_progress(void) {
    sbj *result=sbj_object();AcquireSRWLockShared(&lock);
    sbj_set_str(result,"phase",phase);sbj_set_int(result,"received",(int64_t)received);sbj_set_int(result,"total",download_release?sbj_get_int(download_release,"bytes",0):0);sbj_set_str(result,"id",active_release?active_release->id:"");
    sbj_set_str(result,"error",failure.code);ReleaseSRWLockShared(&lock);return result;
}
static sbw_plugin_storage *open_storage(sbw_error *error) {
    wchar_t *root=sbw_executable_directory(error);sbw_plugin_storage *s=root?sbw_plugin_storage_open(root,error):NULL;free(root);return s;
}
sbj *sbw_store_status(const char *id) {
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *s=open_storage(NULL);
    sbj *out=s?sbw_plugin_storage_status(s,id):sbj_object();sbw_plugin_storage_close(s);ReleaseSRWLockExclusive(&storage_lock);return out;
}
bool sbw_store_verified(const char *id,sbw_error *error) {
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *s=open_storage(error);
    bool ok=s&&sbw_plugin_storage_verified(s,id,error);sbw_plugin_storage_close(s);ReleaseSRWLockExclusive(&storage_lock);return ok;
}
bool sbw_store_allowed(const char *id,sbw_error *error) {
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *s=open_storage(error);
    bool ok=s&&sbw_plugin_storage_allowed(s,id,error);sbw_plugin_storage_close(s);ReleaseSRWLockExclusive(&storage_lock);return ok;
}
sbj *sbw_store_catalog(void) {
    sbj *result=sbj_object(),*items=sbj_array();AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *storage=open_storage(NULL);
    bool fresh=false;int64_t sequence=0;
    for(size_t i=0;i<sizeof(releases)/sizeof(releases[0]);++i){const sbw_extension_release *r=&releases[i];
        sbj *state=storage?sbw_plugin_storage_status(storage,r->id):sbj_object();
        if(sb_streq(r->id,"network-tools")&&!sbj_get_bool(state,"verified",false)){sbj_free(state);continue;}
        const sbj *release=sbj_get(state,"release");sbj *item=sbj_object();
        sbj_set_str(item,"id",r->id);sbj_set_str(item,"name",r->name);sbj_set_str(item,"version",release?sbj_get_str(release,"version",""):"1.0.0");
        sbj_set_int(item,"size",release?sbj_get_int(release,"bytes",0):(int64_t)r->bytes);sbj_set_str(item,"publisher","sb-easy");
        sbj_set_str(item,"description",r->description);sbj_set_str(item,"permissions",r->permissions);
        const char *fields[]={"verified","revoked","build","update_available","rollback_available","pending_health","catalog_fresh"};
        for(size_t j=0;j<sizeof fields/sizeof *fields;++j)if(sbj_has(state,fields[j]))sbj_set(item,fields[j],sbj_clone(sbj_get(state,fields[j])));
        sbj_set_bool(item,"install_available",release!=NULL);sbj_set_str(item,"installed_version",sbj_get_str(state,"version",""));
        if(release)sbj_set_int(item,"available_build",sbj_get_int(release,"build",0));
        fresh=fresh||sbj_get_bool(state,"catalog_fresh",false);sequence=sbj_get_int(state,"sequence",sequence);
        sbj_free(state);sbj_arr_push(items,item);
    }
    sbw_plugin_storage_close(storage);ReleaseSRWLockExclusive(&storage_lock);sbj_set(result,"items",items);
    sbj_set_bool(result,"trust_configured",sbw_plugin_catalog_has_trust());sbj_set_bool(result,"catalog_fresh",fresh);sbj_set_int(result,"sequence",sequence);return result;
}
int sbw_store_catalog_update(const char *envelope,size_t length,sbw_error *error) {
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *s=open_storage(error);int result=s?sbw_plugin_storage_catalog(s,envelope,length,error):-1;
    sbw_plugin_storage_close(s);ReleaseSRWLockExclusive(&storage_lock);return result;
}
int sbw_store_rollback(const char *id,sbw_error *error) {
    if(sbw_store_busy())return sbw_fail(error,"BUSY","A plugin update is in progress.");
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *s=open_storage(error);int result=s?sbw_plugin_storage_rollback(s,id,error):-1;
    sbw_plugin_storage_close(s);ReleaseSRWLockExclusive(&storage_lock);return result;
}
int sbw_store_confirm(const char *id,sbw_error *error) {
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *s=open_storage(error);int result=s?sbw_plugin_storage_confirm(s,id,error):-1;
    sbw_plugin_storage_close(s);ReleaseSRWLockExclusive(&storage_lock);return result;
}

static bool directory(const wchar_t *path) {
    if(!CreateDirectoryW(path,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS)return false;
    DWORD a=GetFileAttributesW(path);return a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_DIRECTORY)&&!(a&FILE_ATTRIBUTE_REPARSE_POINT);
}
static bool safe_root(const wchar_t *root) {
    wchar_t full[32768];DWORD n=GetFullPathNameW(root,32768,full,NULL);
    if(!n||n>=32768||n<3||full[1]!=L':')return false;
    for(DWORD i=3;i<=n;++i)if(full[i]==L'\\'||full[i]==0) {
        wchar_t saved=full[i];full[i]=0;DWORD a=GetFileAttributesW(full);full[i]=saved;
        if(a==INVALID_FILE_ATTRIBUTES||!(a&FILE_ATTRIBUTE_DIRECTORY)||(a&FILE_ATTRIBUTE_REPARSE_POINT))return false;
    }
    return true;
}
static bool make_child(const wchar_t *root,const wchar_t *name) {wchar_t *p=sbw_path_join(root,name);bool ok=directory(p);free(p);return ok;}
static void clean_stage(const sbw_extension_release *release,const wchar_t *stage) {
    for(size_t i=0;i<release->file_count;++i){wchar_t *p=sbw_path_join(stage,release->files[i]);DeleteFileW(p);free(p);}
    for(size_t i=sizeof(dirs)/sizeof(dirs[0]);i>0;--i){wchar_t *p=sbw_path_join(stage,dirs[i-1]);RemoveDirectoryW(p);free(p);}
    RemoveDirectoryW(stage);
}
int sbw_store_publish(const char *id,const wchar_t *root,const void *bytes,size_t length,sbw_error *error) {
    const sbw_extension_release *release=sbw_extension_release_find(id);
    if(!release)return sbw_fail(error,"INVALID_REQUEST","Unknown extension.");
    unsigned char hash[32]={0};BCRYPT_ALG_HANDLE algorithm=NULL;char hex[65];
    if(length!=release->bytes||length>128U*1024U*1024U||memcmp(bytes,"SBECP001",8))
        return sbw_fail(error,"STORE_INTEGRITY","The extension package is incomplete or invalid.");
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)
        return sbw_fail(error,"STORE_INTEGRITY","Package verification is unavailable.");
    NTSTATUS status=BCryptHash(algorithm,NULL,0,(PUCHAR)bytes,(ULONG)length,hash,sizeof hash);BCryptCloseAlgorithmProvider(algorithm,0);
    for(size_t i=0;i<32;++i)sprintf_s(hex+i*2,3,"%02x",hash[i]);
    if(status<0||strcmp(hex,release->sha256))return sbw_fail(error,"STORE_INTEGRITY","The package does not match the trusted release.");
    const unsigned char *data=bytes;size_t offset=8,starts[10];DWORD sizes[10];
    for(size_t i=0;i<release->file_count;++i) {
        if(offset+4>length)goto malformed;
        memcpy(&sizes[i],data+offset,4);offset+=4;starts[i]=offset;
        if(!sizes[i]||sizes[i]>length-offset)goto malformed;offset+=sizes[i];
    }
    if(offset!=length)goto malformed;
    if(!safe_root(root)||!make_child(root,L"extensions")||!make_child(root,L"ui")||!make_child(root,L"ui\\extensions"))
        return sbw_fail(error,"STORE_STORAGE","The installation folder is not writable or safe.");
    wchar_t name[96];swprintf_s(name,96,L".store-capture-%lu-%llu",GetCurrentProcessId(),GetTickCount64());
    wchar_t relative[128];swprintf_s(relative,128,L"extensions\\%S",id);
    wchar_t *stage=sbw_path_join(root,name),*dest=sbw_path_join(root,relative);
    swprintf_s(relative,128,L"ui\\extensions\\%S",id);wchar_t *view=sbw_path_join(root,relative);
    wchar_t *source=sbw_path_join(stage,L"extension"),*source_view=sbw_path_join(stage,L"view");
    int result=-1;bool owned=false,view_moved=false;
    if(GetFileAttributesW(dest)!=INVALID_FILE_ATTRIBUTES||GetFileAttributesW(view)!=INVALID_FILE_ATTRIBUTES) {
        sbw_fail(error,"STORE_EXISTS","The extension is already installed or its destination is occupied.");goto done;
    }
    if(!CreateDirectoryW(stage,NULL))goto storage;owned=true;
    for(size_t i=0;i<sizeof(dirs)/sizeof(dirs[0]);++i)if(!make_child(stage,dirs[i]))goto storage;
    for(size_t i=0;i<release->file_count;++i) {
        wchar_t *path=sbw_path_join(stage,release->files[i]);HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);free(path);
        if(file==INVALID_HANDLE_VALUE)goto storage;
        DWORD written=0;bool ok=WriteFile(file,data+starts[i],sizes[i],&written,NULL)&&written==sizes[i]&&FlushFileBuffers(file);CloseHandle(file);
        if(!ok)goto storage;
    }
    /* Publish UI first and the complete executable directory last. Until the
     * final rename succeeds, discovery cannot observe an installed extension. */
    if(!MoveFileExW(source_view,view,MOVEFILE_WRITE_THROUGH))goto storage;view_moved=true;
    if(!MoveFileExW(source,dest,MOVEFILE_WRITE_THROUGH))goto storage;
    result=0;goto done;
storage:
    if(view_moved&&!MoveFileExW(view,source_view,MOVEFILE_WRITE_THROUGH)) {
        /* Only our two known files can be present here; never recursive-delete. */
        const wchar_t *ui_files[]={L"view.js",L"view.css"};
        for(size_t i=0;i<2;++i){wchar_t *p=sbw_path_join(view,ui_files[i]);DeleteFileW(p);free(p);}RemoveDirectoryW(view);
    }
    sbw_fail(error,"STORE_STORAGE","Installation failed; the extension was not enabled. Retry after checking disk space and permissions.");
done:
    if(owned)clean_stage(release,stage);free(stage);free(dest);free(view);free(source);free(source_view);return result;
malformed:return sbw_fail(error,"STORE_INTEGRITY","The extension package layout is invalid.");
}
static DWORD WINAPI install_worker(void *context) {
    (void)context;sbw_error error={0};HINTERNET session=NULL,connection=NULL,request=NULL;unsigned char *bytes=NULL;size_t length=0;bool ok=false;
    const char *id=active_release->id;size_t expected=(size_t)sbj_get_int(download_release,"bytes",0);
    wchar_t *address=sbw_wide(sbj_get_str(download_release,"url",""),&error),host[256],path[4096];URL_COMPONENTS url={0};url.dwStructSize=sizeof url;url.lpszHostName=host;url.dwHostNameLength=256;url.lpszUrlPath=path;url.dwUrlPathLength=4096;url.dwExtraInfoLength=(DWORD)-1;
    if(!address||!WinHttpCrackUrl(address,0,0,&url)||url.nScheme!=INTERNET_SCHEME_HTTPS||!expected||expected>160U*1024U*1024U)goto done;
    wchar_t target[8192];if(url.dwUrlPathLength+url.dwExtraInfoLength>=8192)goto done;memcpy(target,path,url.dwUrlPathLength*sizeof(wchar_t));if(url.dwExtraInfoLength)memcpy(target+url.dwUrlPathLength,url.lpszExtraInfo,url.dwExtraInfoLength*sizeof(wchar_t));target[url.dwUrlPathLength+url.dwExtraInfoLength]=0;
    session=WinHttpOpen(L"sb-easy extension store/2",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);if(!session)goto done;
    WinHttpSetTimeouts(session,5000,5000,5000,20000);
    connection=WinHttpConnect(session,host,url.nPort,0);if(!connection)goto done;
    request=WinHttpOpenRequest(connection,L"GET",target,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);if(!request)goto done;
    DWORD disabled=WINHTTP_DISABLE_AUTHENTICATION|WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_REDIRECTS;
    if(!WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof disabled))goto done;
    DWORD autologon=WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;if(!WinHttpSetOption(request,WINHTTP_OPTION_AUTOLOGON_POLICY,&autologon,sizeof autologon))goto done;
    if(!WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0)||!WinHttpReceiveResponse(request,NULL))goto done;
    DWORD code=0,size=sizeof code;
    if(!WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&code,&size,WINHTTP_NO_HEADER_INDEX)||code!=200)goto done;
    bytes=sb_xcalloc(expected+1,1);ULONGLONG deadline=GetTickCount64()+(expected>16U*1024U*1024U?300000:60000);
    for(;;) {
        DWORD count=0;
        if(InterlockedCompareExchange(&stopping,0,0)||GetTickCount64()>deadline)goto done;
        if(!WinHttpReadData(request,bytes+length,(DWORD)((expected+1-length)>16384?16384:expected+1-length),&count))goto done;
        if(!count)break;length+=count;progress("downloading",length);
        if(length>expected){sbw_fail(&error,"STORE_INTEGRITY","Package exceeds the trusted release size.");goto done;}
    }
    progress("verifying",length);
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *storage=open_storage(&error);ok=storage&&!sbw_plugin_storage_check_package(storage,id,bytes,length,&error);sbw_plugin_storage_close(storage);ReleaseSRWLockExclusive(&storage_lock);
 done:
    free(address);if(request)WinHttpCloseHandle(request);if(connection)WinHttpCloseHandle(connection);if(session)WinHttpCloseHandle(session);
    if(!ok&&!error.code[0])sbw_fail(&error,"STORE_DOWNLOAD","Could not download the signed plugin release. Check your connection and retry.");
    AcquireSRWLockExclusive(&lock);failure=error;
    if(ok&&!InterlockedCompareExchange(&stopping,0,0)){pending_bytes=bytes;pending_length=length;bytes=NULL;phase="ready";}
    else {phase="failed";busy=false;}
    ReleaseSRWLockExclusive(&lock);free(bytes);return 0;
}
int sbw_store_install(const char *id,sbw_error *error) {
    const sbw_extension_release *release=sbw_extension_release_find(id);if(!release)return sbw_fail(error,"INVALID_REQUEST","Unknown extension.");
    AcquireSRWLockExclusive(&lock);
    if(busy){ReleaseSRWLockExclusive(&lock);return sbw_fail(error,"BUSY","A plugin update is in progress.");}
    if(thread){WaitForSingleObject(thread,INFINITE);CloseHandle(thread);thread=NULL;}
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *storage=open_storage(error);sbj *signed_release=storage?sbw_plugin_storage_release(storage,id,error):NULL;sbw_plugin_storage_close(storage);ReleaseSRWLockExclusive(&storage_lock);
    if(!signed_release){ReleaseSRWLockExclusive(&lock);return -1;}
    sbj_free(download_release);download_release=signed_release;free(pending_bytes);pending_bytes=NULL;pending_length=0;
    active_release=release;memset(&failure,0,sizeof failure);received=0;phase="downloading";busy=true;InterlockedExchange(&stopping,0);
    thread=CreateThread(NULL,0,install_worker,NULL,0,NULL);
    if(!thread){busy=false;phase="failed";sbw_fail(&failure,"STORE_STORAGE","Could not start installer.");if(error)*error=failure;}
    bool started=thread!=NULL;ReleaseSRWLockExclusive(&lock);return started?0:-1;
}
bool sbw_store_ready(void){AcquireSRWLockShared(&lock);bool ready=busy&&pending_bytes&&sb_streq(phase,"ready");ReleaseSRWLockShared(&lock);return ready;}
const char *sbw_store_pending_id(void){AcquireSRWLockShared(&lock);const char *id=busy&&pending_bytes&&active_release?active_release->id:NULL;ReleaseSRWLockShared(&lock);return id;}
int sbw_store_commit(sbw_error *error){
    AcquireSRWLockExclusive(&lock);if(!busy||!pending_bytes||!sb_streq(phase,"ready")){ReleaseSRWLockExclusive(&lock);return sbw_fail(error,"BUSY","No verified plugin update is ready.");}
    phase="installing";const char *id=active_release->id;unsigned char *data=pending_bytes;size_t length=pending_length;pending_bytes=NULL;pending_length=0;ReleaseSRWLockExclusive(&lock);
    AcquireSRWLockExclusive(&storage_lock);sbw_plugin_storage *storage=open_storage(error);int result=storage?sbw_plugin_storage_publish(storage,id,data,length,error):-1;sbw_plugin_storage_close(storage);ReleaseSRWLockExclusive(&storage_lock);free(data);
    AcquireSRWLockExclusive(&lock);busy=false;phase=result?"failed":"complete";if(result&&error)failure=*error;ReleaseSRWLockExclusive(&lock);return result;
}
void sbw_store_abort(const sbw_error *error){
    AcquireSRWLockExclusive(&lock);
    if(busy&&pending_bytes&&sb_streq(phase,"ready")){free(pending_bytes);pending_bytes=NULL;pending_length=0;busy=false;phase="failed";
        if(error&&error->code[0])failure=*error;else sbw_fail(&failure,"STORE_ACTIVATION","The current plugin could not be safely stopped; the verified update was discarded.");}
    ReleaseSRWLockExclusive(&lock);
}
void sbw_store_join(void) {
    InterlockedExchange(&stopping,1);
    if(thread){WaitForSingleObject(thread,INFINITE);CloseHandle(thread);thread=NULL;}
    AcquireSRWLockExclusive(&lock);free(pending_bytes);pending_bytes=NULL;pending_length=0;sbj_free(download_release);download_release=NULL;busy=false;ReleaseSRWLockExclusive(&lock);
}
