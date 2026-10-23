#include "plugin_storage.h"
#include "plugin_catalog.h"
#include "extension_store.h"
#include "secure_store.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>

#ifndef SB_EASY_VERSION_MAJOR
#define SB_EASY_VERSION_MAJOR 0
#define SB_EASY_VERSION_MINOR 6
#define SB_EASY_VERSION_PATCH 9
#endif
#ifndef SB_EASY_CORE_VERSION
#define SB_EASY_CORE_VERSION "1.14.3"
#endif
#define PACKAGE_MAX (160U * 1024U * 1024U)
struct sbw_plugin_storage { wchar_t *root,*private_root; sbw_store *store; sbj *state; };
typedef struct package_layout { const unsigned char *data; size_t length,offsets[10]; DWORD sizes[10]; } package_layout;
static int bad(sbw_error *e){return sbw_fail(e,"STORE_INTEGRITY","The plugin package or installed files do not match a trusted release.");}
static int io(sbw_error *e){return sbw_fail(e,"STORE_STORAGE","Plugin storage could not be safely updated; the previous version is retained.");}
static int64_t now_seconds(void){FILETIME t;ULARGE_INTEGER n;GetSystemTimeAsFileTime(&t);n.LowPart=t.dwLowDateTime;n.HighPart=t.dwHighDateTime;return (int64_t)(n.QuadPart/10000000-11644473600ULL);}
static int64_t os_build(void){typedef LONG (WINAPI *version_fn)(PRTL_OSVERSIONINFOW);version_fn fn=(version_fn)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion");RTL_OSVERSIONINFOW v={0};v.dwOSVersionInfoSize=sizeof v;return fn&&fn(&v)==0?v.dwBuildNumber:0;}
static bool hash_bytes(const void *bytes,size_t length,char result[65]){
    BCRYPT_ALG_HANDLE a=NULL;unsigned char digest[32];if(length>PACKAGE_MAX||BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)return false;
    NTSTATUS status=BCryptHash(a,NULL,0,(PUCHAR)bytes,(ULONG)length,digest,sizeof digest);BCryptCloseAlgorithmProvider(a,0);
    if(status<0)return false;for(size_t i=0;i<32;++i)sprintf_s(result+2*i,3,"%02x",digest[i]);return true;
}
static bool directory(const wchar_t *p){DWORD a=GetFileAttributesW(p);return a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_DIRECTORY)&&!(a&FILE_ATTRIBUTE_REPARSE_POINT);}
static bool create_directory(const wchar_t *p){return (CreateDirectoryW(p,NULL)||GetLastError()==ERROR_ALREADY_EXISTS)&&directory(p);}
static bool present(const wchar_t *p){return GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static bool safe_root(const wchar_t *p){
    wchar_t full[32768];DWORD n=GetFullPathNameW(p,32768,full,NULL);if(!n||n>=32768||n<4||full[1]!=L':'||full[2]!=L'\\')return false;
    for(DWORD i=3;i<=n;++i)if(full[i]==L'\\'||!full[i]){wchar_t c=full[i];full[i]=0;bool ok=directory(full);full[i]=c;if(!ok)return false;}return true;
}
static wchar_t *location(const sbw_plugin_storage *s,const char *id,bool ui){wchar_t suffix[128];swprintf_s(suffix,128,L"%sextensions\\%S",ui?L"ui\\":L"",id);return sbw_path_join(s->root,suffix);}
static wchar_t *private_path(const sbw_plugin_storage *s,const wchar_t *name){return sbw_path_join(s->private_root,name);}
static unsigned char *read_file(const wchar_t *path,size_t maximum,size_t *length){
    *length=0;HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(f==INVALID_HANDLE_VALUE)return NULL;
    LARGE_INTEGER size;FILE_ATTRIBUTE_TAG_INFO info;unsigned char *data=NULL;DWORD got=0;
    if(!GetFileInformationByHandleEx(f,FileAttributeTagInfo,&info,sizeof info)||(info.FileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||!GetFileSizeEx(f,&size)||size.QuadPart<1||(uint64_t)size.QuadPart>maximum)goto done;
    data=sb_xmalloc((size_t)size.QuadPart+1);if(!ReadFile(f,data,(DWORD)size.QuadPart,&got,NULL)||got!=(DWORD)size.QuadPart){free(data);data=NULL;}else{*length=got;data[got]=0;}
done:CloseHandle(f);return data;
}
static bool write_new(const wchar_t *p,const void *data,size_t n){HANDLE f=CreateFileW(p,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,NULL);if(f==INVALID_HANDLE_VALUE)return false;DWORD wrote=0;bool ok=n<=MAXDWORD&&WriteFile(f,data,(DWORD)n,&wrote,NULL)&&wrote==n&&FlushFileBuffers(f);CloseHandle(f);if(!ok)DeleteFileW(p);return ok;}
static int save(sbw_plugin_storage *s,sbw_error *e){return s->store->save(s->store->context,s->state,e);}
static sbj *records(sbw_plugin_storage *s){return sbj_get(s->state,"installed");}
static sbj *record(sbw_plugin_storage *s,const char *id){return sbj_get(records(s),id);}
static sbj *verify_envelope(const sbj *receipt,bool expired,sbw_error *e){
    const sbj *env=sbj_get(receipt,"envelope");if(!sbw_json_string(env,1024U*1024U,false)){bad(e);return NULL;}
    return sbw_plugin_catalog_verify_trusted(env->v.str.ptr,env->v.str.len,now_seconds(),expired,NULL,e);
}
static sbj *receipt_release(sbw_plugin_storage *s,const char *id,const sbj *receipt,bool expired,sbw_error *e){
    if(sbj_get_bool(receipt,"legacy",false)){
        const sbw_extension_release *known=sbw_extension_release_find(id);
        if(!known||sbj_get_int(receipt,"build",0)!=1||!sbj_string_is(sbj_get(receipt,"sha256"),known->sha256)||sbw_plugin_catalog_revoked(sbj_get(s->state,"accepted"),id,"windows",1)){bad(e);return NULL;}
        sbj *r=sbj_object();sbj_set_str(r,"id",id);sbj_set_str(r,"version","1.0.0");sbj_set_str(r,"sha256",known->sha256);sbj_set_int(r,"bytes",(int64_t)known->bytes);sbj_set_int(r,"build",1);return r;
    }
    sbj *payload=verify_envelope(receipt,expired,e);if(!payload)return NULL;
    const sbj *r=sbw_plugin_catalog_release(payload,id,"windows","x86_64",sbj_get_int(receipt,"build",0));
    char host[48];sprintf_s(host,sizeof host,"%d.%d.%d",SB_EASY_VERSION_MAJOR,SB_EASY_VERSION_MINOR,SB_EASY_VERSION_PATCH);
    bool ok=r&&sbj_string_is(sbj_get(r,"sha256"),sbj_get_str(receipt,"sha256",""))&&!sbw_plugin_catalog_compatible(r,host,SB_EASY_CORE_VERSION,os_build(),e)&&!sbw_plugin_catalog_revoked(sbj_get(s->state,"accepted"),id,"windows",sbj_get_int(r,"build",0));
    sbj *out=ok?sbj_clone(r):NULL;sbj_free(payload);if(!out&&!e)bad(e);else if(!out&&e&&!e->code[0])sbw_fail(e,"PLUGIN_REVOKED","This plugin release is revoked or no longer compatible.");return out;
}
static int inspect_package(const char *id,const void *bytes,size_t length,const char *sha,size_t expected,const char *version,int64_t build,package_layout *layout,sbw_error *e){
    const sbw_extension_release *known=sbw_extension_release_find(id);char actual[65];if(!known||length<8||length!=expected||length>PACKAGE_MAX||memcmp(bytes,"SBECP001",8)||!hash_bytes(bytes,length,actual)||strcmp(actual,sha))return bad(e);
    memset(layout,0,sizeof *layout);layout->data=bytes;layout->length=length;size_t offset=8;
    for(size_t i=0;i<known->file_count;++i){if(length-offset<4)return bad(e);DWORD n;memcpy(&n,(const unsigned char*)bytes+offset,4);offset+=4;if(!n||n>length-offset)return bad(e);layout->offsets[i]=offset;layout->sizes[i]=n;offset+=n;}
    if(offset!=length||layout->sizes[0]>4096)return bad(e);
    sbj *manifest=sbj_parse_strict((const char*)bytes+layout->offsets[0],layout->sizes[0],NULL,0);
    bool ok=sbj_string_is(sbj_get(manifest,"id"),id)&&sbj_string_is(sbj_get(manifest,"version"),version)&&sbj_get_int(manifest,"api_version",0)==1;
    if(build>1)ok=ok&&sbj_get_int(manifest,"build",0)==build;
    sbj_free(manifest);return ok?0:bad(e);
}
static wchar_t *cache_path(sbw_plugin_storage *s,const char *hash){if(strlen(hash)!=64||strspn(hash,"0123456789abcdef")!=64)return NULL;wchar_t name[80];swprintf_s(name,80,L"%S.sbe",hash);return private_path(s,name);}
static bool cached_package(sbw_plugin_storage *s,const char *hash,const void *data,size_t length){
    wchar_t *p=cache_path(s,hash);if(!p)return false;bool ok=write_new(p,data,length);
    if(!ok){size_t n=0;unsigned char *previous=read_file(p,PACKAGE_MAX,&n);ok=previous&&n==length&&!memcmp(previous,data,n);free(previous);}free(p);return ok;
}
static void prune_cache(sbw_plugin_storage *s){
    wchar_t *pattern=private_path(s,L"*.sbe");WIN32_FIND_DATAW entry;HANDLE scan=FindFirstFileW(pattern,&entry);free(pattern);if(scan==INVALID_HANDLE_VALUE)return;
    do{if(entry.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)||wcslen(entry.cFileName)!=68)continue;
        char hash[65];bool valid=true;for(size_t i=0;i<64;++i){wchar_t c=entry.cFileName[i];if(!((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f')))valid=false;hash[i]=(char)c;}hash[64]=0;if(!valid)continue;
        bool keep=false;size_t count=0;const sbw_extension_release *known=sbw_extension_releases(&count);
        for(size_t i=0;i<count;++i){const sbj *r=record(s,known[i].id);const char *slots[]={"active","previous"};for(size_t j=0;j<2;++j)if(sbj_string_is(sbj_get(sbj_get(r,slots[j]),"sha256"),hash))keep=true;}
        if(!keep){wchar_t *p=private_path(s,entry.cFileName);DeleteFileW(p);free(p);}
    }while(FindNextFileW(scan,&entry));FindClose(scan);
}
static bool clean_directory(const sbw_extension_release *known,const wchar_t *root,bool ui){
    if(!present(root))return true;if(!directory(root))return false;bool ok=true;
    if(!ui){const wchar_t *dirs[]={L"capture",L"licenses"};for(size_t i=0;i<2;++i){wchar_t *p=sbw_path_join(root,dirs[i]);bool safe=!present(p)||directory(p);free(p);if(!safe)return false;}}
    for(size_t i=0;i<known->file_count;++i){bool view=!wcsncmp(known->files[i],L"view\\",5);if(view!=ui)continue;wchar_t *p=sbw_path_join(root,known->files[i]+(view?5:10));if(!DeleteFileW(p)&&GetLastError()!=ERROR_FILE_NOT_FOUND&&GetLastError()!=ERROR_PATH_NOT_FOUND)ok=false;free(p);}
    if(!ui){wchar_t *p=sbw_path_join(root,L"enabled");if(!DeleteFileW(p)&&GetLastError()!=ERROR_FILE_NOT_FOUND)ok=false;free(p);const wchar_t *dirs[]={L"capture",L"licenses"};for(size_t i=0;i<2;++i){p=sbw_path_join(root,dirs[i]);if(!RemoveDirectoryW(p)&&GetLastError()!=ERROR_FILE_NOT_FOUND&&GetLastError()!=ERROR_PATH_NOT_FOUND)ok=false;free(p);}}
    return RemoveDirectoryW(root)&&ok;
}
static int recover(sbw_plugin_storage *s,sbw_error *e){
    const sbj *pending=sbj_get(s->state,"pending");if(!pending)return 0;
    const char *id=sbj_get_str(pending,"id","");const sbw_extension_release *known=sbw_extension_release_find(id);if(!known)return bad(e);
    wchar_t *dest=location(s,id,false),*view=location(s,id,true),*old=private_path(s,L"old"),*oldview=private_path(s,L"old-view"),*stage=private_path(s,L"new"),*stageview=private_path(s,L"new-view");bool ok=true;
    bool committed=sbj_get_bool(pending,"committed",false),had_old=sbj_get_bool(pending,"had_old",false);
    if(!committed){
        if(present(old)){ok=clean_directory(known,dest,false)&&MoveFileExW(old,dest,MOVEFILE_WRITE_THROUGH);}
        else if(!had_old)ok=clean_directory(known,dest,false);
        if(present(oldview)){ok=clean_directory(known,view,true)&&MoveFileExW(oldview,view,MOVEFILE_WRITE_THROUGH)&&ok;}
        else if(!had_old)ok=clean_directory(known,view,true)&&ok;
    }else{ok=clean_directory(known,old,false)&&clean_directory(known,oldview,true);}
    ok=clean_directory(known,stage,false)&&clean_directory(known,stageview,true)&&ok;
    free(dest);free(view);free(old);free(oldview);free(stage);free(stageview);
    /* A committed replacement is already authoritative. A scanner holding an
     * old file may defer cleanup, but must not prevent verified code starting. */
    if(!ok)return committed?0:io(e);sbj_del(s->state,"pending");return save(s,e);
}
sbw_plugin_storage *sbw_plugin_storage_open(const wchar_t *root,sbw_error *e){
    if(!safe_root(root)){io(e);return NULL;}sbw_plugin_storage *s=sb_xcalloc(1,sizeof *s);s->root=_wcsdup(root);s->private_root=sbw_path_join(root,L".plugin-trust");s->store=sbw_secure_store_new(s->private_root,e);
    if(!s->store||s->store->load(s->store->context,&s->state,e))goto fail;
    if(!s->state){s->state=sbj_object();sbj_set_int(s->state,"version",1);sbj_set(s->state,"installed",sbj_object());}
    if(!sbj_is_object(s->state)||sbj_get_int(s->state,"version",0)!=1||!sbj_is_object(records(s))||sbj_obj_len(records(s))>4){bad(e);goto fail;}
    if(recover(s,e))goto fail;prune_cache(s);return s;
fail:sbw_plugin_storage_close(s);return NULL;
}
void sbw_plugin_storage_close(sbw_plugin_storage *s){if(s){sbw_store_free(s->store);sbj_free(s->state);free(s->root);free(s->private_root);free(s);}}
int sbw_plugin_storage_catalog(sbw_plugin_storage *s,const char *envelope,size_t length,sbw_error *e){
    char hash[65];sbj *payload=sbw_plugin_catalog_verify_trusted(envelope,length,now_seconds(),false,hash,e);if(!payload)return -1;
    sbj *accepted=sbw_plugin_catalog_accept(sbj_get(s->state,"accepted"),payload,hash,e);sbj_free(payload);if(!accepted)return -1;
    sbj *old=sbj_clone(s->state);sbj_set(s->state,"accepted",accepted);sbj_set(s->state,"catalog",sbj_strn(envelope,length));int result=save(s,e);if(result){sbj_free(s->state);s->state=old;}else sbj_free(old);return result;
}
sbj *sbw_plugin_storage_release(sbw_plugin_storage *s,const char *id,sbw_error *e){
    if(!sbw_extension_release_find(id)||sb_streq(id,"network-tools")){bad(e);return NULL;}const sbj *env=sbj_get(s->state,"catalog");
    if(!sbw_json_string(env,1024U*1024U,false)){sbw_fail(e,"CATALOG_REQUIRED","Import a current catalog signed by a trusted plugin publisher first.");return NULL;}
    sbj *payload=sbw_plugin_catalog_verify_trusted(env->v.str.ptr,env->v.str.len,now_seconds(),false,NULL,e);if(!payload)return NULL;
    const sbj *r=sbw_plugin_catalog_release(payload,id,"windows","x86_64",0);sbj *receipt=sbj_object();sbj_set(receipt,"envelope",sbj_clone(env));sbj_set_int(receipt,"build",sbj_get_int(r,"build",0));sbj_set_str(receipt,"sha256",sbj_get_str(r,"sha256",""));
    sbj *out=receipt_release(s,id,receipt,false,e);sbj_free(receipt);sbj_free(payload);
    if(out){int64_t build=sbj_get_int(out,"build",0),highest=sbj_get_int(record(s,id),"highest_build",0);
        if(build<highest||(build==highest&&sbj_has(record(s,id),"highest_sha256")&&!sbj_equal(sbj_get(out,"sha256"),sbj_get(record(s,id),"highest_sha256")))){sbj_free(out);sbw_fail(e,"STORE_DOWNGRADE","A new release must advance its build number; use explicit rollback for verified previous code.");return NULL;}}
    return out;
}
static int package_for_release(const char *id,const sbj *release,const void *bytes,size_t length,package_layout *layout,sbw_error *e){return inspect_package(id,bytes,length,sbj_get_str(release,"sha256",""),(size_t)sbj_get_int(release,"bytes",0),sbj_get_str(release,"version",""),sbj_get_int(release,"build",0),layout,e);}
int sbw_plugin_storage_check_package(sbw_plugin_storage *s,const char *id,const void *bytes,size_t length,sbw_error *e){sbj *r=sbw_plugin_storage_release(s,id,e);if(!r)return -1;package_layout layout;int result=package_for_release(id,r,bytes,length,&layout,e);sbj_free(r);return result;}
static unsigned char *installed_package(sbw_plugin_storage *s,const char *id,size_t expected,size_t *length){
    const sbw_extension_release *known=sbw_extension_release_find(id);if(!known||expected<8||expected>PACKAGE_MAX)return NULL;
    unsigned char *out=sb_xmalloc(expected);memcpy(out,"SBECP001",8);size_t used=8;bool ok=true;
    for(size_t i=0;i<known->file_count&&ok;++i){bool ui=!wcsncmp(known->files[i],L"view\\",5);wchar_t *base=location(s,id,ui),*p=sbw_path_join(base,known->files[i]+(ui?5:10));free(base);wchar_t *parent=_wcsdup(p),*slash=wcsrchr(parent,L'\\');if(slash)*slash=0;bool safe=safe_root(parent);free(parent);size_t size=0;unsigned char *data=safe?read_file(p,expected,&size):NULL;free(p);ok=data&&used<=expected-4&&size<=expected-used-4;if(ok){DWORD n=(DWORD)size;memcpy(out+used,&n,4);used+=4;memcpy(out+used,data,size);used+=size;}free(data);}
    if(!ok||used!=expected){free(out);return NULL;}*length=used;return out;
}
static bool verified_receipt(sbw_plugin_storage *s,const char *id,const sbj *receipt,sbw_error *e){
    sbj *r=receipt_release(s,id,receipt,true,e);if(!r)return false;size_t length=0;unsigned char *data=installed_package(s,id,(size_t)sbj_get_int(r,"bytes",0),&length);package_layout layout;bool ok=data&&!package_for_release(id,r,data,length,&layout,e);free(data);sbj_free(r);if(!ok)bad(e);return ok;
}
bool sbw_plugin_storage_verified(sbw_plugin_storage *s,const char *id,sbw_error *e){
    const sbj *active=sbj_get(record(s,id),"active");if(active)return verified_receipt(s,id,active,e);
    const sbw_extension_release *legacy=sbw_extension_release_find(id);if(!legacy||sbw_plugin_catalog_revoked(sbj_get(s->state,"accepted"),id,"windows",1)){bad(e);return false;}
    size_t length=0;unsigned char *data=installed_package(s,id,legacy->bytes,&length);package_layout layout;bool ok=data&&!inspect_package(id,data,length,legacy->sha256,legacy->bytes,"1.0.0",1,&layout,e);free(data);return ok;
}
bool sbw_plugin_storage_allowed(sbw_plugin_storage *s,const char *id,sbw_error *e){
    const sbj *active=sbj_get(record(s,id),"active");
    if(active){sbj *r=receipt_release(s,id,active,true,e);bool allowed=r!=NULL;sbj_free(r);return allowed;}
    return sbw_extension_release_find(id)&&!sbw_plugin_catalog_revoked(sbj_get(s->state,"accepted"),id,"windows",1);
}
static bool make_parent(sbw_plugin_storage *s,const wchar_t *name){wchar_t *p=sbw_path_join(s->root,name);bool ok=create_directory(p);free(p);return ok;}
static int publish(sbw_plugin_storage *s,const char *id,const sbj *receipt,const sbj *release,const void *data,size_t length,bool rollback,sbw_error *e){
    const sbw_extension_release *known=sbw_extension_release_find(id);package_layout layout;if(!known||package_for_release(id,release,data,length,&layout,e))return -1;
    if(recover(s,e)||!cached_package(s,sbj_get_str(release,"sha256",""),data,length))return io(e);
    if(!make_parent(s,L"extensions")||!make_parent(s,L"ui")||!make_parent(s,L"ui\\extensions"))return io(e);
    wchar_t *dest=location(s,id,false),*view=location(s,id,true),*old=private_path(s,L"old"),*oldview=private_path(s,L"old-view"),*stage=private_path(s,L"new"),*stageview=private_path(s,L"new-view");
    bool had_old=present(dest)||present(view);int result=-1;sbj *oldstate=NULL;
    if(had_old&&(!directory(dest)||!directory(view)))goto storage;
    if(present(old)||present(oldview)||present(stage)||present(stageview)){io(e);goto done;}
    /* Also cache a compiled, pinned legacy installation before its first
     * signed upgrade. Legacy receipts cannot nominate a new hash or layout. */
    if(had_old&&!sbj_get(record(s,id),"active")){
        size_t legacy_length=0;unsigned char *legacy=installed_package(s,id,known->bytes,&legacy_length);
        package_layout legacy_layout;bool ok=legacy&&!inspect_package(id,legacy,legacy_length,known->sha256,known->bytes,"1.0.0",1,&legacy_layout,e)&&cached_package(s,known->sha256,legacy,legacy_length);free(legacy);if(!ok)goto storage;
        sbj *r=sbj_object(),*receipt_old=sbj_object();sbj_set_bool(receipt_old,"legacy",true);sbj_set_int(receipt_old,"build",1);sbj_set_str(receipt_old,"version","1.0.0");sbj_set_str(receipt_old,"sha256",known->sha256);sbj_set(r,"active",receipt_old);sbj_set_int(r,"highest_build",1);sbj_set_str(r,"highest_sha256",known->sha256);sbj_set(records(s),id,r);if(save(s,e))goto storage;
    }
    /* Journal staging too: a crash while writing files must not strand an
     * unowned stage that prevents all future updates. */
    oldstate=sbj_clone(s->state);sbj *pending=sbj_object();sbj_set_str(pending,"id",id);sbj_set_bool(pending,"had_old",had_old);sbj_set_bool(pending,"committed",false);sbj_set(s->state,"pending",pending);
    if(save(s,e))goto storage;
    if(!create_directory(stage)||!create_directory(stageview))goto storage;
    const wchar_t *dirs[]={L"capture",L"licenses"};for(size_t i=0;i<2;++i){wchar_t *p=sbw_path_join(stage,dirs[i]);bool ok=create_directory(p);free(p);if(!ok)goto storage;}
    for(size_t i=0;i<known->file_count;++i){bool ui=!wcsncmp(known->files[i],L"view\\",5);wchar_t *p=sbw_path_join(ui?stageview:stage,known->files[i]+(ui?5:10));bool ok=write_new(p,layout.data+layout.offsets[i],layout.sizes[i]);free(p);if(!ok)goto storage;}
    /* This durable intent precedes the first rename. Recovery rolls it back
     * until both directory publication and the receipt commit have succeeded. */
    if(had_old&&(!MoveFileExW(dest,old,MOVEFILE_WRITE_THROUGH)||!MoveFileExW(view,oldview,MOVEFILE_WRITE_THROUGH)))goto storage;
    if(!MoveFileExW(stageview,view,MOVEFILE_WRITE_THROUGH)||!MoveFileExW(stage,dest,MOVEFILE_WRITE_THROUGH))goto storage;
    sbj *next=record(s,id)?sbj_clone(record(s,id)):sbj_object();const sbj *prior=sbj_get(next,"active");
    sbj *trusted_prior=prior?receipt_release(s,id,prior,true,NULL):NULL;
    if(trusted_prior)sbj_set(next,"previous",sbj_clone(prior));else if(rollback||!prior)sbj_del(next,"previous");sbj_free(trusted_prior);
    sbj_set(next,"active",sbj_clone(receipt));sbj_set_bool(next,"pending_health",true);
    int64_t highest=sbj_get_int(next,"highest_build",0),build=sbj_get_int(release,"build",0);sbj_set_int(next,"highest_build",highest>build?highest:build);if(build>=highest)sbj_set_str(next,"highest_sha256",sbj_get_str(release,"sha256",""));sbj_set_bool(next,"rolled_back",rollback);
    sbj_set(records(s),id,next);sbj_set_bool(sbj_get(s->state,"pending"),"committed",true);
    if(save(s,e)){
        sbj_free(s->state);s->state=oldstate;oldstate=NULL;sbj *intent=sbj_object();sbj_set_str(intent,"id",id);sbj_set_bool(intent,"had_old",had_old);sbj_set_bool(intent,"committed",false);sbj_set(s->state,"pending",intent);goto storage;
    }
    /* The committed receipt is authoritative. Cleanup failure leaves its
     * journal for the next opening, never restores untrusted code. */
    result=recover(s,e);if(!result)prune_cache(s);goto done;
storage:
    if(sbj_has(s->state,"pending")){if(recover(s,e))goto done;}
    else{clean_directory(known,stage,false);clean_directory(known,stageview,true);}
    io(e);
done:sbj_free(oldstate);free(dest);free(view);free(old);free(oldview);free(stage);free(stageview);return result;
}
int sbw_plugin_storage_publish(sbw_plugin_storage *s,const char *id,const void *data,size_t length,sbw_error *e){
    sbj *r=sbw_plugin_storage_release(s,id,e);if(!r)return -1;sbj *receipt=sbj_object();sbj_set(receipt,"envelope",sbj_clone(sbj_get(s->state,"catalog")));sbj_set_int(receipt,"build",sbj_get_int(r,"build",0));sbj_set_str(receipt,"version",sbj_get_str(r,"version",""));sbj_set_str(receipt,"sha256",sbj_get_str(r,"sha256",""));
    int result=publish(s,id,receipt,r,data,length,false,e);sbj_free(r);sbj_free(receipt);return result;
}
int sbw_plugin_storage_rollback(sbw_plugin_storage *s,const char *id,sbw_error *e){
    const sbj *previous=sbj_get(record(s,id),"previous");sbj *r=receipt_release(s,id,previous,true,e);if(!r)return -1;
    wchar_t *p=cache_path(s,sbj_get_str(r,"sha256",""));size_t length=0;unsigned char *data=p?read_file(p,PACKAGE_MAX,&length):NULL;free(p);sbj *receipt=sbj_clone(previous);
    int result=data?publish(s,id,receipt,r,data,length,true,e):bad(e);free(data);sbj_free(receipt);sbj_free(r);return result;
}
int sbw_plugin_storage_confirm(sbw_plugin_storage *s,const char *id,sbw_error *e){if(!sbw_plugin_storage_verified(s,id,e))return -1;sbj *r=record(s,id);if(!r)return 0;sbj_set_bool(r,"pending_health",false);return save(s,e);}
sbj *sbw_plugin_storage_status(sbw_plugin_storage *s,const char *id){
    sbj *out=sbj_object();const sbj *r=record(s,id),*active=sbj_get(r,"active");sbw_error error={0};bool verified=sbw_plugin_storage_verified(s,id,&error);sbj *latest=sbw_plugin_storage_release(s,id,NULL),*previous=receipt_release(s,id,sbj_get(r,"previous"),true,NULL);
    int64_t build=active?sbj_get_int(active,"build",0):(verified?1:0);sbj_set_bool(out,"verified",verified);sbj_set_bool(out,"revoked",build&&sbw_plugin_catalog_revoked(sbj_get(s->state,"accepted"),id,"windows",build));
    sbj_set_int(out,"build",build);sbj *installed=active?receipt_release(s,id,active,true,NULL):NULL;sbj_set_str(out,"version",active?sbj_get_str(active,"version",installed?sbj_get_str(installed,"version",""):""):(verified?"1.0.0":""));
    bool can_rollback=false;if(previous&&!sbj_equal(sbj_get(previous,"sha256"),sbj_get(active,"sha256"))){wchar_t *path=cache_path(s,sbj_get_str(previous,"sha256",""));size_t length=0;unsigned char *bytes=path?read_file(path,PACKAGE_MAX,&length):NULL;package_layout layout;can_rollback=bytes&&!package_for_release(id,previous,bytes,length,&layout,NULL);free(bytes);free(path);}
    sbj_set_bool(out,"update_available",latest&&sbj_get_int(latest,"build",0)>build);sbj_set_bool(out,"rollback_available",can_rollback);sbj_set_bool(out,"pending_health",sbj_get_bool(r,"pending_health",false));
    const sbj *env=sbj_get(s->state,"catalog");sbj *catalog=sbj_is_string(env)?sbw_plugin_catalog_verify_trusted(env->v.str.ptr,env->v.str.len,now_seconds(),false,NULL,NULL):NULL;
    sbj_set_bool(out,"trust_configured",sbw_plugin_catalog_has_trust());sbj_set_bool(out,"catalog_fresh",catalog!=NULL);sbj_set_int(out,"sequence",sbj_get_int(sbj_get(s->state,"accepted"),"sequence",0));if(latest)sbj_set(out,"release",sbj_clone(latest));
    sbj_set_bool(out,"cleanup_pending",sbj_has(s->state,"pending"));sbj_free(catalog);sbj_free(installed);sbj_free(previous);sbj_free(latest);return out;
}
