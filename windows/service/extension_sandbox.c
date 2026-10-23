#include "extension_sandbox.h"
#include "extension_store.h"
#include "secure_store.h"
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sbw_extension_sandbox {
    SECURITY_CAPABILITIES security;
    SID_AND_ATTRIBUTES capabilities[2];
    BYTE network_sids[2][SECURITY_MAX_SID_SIZE];
    wchar_t *directory,*environment;
    bool loopback;
};
/* API families below do not all use GetLastError. Record their actual result
 * before closing handles, which can otherwise replace it with ERROR_SUCCESS.
 * Stage names are fixed constants: no installation paths or secrets are logged. */
static bool sandbox_failure(sbw_error *error,const char *stage,const char *kind,DWORD code){
    char message[256];snprintf(message,sizeof message,"Plugin sandbox stage %s failed (%s=0x%08lx). The plugin was not started.",stage,kind,(unsigned long)code);
    sbw_fail(error,"EXTENSION_SANDBOX",message);
    DWORD win32=code;
    if(strcmp(kind,"Win32"))win32=HRESULT_FACILITY(code)==FACILITY_WIN32?HRESULT_CODE(code):ERROR_GEN_FAILURE;
    SetLastError(win32?win32:ERROR_GEN_FAILURE);return false;
}
static bool sandbox_win32(sbw_error *error,const char *stage,DWORD code){return sandbox_failure(error,stage,"Win32",code?code:ERROR_GEN_FAILURE);}
static SRWLOCK network_lock=SRWLOCK_INIT;
static bool loopback_config(PSID sid,bool allow,sbw_error *error){
    typedef DWORD (WINAPI *get_fn)(DWORD*,PSID_AND_ATTRIBUTES*);
    typedef DWORD (WINAPI *set_fn)(DWORD,PSID_AND_ATTRIBUTES);
    HMODULE library=LoadLibraryExW(L"FirewallAPI.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!library)return sandbox_win32(error,"network.library",GetLastError());
    get_fn get=(get_fn)(void*)GetProcAddress(library,"NetworkIsolationGetAppContainerConfig");
    set_fn set=(set_fn)(void*)GetProcAddress(library,"NetworkIsolationSetAppContainerConfig");
    DWORD count=0,code=ERROR_SUCCESS;PSID_AND_ATTRIBUTES old=NULL;SID_AND_ATTRIBUTES *next=NULL;bool ok=false;const char *stage="network.exports";
    AcquireSRWLockExclusive(&network_lock);
    if(!get||!set){code=ERROR_PROC_NOT_FOUND;goto done;}
    stage="network.query";code=get(&count,&old);if(code!=ERROR_SUCCESS)goto done;
    if(count>4096){code=ERROR_BUFFER_OVERFLOW;goto done;}
    next=sb_xcalloc((size_t)count+1,sizeof *next);DWORD used=0;
    /* Preserve every other application's exemptions. Our deterministic profile
     * has a single service owner, so stale exemptions are removed on shutdown. */
    for(DWORD i=0;i<count;++i)if(!EqualSid(old[i].Sid,sid))next[used++]=old[i];
    if(allow){next[used].Sid=sid;next[used++].Attributes=SE_GROUP_ENABLED;}
    stage="network.update";code=set(used,next);ok=code==ERROR_SUCCESS;
done:
    if(old){for(DWORD i=0;i<count;++i)HeapFree(GetProcessHeap(),0,old[i].Sid);HeapFree(GetProcessHeap(),0,old);}free(next);
    ReleaseSRWLockExclusive(&network_lock);FreeLibrary(library);return ok?true:sandbox_win32(error,stage,code);
}
static BYTE *token_info(HANDLE token,TOKEN_INFORMATION_CLASS kind){DWORD n=0;GetTokenInformation(token,kind,NULL,0,&n);if(!n||n>65536)return NULL;BYTE *out=sb_xmalloc(n);if(!GetTokenInformation(token,kind,out,n,&n)){free(out);return NULL;}return out;}
static bool grant_path(const wchar_t *path,PSID sid,DWORD rights,bool directory,bool low,const char *part,sbw_error *error){
    char stage[96];const char *step="open";DWORD code=ERROR_SUCCESS;
    HANDLE f=CreateFileW(path,READ_CONTROL|WRITE_DAC|FILE_READ_ATTRIBUTES|(low?WRITE_OWNER:0),FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),NULL);
    if(f==INVALID_HANDLE_VALUE){snprintf(stage,sizeof stage,"%s.open",part);return sandbox_win32(error,stage,GetLastError());}
    FILE_ATTRIBUTE_TAG_INFO info;PSECURITY_DESCRIPTOR descriptor=NULL;PACL original=NULL,updated=NULL;PSID owner=NULL;HANDLE token=NULL;BYTE *user=NULL;bool ok=false;
    step="inspect";if(!GetFileInformationByHandleEx(f,FileAttributeTagInfo,&info,sizeof info)){code=GetLastError();goto done;}
    if((info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||((info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)!=directory){code=ERROR_INVALID_DATA;goto done;}
    step="security.read";code=GetSecurityInfo(f,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION,&owner,NULL,&original,NULL,&descriptor);if(code!=ERROR_SUCCESS)goto done;
    step="token.open";if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){code=GetLastError();goto done;}
    step="token.user";user=token_info(token,TokenUser);if(!user){code=GetLastError();goto done;}
    step="owner";if(!sbw_trusted_storage_owner(owner,((TOKEN_USER*)user)->User.Sid)){code=ERROR_ACCESS_DENIED;goto done;}
    EXPLICIT_ACCESSW access={0};access.grfAccessPermissions=rights;access.grfAccessMode=GRANT_ACCESS;access.grfInheritance=directory?SUB_CONTAINERS_AND_OBJECTS_INHERIT:NO_INHERITANCE;access.Trustee.TrusteeForm=TRUSTEE_IS_SID;access.Trustee.TrusteeType=TRUSTEE_IS_UNKNOWN;access.Trustee.ptstrName=(LPWSTR)sid;
    step="acl.merge";code=SetEntriesInAclW(1,&access,original,&updated);if(code!=ERROR_SUCCESS)goto done;
    step="acl.write";code=SetSecurityInfo(f,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,updated,NULL);if(code!=ERROR_SUCCESS)goto done;
    if(low){PSECURITY_DESCRIPTOR label=NULL;PACL sacl=NULL;BOOL exists=FALSE,defaulted=FALSE;
        step="label.parse";if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICI;NW;;;LW)",SDDL_REVISION_1,&label,NULL)){code=GetLastError();goto done;}
        step="label.read";bool labeled=GetSecurityDescriptorSacl(label,&exists,&sacl,&defaulted)!=FALSE;
        if(!labeled)code=GetLastError();else if(!exists){labeled=false;code=ERROR_INVALID_SECURITY_DESCR;}
        if(labeled){step="label.write";code=SetSecurityInfo(f,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,sacl);labeled=code==ERROR_SUCCESS;}
        LocalFree(label);if(!labeled)goto done;}
    ok=true;
done:free(user);if(token)CloseHandle(token);if(updated)LocalFree(updated);if(descriptor)LocalFree(descriptor);CloseHandle(f);
    if(ok)return true;snprintf(stage,sizeof stage,"%s.%s",part,step);return sandbox_win32(error,stage,code);
}
static bool grant_package(sbw_extension_sandbox *s,const char *id,const wchar_t *root,sbw_error *error){
    const sbw_extension_release *release=sbw_extension_release_find(id);if(!release)return sandbox_win32(error,"package.identity",ERROR_INVALID_PARAMETER);
    wchar_t name[128];swprintf_s(name,128,L"extensions\\%S",id);wchar_t *base=sbw_path_join(root,name);
    bool ok=grant_path(base,s->security.AppContainerSid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,true,false,"package.directory",error);
    const wchar_t *directories[]={L"capture",L"licenses"};for(size_t i=0;ok&&i<2;++i){wchar_t *p=sbw_path_join(base,directories[i]);DWORD a=GetFileAttributesW(p);if(a!=INVALID_FILE_ATTRIBUTES)ok=grant_path(p,s->security.AppContainerSid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,true,false,"package.subdirectory",error);else{DWORD code=GetLastError();if(code!=ERROR_FILE_NOT_FOUND&&code!=ERROR_PATH_NOT_FOUND)ok=sandbox_win32(error,"package.subdirectory.attributes",code);}free(p);}
    for(size_t i=0;ok&&i<release->file_count;++i){if(wcsncmp(release->files[i],L"extension\\",10))continue;wchar_t *p=sbw_path_join(base,release->files[i]+10);ok=grant_path(p,s->security.AppContainerSid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,false,false,"package.file",error);free(p);}free(base);return ok;
}
static bool environment(sbw_extension_sandbox *s,sbw_error *error){
    wchar_t system[MAX_PATH],windows[MAX_PATH];UINT n=GetSystemDirectoryW(system,MAX_PATH);if(!n||n>=MAX_PATH)return sandbox_win32(error,"environment.system",n?ERROR_INSUFFICIENT_BUFFER:GetLastError());
    n=GetWindowsDirectoryW(windows,MAX_PATH);if(!n||n>=MAX_PATH)return sandbox_win32(error,"environment.windows",n?ERROR_INSUFFICIENT_BUFFER:GetLastError());
    const wchar_t *keys[]={L"APPDATA",L"LOCALAPPDATA",L"PATH",L"SystemRoot",L"TEMP",L"TMP",L"USERPROFILE",L"WINDIR"};
    const wchar_t *values[]={s->directory,s->directory,system,windows,s->directory,s->directory,s->directory,windows};size_t length=1;
    for(size_t i=0;i<8;++i)length+=wcslen(keys[i])+wcslen(values[i])+2;if(length>32767)return sandbox_win32(error,"environment.size",ERROR_BUFFER_OVERFLOW);s->environment=sb_xcalloc(length,sizeof(wchar_t));size_t at=0;
    for(size_t i=0;i<8;++i){size_t k=wcslen(keys[i]),v=wcslen(values[i]);memcpy(s->environment+at,keys[i],k*sizeof(wchar_t));at+=k;s->environment[at++]=L'=';memcpy(s->environment+at,values[i],v*sizeof(wchar_t));at+=v+1;}return true;
}
sbw_extension_sandbox *sbw_extension_sandbox_new(const char *id,const wchar_t *root,sbw_error *error){
    if(!id||!root||!*root||!sbw_extension_release_find(id)||sb_streq(id,"network-tools")){sandbox_win32(error,"request",ERROR_INVALID_PARAMETER);return NULL;}
    sbw_extension_sandbox *s=sb_xcalloc(1,sizeof *s);unsigned char hash[32];BCRYPT_ALG_HANDLE algorithm=NULL;
    NTSTATUS opened=BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0);if(opened<0){sandbox_failure(error,"identity.hash.open","NTSTATUS",(DWORD)opened);goto fail;}
    NTSTATUS hashed=BCryptHash(algorithm,NULL,0,(PUCHAR)root,(ULONG)(wcslen(root)*sizeof(wchar_t)),hash,sizeof hash);BCryptCloseAlgorithmProvider(algorithm,0);if(hashed<0){sandbox_failure(error,"identity.hash","NTSTATUS",(DWORD)hashed);goto fail;}
    wchar_t name[65];swprintf_s(name,65,L"sb-easy.%S.%02x%02x%02x%02x%02x%02x",id,hash[0],hash[1],hash[2],hash[3],hash[4],hash[5]);
    bool network=sb_streq(id,"http-debug");
    if(network){WELL_KNOWN_SID_TYPE kinds[]={WinCapabilityInternetClientSid,WinCapabilityPrivateNetworkClientServerSid};for(size_t i=0;i<2;++i){DWORD n=SECURITY_MAX_SID_SIZE;if(!CreateWellKnownSid(kinds[i],NULL,s->network_sids[i],&n)){sandbox_win32(error,"capability.sid",GetLastError());goto fail;}s->capabilities[i].Sid=s->network_sids[i];s->capabilities[i].Attributes=SE_GROUP_ENABLED;}s->security.Capabilities=s->capabilities;s->security.CapabilityCount=2;}
    HRESULT created=CreateAppContainerProfile(name,L"sb-easy optional plugin",L"Isolated optional plugin worker",s->capabilities,s->security.CapabilityCount,&s->security.AppContainerSid);
    if(created==HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)){created=DeriveAppContainerSidFromAppContainerName(name,&s->security.AppContainerSid);if(FAILED(created)){sandbox_failure(error,"profile.derive","HRESULT",(DWORD)created);goto fail;}}
    else if(FAILED(created)){sandbox_failure(error,"profile.create","HRESULT",(DWORD)created);goto fail;}
    LPWSTR sid=NULL,folder=NULL;if(!ConvertSidToStringSidW(s->security.AppContainerSid,&sid)){sandbox_win32(error,"profile.sid",GetLastError());goto fail;}
    HRESULT located=GetAppContainerFolderPath(sid,&folder);LocalFree(sid);if(FAILED(located)){sandbox_failure(error,"profile.folder","HRESULT",(DWORD)located);goto fail;}
    s->directory=sbw_path_join(folder,L"sb-easy");CoTaskMemFree(folder);
    if(!s->directory){sandbox_win32(error,"private.path",ERROR_FILENAME_EXCED_RANGE);goto fail;}
    if(!CreateDirectoryW(s->directory,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS){sandbox_win32(error,"private.create",GetLastError());goto fail;}
    if(!grant_path(s->directory,s->security.AppContainerSid,FILE_ALL_ACCESS,true,true,"private.directory",error)||!grant_package(s,id,root,error)||!environment(s,error))goto fail;
    if(network){if(!loopback_config(s->security.AppContainerSid,true,error))goto fail;s->loopback=true;}
    return s;
fail:{DWORD code=GetLastError();sbw_extension_sandbox_free(s);SetLastError(code);return NULL;}
}
void sbw_extension_sandbox_free(sbw_extension_sandbox *s){if(!s)return;if(s->loopback)loopback_config(s->security.AppContainerSid,false,NULL);if(s->security.AppContainerSid)FreeSid(s->security.AppContainerSid);free(s->directory);free(s->environment);free(s);}
const SECURITY_CAPABILITIES *sbw_extension_sandbox_capabilities(sbw_extension_sandbox *s){return s?&s->security:NULL;}
const wchar_t *sbw_extension_sandbox_environment(sbw_extension_sandbox *s){return s?s->environment:NULL;}
const wchar_t *sbw_extension_sandbox_directory(sbw_extension_sandbox *s){return s?s->directory:NULL;}
bool sbw_extension_sandbox_verify_process(sbw_extension_sandbox *s,HANDLE process){
    if(!s){SetLastError(ERROR_INVALID_PARAMETER);return false;}HANDLE token=NULL;if(!OpenProcessToken(process,TOKEN_QUERY,&token))return false;
    BYTE *is=token_info(token,TokenIsAppContainer),*app=token_info(token,TokenAppContainerSid),*il=token_info(token,TokenIntegrityLevel),*privileges=token_info(token,TokenPrivileges);
    bool ok=is&&*(DWORD*)is&&app&&((TOKEN_APPCONTAINER_INFORMATION*)app)->TokenAppContainer&&EqualSid(((TOKEN_APPCONTAINER_INFORMATION*)app)->TokenAppContainer,s->security.AppContainerSid)&&il&&privileges;
    if(ok){PSID level=((TOKEN_MANDATORY_LABEL*)il)->Label.Sid;DWORD count=*GetSidSubAuthorityCount(level);ok=count&&*GetSidSubAuthority(level,count-1)<=SECURITY_MANDATORY_LOW_RID;}
    if(ok){const wchar_t *names[]={SE_DEBUG_NAME,SE_TCB_NAME,SE_LOAD_DRIVER_NAME,SE_IMPERSONATE_NAME};TOKEN_PRIVILEGES *p=(TOKEN_PRIVILEGES*)privileges;for(size_t i=0;i<4;++i){LUID dangerous;if(!LookupPrivilegeValueW(NULL,names[i],&dangerous)){ok=false;break;}for(DWORD j=0;j<p->PrivilegeCount;++j)if(p->Privileges[j].Luid.LowPart==dangerous.LowPart&&p->Privileges[j].Luid.HighPart==dangerous.HighPart&&!(p->Privileges[j].Attributes&SE_PRIVILEGE_REMOVED))ok=false;}}
    free(is);free(app);free(il);free(privileges);CloseHandle(token);if(!ok)SetLastError(ERROR_ACCESS_DENIED);return ok;
}
