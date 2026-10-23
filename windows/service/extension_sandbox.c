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
static SRWLOCK network_lock=SRWLOCK_INIT;
static bool loopback_config(PSID sid,bool allow){
    typedef DWORD (WINAPI *get_fn)(DWORD*,PSID_AND_ATTRIBUTES*);
    typedef DWORD (WINAPI *set_fn)(DWORD,PSID_AND_ATTRIBUTES);
    HMODULE library=LoadLibraryExW(L"FirewallAPI.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!library)return false;
    get_fn get=(get_fn)(void*)GetProcAddress(library,"NetworkIsolationGetAppContainerConfig");
    set_fn set=(set_fn)(void*)GetProcAddress(library,"NetworkIsolationSetAppContainerConfig");
    DWORD count=0;PSID_AND_ATTRIBUTES old=NULL;SID_AND_ATTRIBUTES *next=NULL;bool ok=false;
    AcquireSRWLockExclusive(&network_lock);
    if(!get||!set||get(&count,&old)!=ERROR_SUCCESS||count>4096)goto done;
    next=sb_xcalloc((size_t)count+1,sizeof *next);DWORD used=0;
    /* Preserve every other application's exemptions. Our deterministic profile
     * has a single service owner, so stale exemptions are removed on shutdown. */
    for(DWORD i=0;i<count;++i)if(!EqualSid(old[i].Sid,sid))next[used++]=old[i];
    if(allow){next[used].Sid=sid;next[used++].Attributes=SE_GROUP_ENABLED;}
    ok=set(used,next)==ERROR_SUCCESS;
done:
    if(old){for(DWORD i=0;i<count;++i)HeapFree(GetProcessHeap(),0,old[i].Sid);HeapFree(GetProcessHeap(),0,old);}free(next);
    ReleaseSRWLockExclusive(&network_lock);FreeLibrary(library);return ok;
}
static BYTE *token_info(HANDLE token,TOKEN_INFORMATION_CLASS kind){DWORD n=0;GetTokenInformation(token,kind,NULL,0,&n);if(!n||n>65536)return NULL;BYTE *out=sb_xmalloc(n);if(!GetTokenInformation(token,kind,out,n,&n)){free(out);return NULL;}return out;}
static bool grant_path(const wchar_t *path,PSID sid,DWORD rights,bool directory,bool low){
    HANDLE f=CreateFileW(path,READ_CONTROL|WRITE_DAC|FILE_READ_ATTRIBUTES|(low?WRITE_OWNER:0),FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),NULL);
    if(f==INVALID_HANDLE_VALUE)return false;FILE_ATTRIBUTE_TAG_INFO info;PSECURITY_DESCRIPTOR descriptor=NULL;PACL original=NULL,updated=NULL;PSID owner=NULL;HANDLE token=NULL;BYTE *user=NULL;bool ok=false;
    if(!GetFileInformationByHandleEx(f,FileAttributeTagInfo,&info,sizeof info)||(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||((info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0)!=directory)goto done;
    if(GetSecurityInfo(f,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION,&owner,NULL,&original,NULL,&descriptor)!=ERROR_SUCCESS||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))goto done;
    user=token_info(token,TokenUser);if(!user||!sbw_trusted_storage_owner(owner,((TOKEN_USER*)user)->User.Sid))goto done;
    EXPLICIT_ACCESSW access={0};access.grfAccessPermissions=rights;access.grfAccessMode=GRANT_ACCESS;access.grfInheritance=directory?SUB_CONTAINERS_AND_OBJECTS_INHERIT:NO_INHERITANCE;access.Trustee.TrusteeForm=TRUSTEE_IS_SID;access.Trustee.TrusteeType=TRUSTEE_IS_UNKNOWN;access.Trustee.ptstrName=(LPWSTR)sid;
    if(SetEntriesInAclW(1,&access,original,&updated)!=ERROR_SUCCESS||SetSecurityInfo(f,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,NULL,NULL,updated,NULL)!=ERROR_SUCCESS)goto done;
    if(low){PSECURITY_DESCRIPTOR label=NULL;PACL sacl=NULL;BOOL exists=FALSE,defaulted=FALSE;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICI;NW;;;LW)",SDDL_REVISION_1,&label,NULL))goto done;
        bool labeled=GetSecurityDescriptorSacl(label,&exists,&sacl,&defaulted)&&exists&&SetSecurityInfo(f,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,sacl)==ERROR_SUCCESS;LocalFree(label);if(!labeled)goto done;}
    ok=true;
done:free(user);if(token)CloseHandle(token);if(updated)LocalFree(updated);if(descriptor)LocalFree(descriptor);CloseHandle(f);return ok;
}
static bool grant_package(sbw_extension_sandbox *s,const char *id,const wchar_t *root){
    const sbw_extension_release *release=sbw_extension_release_find(id);if(!release)return false;
    wchar_t name[128];swprintf_s(name,128,L"extensions\\%S",id);wchar_t *base=sbw_path_join(root,name);
    bool ok=grant_path(base,s->security.AppContainerSid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,true,false);
    const wchar_t *directories[]={L"capture",L"licenses"};for(size_t i=0;ok&&i<2;++i){wchar_t *p=sbw_path_join(base,directories[i]);DWORD a=GetFileAttributesW(p);if(a!=INVALID_FILE_ATTRIBUTES)ok=grant_path(p,s->security.AppContainerSid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,true,false);free(p);}
    for(size_t i=0;ok&&i<release->file_count;++i){if(wcsncmp(release->files[i],L"extension\\",10))continue;wchar_t *p=sbw_path_join(base,release->files[i]+10);ok=grant_path(p,s->security.AppContainerSid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,false,false);free(p);}free(base);return ok;
}
static bool environment(sbw_extension_sandbox *s){
    wchar_t system[MAX_PATH],windows[MAX_PATH];if(!GetSystemDirectoryW(system,MAX_PATH)||!GetWindowsDirectoryW(windows,MAX_PATH))return false;
    const wchar_t *keys[]={L"APPDATA",L"LOCALAPPDATA",L"PATH",L"SystemRoot",L"TEMP",L"TMP",L"USERPROFILE",L"WINDIR"};
    const wchar_t *values[]={s->directory,s->directory,system,windows,s->directory,s->directory,s->directory,windows};size_t length=1;
    for(size_t i=0;i<8;++i)length+=wcslen(keys[i])+wcslen(values[i])+2;if(length>32767)return false;s->environment=sb_xcalloc(length,sizeof(wchar_t));size_t at=0;
    for(size_t i=0;i<8;++i){size_t k=wcslen(keys[i]),v=wcslen(values[i]);memcpy(s->environment+at,keys[i],k*sizeof(wchar_t));at+=k;s->environment[at++]=L'=';memcpy(s->environment+at,values[i],v*sizeof(wchar_t));at+=v+1;}return true;
}
sbw_extension_sandbox *sbw_extension_sandbox_new(const char *id,const wchar_t *root,sbw_error *error){
    if(!sbw_extension_release_find(id)||sb_streq(id,"network-tools"))goto invalid;
    sbw_extension_sandbox *s=sb_xcalloc(1,sizeof *s);unsigned char hash[32];BCRYPT_ALG_HANDLE algorithm=NULL;
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)goto fail;
    NTSTATUS hashed=BCryptHash(algorithm,NULL,0,(PUCHAR)root,(ULONG)(wcslen(root)*sizeof(wchar_t)),hash,sizeof hash);BCryptCloseAlgorithmProvider(algorithm,0);if(hashed<0)goto fail;
    wchar_t name[65];swprintf_s(name,65,L"sb-easy.%S.%02x%02x%02x%02x%02x%02x",id,hash[0],hash[1],hash[2],hash[3],hash[4],hash[5]);
    bool network=sb_streq(id,"http-debug");
    if(network){WELL_KNOWN_SID_TYPE kinds[]={WinCapabilityInternetClientSid,WinCapabilityPrivateNetworkClientServerSid};for(size_t i=0;i<2;++i){DWORD n=SECURITY_MAX_SID_SIZE;if(!CreateWellKnownSid(kinds[i],NULL,s->network_sids[i],&n))goto fail;s->capabilities[i].Sid=s->network_sids[i];s->capabilities[i].Attributes=SE_GROUP_ENABLED;}s->security.Capabilities=s->capabilities;s->security.CapabilityCount=2;}
    HRESULT created=CreateAppContainerProfile(name,L"sb-easy optional plugin",L"Isolated optional plugin worker",s->capabilities,s->security.CapabilityCount,&s->security.AppContainerSid);
    if(created==HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))created=DeriveAppContainerSidFromAppContainerName(name,&s->security.AppContainerSid);if(FAILED(created))goto fail;
    LPWSTR sid=NULL,folder=NULL;if(!ConvertSidToStringSidW(s->security.AppContainerSid,&sid))goto fail;
    HRESULT located=GetAppContainerFolderPath(sid,&folder);LocalFree(sid);if(FAILED(located))goto fail;
    s->directory=sbw_path_join(folder,L"sb-easy");CoTaskMemFree(folder);
    if(!CreateDirectoryW(s->directory,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS)goto fail;
    if(!grant_path(s->directory,s->security.AppContainerSid,FILE_ALL_ACCESS,true,true)||!grant_package(s,id,root)||!environment(s))goto fail;
    if(network){if(!loopback_config(s->security.AppContainerSid,true))goto fail;s->loopback=true;}
    return s;
fail:sbw_extension_sandbox_free(s);
invalid:sbw_fail(error,"EXTENSION_SANDBOX","Windows could not establish this plugin's isolated environment. The plugin was not started.");return NULL;
}
void sbw_extension_sandbox_free(sbw_extension_sandbox *s){if(!s)return;if(s->loopback)loopback_config(s->security.AppContainerSid,false);if(s->security.AppContainerSid)FreeSid(s->security.AppContainerSid);free(s->directory);free(s->environment);free(s);}
const SECURITY_CAPABILITIES *sbw_extension_sandbox_capabilities(sbw_extension_sandbox *s){return s?&s->security:NULL;}
const wchar_t *sbw_extension_sandbox_environment(sbw_extension_sandbox *s){return s?s->environment:NULL;}
const wchar_t *sbw_extension_sandbox_directory(sbw_extension_sandbox *s){return s?s->directory:NULL;}
bool sbw_extension_sandbox_verify_process(sbw_extension_sandbox *s,HANDLE process){
    if(!s)return false;HANDLE token=NULL;if(!OpenProcessToken(process,TOKEN_QUERY,&token))return false;
    BYTE *is=token_info(token,TokenIsAppContainer),*app=token_info(token,TokenAppContainerSid),*il=token_info(token,TokenIntegrityLevel),*privileges=token_info(token,TokenPrivileges);
    bool ok=is&&*(DWORD*)is&&app&&((TOKEN_APPCONTAINER_INFORMATION*)app)->TokenAppContainer&&EqualSid(((TOKEN_APPCONTAINER_INFORMATION*)app)->TokenAppContainer,s->security.AppContainerSid)&&il&&privileges;
    if(ok){PSID level=((TOKEN_MANDATORY_LABEL*)il)->Label.Sid;DWORD count=*GetSidSubAuthorityCount(level);ok=count&&*GetSidSubAuthority(level,count-1)<=SECURITY_MANDATORY_LOW_RID;}
    if(ok){const wchar_t *names[]={SE_DEBUG_NAME,SE_TCB_NAME,SE_LOAD_DRIVER_NAME,SE_IMPERSONATE_NAME};TOKEN_PRIVILEGES *p=(TOKEN_PRIVILEGES*)privileges;for(size_t i=0;i<4;++i){LUID dangerous;if(!LookupPrivilegeValueW(NULL,names[i],&dangerous)){ok=false;break;}for(DWORD j=0;j<p->PrivilegeCount;++j)if(p->Privileges[j].Luid.LowPart==dangerous.LowPart&&p->Privileges[j].Luid.HighPart==dangerous.HighPart&&!(p->Privileges[j].Attributes&SE_PRIVILEGE_REMOVED))ok=false;}}
    free(is);free(app);free(il);free(privileges);CloseHandle(token);return ok;
}
