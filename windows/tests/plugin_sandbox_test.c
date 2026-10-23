#include "../service/plugin_storage.h"
#include "../service/extension_process.h"
#include "../service/extension_sandbox.h"
#include "../service/secure_store.h"
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static sbw_error error;
#define CHECK(c) do{if(!(c)){fprintf(stderr,"line %d: %s (%s: %s, Win32=%lu)\n",__LINE__,#c,error.code,error.message,GetLastError());exit(1);}}while(0)
static void private_acl_diagnostics(const wchar_t *directory){
    HANDLE file=CreateFileW(directory,READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(file==INVALID_HANDLE_VALUE){fprintf(stderr,"Private ACL diagnostics: open_error=%lu\n",GetLastError());return;}
    HANDLE token=NULL;BYTE *user=NULL;DWORD length=0;PSECURITY_DESCRIPTOR descriptor=NULL;PACL acl=NULL,label=NULL;
    DWORD code=GetSecurityInfo(file,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION,NULL,NULL,&acl,&label,&descriptor);
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){GetTokenInformation(token,TokenUser,NULL,0,&length);if(length&&length<=65536){user=sb_xmalloc(length);if(!GetTokenInformation(token,TokenUser,user,length,&length)){free(user);user=NULL;}}}
    DWORD user_allow=0,admins_allow=0,integrity=MAXDWORD;
    if(code==ERROR_SUCCESS&&acl&&user)for(DWORD i=0;i<acl->AceCount;++i){void *raw=NULL;if(!GetAce(acl,i,&raw))continue;ACE_HEADER *header=raw;if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE||(header->AceFlags&INHERIT_ONLY_ACE))continue;ACCESS_ALLOWED_ACE *ace=raw;PSID sid=(PSID)&ace->SidStart;if(EqualSid(sid,((TOKEN_USER*)user)->User.Sid))user_allow|=ace->Mask;if(IsWellKnownSid(sid,WinBuiltinAdministratorsSid))admins_allow|=ace->Mask;}
    if(code==ERROR_SUCCESS&&label)for(DWORD i=0;i<label->AceCount;++i){void *raw=NULL;if(!GetAce(label,i,&raw)||((ACE_HEADER*)raw)->AceType!=SYSTEM_MANDATORY_LABEL_ACE_TYPE)continue;PSID sid=(PSID)&((SYSTEM_MANDATORY_LABEL_ACE*)raw)->SidStart;DWORD count=*GetSidSubAuthorityCount(sid);if(count)integrity=*GetSidSubAuthority(sid,count-1);}
    fprintf(stderr,"Private ACL diagnostics: query_error=%lu, token_user_read=%d, user_allow_mask=0x%08lx, administrators_allow_mask=0x%08lx, integrity_rid=%lu\n",code,user!=NULL,(unsigned long)user_allow,(unsigned long)admins_allow,(unsigned long)integrity);
    free(user);if(token)CloseHandle(token);if(descriptor)LocalFree(descriptor);CloseHandle(file);
}
/* The path helper has no trust decision; the production process/store modules
 * below still validate the signed artifact before creating an AppContainer. */
wchar_t *sbw_extension_path(const wchar_t *relative){wchar_t *root=sbw_executable_directory(NULL),*out=root?sbw_path_join(root,relative):NULL;free(root);return out;}
static unsigned char *read(const char *folder,const char *name,size_t *length){char p[4096];snprintf(p,sizeof p,"%s/%s",folder,name);FILE *f=fopen(p,"rb");CHECK(f);fseek(f,0,SEEK_END);long n=ftell(f);CHECK(n>0&&n<16*1024*1024);rewind(f);unsigned char *v=sb_xmalloc((size_t)n+1);*length=fread(v,1,(size_t)n,f);fclose(f);CHECK(*length==(size_t)n);v[n]=0;return v;}
int main(int argc,char **argv){
    CHECK(argc==2||argc==3);
    /* Failure diagnostics survive cleanup and contain no caller-selected path. */
    CHECK(!sbw_extension_sandbox_new("network-tools",L"C:\\private-path-must-not-be-logged",&error));
    CHECK(!strcmp(error.code,"EXTENSION_SANDBOX"));CHECK(strstr(error.message,"stage request")!=NULL);
    CHECK(strstr(error.message,"0x00000057")!=NULL);CHECK(strstr(error.message,"private-path")==NULL);
    CHECK(GetLastError()==ERROR_INVALID_PARAMETER);memset(&error,0,sizeof error);
    if(argc==2){
        wchar_t temp[MAX_PATH],directory[MAX_PATH],self[32768];CHECK(GetTempPathW(MAX_PATH,temp));CHECK(GetTempFileNameW(temp,L"psb",0,directory));CHECK(DeleteFileW(directory));CHECK(CreateDirectoryW(directory,NULL));CHECK(GetModuleFileNameW(NULL,self,32768));
        wchar_t *copy=sbw_path_join(directory,L"sandbox-test.exe"),*fixtures=sbw_wide(argv[1],NULL);CHECK(CopyFileW(self,copy,TRUE));wchar_t command[32768];swprintf_s(command,32768,L"\"%s\" \"%s\" child",copy,fixtures);STARTUPINFOW si={0};si.cb=sizeof si;PROCESS_INFORMATION pi={0};CHECK(CreateProcessW(copy,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi));CHECK(WaitForSingleObject(pi.hProcess,60000)==WAIT_OBJECT_0);DWORD code=1;CHECK(GetExitCodeProcess(pi.hProcess,&code));CloseHandle(pi.hThread);CloseHandle(pi.hProcess);free(copy);free(fixtures);return (int)code;
    }
    wchar_t *root=sbw_executable_directory(&error);CHECK(root);sbw_plugin_storage *s=sbw_plugin_storage_open(root,&error);CHECK(s);size_t n=0;unsigned char *data=read(argv[1],"catalog-2.json",&n);CHECK(!sbw_plugin_storage_catalog(s,(const char*)data,n,&error));free(data);data=read(argv[1],"package-2.sbe",&n);CHECK(!sbw_plugin_storage_publish(s,"statistics",data,n,&error));free(data);sbw_plugin_storage_close(s);
    wchar_t *secret_dir=sbw_path_join(root,L"host-private");sbw_store *private_store=sbw_secure_store_new(secret_dir,&error);CHECK(private_store);wchar_t *secret=sbw_path_join(secret_dir,L"secret.txt");SECURITY_ATTRIBUTES sa={sizeof sa,NULL,TRUE};HANDLE f=CreateFileW(secret,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,&sa,CREATE_NEW,0,NULL);CHECK(f!=INVALID_HANDLE_VALUE);DWORD wrote=0;CHECK(WriteFile(f,"test-host-secret",16,&wrote,NULL));CHECK(SetEnvironmentVariableW(L"SBEASY_TEST_SECRET",L"must-not-reach-plugin"));
    sbw_extension_process *p=sbw_extension_process_new(L"extensions\\statistics\\sb-easy-statistics.exe",&error);CHECK(sbw_extension_process_running(p));sbj *params=sbj_object();char *utf=sbw_utf8(secret,NULL);sbj_set_str(params,"secret",utf);free(utf);sbj_set_int(params,"parent",GetCurrentProcessId());sbj_set_int(params,"inheritable_handle",(int64_t)(uintptr_t)f);
    utf=sbw_utf8(sbw_extension_process_work_directory(p),NULL);CHECK(utf);sbj_set_str(params,"work_directory",utf);free(utf);
    sbj *result=sbw_extension_process_call(p,"probe",params,&error);CHECK(result);const char *checks[]={"appcontainer","capabilities_empty","secret_denied","code_write_denied","private_write","environment_filtered","parent_denied","handle_not_inherited","child_process_denied"};
    bool passed=true;for(size_t i=0;i<sizeof checks/sizeof *checks;++i){if(!sbj_get_bool(result,checks[i],false)){fprintf(stderr,"Boundary check failed: %s\n",checks[i]);passed=false;}}
    if(!passed)fprintf(stderr,"Private directory diagnostics: local_present=%d, local_matches_expected=%d, current_matches_expected=%d, private_write_error=%lu, expected_private_write=%d, expected_private_write_error=%lu\n",sbj_get_bool(result,"local_present",false),sbj_get_bool(result,"local_matches_expected",false),sbj_get_bool(result,"current_matches_expected",false),(unsigned long)sbj_get_int(result,"private_write_error",0),sbj_get_bool(result,"expected_private_write",false),(unsigned long)sbj_get_int(result,"expected_private_write_error",0));
    if(!passed){fprintf(stderr,"Private token diagnostics: administrators_attributes=0x%08lx\n",(unsigned long)sbj_get_int(result,"administrators_token_attributes",0));private_acl_diagnostics(sbw_extension_process_work_directory(p));}CHECK(passed);
    sbj_free(result);sbj_free(params);sbw_extension_process_free(p);CloseHandle(f);sbw_store_free(private_store);free(secret_dir);free(secret);free(root);puts("PASS: native AppContainer token, private data, immutable code, filtered environment, handle/process and job boundaries");return 0;
}
