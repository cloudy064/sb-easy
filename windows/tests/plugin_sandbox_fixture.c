#include "../service/extension_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bool private_write(const wchar_t *directory,const wchar_t *name,DWORD *error){
    *error=ERROR_INVALID_NAME;wchar_t *path=directory&&*directory?sbw_path_join(directory,name):NULL;if(!path)return false;
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);bool wrote=false;
    if(file==INVALID_HANDLE_VALUE)*error=GetLastError();else{DWORD count=0;bool ok=WriteFile(file,"ok",2,&count,NULL)!=FALSE;*error=ok?(count==2?ERROR_SUCCESS:ERROR_WRITE_FAULT):GetLastError();wrote=ok&&count==2;CloseHandle(file);DeleteFileW(path);}
    free(path);return wrote;
}
static bool environment_write(const wchar_t *key,DWORD *error){
    wchar_t *directory=sb_xcalloc(32768,sizeof *directory);DWORD size=GetEnvironmentVariableW(key,directory,32768);
    if(!size||size>=32768)directory[0]=0;bool wrote=private_write(directory,L"sandbox-temporary-write-test.tmp",error);free(directory);return wrote;
}
static bool probe_file_identity(HANDLE file,BY_HANDLE_FILE_INFORMATION *identity,bool *invalid_exception){
    *invalid_exception=false;
#ifdef _MSC_VER
    /* This negative probe deliberately uses a handle that must not have been
     * inherited. Native strict-handle checking raises instead of returning
     * ERROR_INVALID_HANDLE. Catch exactly that expected denial locally. */
    __try {
#endif
        return GetFileInformationByHandle(file,identity)!=FALSE;
#ifdef _MSC_VER
    } __except(GetExceptionCode()==STATUS_INVALID_HANDLE?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){
        *invalid_exception=true;return false;
    }
#endif
}
int main(int argc,char **argv){
    if(argc>1)return 7;(void)argv;HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);sbj *request;
    while((request=extension_read(input))!=NULL){
        const sbj *params=sbj_get(request,"params");sbj *result=sbj_object();HANDLE token=NULL;DWORD is=0,n=sizeof is;
        bool app=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)&&GetTokenInformation(token,TokenIsAppContainer,&is,sizeof is,&n)&&is;sbj_set_bool(result,"appcontainer",app);
        /* A zero-capability plugin must not gain network/device access just to
         * make AppContainer profile creation succeed. Query the actual token. */
        DWORD needed=0;if(token)GetTokenInformation(token,TokenCapabilities,NULL,0,&needed);
        TOKEN_GROUPS *capabilities=needed&&needed<=65536?sb_xmalloc(needed):NULL;
        bool no_capabilities=capabilities&&GetTokenInformation(token,TokenCapabilities,capabilities,needed,&needed)&&capabilities->GroupCount==0;
        sbj_set_bool(result,"capabilities_empty",no_capabilities);free(capabilities);
        needed=0;if(token)GetTokenInformation(token,TokenGroups,NULL,0,&needed);TOKEN_GROUPS *groups=needed&&needed<=65536?sb_xmalloc(needed):NULL;DWORD admin_attributes=0;
        if(groups&&GetTokenInformation(token,TokenGroups,groups,needed,&needed))for(DWORD i=0;i<groups->GroupCount;++i)if(IsWellKnownSid(groups->Groups[i].Sid,WinBuiltinAdministratorsSid))admin_attributes=groups->Groups[i].Attributes;
        sbj_set_int(result,"administrators_token_attributes",admin_attributes);free(groups);if(token)CloseHandle(token);
        wchar_t *secret=sbw_wide(sbj_get_str(params,"secret",""),NULL);HANDLE f=secret?CreateFileW(secret,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL):INVALID_HANDLE_VALUE;sbj_set_bool(result,"secret_denied",f==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_ACCESS_DENIED);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);free(secret);
        wchar_t exe[32768];GetModuleFileNameW(NULL,exe,32768);f=CreateFileW(exe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);sbj_set_bool(result,"code_write_denied",f==INVALID_HANDLE_VALUE);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);
        /* Windows may rewrite AppContainer environment folders. Compare them
         * with the actual host-selected work directory without logging paths,
         * and retain the raw file error before cleanup replaces GetLastError. */
        wchar_t local[32768],current[32768];DWORD size=GetEnvironmentVariableW(L"LOCALAPPDATA",local,32768),local_error=ERROR_SUCCESS,expected_error=ERROR_SUCCESS;
        bool local_valid=size&&size<32768;if(!local_valid)local[0]=0;
        DWORD current_size=GetCurrentDirectoryW(32768,current);bool current_valid=current_size&&current_size<32768;
        wchar_t *expected=sbw_wide(sbj_get_str(params,"work_directory",""),NULL);
        sbj_set_bool(result,"local_present",local_valid);
        sbj_set_bool(result,"local_matches_expected",local_valid&&expected&&CompareStringOrdinal(local,-1,expected,-1,TRUE)==CSTR_EQUAL);
        sbj_set_bool(result,"current_matches_expected",current_valid&&expected&&CompareStringOrdinal(current,-1,expected,-1,TRUE)==CSTR_EQUAL);
        sbj_set_bool(result,"local_private_write",private_write(local,L"sandbox-write-test.tmp",&local_error));
        sbj_set_int(result,"private_write_error",local_error);
        bool expected_write=private_write(expected,L"sandbox-write-expected-test.tmp",&expected_error);
        sbj_set_bool(result,"expected_private_write",expected_write);
        /* Production capture and HTTP workers receive this explicit directory.
         * LOCALAPPDATA is Windows-owned and may be rewritten independently. */
        sbj_set_bool(result,"private_write",expected_write&&sbj_get_bool(result,"current_matches_expected",false));
        sbj_set_int(result,"expected_private_write_error",expected_error);free(expected);
        DWORD temp_error=0,tmp_error=0;bool temp_write=environment_write(L"TEMP",&temp_error),tmp_write=environment_write(L"TMP",&tmp_error);
        sbj_set_bool(result,"temporary_write",temp_write&&tmp_write);sbj_set_int(result,"temp_write_error",temp_error);sbj_set_int(result,"tmp_write_error",tmp_error);
        sbj_set_bool(result,"environment_filtered",GetEnvironmentVariableW(L"SBEASY_TEST_SECRET",NULL,0)==0);
        HANDLE parent=OpenProcess(PROCESS_VM_READ|PROCESS_DUP_HANDLE,FALSE,(DWORD)sbj_get_int(params,"parent",0));sbj_set_bool(result,"parent_denied",parent==NULL);if(parent)CloseHandle(parent);
        /* Handle values are process-local slots and can be reused by the
         * worker. Only the same underlying host secret file is a leak. */
        HANDLE leaked=(HANDLE)(uintptr_t)sbj_get_int(params,"inheritable_handle",0);BY_HANDLE_FILE_INFORMATION identity={0};
        bool invalid_exception=false;
        bool inherited_secret=probe_file_identity(leaked,&identity,&invalid_exception)&&identity.dwVolumeSerialNumber==(DWORD)sbj_get_int(params,"secret_volume",0)&&identity.nFileIndexHigh==(DWORD)sbj_get_int(params,"secret_index_high",0)&&identity.nFileIndexLow==(DWORD)sbj_get_int(params,"secret_index_low",0);
        sbj_set_bool(result,"handle_not_inherited",!inherited_secret);
        sbj_set_bool(result,"invalid_handle_exception",invalid_exception);
        wchar_t command[32768];swprintf_s(command,32768,L"\"%s\" child",exe);STARTUPINFOW startup={0};startup.cb=sizeof startup;PROCESS_INFORMATION child={0};bool spawned=CreateProcessW(exe,command,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&startup,&child)!=FALSE;
        sbj_set_bool(result,"child_process_denied",!spawned);if(spawned){TerminateProcess(child.hProcess,1);CloseHandle(child.hThread);CloseHandle(child.hProcess);}
        sbj *reply=sbj_object();sbj_set_bool(reply,"ok",true);sbj_set(reply,"result",result);bool ok=extension_write(output,reply);sbj_free(reply);sbj_free(request);if(!ok)break;
    }return 0;
}
