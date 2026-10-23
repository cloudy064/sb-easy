#include "../service/extension_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv){
    if(argc>1)return 7;(void)argv;HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);sbj *request;
    while((request=extension_read(input))!=NULL){
        const sbj *params=sbj_get(request,"params");sbj *result=sbj_object();HANDLE token=NULL;DWORD is=0,n=sizeof is;
        bool app=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)&&GetTokenInformation(token,TokenIsAppContainer,&is,sizeof is,&n)&&is;sbj_set_bool(result,"appcontainer",app);if(token)CloseHandle(token);
        wchar_t *secret=sbw_wide(sbj_get_str(params,"secret",""),NULL);HANDLE f=secret?CreateFileW(secret,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL):INVALID_HANDLE_VALUE;sbj_set_bool(result,"secret_denied",f==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_ACCESS_DENIED);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);free(secret);
        wchar_t exe[32768];GetModuleFileNameW(NULL,exe,32768);f=CreateFileW(exe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);sbj_set_bool(result,"code_write_denied",f==INVALID_HANDLE_VALUE);if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);
        wchar_t local[32768];DWORD size=GetEnvironmentVariableW(L"LOCALAPPDATA",local,32768);wchar_t *path=size&&size<32768?sbw_path_join(local,L"sandbox-write-test.tmp"):NULL;
        f=path?CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL):INVALID_HANDLE_VALUE;bool wrote=false;if(f!=INVALID_HANDLE_VALUE){DWORD count=0;wrote=WriteFile(f,"ok",2,&count,NULL)&&count==2;CloseHandle(f);DeleteFileW(path);}free(path);sbj_set_bool(result,"private_write",wrote);
        sbj_set_bool(result,"environment_filtered",GetEnvironmentVariableW(L"SBEASY_TEST_SECRET",NULL,0)==0);
        HANDLE parent=OpenProcess(PROCESS_VM_READ|PROCESS_DUP_HANDLE,FALSE,(DWORD)sbj_get_int(params,"parent",0));sbj_set_bool(result,"parent_denied",parent==NULL);if(parent)CloseHandle(parent);
        DWORD flags=0;HANDLE leaked=(HANDLE)(uintptr_t)sbj_get_int(params,"inheritable_handle",0);sbj_set_bool(result,"handle_not_inherited",!GetHandleInformation(leaked,&flags));
        wchar_t command[32768];swprintf_s(command,32768,L"\"%s\" child",exe);STARTUPINFOW startup={0};startup.cb=sizeof startup;PROCESS_INFORMATION child={0};bool spawned=CreateProcessW(exe,command,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&startup,&child)!=FALSE;
        sbj_set_bool(result,"child_process_denied",!spawned);if(spawned){TerminateProcess(child.hProcess,1);CloseHandle(child.hThread);CloseHandle(child.hProcess);}
        sbj *reply=sbj_object();sbj_set_bool(reply,"ok",true);sbj_set(reply,"result",result);bool ok=extension_write(output,reply);sbj_free(reply);sbj_free(request);if(!ok)break;
    }return 0;
}
