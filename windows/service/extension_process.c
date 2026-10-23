#include "extension_process.h"
#include "extensions.h"
#include "extension_wire.h"
#include "extension_sandbox.h"
#include "extension_store.h"
#include <stdio.h>
struct sbw_extension_process { SRWLOCK lock; HANDLE process,job,input,output,executable; sbw_extension_sandbox *sandbox; bool failed; };
static void close_worker(sbw_extension_process *c) {
    if(c->job){CloseHandle(c->job);c->job=NULL;}
    if(c->process){if(WaitForSingleObject(c->process,0)==WAIT_TIMEOUT)TerminateProcess(c->process,1);WaitForSingleObject(c->process,3000);CloseHandle(c->process);c->process=NULL;}
    if(c->input){CloseHandle(c->input);c->input=NULL;}if(c->output){CloseHandle(c->output);c->output=NULL;}
    if(c->executable){CloseHandle(c->executable);c->executable=NULL;}
    sbw_extension_sandbox_free(c->sandbox);c->sandbox=NULL;
}
bool sbw_extension_process_running(sbw_extension_process *c) { return c&&c->process&&!c->failed&&WaitForSingleObject(c->process,0)==WAIT_TIMEOUT; }
const wchar_t *sbw_extension_process_work_directory(sbw_extension_process *c){return c?sbw_extension_sandbox_directory(c->sandbox):NULL;}
bool sbw_extension_process_duplicate(sbw_extension_process *c,HANDLE source,HANDLE *remote){return c&&sbw_extension_process_running(c)&&DuplicateHandle(GetCurrentProcess(),source,c->process,remote,0,FALSE,DUPLICATE_SAME_ACCESS);}
typedef struct exchange {sbw_extension_process *capture;sbj *request,*response;} exchange;
static DWORD WINAPI exchange_main(void *context) {
    exchange *x=context;if(extension_write(x->capture->input,x->request))x->response=extension_read(x->capture->output);return 0;
}
sbj *sbw_extension_process_call(sbw_extension_process *c,const char *method,const sbj *params,sbw_error *error) {
    if(!c){sbw_fail(error,"EXTENSION_MISSING","Extension is not enabled.");return NULL;}
    AcquireSRWLockExclusive(&c->lock);sbj *result=NULL;
    if(!sbw_extension_process_running(c)){sbw_fail(error,"EXTENSION_FAILED","Extension stopped. Re-enable it in Extensions.");goto done;}
    exchange x={c,sbj_object(),NULL};sbj_set_str(x.request,"method",method);sbj_set(x.request,"params",params?sbj_clone(params):sbj_object());
    HANDLE thread=CreateThread(NULL,0,exchange_main,&x,0,NULL);
    if(!thread||WaitForSingleObject(thread,sb_streq(method,"start")?20000:3000)!=WAIT_OBJECT_0) {
        c->failed=true;
        /* Terminating the optional child releases both pipe ends and unblocks
         * any pending synchronous read/write. The proxy core is independent. */
        if(thread)CancelSynchronousIo(thread);
        if(c->process)TerminateProcess(c->process,1);
        if(thread)WaitForSingleObject(thread,INFINITE);
    }
    if(thread)CloseHandle(thread);
    if(!x.response){c->failed=true;close_worker(c);sbw_fail(error,"EXTENSION_FAILED","Extension did not respond. Proxy remains connected.");}
    else if(!sbj_get_bool(x.response,"ok",false))sbw_fail(error,sbj_get_str(x.response,"code","EXTENSION_FAILED"),sbj_get_str(x.response,"message","Extension operation failed."));
    else result=sbj_clone(sbj_get(x.response,"result"));
    sbj_free(x.request);sbj_free(x.response);
done:ReleaseSRWLockExclusive(&c->lock);return result;
}
sbw_extension_process *sbw_extension_process_new(const wchar_t *relative,sbw_error *error) {
    sbw_extension_process *c=sb_xcalloc(1,sizeof *c);InitializeSRWLock(&c->lock);
    SECURITY_ATTRIBUTES sa={sizeof sa,NULL,TRUE};HANDLE child_in=NULL,child_out=NULL;LPPROC_THREAD_ATTRIBUTE_LIST attributes=NULL;
    const char *id=!wcscmp(relative,L"extensions\\capture\\sb-easy-capture.exe")?"capture":!wcscmp(relative,L"extensions\\statistics\\sb-easy-statistics.exe")?"statistics":!wcscmp(relative,L"extensions\\http-debug\\sb-easy-http-debug.exe")?"http-debug":NULL;
    wchar_t *exe=id?sbw_extension_path(relative):NULL,*root=id?sbw_executable_directory(error):NULL;
    if(!id||!root||!sbw_store_verified(id,error))goto failed;
    c->sandbox=sbw_extension_sandbox_new(id,root,error);if(!c->sandbox)goto failed;
    c->executable=CreateFileW(exe,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(c->executable==INVALID_HANDLE_VALUE){c->executable=NULL;goto failed;}
    if(!exe||!CreatePipe(&child_in,&c->input,&sa,0)||!CreatePipe(&c->output,&child_out,&sa,0))goto failed;
    if(!SetHandleInformation(c->input,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(c->output,HANDLE_FLAG_INHERIT,0))goto failed;
    SIZE_T size=0;InitializeProcThreadAttributeList(NULL,2,0,&size);attributes=sb_xmalloc(size);
    if(!InitializeProcThreadAttributeList(attributes,2,0,&size)){free(attributes);attributes=NULL;goto failed;}
    HANDLE inherited[]={child_in,child_out};
    if(!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof inherited,NULL,NULL))goto failed;
    if(!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,(void*)sbw_extension_sandbox_capabilities(c->sandbox),sizeof(SECURITY_CAPABILITIES),NULL,NULL))goto failed;
    STARTUPINFOEXW startup={0};startup.StartupInfo.cb=sizeof startup;startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=child_in;startup.StartupInfo.hStdOutput=child_out;startup.StartupInfo.hStdError=child_out;startup.lpAttributeList=attributes;
    c->job=CreateJobObjectW(NULL,NULL);JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit=sb_streq(id,"http-debug")?4:1;limits.ProcessMemoryLimit=512U*1024U*1024U;limits.JobMemoryLimit=768U*1024U*1024U;
    if(!c->job||!SetInformationJobObject(c->job,JobObjectExtendedLimitInformation,&limits,sizeof limits))goto failed;
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu={0};cpu.ControlFlags=JOB_OBJECT_CPU_RATE_CONTROL_ENABLE|JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;cpu.CpuRate=2500;
    if(!SetInformationJobObject(c->job,JobObjectCpuRateControlInformation,&cpu,sizeof cpu))goto failed;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui={JOB_OBJECT_UILIMIT_DESKTOP|JOB_OBJECT_UILIMIT_DISPLAYSETTINGS|JOB_OBJECT_UILIMIT_EXITWINDOWS|JOB_OBJECT_UILIMIT_GLOBALATOMS|JOB_OBJECT_UILIMIT_HANDLES|JOB_OBJECT_UILIMIT_READCLIPBOARD|JOB_OBJECT_UILIMIT_WRITECLIPBOARD|JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS};
    if(!SetInformationJobObject(c->job,JobObjectBasicUIRestrictions,&ui,sizeof ui))goto failed;
    PROCESS_INFORMATION pi={0};
    if(!CreateProcessW(exe,NULL,NULL,NULL,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT,(void*)sbw_extension_sandbox_environment(c->sandbox),sbw_extension_sandbox_directory(c->sandbox),&startup.StartupInfo,&pi))goto failed;
    c->process=pi.hProcess;
    if(!sbw_extension_sandbox_verify_process(c->sandbox,c->process)||!AssignProcessToJobObject(c->job,c->process)||ResumeThread(pi.hThread)==(DWORD)-1){TerminateProcess(c->process,1);CloseHandle(pi.hThread);goto failed;}
    CloseHandle(pi.hThread);CloseHandle(child_in);child_in=NULL;CloseHandle(child_out);child_out=NULL;
    DeleteProcThreadAttributeList(attributes);free(attributes);attributes=NULL;free(exe);exe=NULL;free(root);root=NULL;
    return c;
failed:
    if(attributes){DeleteProcThreadAttributeList(attributes);free(attributes);}free(exe);free(root);if(child_in)CloseHandle(child_in);if(child_out)CloseHandle(child_out);
    /* Keep a faulted descriptor so the monitor does not launch a broken
     * extension every two seconds. An explicit re-enable resets it. */
    close_worker(c);c->failed=true;if(!error||!error->code[0])sbw_fail(error,"EXTENSION_FAILED","Could not start the isolated extension.");return c;
}

void sbw_extension_process_free(sbw_extension_process *c){if(c){close_worker(c);free(c);}}
