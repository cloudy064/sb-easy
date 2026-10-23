/* The host brokers only a fixed, read-only TUN driver handle. Parsing, BPF,
 * attribution and file storage remain in the isolated optional worker. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "extensions.h"
#include "extension_process.h"
#include "capture_broker.h"
struct sbw_capture { sbw_extension_process *process;sbw_capture_broker *broker;DWORD attempted_pid;bool enabled;char issue[256]; };
bool sbw_capture_worker_running(sbw_capture *c){return c&&sbw_extension_process_running(c->process);}
static sbj *call(sbw_capture *c,const char *method,const sbj *params,sbw_error *error){return sbw_extension_process_call(c?c->process:NULL,method,params,error);}
sbw_capture *sbw_capture_new(const wchar_t *work,const sbj *identity,sbw_error *error) {
    (void)work;
    if(!sbw_extension_enabled()){sbw_fail(error,"EXTENSION_MISSING","Enable capture first.");return NULL;}
    sbw_capture *c=sb_xcalloc(1,sizeof *c);c->process=sbw_extension_process_new(L"extensions\\capture\\sb-easy-capture.exe",error);
    const wchar_t *private_work=sbw_extension_process_work_directory(c->process);if(!private_work)return c;
    sbj *params=sbj_object(),*scope=sbj_object();char *directory=sbw_utf8(private_work,error);sbj_set_str(params,"work",directory);free(directory);
    sbj_set_str(scope,"server",sbj_get_str(identity,"server",""));sbj_set_str(scope,"host_id",sbj_get_str(identity,"host_id",""));sbj_set(params,"identity",scope);
    sbj *result=call(c,"init",params,error);sbj_free(params);
    if(!result){sbw_extension_process_free(c->process);c->process=NULL;}sbj_free(result);
    sbj *snapshot=call(c,"snapshot",NULL,NULL);c->enabled=sbj_get_bool(sbj_get(snapshot,"config"),"enabled",false);sbj_free(snapshot);return c;
}
void sbw_capture_free(sbw_capture *c) {if(!c)return;sbw_capture_broker_stop(c->broker);sbj *v=call(c,"stop",NULL,NULL);sbj_free(v);sbw_extension_process_free(c->process);sbw_capture_broker_free(c->broker);free(c);}
sbj *sbw_capture_worker_validate(sbw_capture *c,const sbj *config,sbw_error *error){return call(c,"validate",config,error);}
sbj *sbw_capture_snapshot(sbw_capture *c){sbj *out=call(c,"snapshot",NULL,NULL);if(out&&c->issue[0])sbj_set_str(out,"issue",c->issue);return out;}
static int action(sbw_capture *c,const char *method,const sbj *params,sbw_error *error){sbj *v=call(c,method,params,error);if(!v)return -1;sbj_free(v);return 0;}
int sbw_capture_configure(sbw_capture *c,const sbj *config,sbw_error *e){if(c){sbw_capture_broker_stop(c->broker);c->enabled=false;c->attempted_pid=0;c->issue[0]=0;}int result=action(c,"configure",config,e);if(!result)c->enabled=sbj_get_bool(config,"enabled",false);return result;}
void sbw_capture_stop(sbw_capture *c){if(c){sbw_capture_broker_stop(c->broker);c->attempted_pid=0;action(c,"stop",NULL,NULL);}}
int sbw_capture_rotate(sbw_capture *c,sbw_error *e){return action(c,"rotate",NULL,e);}
void sbw_capture_observe(sbw_capture *c,DWORD pid,const wchar_t *interface_name,const sbj *connections){
    if(!c)return;if(!sbw_capture_worker_running(c)){sbw_capture_broker_stop(c->broker);return;}
    if(!pid||!interface_name||!c->enabled){sbw_capture_stop(c);return;}
    if(c->attempted_pid!=pid){
        sbw_capture_stop(c);c->attempted_pid=pid;c->issue[0]=0;sbw_error error={0};
        if(!c->broker){wchar_t *root=sbw_executable_directory(&error);c->broker=root?sbw_capture_broker_new(root,&error):NULL;free(root);}
        DWORD index=0;HANDLE source=c->broker?sbw_capture_broker_open(c->broker,interface_name,&index,&error):INVALID_HANDLE_VALUE,remote=NULL;
        if(source==INVALID_HANDLE_VALUE||!sbw_extension_process_duplicate(c->process,source,&remote)){sbw_capture_broker_stop(c->broker);strcpy_s(c->issue,sizeof c->issue,error.message[0]?error.message:"The capture broker could not transfer a read-only driver handle.");return;}
        sbj *params=sbj_object();sbj_set_int(params,"handle",(int64_t)(uintptr_t)remote);sbj_set_int(params,"pid",pid);sbj_set_int(params,"interface_index",index);
        sbj *accepted=call(c,"broker",params,&error);sbj_free(params);if(!accepted){sbw_capture_broker_stop(c->broker);strcpy_s(c->issue,sizeof c->issue,error.message);return;}sbj_free(accepted);
    }
    sbj *p=sbj_object();char *name=interface_name?sbw_utf8(interface_name,NULL):NULL;
    sbj_set_int(p,"pid",pid);sbj_set_str(p,"interface",name?name:"");free(name);sbj_set(p,"connections",connections?sbj_clone(connections):sbj_object());action(c,"observe",p,NULL);sbj_free(p);
}
bool sbw_capture_digest_valid(const char *s){if(!s||strlen(s)!=64)return false;for(;*s;++s)if(!strchr("0123456789abcdef",*s))return false;return true;}
static int digest_action(sbw_capture *c,const char *method,const char *digest,sbw_error *e){sbj *p=sbj_object();sbj_set_str(p,"digest",digest);int r=action(c,method,p,e);sbj_free(p);return r;}
int sbw_capture_delete(sbw_capture *c,const char *digest,sbw_error *e){return digest_action(c,"delete",digest,e);}
int sbw_capture_mark_uploaded(sbw_capture *c,const char *digest,sbw_error *e){return digest_action(c,"uploaded",digest,e);}
int sbw_capture_read(sbw_capture *c,const char *digest,unsigned char **bytes,size_t *size,sbw_error *e){
    *bytes=NULL;*size=0;sbj *p=sbj_object();sbj_set_str(p,"digest",digest);sbj *v=call(c,"read",p,e);sbj_free(p);if(!v)return -1;
    const char *hex=sbj_get_str(v,"hex","");size_t n=strlen(hex);if(!n||n%2||n>1572864||strspn(hex,"0123456789abcdef")!=n){sbj_free(v);return sbw_fail(e,"EXTENSION_FAILED","Invalid capture data from extension.");}
    const char *digits="0123456789abcdef";
    *size=n/2;*bytes=sb_xmalloc(*size);for(size_t i=0;i<*size;++i)(*bytes)[i]=(unsigned char)(((strchr(digits,hex[2*i])-digits)<<4)|(strchr(digits,hex[2*i+1])-digits));sbj_free(v);return 0;
}
bool sbw_capture_wifi(void){MIB_IF_TABLE2 *table=NULL;bool wifi=false;if(GetIfTable2(&table)!=NO_ERROR)return false;for(ULONG i=0;i<table->NumEntries;++i)if(table->Table[i].Type==IF_TYPE_IEEE80211&&table->Table[i].OperStatus==IfOperStatusUp)wifi=true;FreeMibTable(table);return wifi;}
