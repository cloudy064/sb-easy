/* The base service never links libpcap or loads WinDivert. Only this bounded
 * private pipe connects it to the optional, separately packaged worker. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "extensions.h"
#include "extension_process.h"
struct sbw_capture { sbw_extension_process *process; };
bool sbw_capture_worker_running(sbw_capture *c){return c&&sbw_extension_process_running(c->process);}
static sbj *call(sbw_capture *c,const char *method,const sbj *params,sbw_error *error){return sbw_extension_process_call(c?c->process:NULL,method,params,error);}
sbw_capture *sbw_capture_new(const wchar_t *work,const sbj *identity,sbw_error *error) {
    if(!sbw_extension_enabled()){sbw_fail(error,"EXTENSION_MISSING","Enable capture first.");return NULL;}
    sbw_capture *c=sb_xcalloc(1,sizeof *c);c->process=sbw_extension_process_new(L"extensions\\capture\\sb-easy-capture.exe",error);
    sbj *params=sbj_object(),*scope=sbj_object();char *directory=sbw_utf8(work,error);sbj_set_str(params,"work",directory);free(directory);
    sbj_set_str(scope,"server",sbj_get_str(identity,"server",""));sbj_set_str(scope,"host_id",sbj_get_str(identity,"host_id",""));sbj_set(params,"identity",scope);
    sbj *result=call(c,"init",params,error);sbj_free(params);
    if(!result){sbw_extension_process_free(c->process);c->process=NULL;}sbj_free(result);return c;
}
void sbw_capture_free(sbw_capture *c) {if(!c)return;sbj *v=call(c,"stop",NULL,NULL);sbj_free(v);sbw_extension_process_free(c->process);free(c);}
sbj *sbw_capture_worker_validate(sbw_capture *c,const sbj *config,sbw_error *error){return call(c,"validate",config,error);}
sbj *sbw_capture_snapshot(sbw_capture *c){return call(c,"snapshot",NULL,NULL);}
static int action(sbw_capture *c,const char *method,const sbj *params,sbw_error *error){sbj *v=call(c,method,params,error);if(!v)return -1;sbj_free(v);return 0;}
int sbw_capture_configure(sbw_capture *c,const sbj *config,sbw_error *e){return action(c,"configure",config,e);}
void sbw_capture_stop(sbw_capture *c){if(c)action(c,"stop",NULL,NULL);}
int sbw_capture_rotate(sbw_capture *c,sbw_error *e){return action(c,"rotate",NULL,e);}
void sbw_capture_observe(sbw_capture *c,DWORD pid,const wchar_t *interface_name,const sbj *connections){
    if(!c||!sbw_capture_worker_running(c))return;sbj *p=sbj_object();char *name=interface_name?sbw_utf8(interface_name,NULL):NULL;
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
