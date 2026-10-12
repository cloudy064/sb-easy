/* Optional statistics live in a separate worker; the base only brokers bounded
 * snapshots and encrypted persistence. No aggregation implementation is linked. */
#include "traffic.h"
#include "extensions.h"
#include "extension_process.h"
#include <stdlib.h>
struct sbw_traffic { sbw_extension_process *process; };
bool sbw_traffic_running(sbw_traffic *t){return t&&sbw_extension_process_running(t->process);}
static sbj *call(const sbw_traffic *t,const char *method,const sbj *params){return t?sbw_extension_process_call(t->process,method,params,NULL):NULL;}
sbw_traffic *sbw_traffic_new(void){
    if(!sbw_extension_is_enabled("statistics"))return NULL;
    sbw_traffic *t=sb_xcalloc(1,sizeof *t);t->process=sbw_extension_process_new(L"extensions\\statistics\\sb-easy-statistics.exe",NULL);return t;
}
void sbw_traffic_free(sbw_traffic *t){if(t){sbw_extension_process_free(t->process);free(t);}}
void sbw_traffic_record(sbw_traffic *t,const sbj *snapshot,DWORD pid){
    if(!sbw_traffic_running(t))return;
    sbj *p=sbj_object();sbj_set(p,"snapshot",sbj_clone(snapshot));sbj_set_int(p,"pid",pid);sbj *r=call(t,"record",p);sbj_free(r);sbj_free(p);
}
void sbw_traffic_new_core(sbw_traffic *t){sbj *r=call(t,"new_core",NULL);sbj_free(r);}
void sbw_traffic_clear(sbw_traffic *t){sbj *r=call(t,"clear",NULL);sbj_free(r);}
sbj *sbw_traffic_snapshot(const sbw_traffic *t){return call(t,"snapshot",NULL);}
bool sbw_traffic_restore(sbw_traffic *t,const sbj *saved){sbj *r=call(t,"restore",saved);bool ok=r!=NULL;sbj_free(r);return ok;}
