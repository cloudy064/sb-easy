#include "traffic.h"
#include "extension_wire.h"
int main(void) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    sbw_traffic *traffic=sbw_traffic_new();sbj *request;bool baseline=true;
    HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);
    while((request=extension_read(input))!=NULL) {
        const char *method=sbj_get_str(request,"method","");const sbj *params=sbj_get(request,"params");sbj *value=NULL;
        if(sb_streq(method,"snapshot"))value=sbw_traffic_snapshot(traffic);
        else if(sb_streq(method,"record")){
            /* First sample establishes counters only: never recount traffic
             * accumulated before installation, while disabled, or before restart. */
            sbj *saved=baseline?sbw_traffic_snapshot(traffic):NULL;
            sbw_traffic_record(traffic,sbj_get(params,"snapshot"),(DWORD)sbj_get_int(params,"pid",0));
            if(saved){sbw_traffic_restore(traffic,saved);sbj_free(saved);baseline=false;}value=sbj_object();
        }
        else if(sb_streq(method,"restore")){if(sbw_traffic_restore(traffic,params))value=sbj_object();}
        else if(sb_streq(method,"clear")){sbw_traffic_clear(traffic);value=sbj_object();}
        else if(sb_streq(method,"new_core")){sbw_traffic_new_core(traffic);value=sbj_object();}
        sbj *response=sbj_object();sbj_set_bool(response,"ok",value!=NULL);
        if(value)sbj_set(response,"result",value);else{sbj_set_str(response,"code","STATISTICS_INVALID");sbj_set_str(response,"message","Statistics data or operation is invalid.");}
        bool ok=extension_write(output,response);sbj_free(response);sbj_free(request);if(!ok)break;
    }
    sbw_traffic_free(traffic);return 0;
}
