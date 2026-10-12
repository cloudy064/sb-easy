#include "capture.h"
#include "extension_wire.h"
#include <string.h>
int main(void) {
    HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);sbw_capture *capture=NULL;sbj *request;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    while((request=extension_read(input))!=NULL) {
        const char *method=sbj_get_str(request,"method","");const sbj *params=sbj_get(request,"params");sbw_error error={0};sbj *value=NULL;
        if(sb_streq(method,"init")&&!capture) {
            wchar_t *work=sbw_wide(sbj_get_str(params,"work",""),&error);if(work)capture=sbw_capture_new(work,sbj_get(params,"identity"),&error);free(work);
            if(capture)value=sbj_object();
        } else if(sb_streq(method,"validate"))value=sbw_capture_validate(params,&error);
        else if(capture) {
            int result=0;
            if(sb_streq(method,"snapshot"))value=sbw_capture_snapshot(capture);
            else if(sb_streq(method,"configure"))result=sbw_capture_configure(capture,params,&error);
            else if(sb_streq(method,"observe")) {
                wchar_t *interface=sbw_wide(sbj_get_str(params,"interface",""),NULL);
                sbw_capture_observe(capture,(DWORD)sbj_get_int(params,"pid",0),interface,sbj_get(params,"connections"));free(interface);
            } else if(sb_streq(method,"stop"))sbw_capture_stop(capture);
            else if(sb_streq(method,"rotate"))result=sbw_capture_rotate(capture,&error);
            else if(sb_streq(method,"delete"))result=sbw_capture_delete(capture,sbj_get_str(params,"digest",""),&error);
            else if(sb_streq(method,"uploaded"))result=sbw_capture_mark_uploaded(capture,sbj_get_str(params,"digest",""),&error);
            else if(sb_streq(method,"read")) {
                unsigned char *bytes=NULL;size_t size=0;result=sbw_capture_read(capture,sbj_get_str(params,"digest",""),&bytes,&size,&error);
                if(!result){char *hex=sb_xmalloc(size*2+1);for(size_t i=0;i<size;++i){hex[2*i]="0123456789abcdef"[bytes[i]>>4];hex[2*i+1]="0123456789abcdef"[bytes[i]&15];}hex[size*2]=0;value=sbj_object();sbj_set_str(value,"hex",hex);SecureZeroMemory(hex,size*2);free(hex);}if(bytes)SecureZeroMemory(bytes,size);free(bytes);
            } else result=sbw_fail(&error,"INVALID_REQUEST","Unknown extension operation.");
            if(!result&&!value)value=sbj_object();
        }
        sbj *response=sbj_object();sbj_set_bool(response,"ok",value!=NULL);
        if(value)sbj_set(response,"result",value);else {sbj_set_str(response,"code",error.code[0]?error.code:"EXTENSION_FAILED");sbj_set_str(response,"message",error.message[0]?error.message:"Capture extension failed.");}
        bool ok=extension_write(output,response);sbj_free(response);sbj_free(request);if(!ok)break;
    }
    sbw_capture_free(capture);return 0;
}
