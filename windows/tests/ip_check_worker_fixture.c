#include "../service/extension_wire.h"
#include <stdio.h>

/* A private IPC fixture: cleanup only happens after the parent closes stdin.
 * The hanging mode exercises bounded job termination without network access. */
int main(void) {
    HANDLE input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);
    wchar_t *marker=NULL;bool hang=false;
    for(;;) {
        sbj *request=extension_read(input);if(!request)break;
        const sbj *params=sbj_get(request,"params");
        free(marker);marker=sbw_wide(sbj_get_str(params,"marker",""),NULL);hang=sbj_get_bool(params,"hang",false);
        sbj *reply=sbj_object(),*result=sbj_object();sbj_set_bool(reply,"ok",true);sbj_set_int(result,"pid",GetCurrentProcessId());sbj_set(reply,"result",result);
        bool sent=extension_write(output,reply);sbj_free(reply);sbj_free(request);if(!sent)break;
    }
    if(hang)Sleep(INFINITE);
    Sleep(200);
    if(marker&&*marker) {
        HANDLE f=CreateFileW(marker,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
        if(f!=INVALID_HANDLE_VALUE){DWORD n;WriteFile(f,"clean",5,&n,NULL);CloseHandle(f);}
    }
    free(marker);return 0;
}
