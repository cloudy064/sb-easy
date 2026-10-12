#ifndef SBW_EXTENSION_WIRE_H
#define SBW_EXTENSION_WIRE_H
#include "../common.h"
#include <stdlib.h>
#include <string.h>
#define SBW_EXTENSION_FRAME (2U*1024U*1024U)
static bool extension_io(HANDLE h,void *buffer,DWORD size,bool write) {
    DWORD offset=0;
    while(offset<size){DWORD n=0;BOOL ok=write?WriteFile(h,(char*)buffer+offset,size-offset,&n,NULL):ReadFile(h,(char*)buffer+offset,size-offset,&n,NULL);if(!ok||!n)return false;offset+=n;}
    return true;
}
static sbj *extension_read(HANDLE h) {
    DWORD size=0;if(!extension_io(h,&size,4,false)||!size||size>SBW_EXTENSION_FRAME)return NULL;
    char *data=sb_xmalloc(size);sbj *value=extension_io(h,data,size,false)?sbw_json_parse(data,size,40,NULL):NULL;
    SecureZeroMemory(data,size);free(data);return value;
}
static bool extension_write(HANDLE h,const sbj *value) {
    char *data=sbj_dump(value,-1);size_t n=data?strlen(data):0;DWORD size=(DWORD)n;
    bool ok=n&&n<=SBW_EXTENSION_FRAME&&extension_io(h,&size,4,true)&&extension_io(h,data,size,true);
    if(data)SecureZeroMemory(data,n);free(data);return ok;
}
#endif
