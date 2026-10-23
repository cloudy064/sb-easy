#include "../service/capture_broker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do{if(!(v)){fprintf(stderr,"line %d: %s\n",__LINE__,#v);return 1;}}while(0)
int main(int argc,char **argv){
    unsigned char fake[64]={0};CHECK(!sbw_capture_broker_vendor(L"WinDivert.dll",fake,sizeof fake));CHECK(!sbw_capture_broker_vendor(L"other.dll",fake,sizeof fake));CHECK(!sbw_capture_broker_vendor(L"WinDivert64.sys",NULL,0));
    if(argc>1){const char *names[]={"WinDivert.dll","WinDivert64.sys"};const wchar_t *wide[]={L"WinDivert.dll",L"WinDivert64.sys"};for(size_t i=0;i<2;++i){char path[4096];snprintf(path,sizeof path,"%s/%s",argv[1],names[i]);FILE *f=fopen(path,"rb");CHECK(f);fseek(f,0,SEEK_END);long n=ftell(f);CHECK(n>0&&n<4*1024*1024);rewind(f);unsigned char *bytes=sb_xmalloc((size_t)n);CHECK(fread(bytes,1,(size_t)n,f)==(size_t)n);fclose(f);CHECK(sbw_capture_broker_vendor(wide[i],bytes,(size_t)n));bytes[n/2]^=1;CHECK(!sbw_capture_broker_vendor(wide[i],bytes,(size_t)n));free(bytes);}}
    puts("PASS: broker rejects unknown privileged code; vendor bytes and corruption checks never load a driver");return 0;
}
