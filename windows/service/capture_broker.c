#include <winsock2.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "capture_broker.h"
#include "secure_store.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Exact files from the already pinned WinDivert-2.2.2-A release archive.
 * Catalog publishers cannot change privileged code through a plugin update. */
static const struct {const wchar_t *name;const char *sha;} vendor[]={
    {L"WinDivert.dll","c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"},
    {L"WinDivert64.sys","8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"}
};
typedef HANDLE (*open_fn)(const char*,int,INT16,UINT64);
typedef BOOL (*close_fn)(HANDLE);
typedef BOOL (*shutdown_fn)(HANDLE,int);
typedef BOOL (*param_fn)(HANDLE,int,UINT64);
struct sbw_capture_broker {sbw_store *directory_pin;HMODULE library;HANDLE driver,files[2];open_fn open;close_fn close;shutdown_fn shutdown;param_fn param;};
bool sbw_capture_broker_vendor(const wchar_t *name,const void *data,size_t length){
    if(!data||!length||length>4U*1024U*1024U)return false;const char *expected=NULL;for(size_t i=0;i<2;++i)if(!wcscmp(name,vendor[i].name))expected=vendor[i].sha;if(!expected)return false;
    BCRYPT_ALG_HANDLE a=NULL;unsigned char digest[32];if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)return false;NTSTATUS status=BCryptHash(a,NULL,0,(PUCHAR)data,(ULONG)length,digest,32);BCryptCloseAlgorithmProvider(a,0);if(status<0)return false;char actual[65];for(size_t i=0;i<32;++i)sprintf_s(actual+2*i,3,"%02x",digest[i]);return !strcmp(actual,expected);
}
static unsigned char *read_vendor(const wchar_t *path,const wchar_t *name,size_t *length,HANDLE *held){
    *held=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(*held==INVALID_HANDLE_VALUE){*held=NULL;return NULL;}
    FILE_ATTRIBUTE_TAG_INFO info;LARGE_INTEGER size;DWORD count=0;unsigned char *data=NULL;
    if(!GetFileInformationByHandleEx(*held,FileAttributeTagInfo,&info,sizeof info)||(info.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||!GetFileSizeEx(*held,&size)||size.QuadPart<1||size.QuadPart>4*1024*1024)goto fail;
    data=sb_xmalloc((size_t)size.QuadPart);if(!ReadFile(*held,data,(DWORD)size.QuadPart,&count,NULL)||count!=(DWORD)size.QuadPart||!sbw_capture_broker_vendor(name,data,count))goto fail;*length=count;return data;
fail:free(data);CloseHandle(*held);*held=NULL;return NULL;
}
static bool stage_vendor(sbw_capture_broker *b,const wchar_t *installation,const wchar_t *directory,size_t index){
    wchar_t source_name[160];swprintf_s(source_name,160,L"extensions\\capture\\capture\\%s",vendor[index].name);wchar_t *source=sbw_path_join(installation,source_name),*dest=sbw_path_join(directory,vendor[index].name);size_t length=0;HANDLE source_file=NULL;
    unsigned char *bytes=read_vendor(dest,vendor[index].name,&length,&b->files[index]);bool ok=bytes!=NULL;free(bytes);if(ok)goto done;
    /* Never load from the plugin directory. Copy only independently pinned
     * bytes into a host-only directory and pin the destination before loading. */
    bytes=read_vendor(source,vendor[index].name,&length,&source_file);if(!bytes)goto done;
    HANDLE f=CreateFileW(dest,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,NULL);
    if(f!=INVALID_HANDLE_VALUE){DWORD count=0;ok=WriteFile(f,bytes,(DWORD)length,&count,NULL)&&count==length&&FlushFileBuffers(f);CloseHandle(f);if(!ok)DeleteFileW(dest);}free(bytes);bytes=NULL;
    if(ok){bytes=read_vendor(dest,vendor[index].name,&length,&b->files[index]);ok=bytes!=NULL;free(bytes);}
done:if(source_file)CloseHandle(source_file);free(source);free(dest);return ok;
}
sbw_capture_broker *sbw_capture_broker_new(const wchar_t *installation,sbw_error *error){
    sbw_capture_broker *b=sb_xcalloc(1,sizeof *b);b->driver=INVALID_HANDLE_VALUE;wchar_t *directory=sbw_path_join(installation,L".capture-driver-2.2.2");b->directory_pin=sbw_secure_store_new(directory,error);
    if(!b->directory_pin||!stage_vendor(b,installation,directory,0)||!stage_vendor(b,installation,directory,1))goto fail;
    wchar_t *dll=sbw_path_join(directory,L"WinDivert.dll");b->library=LoadLibraryExW(dll,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);free(dll);if(!b->library)goto fail;
    b->open=(open_fn)(void*)GetProcAddress(b->library,"WinDivertOpen");b->close=(close_fn)(void*)GetProcAddress(b->library,"WinDivertClose");b->shutdown=(shutdown_fn)(void*)GetProcAddress(b->library,"WinDivertShutdown");b->param=(param_fn)(void*)GetProcAddress(b->library,"WinDivertSetParam");
    if(!b->open||!b->close||!b->shutdown||!b->param)goto fail;free(directory);return b;
fail:free(directory);sbw_capture_broker_free(b);sbw_fail(error,"CAPTURE_DRIVER_TRUST","The capture driver does not match the host's pinned vendor release. Capture was not started.");return NULL;
}
HANDLE sbw_capture_broker_open(sbw_capture_broker *b,const wchar_t *interface_name,DWORD *index,sbw_error *error){
    sbw_capture_broker_stop(b);NET_LUID luid;NET_IFINDEX value;
    if(!b||!interface_name||ConvertInterfaceAliasToLuid(interface_name,&luid)!=NO_ERROR||ConvertInterfaceLuidToIndex(&luid,&value)!=NO_ERROR||!value){sbw_fail(error,"CAPTURE_INTERFACE","The managed TUN interface is unavailable.");return INVALID_HANDLE_VALUE;}
    char filter[120];sprintf_s(filter,sizeof filter,"(tcp or udp) and ifIdx == %lu",value);
    /* NETWORK=0, SNIFF=1, RECV_ONLY=4. Driver enforces non-injection even if
     * a compromised worker tries to invoke WinDivertSend on its handle. */
    b->driver=b->open(filter,0,0,UINT64_C(0x0005));
    if(b->driver==INVALID_HANDLE_VALUE){sbw_fail(error,"CAPTURE_DRIVER","Windows could not open the signed capture driver for this TUN interface.");return INVALID_HANDLE_VALUE;}
    b->param(b->driver,0,1024);b->param(b->driver,2,8U*1024U*1024U);*index=value;return b->driver;
}
void sbw_capture_broker_stop(sbw_capture_broker *b){if(b&&b->driver!=INVALID_HANDLE_VALUE){if(b->shutdown)b->shutdown(b->driver,3);if(b->close)b->close(b->driver);else CloseHandle(b->driver);b->driver=INVALID_HANDLE_VALUE;}}
void sbw_capture_broker_free(sbw_capture_broker *b){if(!b)return;sbw_capture_broker_stop(b);if(b->library)FreeLibrary(b->library);for(size_t i=0;i<2;++i)if(b->files[i])CloseHandle(b->files[i]);sbw_store_free(b->directory_pin);free(b);}
