#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <bcrypt.h>
#include <pcap/pcap.h>
#include <windivert.h>
#include "capture.h"
#include "secure_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_MAX (768U * 1024U)
#define PACKETS_MAX 128
#define FLOWS_MAX 4096
typedef struct packet_key { unsigned char local[16], remote[16]; unsigned short local_port, remote_port; unsigned char protocol; } packet_key;
typedef struct attribution { packet_key key; char app[97], host[254]; } attribution;
typedef struct pending_packet { unsigned char *bytes; unsigned length; ULONGLONG tick; uint64_t timestamp; packet_key key; } pending_packet;
typedef HANDLE (*open_fn)(const char *, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL (*recv_fn)(HANDLE, void *, UINT, UINT *, UINT64, WINDIVERT_ADDRESS *, UINT *, OVERLAPPED *);
typedef BOOL (*close_fn)(HANDLE);
typedef BOOL (*shutdown_fn)(HANDLE, WINDIVERT_SHUTDOWN);
typedef BOOL (*param_fn)(HANDLE, WINDIVERT_PARAM, UINT64);
struct sbw_capture {
    SRWLOCK lock;
    wchar_t *directory, *part;
    sbw_store *store;
    sbj *config;
    struct bpf_program bpf;
    bool has_bpf, running;
    HANDLE driver, thread, stop, file;
    HMODULE library;
    recv_fn receive; close_fn close; shutdown_fn shutdown;
    DWORD attempted_pid;
    unsigned file_size, file_count;
    uint64_t stored_bytes, packets, dropped;
    ULONGLONG opened;
    attribution flows[FLOWS_MAX]; size_t flow_count;
    pending_packet pending[PACKETS_MAX]; size_t pending_count;
    char issue[256];
};
static int failure(sbw_error *error, const char *message) { return sbw_fail(error, "CAPTURE_FAILED", message); }
static uint64_t timestamp_us(void) {
    FILETIME f; ULARGE_INTEGER n; GetSystemTimePreciseAsFileTime(&f);
    n.LowPart=f.dwLowDateTime; n.HighPart=f.dwHighDateTime;
    return (n.QuadPart-UINT64_C(116444736000000000))/10;
}
int sbw_capture_hash(const void *bytes, size_t size, char digest[65]) {
    BCRYPT_ALG_HANDLE algorithm = NULL; unsigned char hash[32];
    if (size > ULONG_MAX || BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return -1;
    NTSTATUS status = BCryptHash(algorithm, NULL, 0, (PUCHAR)bytes, (ULONG)size, hash, sizeof hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status != 0) return -1;
    for (size_t i=0;i<32;++i) sprintf_s(digest+i*2,65-i*2,"%02x",hash[i]);
    return 0;
}
bool sbw_capture_digest_valid(const char *digest) {
    if (!digest || strlen(digest)!=64) return false;
    for (const char *p=digest;*p;++p) if (!(*p>='0'&&*p<='9')&&!(*p>='a'&&*p<='f')) return false;
    return true;
}
static wchar_t *capture_path(sbw_capture *c, const char *digest, const wchar_t *suffix) {
    if (!sbw_capture_digest_valid(digest)) return NULL;
    wchar_t name[90]; for(size_t i=0;i<64;++i) name[i]=(wchar_t)digest[i]; name[64]=0;
    wcscat_s(name,90,suffix); return sbw_path_join(c->directory,name);
}
static bool regular(HANDLE h) {
    FILE_ATTRIBUTE_TAG_INFO info;
    return GetFileInformationByHandleEx(h,FileAttributeTagInfo,&info,sizeof info) &&
        !(info.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT));
}
static int read_path(const wchar_t *path, unsigned char **bytes, size_t *size, sbw_error *error) {
    *bytes=NULL; *size=0;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    LARGE_INTEGER length; DWORD read=0;
    if(file==INVALID_HANDLE_VALUE) return failure(error,"Capture file is unavailable.");
    if(!regular(file)||!GetFileSizeEx(file,&length)||length.QuadPart<24||length.QuadPart>FILE_MAX) {
        CloseHandle(file); return failure(error,"Invalid capture file.");
    }
    unsigned char *data=sb_xmalloc((size_t)length.QuadPart);
    bool ok=ReadFile(file,data,(DWORD)length.QuadPart,&read,NULL)&&read==(DWORD)length.QuadPart;
    CloseHandle(file);
    if(!ok) { free(data); return failure(error,"Capture file could not be read."); }
    *bytes=data; *size=read; return 0;
}
static bool host_valid(const char *s) {
    if (!*s || strlen(s)>253) return false;
    for(const unsigned char *p=(const unsigned char *)s;*p;++p)
        if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='.'||*p=='-'||*p==':'||*p=='_')) return false;
    return true;
}
static bool allowed_key(const char *key) {
    const char *names[]={"enabled","apps","domains","hosts","bpf","file_kb","quota_mb","rotate_seconds","auto_upload","wifi_only","upload_seconds","delete_after_upload"};
    for(size_t i=0;i<sizeof names/sizeof names[0];++i) if(sb_streq(key,names[i])) return true;
    return false;
}
static int compile(const char *expression, struct bpf_program *program, sbw_error *error) {
    pcap_t *pcap=pcap_open_dead(DLT_RAW,65535);
    if(!pcap) return failure(error,"BPF compiler is unavailable.");
    int result=pcap_compile(pcap,program,expression,1,PCAP_NETMASK_UNKNOWN);
    if(result!=0) sbw_fail(error,"INVALID_BPF",pcap_geterr(pcap));
    pcap_close(pcap); return result;
}
sbj *sbw_capture_validate(const sbj *config, sbw_error *error) {
    if(!sbj_is_object(config)) goto invalid;
    for(size_t i=0;i<sbj_obj_len(config);++i) if(!allowed_key(sbj_obj_key(config,i))) goto invalid;
    sbj *out=sbj_object(); size_t filters=0;
    const char *lists[]={"apps","domains","hosts"};
    for(size_t i=0;i<3;++i) {
        const sbj *items=sbj_get(config,lists[i]);
        if(items&&!sbj_is_array(items)) { sbj_free(out); goto invalid; }
        sbj *normalized=sbj_array();
        for(size_t j=0;j<sbj_arr_len(items);++j) {
            const sbj *value=sbj_arr_at(items,j); const char *s=sbj_as_str(value,"");
            if(++filters>100||!sbw_json_string(value,i==0?96:253,false)||(i>0&&!host_valid(s))) { sbj_free(normalized);sbj_free(out);goto invalid; }
            for(const char *p=s;*p;++p) if((unsigned char)*p<32||*p=='/'||*p=='\\') {sbj_free(normalized);sbj_free(out);goto invalid;}
            char *lower=sb_strdup(s); for(char *p=lower;*p;++p) if(*p>='A'&&*p<='Z') *p=(char)(*p+32);
            size_t len=strlen(lower); if(i>0&&len&&lower[len-1]=='.')lower[len-1]=0;
            sbj_arr_push(normalized,sbj_str_take(lower));
        }
        sbj_set(out,lists[i],normalized);
    }
    const char *booleans[]={"enabled","auto_upload","wifi_only","delete_after_upload"};
    for(size_t i=0;i<4;++i) {
        const sbj *v=sbj_get(config,booleans[i]);
        if(v&&!sbj_is_bool(v)) {sbj_free(out);goto invalid;}
        sbj_set_bool(out,booleans[i],v?sbj_as_bool(v,false):i==2);
    }
    const char *integers[]={"file_kb","quota_mb","rotate_seconds","upload_seconds"};
    const int low[]={128,8,10,30},high[]={768,256,600,3600},defaults[]={512,64,60,60};
    for(size_t i=0;i<4;++i) {
        const sbj *v=sbj_get(config,integers[i]);int64_t n=v?sbj_as_int(v,-1):defaults[i];
        if((v&&!sbj_is_integer(v))||n<low[i]||n>high[i]) {sbj_free(out);goto invalid;}
        sbj_set_int(out,integers[i],n);
    }
    const sbj *bpf=sbj_get(config,"bpf");
    if(bpf&&!sbw_json_string(bpf,4096,true)) {sbj_free(out);goto invalid;}
    const char *expression=sbj_as_str(bpf,"");
    if(sbj_get_bool(out,"enabled",false)&&!filters&&!*expression) {sbj_free(out);goto invalid;}
    if(*expression) {struct bpf_program program={0};if(compile(expression,&program,error)!=0){sbj_free(out);return NULL;}pcap_freecode(&program);}
    sbj_set_str(out,"bpf",expression);return out;
invalid:
    sbw_fail(error,"INVALID_CAPTURE_CONFIG","Choose apps, domains, host/IP or BPF; check filter and storage limits.");return NULL;
}
static void put32(unsigned char *p,uint32_t n) {for(size_t i=0;i<4;++i)p[i]=(unsigned char)(n>>(8*i));}
static uint32_t get32(const unsigned char *p) {return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static const unsigned char pcap_header[24]={0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,101,0,0,0};
static int seal_path(sbw_capture *c,const wchar_t *path,sbw_error *error) {
    unsigned char *bytes=NULL;size_t size=0;
    if(read_path(path,&bytes,&size,error)!=0)return -1;
    size_t valid=24;
    if(memcmp(bytes,pcap_header,24)!=0){free(bytes);return failure(error,"Invalid pending PCAP header.");}
    while(size-valid>=16) {uint32_t n=get32(bytes+valid+8);if(!n||n>65535||n!=get32(bytes+valid+12)||get32(bytes+valid+4)>=1000000||n>size-valid-16)break;valid+=16+n;}
    if(valid==24){free(bytes);DeleteFileW(path);return 0;}
    if(valid!=size) {
        HANDLE f=CreateFileW(path,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        LARGE_INTEGER end;end.QuadPart=(LONGLONG)valid;
        bool ok=f!=INVALID_HANDLE_VALUE&&regular(f)&&SetFilePointerEx(f,end,NULL,FILE_BEGIN)&&SetEndOfFile(f)&&FlushFileBuffers(f);
        if(f!=INVALID_HANDLE_VALUE)CloseHandle(f);
        if(!ok){free(bytes);return failure(error,"Could not recover pending capture.");}
    }
    char digest[65];int result=sbw_capture_hash(bytes,valid,digest);free(bytes);
    if(result!=0)return failure(error,"Capture checksum failed.");
    wchar_t *target=capture_path(c,digest,L".pcap");
    if(!MoveFileExW(path,target,MOVEFILE_WRITE_THROUGH)) {
        if(GetLastError()==ERROR_ALREADY_EXISTS) DeleteFileW(path);
        else { char message[128];sprintf_s(message,sizeof message,"Could not seal capture file (Windows error %lu).",GetLastError());result=failure(error,message); }
    }
    free(target);return result;
}
static sbj *inventory(sbw_capture *c) {
    sbj *files=sbj_array(); c->file_count=0;c->stored_bytes=0;
    wchar_t *pattern=sbw_path_join(c->directory,L"*");WIN32_FIND_DATAW item;
    HANDLE search=FindFirstFileW(pattern,&item);free(pattern);
    if(search==INVALID_HANDLE_VALUE)return files;
    do {
        if(item.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))continue;
        size_t len=wcslen(item.cFileName);
        bool part=len>5&&!wcscmp(item.cFileName+len-5,L".part");
        bool pcap=len==69&&!wcscmp(item.cFileName+64,L".pcap");
        if(!part&&!pcap)continue;
        ++c->file_count;c->stored_bytes+=((uint64_t)item.nFileSizeHigh<<32)+item.nFileSizeLow;
        if(!pcap||sbj_arr_len(files)>=1000)continue;
        char digest[65];for(size_t i=0;i<64;++i)digest[i]=(char)item.cFileName[i];digest[64]=0;
        if(!sbw_capture_digest_valid(digest))continue;
        wchar_t *marker=capture_path(c,digest,L".uploaded");bool uploaded=GetFileAttributesW(marker)!=INVALID_FILE_ATTRIBUTES;free(marker);
        sbj *row=sbj_object();sbj_set_str(row,"digest",digest);sbj_set_int(row,"size",item.nFileSizeLow);sbj_set_bool(row,"uploaded",uploaded);
        ULARGE_INTEGER t;t.LowPart=item.ftLastWriteTime.dwLowDateTime;t.HighPart=item.ftLastWriteTime.dwHighDateTime;
        sbj_set_int(row,"created_at",(int64_t)((t.QuadPart-UINT64_C(116444736000000000))/10000));sbj_arr_push(files,row);
    }while(FindNextFileW(search,&item));FindClose(search);return files;
}
static int seal(sbw_capture *c,sbw_error *error) {
    if(c->file==INVALID_HANDLE_VALUE)return 0;
    bool flushed=FlushFileBuffers(c->file)!=FALSE;CloseHandle(c->file);c->file=INVALID_HANDLE_VALUE;
    int result=flushed?seal_path(c,c->part,error):failure(error,"Could not flush capture file.");
    free(c->part);c->part=NULL;c->file_size=0;
    sbj *files=inventory(c);sbj_free(files);return result;
}
static int write_packet(sbw_capture *c,const unsigned char *bytes,unsigned length,uint64_t stamp,sbw_error *error) {
    if(c->has_bpf) {struct pcap_pkthdr header={0};header.caplen=length;header.len=length;if(!pcap_offline_filter(&c->bpf,&header,bytes))return 0;}
    if(c->file!=INVALID_HANDLE_VALUE&&(c->file_size+16+length>(unsigned)sbj_get_int(c->config,"file_kb",512)*1024||
        GetTickCount64()-c->opened>=(ULONGLONG)sbj_get_int(c->config,"rotate_seconds",60)*1000))if(seal(c,error)!=0)return -1;
    uint64_t needed=length+16+(c->file==INVALID_HANDLE_VALUE?24:0);
    if(c->stored_bytes+needed>(uint64_t)sbj_get_int(c->config,"quota_mb",64)*1024*1024||(c->file==INVALID_HANDLE_VALUE&&c->file_count>=1000)) {
        return failure(error,"Capture storage full; delete files to resume.");
    }
    if(c->file==INVALID_HANDLE_VALUE) {
        unsigned char random[16];if(BCryptGenRandom(NULL,random,sizeof random,BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)return failure(error,"Capture filename generation failed.");
        wchar_t name[64]=L"capture-";for(size_t i=0;i<16;++i)swprintf_s(name+8+i*2,64-8-i*2,L"%02x",random[i]);wcscat_s(name,64,L".part");
        c->part=sbw_path_join(c->directory,name);
        c->file=CreateFileW(c->part,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
        DWORD written=0;
        if(c->file==INVALID_HANDLE_VALUE||!WriteFile(c->file,pcap_header,24,&written,NULL)||written!=24)return failure(error,"Could not create capture file.");
        c->file_size=24;c->stored_bytes+=24;++c->file_count;c->opened=GetTickCount64();
    }
    unsigned char record[16];put32(record,(uint32_t)(stamp/1000000));put32(record+4,(uint32_t)(stamp%1000000));put32(record+8,length);put32(record+12,length);
    DWORD written=0;
    if(!WriteFile(c->file,record,16,&written,NULL)||written!=16||!WriteFile(c->file,bytes,length,&written,NULL)||written!=length)return failure(error,"Capture write failed.");
    c->file_size+=16+length;c->stored_bytes+=16+length;++c->packets;return 0;
}
static bool list_matches(const sbj *list,const char *value,bool suffix) {
    if(!value||!*value)return false;
    size_t length=strlen(value);
    for(size_t i=0;i<sbj_arr_len(list);++i) {
        const char *item=sbj_as_str(sbj_arr_at(list,i),"");size_t n=strlen(item);
        if(!_stricmp(item,value)||(suffix&&length>n&&value[length-n-1]=='.'&&!_stricmp(value+length-n,item)))return true;
    }return false;
}
static bool selected(sbw_capture *c,const char *app,const char *host,const char *ip) {
    const sbj *apps=sbj_get(c->config,"apps"),*domains=sbj_get(c->config,"domains"),*hosts=sbj_get(c->config,"hosts");
    return (!sbj_arr_len(apps)&&!sbj_arr_len(domains)&&!sbj_arr_len(hosts))||list_matches(apps,app,false)||
        list_matches(domains,host,true)||list_matches(hosts,host,false)||list_matches(hosts,ip,false);
}
static unsigned short port(const unsigned char *p){return (unsigned short)(((unsigned)p[0]<<8)|p[1]);}
static bool parse_packet(const unsigned char *bytes,unsigned length,bool outbound,packet_key *key) {
    memset(key,0,sizeof *key);unsigned offset;unsigned char src[16]={0},dst[16]={0};
    if(length>=20&&(bytes[0]>>4)==4) {
        offset=(unsigned)(bytes[0]&15)*4;if(offset<20||offset>length||(port(bytes+6)&0x3fff))return false;
        if(port(bytes+2)!=length)return false;key->protocol=bytes[9];src[10]=dst[10]=255;src[11]=dst[11]=255;
        memcpy(src+12,bytes+12,4);memcpy(dst+12,bytes+16,4);
    }else if(length>=40&&(bytes[0]>>4)==6) {
        if((unsigned)port(bytes+4)+40!=length)return false;
        offset=40;key->protocol=bytes[6];memcpy(src,bytes+8,16);memcpy(dst,bytes+24,16);
        for(int n=0;n<8&&(key->protocol==0||key->protocol==43||key->protocol==60);++n){if(length-offset<8)return false;unsigned size=((unsigned)bytes[offset+1]+1)*8;key->protocol=bytes[offset];if(size>length-offset)return false;offset+=size;}
    }else return false;
    if((key->protocol!=6&&key->protocol!=17)||length-offset<(key->protocol==6?20U:8U))return false;
    memcpy(key->local,outbound?src:dst,16);memcpy(key->remote,outbound?dst:src,16);
    key->local_port=port(bytes+offset+(outbound?0:2));key->remote_port=port(bytes+offset+(outbound?2:0));return true;
}
static void ip_text(const unsigned char address[16],char text[64]) {
    static const unsigned char prefix[12]={0,0,0,0,0,0,0,0,0,0,255,255};
    if(!memcmp(address,prefix,12))InetNtopA(AF_INET,(void *)(address+12),text,64);
    else InetNtopA(AF_INET6,(void *)address,text,64);
}
static void drain(sbw_capture *c,bool stopping) {
    ULONGLONG now=GetTickCount64();
    for(size_t i=0;i<c->pending_count;) {
        pending_packet *p=&c->pending[i];const attribution *match=NULL;bool ambiguous=false, exact=false;
        for(size_t j=0;j<c->flow_count;++j) {
            const attribution *flow=&c->flows[j];
            if(flow->key.protocol!=p->key.protocol||flow->key.local_port!=p->key.local_port||flow->key.remote_port!=p->key.remote_port||memcmp(flow->key.local,p->key.local,16))continue;
            if(!memcmp(flow->key.remote,p->key.remote,16)){
                if(exact) { if(_stricmp(match->app,flow->app)||_stricmp(match->host,flow->host))ambiguous=true; }
                else { match=flow;exact=true;ambiguous=false; }
                continue;
            }
            /* FakeIP can differ from Clash's resolved destination. Never guess
             * when several destinations share a UDP socket/local endpoint. */
            bool fake = p->key.remote[10]==255 && p->key.remote[11]==255 && p->key.remote[12]==198 && (p->key.remote[13]==18||p->key.remote[13]==19);
            if (fake && !exact) { if(match)ambiguous=true;else match=flow; }
        }
        if(ambiguous)match=NULL;
        char ip[64]={0};ip_text(p->key.remote,ip);
        bool accepted=selected(c,match?match->app:"",match?match->host:"",ip);
        if(accepted) {sbw_error error={0};if(write_packet(c,p->bytes,p->length,p->timestamp,&error)!=0){++c->dropped;strcpy_s(c->issue,sizeof c->issue,error.message);}}
        if(accepted||(match&&*match->host&&*match->app)||stopping||now-p->tick>=10000) {
            if(!accepted&&!match)++c->dropped;
            SecureZeroMemory(p->bytes,p->length);free(p->bytes);--c->pending_count;
            memmove(c->pending+i,c->pending+i+1,(c->pending_count-i)*sizeof *c->pending);
        }else ++i;
    }
    if(c->file!=INVALID_HANDLE_VALUE&&now-c->opened>=(ULONGLONG)sbj_get_int(c->config,"rotate_seconds",60)*1000){sbw_error error={0};if(seal(c,&error)!=0)strcpy_s(c->issue,sizeof c->issue,error.message);}
}
static DWORD WINAPI capture_thread(void *context) {
    sbw_capture *c=context;unsigned char *bytes=sb_xmalloc(65535);OVERLAPPED io={0};io.hEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!io.hEvent){AcquireSRWLockExclusive(&c->lock);c->running=false;strcpy_s(c->issue,sizeof c->issue,"Capture event could not be created.");ReleaseSRWLockExclusive(&c->lock);free(bytes);return 0;}
    while(WaitForSingleObject(c->stop,0)!=WAIT_OBJECT_0) {
        WINDIVERT_ADDRESS address={0};UINT received=0,addr_size=sizeof address;ResetEvent(io.hEvent);
        bool done=c->receive(c->driver,bytes,65535,&received,0,&address,&addr_size,&io)!=FALSE;
        if(!done&&GetLastError()!=ERROR_IO_PENDING)break;
        while(!done) {
            HANDLE events[]={c->stop,io.hEvent};DWORD waited=WaitForMultipleObjects(2,events,FALSE,200);
            if(waited==WAIT_OBJECT_0||waited==WAIT_FAILED){CancelIoEx(c->driver,&io);DWORD ignored;GetOverlappedResult(c->driver,&io,&ignored,TRUE);goto finished;}
            if(waited==WAIT_OBJECT_0+1){DWORD count=0;done=GetOverlappedResult(c->driver,&io,&count,FALSE)!=FALSE;received=count;if(!done)goto finished;}
            AcquireSRWLockExclusive(&c->lock);drain(c,false);ReleaseSRWLockExclusive(&c->lock);
        }
        packet_key key;if(!parse_packet(bytes,received,address.Outbound!=0,&key))continue;
        AcquireSRWLockExclusive(&c->lock);
        if(c->has_bpf){struct pcap_pkthdr h={0};h.caplen=received;h.len=received;if(!pcap_offline_filter(&c->bpf,&h,bytes)){ReleaseSRWLockExclusive(&c->lock);continue;}}
        if(c->pending_count<PACKETS_MAX){pending_packet *p=&c->pending[c->pending_count++];p->bytes=sb_xmalloc(received);memcpy(p->bytes,bytes,received);p->length=received;p->tick=GetTickCount64();p->timestamp=timestamp_us();p->key=key;}
        else ++c->dropped;
        drain(c,false);ReleaseSRWLockExclusive(&c->lock);
    }
finished:
    AcquireSRWLockExclusive(&c->lock);drain(c,true);sbw_error error={0};if(seal(c,&error)!=0)strcpy_s(c->issue,sizeof c->issue,error.message);
    if(WaitForSingleObject(c->stop,0)!=WAIT_OBJECT_0&&!c->issue[0])strcpy_s(c->issue,sizeof c->issue,"Capture driver stopped unexpectedly; save settings to retry.");
    c->running=false;ReleaseSRWLockExclusive(&c->lock);CloseHandle(io.hEvent);SecureZeroMemory(bytes,65535);free(bytes);return 0;
}
void sbw_capture_stop(sbw_capture *c) {
    if(!c)return;
    if(c->stop)SetEvent(c->stop);
    if(c->driver!=INVALID_HANDLE_VALUE&&c->shutdown)c->shutdown(c->driver,WINDIVERT_SHUTDOWN_BOTH);
    if(c->thread){WaitForSingleObject(c->thread,INFINITE);CloseHandle(c->thread);c->thread=NULL;}
    if(c->stop){CloseHandle(c->stop);c->stop=NULL;}
    if(c->driver!=INVALID_HANDLE_VALUE&&c->close){c->close(c->driver);c->driver=INVALID_HANDLE_VALUE;}
    c->running=false;if(c->has_bpf){pcap_freecode(&c->bpf);c->has_bpf=false;}
    AcquireSRWLockExclusive(&c->lock);seal(c,NULL);ReleaseSRWLockExclusive(&c->lock);
}
sbw_capture *sbw_capture_new(const wchar_t *work,const sbj *identity,sbw_error *error) {
    const char *server=sbj_get_str(identity,"server",""),*host=sbj_get_str(identity,"host_id","");
    if(!*server||!*host)return NULL;
    sb_buf scope={0};sb_buf_printf(&scope,"%s\n%s",server,host);char digest[65];
    int hashed=sbw_capture_hash(scope.p,scope.len,digest);sb_buf_free(&scope);if(hashed!=0)return NULL;
    wchar_t name[90]=L"captures-";for(size_t i=0;i<64;++i)name[9+i]=(wchar_t)digest[i];name[73]=0;
    sbw_capture *c=sb_xcalloc(1,sizeof *c);InitializeSRWLock(&c->lock);c->driver=c->file=INVALID_HANDLE_VALUE;
    wchar_t *directory=sbw_path_join(work,name);
    c->store=sbw_secure_store_new(directory,error);
    /* Digest filenames can exceed MAX_PATH in portable/test workspaces. */
    if(!wcsncmp(directory,L"\\\\?\\",4))c->directory=directory;
    else { size_t n=wcslen(directory);c->directory=sb_xcalloc(n+5,sizeof(wchar_t));wcscpy_s(c->directory,n+5,L"\\\\?\\");wcscat_s(c->directory,n+5,directory);free(directory); }
    if(!c->store){sbw_capture_free(c);return NULL;}
    sbj *saved=NULL;if(c->store->load(c->store->context,&saved,error)!=0){sbw_capture_free(c);return NULL;}
    sbj *empty=sbj_object();c->config=sbw_capture_validate(saved?saved:empty,error);sbj_free(empty);sbj_free(saved);
    if(!c->config){sbw_capture_free(c);return NULL;}
    wchar_t *pattern=sbw_path_join(c->directory,L"capture-*.part");WIN32_FIND_DATAW item;HANDLE search=FindFirstFileW(pattern,&item);free(pattern);
    if(search!=INVALID_HANDLE_VALUE){unsigned count=0;do{if(++count>1000)break;if(item.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))continue;wchar_t *path=sbw_path_join(c->directory,item.cFileName);seal_path(c,path,NULL);free(path);}while(FindNextFileW(search,&item));FindClose(search);}
    sbj *files=inventory(c);sbj_free(files);return c;
}
void sbw_capture_free(sbw_capture *c) {
    if(!c)return;sbw_capture_stop(c);if(c->library)FreeLibrary(c->library);sbw_store_free(c->store);sbj_free(c->config);free(c->directory);free(c->part);free(c);
}
int sbw_capture_configure(sbw_capture *c,const sbj *config,sbw_error *error) {
    sbj *normalized=sbw_capture_validate(config,error);if(!normalized)return -1;
    if(c->store->save(c->store->context,normalized,error)!=0){sbj_free(normalized);return -1;}
    sbw_capture_stop(c);AcquireSRWLockExclusive(&c->lock);sbj_free(c->config);c->config=normalized;c->attempted_pid=0;c->issue[0]=0;c->flow_count=0;ReleaseSRWLockExclusive(&c->lock);return 0;
}
static void parse_address(const char *text,unsigned char out[16]) {
    if(InetPtonA(AF_INET6,text,out)==1)return;memset(out,0,16);out[10]=out[11]=255;if(InetPtonA(AF_INET,text,out+12)!=1)memset(out,0,16);
}
void sbw_capture_observe(sbw_capture *c,DWORD pid,const wchar_t *interface_name,const sbj *connections) {
    if(!c)return;
    if(!pid||!interface_name){sbw_capture_stop(c);c->attempted_pid=0;return;}
    AcquireSRWLockExclusive(&c->lock);c->flow_count=0;
    const sbj *rows=sbj_get(connections,"connections");
    for(size_t i=0;i<sbj_arr_len(rows)&&c->flow_count<FLOWS_MAX;++i) {
        const sbj *m=sbj_get(sbj_arr_at(rows,i),"metadata");attribution *flow=&c->flows[c->flow_count++];memset(flow,0,sizeof *flow);
        parse_address(sbj_get_str(m,"sourceIP",""),flow->key.local);parse_address(sbj_get_str(m,"destinationIP",""),flow->key.remote);
        flow->key.local_port=(unsigned short)atoi(sbj_get_str(m,"sourcePort","0"));flow->key.remote_port=(unsigned short)atoi(sbj_get_str(m,"destinationPort","0"));
        flow->key.protocol=_stricmp(sbj_get_str(m,"network",""),"tcp")==0?6:17;
        const char *app=sbj_get_str(m,"processPath",""),*base=app;for(const char *p=app;*p;++p)if(*p=='/'||*p=='\\')base=p+1;
        if(!*base)base=sbj_get_str(m,"process","");if(strlen(base)<sizeof flow->app)strcpy_s(flow->app,sizeof flow->app,base);
        const char *host=sbj_get_str(m,"host","");if(strlen(host)<sizeof flow->host)strcpy_s(flow->host,sizeof flow->host,host);
    }
    bool enabled=sbj_get_bool(c->config,"enabled",false);ReleaseSRWLockExclusive(&c->lock);
    if(!enabled||c->attempted_pid==pid)return;
    sbw_capture_stop(c);c->attempted_pid=pid;
    NET_LUID luid;NET_IFINDEX index;
    if(ConvertInterfaceAliasToLuid(interface_name,&luid)!=NO_ERROR||ConvertInterfaceLuidToIndex(&luid,&index)!=NO_ERROR){strcpy_s(c->issue,sizeof c->issue,"The sb-easy TUN interface is unavailable.");return;}
    if(!c->library) {
        wchar_t *base=sbw_executable_directory(NULL),*path=base?sbw_path_join(base,L"capture\\WinDivert.dll"):NULL;free(base);
        if(path)c->library=LoadLibraryExW(path,NULL,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);free(path);
    }
    if(!c->library){strcpy_s(c->issue,sizeof c->issue,"WinDivert is missing. Install the complete sb-easy package.");return;}
    open_fn open_driver=(open_fn)(void *)GetProcAddress(c->library,"WinDivertOpen");
    c->receive=(recv_fn)(void *)GetProcAddress(c->library,"WinDivertRecvEx");c->close=(close_fn)(void *)GetProcAddress(c->library,"WinDivertClose");c->shutdown=(shutdown_fn)(void *)GetProcAddress(c->library,"WinDivertShutdown");
    param_fn set_param=(param_fn)(void *)GetProcAddress(c->library,"WinDivertSetParam");
    if(!open_driver||!c->receive||!c->close||!c->shutdown){strcpy_s(c->issue,sizeof c->issue,"Invalid WinDivert library.");return;}
    const char *expression=sbj_get_str(c->config,"bpf","");sbw_error error={0};
    if(*expression&&compile(expression,&c->bpf,&error)!=0){strcpy_s(c->issue,sizeof c->issue,error.message);return;}c->has_bpf=*expression!=0;
    char filter[120];sprintf_s(filter,sizeof filter,"(tcp or udp) and ifIdx == %lu",index);
    c->driver=open_driver(filter,WINDIVERT_LAYER_NETWORK,0,WINDIVERT_FLAG_SNIFF|WINDIVERT_FLAG_RECV_ONLY);
    if(c->driver==INVALID_HANDLE_VALUE){sprintf_s(c->issue,sizeof c->issue,"WinDivert could not start (Windows error %lu). Capture needs an elevated service and an allowed signed driver.",GetLastError());return;}
    if(set_param){set_param(c->driver,WINDIVERT_PARAM_QUEUE_LENGTH,1024);set_param(c->driver,WINDIVERT_PARAM_QUEUE_SIZE,8*1024*1024);}
    c->stop=CreateEventW(NULL,TRUE,FALSE,NULL);c->running=true;
    c->thread=c->stop?CreateThread(NULL,0,capture_thread,c,0,NULL):NULL;
    if(!c->thread){sbw_capture_stop(c);strcpy_s(c->issue,sizeof c->issue,"Capture worker could not start.");}
}
sbj *sbw_capture_snapshot(sbw_capture *c) {
    AcquireSRWLockExclusive(&c->lock);sbj *result=sbj_object();sbj_set(result,"config",sbj_clone(c->config));sbj_set(result,"files",inventory(c));
    sbj_set_bool(result,"running",c->running);sbj_set_int(result,"packets",(int64_t)c->packets);sbj_set_int(result,"dropped",(int64_t)c->dropped);sbj_set_int(result,"stored_bytes",(int64_t)c->stored_bytes);sbj_set_str(result,"error",c->issue);
    ReleaseSRWLockExclusive(&c->lock);return result;
}
int sbw_capture_rotate(sbw_capture *c,sbw_error *error){AcquireSRWLockExclusive(&c->lock);int r=seal(c,error);ReleaseSRWLockExclusive(&c->lock);return r;}
int sbw_capture_read(sbw_capture *c,const char *digest,unsigned char **bytes,size_t *size,sbw_error *error) {
    wchar_t *path=capture_path(c,digest,L".pcap");if(!path)return failure(error,"Invalid capture identifier.");
    int r=read_path(path,bytes,size,error);free(path);
    if(!r){char actual[65];if(sbw_capture_hash(*bytes,*size,actual)!=0||strcmp(actual,digest)){free(*bytes);*bytes=NULL;*size=0;return failure(error,"Capture checksum mismatch.");}}
    return r;
}
int sbw_capture_delete(sbw_capture *c,const char *digest,sbw_error *error) {
    wchar_t *path=capture_path(c,digest,L".pcap"),*marker=capture_path(c,digest,L".uploaded");if(!path||!marker){free(path);free(marker);return failure(error,"Invalid capture identifier.");}
    AcquireSRWLockExclusive(&c->lock);bool ok=DeleteFileW(path)!=FALSE;if(ok){DeleteFileW(marker);c->issue[0]=0;sbj *files=inventory(c);sbj_free(files);}ReleaseSRWLockExclusive(&c->lock);free(path);free(marker);return ok?0:failure(error,"Could not delete capture.");
}
int sbw_capture_mark_uploaded(sbw_capture *c,const char *digest,sbw_error *error) {
    wchar_t *path=capture_path(c,digest,L".uploaded");if(!path)return failure(error,"Invalid capture identifier.");
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);free(path);
    if(file==INVALID_HANDLE_VALUE)return GetLastError()==ERROR_FILE_EXISTS?0:failure(error,"Could not save upload acknowledgement.");
    CloseHandle(file);return 0;
}
bool sbw_capture_wifi(void) {
    MIB_IF_TABLE2 *table=NULL;bool wifi=false;if(GetIfTable2(&table)!=NO_ERROR)return false;
    for(ULONG i=0;i<table->NumEntries;++i)if(table->Table[i].Type==IF_TYPE_IEEE80211&&table->Table[i].OperStatus==IfOperStatusUp)wifi=true;
    FreeMibTable(table);return wifi;
}
int sbw_capture_test_packet(sbw_capture *c,const void *packet,size_t length,const char *app,const char *host,sbw_error *error) {
    packet_key key;if(length>65535||!parse_packet(packet,(unsigned)length,true,&key))return failure(error,"Invalid raw IP packet.");
    char ip[64]={0};ip_text(key.remote,ip);if(!selected(c,app,host,ip))return 0;
    if(!c->has_bpf&&*sbj_get_str(c->config,"bpf","")){if(compile(sbj_get_str(c->config,"bpf",""),&c->bpf,error)!=0)return -1;c->has_bpf=true;}
    return write_packet(c,packet,(unsigned)length,timestamp_us(),error);
}
