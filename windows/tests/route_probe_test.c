#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/route_probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if(!(c)){fprintf(stderr,"%s:%d: %s (%s)\n",__FILE__,__LINE__,#c,error.code);exit(1);} }while(0)

typedef struct fixture {
    SOCKET listener;
    unsigned short port;
    HANDLE stop,thread;
    bool api,hang,tls_fail,invalid_delay;
    volatile LONG proxy_port,requests,authenticated,delay_seen;
    struct fixture *proxy;
} fixture;
static const char secret[]="1111111111111111111111111111111111111111111111111111111111111111";
static void send_all(SOCKET peer,const char *text) {
    size_t len=strlen(text),used=0;
    while(used<len){int n=send(peer,text+used,(int)(len-used),0);if(n<=0)return;used+=(size_t)n;}
}
static DWORD WINAPI server_thread(void *context) {
    fixture *f=context;
    while(WaitForSingleObject(f->stop,0)==WAIT_TIMEOUT) {
        fd_set set;FD_ZERO(&set);FD_SET(f->listener,&set);struct timeval wait={0,20000};
        if(select(0,&set,NULL,NULL,&wait)<=0)continue;
        struct sockaddr_in address={0};int size=sizeof(address);
        SOCKET peer=accept(f->listener,(struct sockaddr *)&address,&size);if(peer==INVALID_SOCKET)continue;
        DWORD timeout=1000;setsockopt(peer,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout));
        char request[8192]={0};size_t used=0;
        while(used+1<sizeof(request)) {
            int n=recv(peer,request+used,(int)(sizeof(request)-used-1),0);if(n<=0)break;
            used+=(size_t)n;request[used]=0;if(strstr(request,"\r\n\r\n"))break;
        }
        InterlockedIncrement(&f->requests);
        if(f->api) {
            if(strstr(request,"Authorization: Bearer 1111111111111111111111111111111111111111111111111111111111111111\r\n"))InterlockedIncrement(&f->authenticated);
            char body[2048]="{}";
            if(!strncmp(request,"GET /proxies HTTP",17))strcpy_s(body,sizeof(body),"{\"proxies\":{\"node/a\":{\"type\":\"HTTP\"}}}");
            else if(strstr(request,"GET /proxies/node%2Fa/delay?url=http%3A%2F%2Fprobe.invalid%2Fping&timeout=1000 HTTP")) {
                InterlockedIncrement(&f->delay_seen);strcpy_s(body,sizeof(body),f->invalid_delay?"{\"delay\":\"fake\"}":"{\"delay\":42}");
            } else if(!strncmp(request,"GET /connections HTTP",21)) {
                LONG source=InterlockedCompareExchange(&f->proxy->proxy_port,0,0);
                if(source)sprintf_s(body,sizeof(body),"{\"connections\":[{\"id\":\"actual-fixture-connection\",\"metadata\":{\"type\":\"http/sb-easy-diagnostic\",\"host\":\"probe.invalid\",\"sourcePort\":\"%ld\",\"destinationPort\":\"80\",\"destinationIP\":\"192.0.2.10\",\"processPath\":\"sb-easy-service.exe\"},\"rule\":\"domain=probe.invalid => route(proxy)\",\"chains\":[\"node/a\",\"sb-easy-local-default\"]}]}",(long)source);
                else strcpy_s(body,sizeof(body),"{\"connections\":[]}");
            }
            char response[3072];sprintf_s(response,sizeof(response),"HTTP/1.0 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",strlen(body),body);send_all(peer,response);
        } else if(!strstr(request,"Proxy-Authorization: Basic ")) {
            send_all(peer,"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fixture\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        } else {
            InterlockedIncrement(&f->authenticated);InterlockedExchange(&f->proxy_port,ntohs(address.sin_port));
            if(f->hang)(void)WaitForSingleObject(f->stop,4000);
            else if(f->tls_fail) {send_all(peer,"HTTP/1.1 200 Connection Established\r\n\r\n");send_all(peer,"this is not TLS");}
            else {
                Sleep(120);send_all(peer,"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
        shutdown(peer,SD_BOTH);closesocket(peer);
    }
    return 0;
}
static bool fixture_start(fixture *f) {
    f->listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(f->listener==INVALID_SOCKET)return false;
    struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);int size=sizeof(address);
    if(bind(f->listener,(struct sockaddr *)&address,sizeof(address)) || listen(f->listener,16) || getsockname(f->listener,(struct sockaddr *)&address,&size))return false;
    f->port=ntohs(address.sin_port);f->stop=CreateEventW(NULL,TRUE,FALSE,NULL);if(!f->stop)return false;
    f->thread=CreateThread(NULL,0,server_thread,f,0,NULL);return f->thread!=NULL;
}
static void fixture_stop(fixture *f) {
    SetEvent(f->stop);WaitForSingleObject(f->thread,5000);CloseHandle(f->thread);CloseHandle(f->stop);closesocket(f->listener);
}
int main(void) {
    sbw_error error={0};WSADATA data;CHECK(WSAStartup(MAKEWORD(2,2),&data)==0);
    fixture proxy={0},api={0};api.api=true;api.proxy=&proxy;CHECK(fixture_start(&proxy));CHECK(fixture_start(&api));
    sbw_runtime_config config={0};config.port=api.port;config.probe_port=proxy.port;config.secret=sb_strdup(secret);config.probe_secret=sb_strdup(secret);config.json=sb_strdup("{}");
    sbj *params=sbj_parse_cstr("{\"url\":\"file:///secret\"}");
    CHECK(!sbw_route_probe(&config,NULL,GetCurrentProcessId(),NULL,params,&error));CHECK(!strcmp(error.code,"INVALID_REQUEST"));
    sbj_set_str(params,"url","http://user:password@probe.invalid/");CHECK(!sbw_route_probe(&config,NULL,GetCurrentProcessId(),NULL,params,&error));
    sbj_set_str(params,"url","http://probe.invalid/ping?secret=never-return#private");sbj_set_int(params,"timeout_ms",3000);
    CHECK(!sbw_route_probe(&config,NULL,GetCurrentProcessId()+100000,NULL,params,&error));CHECK(!strcmp(error.code,"CORE_HEALTH_IDENTITY"));
    HANDLE cancel=CreateEventW(NULL,TRUE,TRUE,NULL);CHECK(cancel);
    CHECK(!sbw_route_probe(&config,NULL,GetCurrentProcessId(),cancel,params,&error));CHECK(!strcmp(error.code,"CORE_CANCELLED"));CloseHandle(cancel);
    CHECK(proxy.requests==0);
    sbj *result=sbw_route_probe(&config,NULL,GetCurrentProcessId(),NULL,params,&error);CHECK(result);
    CHECK(sbj_get_bool(result,"success",false) && sbj_get_int(result,"http_status",0)==204 && proxy.authenticated>0);
    CHECK(sbj_string_is(sbj_get(result,"url"),"http://probe.invalid/ping"));
    CHECK(sbj_get_bool(sbj_get(result,"evidence"),"observed",false));
    CHECK(sbj_string_is(sbj_get(sbj_get(result,"evidence"),"public_exit_ip"),"unobserved"));
    char *serialized=sbj_dump(result,-1);CHECK(!strstr(serialized,secret) && !strstr(serialized,"never-return"));free(serialized);sbj_free(result);
    sbj_set_str(params,"url","http://[2001:db8::1]:8080/ping");
    result=sbw_route_probe(&config,NULL,GetCurrentProcessId(),NULL,params,&error);CHECK(result && sbj_get_bool(result,"success",false));
    CHECK(sbj_string_is(sbj_get(result,"host"),"2001:db8::1") && sbj_get_int(result,"port",0)==8080);
    CHECK(!sbj_get_bool(sbj_get(result,"evidence"),"observed",true));sbj_free(result);
    proxy.tls_fail=true;sbj_set_str(params,"url","https://probe.invalid/");
    result=sbw_route_probe(&config,NULL,GetCurrentProcessId(),NULL,params,&error);CHECK(result && !sbj_get_bool(result,"success",true));
    CHECK(sbj_get_int(result,"http_status",0)==0 && strlen(sbj_get_str(result,"error_code",""))>0);sbj_free(result);
    proxy.tls_fail=false;proxy.hang=true;sbj_set_str(params,"url","http://probe.invalid/");sbj_set_int(params,"timeout_ms",1000);
    ULONGLONG start=GetTickCount64();result=sbw_route_probe(&config,NULL,GetCurrentProcessId(),NULL,params,&error);
    CHECK(result && !sbj_get_bool(result,"success",true) && GetTickCount64()-start<3500);sbj_free(result);
    sbj_free(params);params=sbj_parse_cstr("{\"target\":\"node/a\",\"url\":\"http://probe.invalid/ping\",\"timeout_ms\":1000}");
    result=sbw_route_delay(&config,GetCurrentProcessId(),NULL,params,&error);CHECK(result && sbj_get_int(result,"delay_ms",0)==42 && api.delay_seen==1);sbj_free(result);
    api.invalid_delay=true;CHECK(!sbw_route_delay(&config,GetCurrentProcessId(),NULL,params,&error));CHECK(!strcmp(error.code,"PROBE_INVALID_RESPONSE"));
    sbj_set_str(params,"target","missing");CHECK(!sbw_route_delay(&config,GetCurrentProcessId(),NULL,params,&error));CHECK(!strcmp(error.code,"ROUTING_NODE_UNAVAILABLE"));
    CHECK(api.requests==api.authenticated);sbj_free(params);
    fixture_stop(&proxy);fixture_stop(&api);sbw_runtime_config_free(&config);WSACleanup();
    puts("Route probes: owned/authenticated real HTTP, TLS failure, timeout, cancellation, evidence, URL redaction and actual delay passed.");return 0;
}
