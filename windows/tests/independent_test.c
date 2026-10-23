#include <winsock2.h>
#include <ws2tcpip.h>
#include "../service/independent.h"
#include "../service/subscriptions.h"
#include "../service/routing.h"
#include "../service/runtime_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"%s:%d: %s (%s)\n",__FILE__,__LINE__,#c,error.code);exit(1);}}while(0)
static const char body[]="{\"outbounds\":[{\"type\":\"http\",\"tag\":\"office\",\"server\":\"proxy.test\",\"server_port\":8080,\"username\":\"u\",\"password\":\"PRIVATE_NODE\"}]}";
typedef struct fixture {SOCKET listener;unsigned short port;HANDLE stop,thread;volatile LONG fail,requests;} fixture;
static DWORD WINAPI serve(void *context) {
    fixture *f=context;
    while(WaitForSingleObject(f->stop,0)==WAIT_TIMEOUT) {
        fd_set set;FD_ZERO(&set);FD_SET(f->listener,&set);struct timeval interval={0,20000};
        if(select(0,&set,NULL,NULL,&interval)<=0)continue;
        SOCKET peer=accept(f->listener,NULL,NULL);if(peer==INVALID_SOCKET)continue;
        DWORD timeout=1000;setsockopt(peer,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout));
        char request[2048]={0};recv(peer,request,sizeof(request)-1,0);InterlockedIncrement(&f->requests);
        char response[4096];
        if(InterlockedCompareExchange(&f->fail,0,0)==2)(void)WaitForSingleObject(f->stop,5000);
        if(InterlockedCompareExchange(&f->fail,0,0))strcpy_s(response,sizeof(response),"HTTP/1.1 500 Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        else sprintf_s(response,sizeof(response),"HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=10; download=20; total=100; expire=4102444800\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",strlen(body),body);
        size_t used=0,length=strlen(response);while(used<length){int n=send(peer,response+used,(int)(length-used),0);if(n<=0)break;used+=(size_t)n;}
        shutdown(peer,SD_BOTH);closesocket(peer);
    }
    return 0;
}
static bool start_fixture(fixture *f) {
    f->listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);int size=sizeof(address);
    if(f->listener==INVALID_SOCKET || bind(f->listener,(struct sockaddr *)&address,sizeof(address)) || listen(f->listener,8) || getsockname(f->listener,(struct sockaddr *)&address,&size))return false;
    f->port=ntohs(address.sin_port);f->stop=CreateEventW(NULL,TRUE,FALSE,NULL);if(!f->stop)return false;
    f->thread=CreateThread(NULL,0,serve,f,0,NULL);return f->thread!=NULL;
}
static DWORD WINAPI cancel_soon(void *event) {Sleep(100);SetEvent((HANDLE)event);return 0;}
static sbj *parse(const char *text) {static unsigned index=0;++index;sbw_error error={0};sbj *p=sbw_subscription_parse(text,strlen(text),&error);if(!p)fprintf(stderr,"parser case %u failed\n",index);CHECK(p);return p;}
int main(void) {
    sbw_error error={0};WSADATA startup;CHECK(!WSAStartup(MAKEWORD(2,2),&startup));
    sbj *parsed=parse(body);CHECK(sbj_arr_len(sbj_get(parsed,"nodes"))==1 && sbj_get_int(sbj_get(parsed,"report"),"skipped",-1)==0);sbj_free(parsed);
    parsed=parse("http://u:p@proxy.test:8080#http\nsocks5://u:p@proxy.test:1080#socks\nunsupported://PRIVATE_URI\n");
    CHECK(sbj_arr_len(sbj_get(parsed,"nodes"))==2 && sbj_get_int(sbj_get(parsed,"report"),"skipped",0)==1);
    char *report=sbj_dump(sbj_get(parsed,"report"),-1);CHECK(!strstr(report,"PRIVATE_URI") && !strstr(report,"proxy.test"));free(report);sbj_free(parsed);
    parsed=parse("aHR0cDovL3U6cEBwcm94eS50ZXN0OjgwODAjaHR0cA==");CHECK(sbj_get_bool(sbj_get(parsed,"report"),"base64",false));sbj_free(parsed);
    parsed=parse("proxies:\n - {name: h, type: http, server: proxy.test, port: 8080}\n - {name: s, type: socks5, server: socks.test, port: 1080}\n - {name: old, type: unsupported, server: private.test, port: 1}\n");
    CHECK(sbj_arr_len(sbj_get(parsed,"nodes"))==2 && sbj_get_int(sbj_get(parsed,"report"),"skipped",0)==1);sbj_free(parsed);
    const char invalid[]="{\"outbounds\":[{\"type\":\"http\",\"tag\":\"unsafe\",\"server\":\"proxy.test\",\"server_port\":80,\"tls\":{\"certificate_path\":\"C:/secret\"}}]}";
    CHECK(!sbw_subscription_parse(invalid,strlen(invalid),&error));
    parsed=parse("http://proxy.test:80#same\nhttp://other.test:80#same\n");CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(parsed,"nodes"),1),"tag"),"same (2)"));sbj_free(parsed);
    sbj *m=sbw_subscription_metadata("upload=10;download=20;total=100;expire=1000",1001);CHECK(sbj_get_bool(m,"available",false) && sbj_get_int(m,"remaining_bytes",0)==70 && sbj_get_bool(m,"expired",false));sbj_free(m);
    const char *bad[]={"upload=-1","download=1.5","total=9007199254740992","expire=253402300800","upload=1;upload=2","upload=9007199254740991;download=1"};
    for(size_t i=0;i<sizeof(bad)/sizeof(*bad);++i){m=sbw_subscription_metadata(bad[i],0);CHECK(!sbj_get_bool(m,"available",true) && !sbj_get(m,"remaining_bytes"));sbj_free(m);}
    m=sbw_subscription_metadata(NULL,0);CHECK(!sbj_get_bool(m,"available",true) && !sbj_get_bool(m,"header_present",true));sbj_free(m);
    sbj *identity=sbw_independent_identity();CHECK(sbw_identity_is_independent(identity) && !*sbj_get_str(identity,"agent_token","notempty"));
    sbj *empty=sbw_independent_snapshot(identity,&error);CHECK(empty);sbj_free(empty);
    sbj *params=sbj_object();sbj_set_str(params,"name","Offline");sbj_set_str(params,"body",body);sbj_set_int(params,"refresh_interval_minutes",60);
    sbj *updated=sbw_subscriptions_import(identity,params,NULL,&error);CHECK(updated && !sbj_arr_len(sbj_get(identity,"local_subscriptions")));
    const sbj *offline=sbj_arr_at(sbj_get(updated,"local_subscriptions"),0);CHECK(sbj_get_int(offline,"refresh_interval_minutes",-1)==0 && !sbw_subscriptions_due(updated,(uint64_t)time(NULL)+100000));
    sbj *source=sbw_independent_snapshot(updated,&error);CHECK(source);
    sbj *effective=sbw_routing_apply(source,updated,true,&error);CHECK(effective);
    sbj *cfg=sbj_parse_cstr(sbj_get_str(effective,"content",""));CHECK(sbj_arr_len(sbj_get(cfg,"outbounds"))==3);
    CHECK(sbj_string_is(sbj_get(sbj_get(cfg,"route"),"final"),SBW_DEFAULT_SELECTOR));
    CHECK(sbj_string_is(sbj_get(sbj_get(cfg,"route"),"default_domain_resolver"),"local-bootstrap-dns"));
    CHECK(!sbj_get(cfg,"endpoints"));sbj_free(cfg);
    sbw_runtime_config runtime={0};const char *content=sbj_get_str(effective,"content","");
    CHECK(!sbw_runtime_config_prepare(content,strlen(content),"",&runtime,&error));
    cfg=sbj_parse_cstr(runtime.json);CHECK(!sbj_has(sbj_arr_at(sbj_get(sbj_get(cfg,"route"),"rules"),1),"domain"));sbj_free(cfg);sbw_runtime_config_free(&runtime);
    sbj *summary=sbw_subscriptions_summary(source,updated);char *public=sbj_dump(summary,-1);CHECK(!strstr(public,"PRIVATE_NODE") && !strstr(public,"proxy.test"));free(public);sbj_free(summary);
    fixture server={0};CHECK(start_fixture(&server));char url[128];sprintf_s(url,sizeof(url),"http://127.0.0.1:%u/sub?token=PRIVATE_URL",server.port);
    sbj_del(params,"body");sbj_set_str(params,"name","Remote");sbj_set_str(params,"url",url);sbj_set_int(params,"refresh_interval_minutes",15);
    sbj *remote=sbw_subscriptions_import(updated,params,NULL,&error);CHECK(remote);
    const sbj *subscription=sbj_arr_at(sbj_get(remote,"local_subscriptions"),1);char *id=sb_strdup(sbj_get_str(subscription,"id",""));
    CHECK(sbj_get_int(sbj_get(subscription,"metadata"),"remaining_bytes",0)==70 && sbj_get_int(subscription,"last_success_at",0)>0);
    uint64_t due=(uint64_t)sbj_get_int(subscription,"next_refresh_at",0);CHECK(sb_streq(sbw_subscriptions_due(remote,due),id));
    sbj *refresh=sbw_subscriptions_refresh(remote,id,NULL,&error);CHECK(refresh && sbj_string_is(sbj_get(sbj_arr_at(sbj_get(refresh,"local_subscriptions"),1),"id"),id));
    InterlockedExchange(&server.fail,1);CHECK(!sbw_subscriptions_refresh(remote,id,NULL,&error));
    sbj *failure=sbw_subscriptions_failure(remote,id,error.code,due);const sbj *failed=sbj_arr_at(sbj_get(failure,"local_subscriptions"),1);
    CHECK(sbj_equal(sbj_get(subscription,"nodes"),sbj_get(failed,"nodes")) && sbj_equal(sbj_get(subscription,"url"),sbj_get(failed,"url")));
    CHECK(sbj_get_int(failed,"next_refresh_at",0)==(int64_t)due+60 && *sbj_get_str(failed,"last_error",""));
    HANDLE cancel=CreateEventW(NULL,TRUE,TRUE,NULL);LONG before=server.requests;CHECK(!sbw_subscription_fetch(url,cancel,&error) && server.requests==before);CloseHandle(cancel);
    InterlockedExchange(&server.fail,2);cancel=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(cancel);
    HANDLE canceller=CreateThread(NULL,0,cancel_soon,cancel,0,NULL);CHECK(canceller);ULONGLONG begin=GetTickCount64();
    CHECK(!sbw_subscription_fetch(url,cancel,&error) && !strcmp(error.code,"SUBSCRIPTION_CANCELLED") && GetTickCount64()-begin<2500);
    WaitForSingleObject(canceller,2000);CloseHandle(canceller);CloseHandle(cancel);
    summary=sbw_subscriptions_summary(source,failure);public=sbj_dump(summary,-1);CHECK(!strstr(public,"PRIVATE_URL") && !strstr(public,"PRIVATE_NODE"));free(public);sbj_free(summary);
    SetEvent(server.stop);WaitForSingleObject(server.thread,3000);CloseHandle(server.thread);CloseHandle(server.stop);closesocket(server.listener);
    free(id);sbj_free(identity);sbj_free(updated);sbj_free(remote);sbj_free(refresh);sbj_free(failure);sbj_free(source);sbj_free(effective);sbj_free(params);WSACleanup();
    puts("Independent subscriptions: native JSON/YAML/URI/base64, reports, metadata, DNS bootstrap, native refresh, stable IDs and failed-update retention passed.");return 0;
}
