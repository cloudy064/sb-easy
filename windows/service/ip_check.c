#include <winsock2.h>
#include <ws2tcpip.h>
#include "ip_check.h"
#include "subscriptions.h"
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdlib.h>
#include <string.h>

static bool label(const sbj *value,size_t limit) {
    if(!sbw_json_string(value,limit,false))return false;
    for(const unsigned char *p=(const unsigned char *)value->v.str.ptr;*p;++p)if(*p<32||*p==127)return false;
    return true;
}
static bool concrete(const sbj *node) {
    static const char *types[]={"http","socks","shadowsocks","vmess","trojan","vless","hysteria","hysteria2","tuic","anytls","shadowtls","ssh","naive"};
    if(!label(sbj_get(node,"tag"),256))return false;
    for(size_t i=0;i<sizeof(types)/sizeof(types[0]);++i)
        if(sbj_string_is(sbj_get(node,"type"),types[i]))return true;
    return false;
}
static const char *source_name(const sbj *sources,const char *tag) {
    for(size_t i=0;i<sbj_arr_len(sources);++i) {
        const sbj *source=sbj_arr_at(sources,i),*tags=sbj_get(source,"tags");
        if(!label(sbj_get(source,"name"),256))continue;
        for(size_t j=0;j<sbj_arr_len(tags);++j)
            if(sbj_string_is(sbj_arr_at(tags,j),tag))return sbj_get_str(source,"name","");
    }
    return NULL;
}
sbj *sbw_ipcheck_nodes(const sbj *config,const sbj *source,const sbj *identity,sbw_error *error) {
    const sbj *nodes=sbj_get(config,"outbounds");
    if(!sbj_is_array(nodes)||sbj_arr_len(nodes)>1024) {
        sbw_fail(error,"INVALID_CONFIGURATION","IP detection supports at most 1024 configured nodes.");return NULL;
    }
    sbj *result=sbj_array(),*sources=sbw_subscriptions_summary(source,identity);
    for(size_t i=0;i<sbj_arr_len(nodes);++i) {
        const sbj *node=sbj_arr_at(nodes,i);if(!concrete(node))continue;
        const char *tag=sbj_get_str(node,"tag","");
        const char *name=source_name(sbj_get(sources,"local"),tag);
        if(!name)name=source_name(sbj_get(sources,"managed"),tag);
        sbj *item=sbj_object();sbj_set_str(item,"tag",tag);sbj_set_str(item,"type",sbj_get_str(node,"type",""));
        sbj_set_str(item,"source",name?name:"共享配置");sbj_arr_push(result,item);
    }
    sbj_free(sources);return result;
}
sbj *sbw_ipcheck_interfaces(void) {
    sbj *result=sbj_object(),*list=sbj_array();sbj_set(result,"interfaces",list);sbj_set_str(result,"default_interface","");
    ULONG size=16384,status=ERROR_BUFFER_OVERFLOW;IP_ADAPTER_ADDRESSES *adapters=NULL;
    for(int attempt=0;attempt<3&&status==ERROR_BUFFER_OVERFLOW;++attempt) {
        free(adapters);adapters=sb_xcalloc(size,1);
        status=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER|GAA_FLAG_INCLUDE_GATEWAYS,NULL,adapters,&size);
    }
    ULONG best=MAXDWORD;
    if(status==NO_ERROR)for(IP_ADAPTER_ADDRESSES *a=adapters;a;a=a->Next) {
        if(a->OperStatus!=IfOperStatusUp||!a->FirstUnicastAddress||!a->FriendlyName||
           (a->IfType!=IF_TYPE_ETHERNET_CSMACD&&a->IfType!=IF_TYPE_IEEE80211))continue;
        MIB_IF_ROW2 row={0};row.InterfaceLuid=a->Luid;
        if(GetIfEntry2(&row)!=NO_ERROR||!row.InterfaceAndOperStatusFlags.HardwareInterface||row.InterfaceAndOperStatusFlags.FilterInterface)continue;
        char *name=sbw_utf8(a->FriendlyName,NULL);
        bool safe=name&&*name&&strlen(name)<=256;
        for(const unsigned char *p=(const unsigned char *)(name?name:"");safe&&*p;++p)if(*p<32||*p==127)safe=false;
        if(!safe){free(name);continue;}
        sbj *item=sbj_object();sbj_set_str(item,"name",name);sbj_arr_push(list,item);
        /* Prefer a physical interface with a gateway; do not consult the active
         * TUN's default route or reuse its selected outbound. */
        ULONG metric=a->FirstGatewayAddress?a->Ipv4Metric:MAXDWORD-1;
        if(metric<best){best=metric;sbj_set_str(result,"default_interface",name);}
        free(name);
    }
    free(adapters);return result;
}
int sbw_ipcheck_validate(const sbj *config,const sbj *params,const sbj *interfaces,sbw_error *error) {
    const sbj *tags=sbj_get(params,"tags"),*nodes=sbj_get(config,"outbounds");
    if(!sbj_is_object(params)||sbj_obj_len(params)!=3||!sbj_is_array(tags)||!sbj_arr_len(tags)||sbj_arr_len(tags)>100||
       !sbj_is_bool(sbj_get(params,"ipv6"))||!label(sbj_get(params,"interface"),256))goto invalid;
    bool available=false;const char *name=sbj_get_str(params,"interface","");
    for(size_t i=0;i<sbj_arr_len(interfaces);++i)
        if(sbj_string_is(sbj_get(sbj_arr_at(interfaces,i),"name"),name))available=true;
    if(!available)return sbw_fail(error,"IPCHECK_INTERFACE","Choose an available physical Ethernet or Wi-Fi interface.");
    for(size_t i=0;i<sbj_arr_len(tags);++i) {
        if(!label(sbj_arr_at(tags,i),256))goto invalid;
        for(size_t j=0;j<i;++j)if(sbj_equal(sbj_arr_at(tags,i),sbj_arr_at(tags,j)))goto invalid;
        size_t matches=0;
        for(size_t j=0;j<sbj_arr_len(nodes);++j)
            if(concrete(sbj_arr_at(nodes,j))&&sbj_equal(sbj_get(sbj_arr_at(nodes,j),"tag"),sbj_arr_at(tags,i)))++matches;
        if(matches!=1)goto invalid;
    }
    return 0;
invalid:return sbw_fail(error,"INVALID_REQUEST","Select 1 to 100 distinct configured proxy nodes, a physical interface and the IPv6 option.");
}
sbj *sbw_ipcheck_failed_snapshot(const sbj *previous) {
    sbj *result=previous?sbj_clone(previous):sbj_object();
    if(!previous) {
        sbj *summary=sbj_object();sbj_set_str(summary,"status","failed");
        const char *counts[]={"node_count","processed_count","measured_count","info_count","complete_count"};
        for(size_t i=0;i<sizeof(counts)/sizeof(counts[0]);++i)sbj_set_int(summary,counts[i],0);
        sbj_set(result,"summary",summary);sbj_set(result,"results",sbj_array());
    }
    sbj_set_str(result,"phase","failed");sbj_set_bool(result,"cancel_requested",false);
    sbj_set_str(result,"error","probe_worker_stopped");return result;
}
