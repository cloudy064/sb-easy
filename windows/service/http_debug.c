#include "http_debug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
char *sbw_http_debug_overlay(const char *json,const sbj *domains,const char *password,sbw_error *error) {
    if(!sbj_is_array(domains)||!sbj_arr_len(domains)||sbj_arr_len(domains)>64||strlen(password)!=64)goto invalid;
    for(size_t i=0;i<sbj_arr_len(domains);i++) {
        const char *d=sbj_as_str(sbj_arr_at(domains,i),"");size_t n=strlen(d);
        if(!n||n>253||d[0]=='.'||d[n-1]=='.'||strspn(d,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")!=n)goto invalid;
    }
    sbj *root=sbj_parse_cstr(json),*in=sbj_get(root,"inbounds"),*out=sbj_get(root,"outbounds"),*rules=sbj_get(sbj_get(root,"route"),"rules");
    if(!sbj_is_array(in)||!sbj_is_array(out)||!sbj_is_array(rules)){sbj_free(root);goto invalid;}
    sbj *tags=sbj_array();
    for(size_t i=0;i<sbj_arr_len(in);i++) {
        sbj *entry=sbj_arr_at(in,i);
        const char *type=sbj_get_str(entry,"type","");
        if(!strcmp(type,"tun")||!strcmp(type,"mixed")||!strcmp(type,"http")||!strcmp(type,"socks")) {
            const char *tag=sbj_get_str(entry,"tag","");
            if(!strncmp(tag,"sb-httpdebug-",13)){sbj_free(tags);sbj_free(root);goto invalid;}
            if(!*tag){char generated[64];sprintf_s(generated,sizeof generated,"sb-httpdebug-ingress-%zu",i);sbj_set_str(entry,"tag",generated);tag=sbj_get_str(entry,"tag","");}
            sbj_arr_push(tags,sbj_str(tag));
        }
    }
    if(!sbj_arr_len(tags)){sbj_free(tags);sbj_free(root);sbw_fail(error,"HTTP_DEBUG_INGRESS","HTTP debugging requires an active TUN or local proxy listener.");return NULL;}
    for(size_t i=0;i<sbj_arr_len(out);i++)if(!strncmp(sbj_get_str(sbj_arr_at(out,i),"tag",""),"sb-httpdebug-",13)){sbj_free(tags);sbj_free(root);goto invalid;}
    sbj *up=sbj_object();sbj_set_str(up,"type","http");sbj_set_str(up,"tag","sb-httpdebug-upstream");sbj_set_str(up,"listen","127.0.0.1");sbj_set_int(up,"listen_port",17992);sbj_arr_push(in,up);
    sbj *proxy=sbj_object();sbj_set_str(proxy,"type","http");sbj_set_str(proxy,"tag","sb-httpdebug-engine");sbj_set_str(proxy,"server","127.0.0.1");sbj_set_int(proxy,"server_port",17990);sbj_set_str(proxy,"username","sbeasy");sbj_set_str(proxy,"password",password);sbj_arr_push(out,proxy);
    sbj *match=sbj_object();sbj_set(match,"inbound",tags);sbj_set(match,"domain_suffix",sbj_clone(domains));sbj_set_int(match,"port",443);
    sbj *quic=sbj_clone(match);sbj_set_str(quic,"network","udp");sbj_set_str(quic,"action","reject");
    sbj_del(match,"port");sbj *ports=sbj_array();sbj_arr_push(ports,sbj_int(80));sbj_arr_push(ports,sbj_int(443));sbj_set(match,"port",ports);sbj_set_str(match,"network","tcp");sbj_set_str(match,"action","route");sbj_set_str(match,"outbound","sb-httpdebug-engine");
    // Sniff before domain matching; upstream inbound is excluded by tag.
    sbj *sniff=sbj_object();sbj_set(sniff,"inbound",sbj_clone(sbj_get(match,"inbound")));sbj_set_str(sniff,"action","sniff");
    sbj_arr_insert(rules,0,match);sbj_arr_insert(rules,0,quic);sbj_arr_insert(rules,0,sniff);
    char *result=sbj_dump(root,-1);sbj_free(root);return result;
invalid:sbw_fail(error,"INVALID_REQUEST","Provide 1–64 valid domain names and a fresh capture session.");return NULL;
}
