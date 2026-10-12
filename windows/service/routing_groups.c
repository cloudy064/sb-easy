#include "subscriptions.h"
#include "routing.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static bool simple(const sbj *r, const char *target) {
    if (!sbj_is_object(r) || !sb_streq(sbj_get_str(r, "action", "route"), "route")) return false;
    for (size_t i = 0; i < sbj_obj_len(r); ++i) {
        const char *k = sbj_obj_key(r, i);
        if (strcmp(k, "domain_suffix") && strcmp(k, "action") && strcmp(k, target)) return false;
    }
    return true;
}
static bool contains(const sbj *a, const char *s) {
    for (size_t i = 0; i < sbj_arr_len(a); ++i) if (sbj_string_is(sbj_arr_at(a, i), s)) return true;
    return false;
}
static bool same_domains(const sbj *a, const sbj *b) {
    if (!sbj_arr_len(a) || sbj_arr_len(a) != sbj_arr_len(b)) return false;
    for (size_t i = 0; i < sbj_arr_len(a); ++i)
        if (!contains(b, sbj_as_str(sbj_arr_at(a, i), ""))) return false;
    return true;
}
static const sbj *named(const sbj *items, const char *tag) {
    for (size_t i = 0; i < sbj_arr_len(items); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(items, i), "tag"), tag)) return sbj_arr_at(items, i);
    return NULL;
}
static bool remote_dns(const sbj *s) {
    const char *type = sbj_get_str(s, "type", "");
    return !strcmp(type,"https") || !strcmp(type,"tls") || !strcmp(type,"tcp") ||
        !strcmp(type,"udp") || !strcmp(type,"quic") || !strcmp(type,"h3");
}
static int compare(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }
static void group_id(const sbj *domains, char *id, size_t size) {
    if (contains(domains,"openai.com") || contains(domains,"chatgpt.com")) { strcpy_s(id,size,"gpt"); return; }
    if (contains(domains,"claude.ai") || contains(domains,"anthropic.com")) { strcpy_s(id,size,"claude"); return; }
    size_t count = sbj_arr_len(domains);
    const char **sorted = sb_xcalloc(count, sizeof(*sorted));
    for (size_t i=0;i<count;++i) sorted[i]=sbj_as_str(sbj_arr_at(domains,i),"");
    qsort(sorted,count,sizeof(*sorted),compare);
    unsigned long long hash=14695981039346656037ULL;
    for(size_t i=0;i<count;++i) {
        for(const unsigned char *p=(const unsigned char *)sorted[i];*p;++p) {hash^=*p;hash*=1099511628211ULL;}
        hash^=0xff;hash*=1099511628211ULL;
    }
    free(sorted); sprintf_s(id,size,"service-%016llx",hash);
}
static sbj *preference(const sbj *identity, const char *id) {
    const sbj *stored=sbj_get(sbj_get(identity,"windows_routing"),id);
    if(stored) return sbj_clone(stored);
    sbj *p=sbj_object();
    const char *node=!strcmp(id,"gpt") ? sbj_get_str(identity,"windows_gpt_outbound","") : "";
    bool def=!strcmp(id,"gpt") && sbj_get_bool(identity,"windows_gpt_use_default",false);
    sbj_set_str(p,"mode",*node?"node":def?"default":"server");
    if(*node) sbj_set_str(p,"node",node);
    return p;
}
static sbj *discover(const sbj *config, const sbj *identity) {
    sbj *groups=sbj_array();
    const sbj *route=sbj_get(config,"route"), *dns=sbj_get(config,"dns");
    const sbj *rules=sbj_get(route,"rules"), *drules=sbj_get(dns,"rules"), *servers=sbj_get(dns,"servers");
    const sbj *nodes=sbj_get(config,"outbounds");
    bool collision=false;
    for(size_t i=0;i<sbj_arr_len(nodes);++i)
        if(!strncmp(sbj_get_str(sbj_arr_at(nodes,i),"tag",""),"sb-easy-local-",14)) collision=true;
    for(size_t i=0;i<sbj_arr_len(servers);++i)
        if(!strncmp(sbj_get_str(sbj_arr_at(servers,i),"tag",""),"sb-easy-local-",14)) collision=true;
    for(size_t slot=0;slot<=sbj_arr_len(rules) && sbj_arr_len(groups)<64;++slot) {
        const sbj *r=slot?sbj_arr_at(rules,slot-1):NULL;
        const sbj *domains=sbj_get(r,"domain_suffix");
        if(slot && (!sbj_arr_len(domains) || !sbj_get(r,"outbound"))) continue;
        char id[64]="default", selector[96]; if(slot) group_id(domains,id,sizeof(id));
        sprintf_s(selector,sizeof(selector),"sb-easy-local-%s",id);
        const char *server=slot?sbj_get_str(r,"outbound",""):sbj_get_str(route,"final","");
        const char *dns_tag=sbj_get_str(dns,"final","");
        bool eligible=!collision && *server;
        int dns_index=-1;
        if(slot) {
            eligible &= simple(r,"outbound");
            int matches=0;
            for(size_t j=0;j<sbj_arr_len(drules);++j) {
                const sbj *dr=sbj_arr_at(drules,j);
                if(same_domains(domains,sbj_get(dr,"domain_suffix"))) {
                    ++matches; dns_index=(int)j; dns_tag=sbj_get_str(dr,"server","");
                    eligible &= simple(dr,"server");
                }
            }
            eligible &= matches==1;
        }
        eligible &= remote_dns(named(servers,dns_tag));
        sbj *g=sbj_object(), *p=preference(identity,id);
        const char *mode=sbj_get_str(p,"mode","server");
        const char *target= !strcmp(mode,"node")?sbj_get_str(p,"node",""):server;
        if(!strcmp(mode,"default")) {
            const sbj *base=sbj_arr_at(groups,0); target=sbj_get_str(base,"outbound",server);
        }
        sbj_set_str(g,"id",id); sbj_set_str(g,"selector",selector);
        sbj_set_str(g,"label",!slot?"默认代理":!strcmp(id,"gpt")?"GPT / Codex":!strcmp(id,"claude")?"Claude":sbj_as_str(sbj_arr_at(domains,0),"服务分组"));
        sbj_set_str(g,"server_outbound",server); sbj_set_str(g,"outbound",target); sbj_set_str(g,"mode",mode);
        sbj_set_bool(g,"editable",eligible);
        sbj_set_str(g,"reason",eligible?"":"此规则或 DNS 结构暂不支持安全的本地覆盖");
        sbj_set_int(g,"route_index",slot?(long long)slot-1:-1);
        sbj_set_int(g,"dns_index",dns_index); sbj_set_str(g,"dns_tag",dns_tag);
        sbj_arr_push(groups,g); sbj_free(p);
    }
    /* Ambiguous identities must never silently change more than one rule. */
    for(size_t i=0;i<sbj_arr_len(groups);++i) for(size_t j=i+1;j<sbj_arr_len(groups);++j) {
        sbj *a=sbj_arr_at(groups,i), *b=sbj_arr_at(groups,j);
        if(sb_streq(sbj_get_str(a,"id",""),sbj_get_str(b,"id",""))) {
            sbj_set_bool(a,"editable",false);sbj_set_bool(b,"editable",false);
            sbj_set_str(a,"reason","存在多个同名服务规则，暂不支持本地覆盖");
            sbj_set_str(b,"reason","存在多个同名服务规则，暂不支持本地覆盖");
        }
    }
    return groups;
}
sbj *sbw_routing_groups(const sbj *source,const sbj *identity) {
    if(!source) return sbj_array();
    sbj *config=sbj_parse_cstr(sbj_get_str(source,"content",""));
    sbw_error ignored={0};if(sbw_subscriptions_merge(config,identity,&ignored)!=0){sbj_free(config);return sbj_array();}
    sbj *groups=discover(config,identity);sbj_free(config);return groups;
}
sbj *sbw_routing_apply(const sbj *source,const sbj *identity,bool runtime,sbw_error *error) {
    if(!source)return NULL;
    sbj *config=sbj_parse_cstr(sbj_get_str(source,"content",""));
    if(!config){sbw_fail(error,"ROUTING_UNSUPPORTED","Invalid routing source.");return NULL;}
    if(sbw_subscriptions_merge(config,identity,error)!=0){sbj_free(config);return NULL;}
    sbj *groups=discover(config,identity), *route=sbj_get(config,"route"), *dns=sbj_get(config,"dns");
    sbj *nodes=sbj_get(config,"outbounds"), *servers=sbj_get(dns,"servers");
    size_t node_count=sbj_arr_len(nodes);
    const sbj *overrides=sbj_get(identity,"windows_routing");
    if(!sbj_get(overrides,"gpt") && (sbj_get_bool(identity,"windows_gpt_use_default",false) || sbj_get_str(identity,"windows_gpt_outbound",NULL))) {
        bool found=false;
        for(size_t i=0;i<sbj_arr_len(groups);++i) if(sbj_string_is(sbj_get(sbj_arr_at(groups,i),"id"),"gpt"))found=true;
        if(!found)goto unavailable;
    }
    for(size_t i=0;i<sbj_obj_len(overrides);++i) {
        bool found=false;
        for(size_t j=0;j<sbj_arr_len(groups);++j)
            if(sbj_string_is(sbj_get(sbj_arr_at(groups,j),"id"),sbj_obj_key(overrides,i)))found=true;
        if(!found && !sbj_string_is(sbj_get(sbj_obj_val(overrides,i),"mode"),"server"))goto unsupported;
    }
    for(size_t i=0;i<sbj_arr_len(groups);++i) {
        const sbj *g=sbj_arr_at(groups,i);
        const char *mode=sbj_get_str(g,"mode","server"), *id=sbj_get_str(g,"id","");
        const char *target=sbj_get_str(g,"outbound",""), *selector=sbj_get_str(g,"selector","");
        bool local=strcmp(mode,"server")!=0, editable=sbj_get_bool(g,"editable",false);
        if(strcmp(mode,"server") && strcmp(mode,"node") && strcmp(mode,"default"))goto unsupported;
        if(local && !editable)goto unsupported;
        if(!editable || (!runtime && !local))continue;
        const sbj *node=named(nodes,target);
        if(!node || sbj_string_is(sbj_get(node,"type"),"block"))goto unavailable;
        if(!strcmp(mode,"default") && !strcmp(id,"default"))goto unsupported;
        char dns_name[112];sprintf_s(dns_name,sizeof(dns_name),"%s-dns",selector);
        sbj *copy=sbj_clone(named(servers,sbj_get_str(g,"dns_tag","")));
        sbj_set_str(copy,"tag",dns_name);
        const char *selected=runtime && !strcmp(mode,"default") && sbj_get_bool(sbj_arr_at(groups,0),"editable",false)?SBW_DEFAULT_SELECTOR:target;
        if(runtime) {
            sbj *s=sbj_object(), *members=sbj_array();
            for(size_t j=0;j<node_count;++j) {
                const sbj *n=sbj_arr_at(nodes,j);
                if(!sbj_string_is(sbj_get(n,"type"),"block")) sbj_arr_push(members,sbj_str(sbj_get_str(n,"tag","")));
            }
            if(strcmp(id,"default") && sbj_get_bool(sbj_arr_at(groups,0),"editable",false))sbj_arr_push(members,sbj_str(SBW_DEFAULT_SELECTOR));
            sbj_set_str(s,"tag",selector);sbj_set_str(s,"type","selector");
            sbj_set(s,"outbounds",members);sbj_set_str(s,"default",selected);
            sbj_set_bool(s,"interrupt_exist_connections",false);sbj_arr_push(nodes,s);
        }
        sbj_set_str(copy,"detour",runtime?selector:target);sbj_arr_push(servers,copy);
        if(!strcmp(id,"default")) {
            sbj_set_str(route,"final",runtime?selector:target);sbj_set_str(dns,"final",dns_name);
        } else {
            sbj *r=sbj_arr_at(sbj_get(route,"rules"),(size_t)sbj_get_int(g,"route_index",0));
            sbj *dr=sbj_arr_at(sbj_get(dns,"rules"),(size_t)sbj_get_int(g,"dns_index",0));
            sbj_set_str(r,"outbound",runtime?selector:target);sbj_set_str(dr,"server",dns_name);
        }
    }
    sbj *out=sbj_clone(source);sbj_set(out,"content",sbj_str_take(sbj_dump(config,-1)));
    sbj_free(groups);sbj_free(config);return out;
unavailable:
    sbw_fail(error, !sbj_get(identity,"windows_routing") && sbj_get_str(identity,"windows_gpt_outbound",NULL) ? "GPT_OUTBOUND_UNAVAILABLE" : "ROUTING_NODE_UNAVAILABLE","A locally selected node was removed. Choose another node or restore server routing.");
    sbj_free(groups);sbj_free(config);return NULL;
unsupported:
    sbw_fail(error,"ROUTING_UNSUPPORTED","A locally overridden service or its DNS changed. Restore server routing for that group.");
    sbj_free(groups);sbj_free(config);return NULL;
}
