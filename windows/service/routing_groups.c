#include "subscriptions.h"
#include "routing.h"
#include "health.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static bool valid_id(const sbj *value) {
    if (!sbw_json_string(value, 48, false)) return false;
    const char *id = sbj_as_str(value, "");
    return !strncmp(id, "custom-", 7) && strlen(id) > 7 &&
        strspn(id, "abcdefghijklmnopqrstuvwxyz0123456789-") == strlen(id);
}
static bool valid_domain(const sbj *value) {
    if (!sbw_json_string(value, 253, false)) return false;
    const char *s = sbj_as_str(value, ""), *label = s;
    if (!strchr(s, '.') || strspn(s, "0123456789.") == strlen(s)) return false;
    for (const char *p = s;; ++p) {
        if (*p && *p != '.') {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-')) return false;
            continue;
        }
        size_t n = (size_t)(p - label);
        if (!n || n > 63 || *label == '-' || p[-1] == '-') return false;
        if (!*p) break;
        label = p + 1;
    }
    return true;
}
static bool valid_process(const sbj *value) {
    if (!sbw_json_string(value, 128, false)) return false;
    const char *s = sbj_as_str(value, ""); size_t n = strlen(s);
    if (n < 5 || _stricmp(s + n - 4, ".exe") || strpbrk(s, "\\/:*?\"<>|")) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) if (*p < 32) return false;
    return *s != ' ' && s[n - 1] != ' ';
}
static bool domain_overlap(const char *a, const char *b) {
    size_t na = strlen(a), nb = strlen(b);
    return !strcmp(a,b) || (na > nb && a[na-nb-1] == '.' && !strcmp(a+na-nb,b)) ||
        (nb > na && b[nb-na-1] == '.' && !strcmp(b+nb-na,a));
}
static bool valid_label(const sbj *value) {
    if(!sbw_json_string(value,160,false))return false;
    const unsigned char *s=(const unsigned char *)sbj_as_str(value,"");
    if(*s==' ' || s[strlen((const char *)s)-1]==' ')return false;
    for(;*s;++s)if(*s<32 || *s==127)return false;
    return true;
}
static bool local_valid(const sbj *groups) {
    if (!groups) return true;
    if (!sbj_is_array(groups) || sbj_arr_len(groups) > 32) return false;
    for (size_t i = 0; i < sbj_arr_len(groups); ++i) {
        const sbj *g = sbj_arr_at(groups,i), *domains = sbj_get(g,"domains"), *processes = sbj_get(g,"processes");
        const char *mode = sbj_get_str(g,"mode","");
        if (!valid_id(sbj_get(g,"id")) || !valid_label(sbj_get(g,"label")) ||
            !sbj_is_array(domains) || !sbj_is_array(processes) || sbj_arr_len(domains) > 256 ||
            sbj_arr_len(processes) > 64 || (!sbj_arr_len(domains) && !sbj_arr_len(processes)) ||
            (strcmp(mode,"default") && strcmp(mode,"node")) ||
            (!strcmp(mode,"node") && !sbw_json_string(sbj_get(g,"node"),512,false))) return false;
        for (size_t d=0; d<sbj_arr_len(domains); ++d) if (!valid_domain(sbj_arr_at(domains,d))) return false;
        for (size_t d=0; d<sbj_arr_len(processes); ++d) if (!valid_process(sbj_arr_at(processes,d))) return false;
        for (size_t j=0; j<=i; ++j) {
            const sbj *prev=sbj_arr_at(groups,j);
            if (j<i && (!strcmp(sbj_get_str(g,"id",""),sbj_get_str(prev,"id","")) ||
                !_stricmp(sbj_get_str(g,"label",""),sbj_get_str(prev,"label","")))) return false;
            const sbj *pd=sbj_get(prev,"domains"), *pp=sbj_get(prev,"processes");
            for (size_t d=0; d<sbj_arr_len(domains); ++d) for (size_t e=0; e<sbj_arr_len(pd); ++e)
                if ((j<i || e<d) && domain_overlap(sbj_as_str(sbj_arr_at(domains,d),""),sbj_as_str(sbj_arr_at(pd,e),""))) return false;
            for (size_t d=0; d<sbj_arr_len(processes); ++d) for (size_t e=0; e<sbj_arr_len(pp); ++e)
                if ((j<i || e<d) && !_stricmp(sbj_as_str(sbj_arr_at(processes,d),""),sbj_as_str(sbj_arr_at(pp,e),""))) return false;
        }
    }
    return true;
}
sbj *sbw_routing_change(const sbj *identity,const sbj *params,bool remove,sbw_error *error) {
    if (!sbj_is_object(identity) || !sbj_is_object(params) || !valid_id(sbj_get(params,"id")) ||
        (remove ? sbj_obj_len(params)!=1 : sbj_obj_len(params)!=(!strcmp(sbj_get_str(params,"mode",""),"node")?6U:5U))) goto invalid;
    const sbj *stored=sbj_get(identity,"windows_local_groups");
    if (!local_valid(stored)) goto invalid;
    sbj *groups=sbj_array(); bool found=false;
    for (size_t i=0;i<sbj_arr_len(stored);++i) {
        const sbj *g=sbj_arr_at(stored,i);
        if (sbj_string_is(sbj_get(g,"id"),sbj_get_str(params,"id",""))) {
            found=true; if(!remove)sbj_arr_push(groups,sbj_clone(params));
        } else sbj_arr_push(groups,sbj_clone(g));
    }
    if (!found && !remove) sbj_arr_push(groups,sbj_clone(params));
    if (remove && !found) { sbj_free(groups);sbw_fail(error,"ROUTING_GROUP_NOT_FOUND","This local group no longer exists.");return NULL; }
    if (!local_valid(groups)) {sbj_free(groups);goto invalid;}
    sbj *out=sbj_clone(identity);sbj_set(out,"windows_local_groups",groups);
    sbj_del(sbj_get(out,"windows_routing"),sbj_get_str(params,"id",""));return out;
invalid:
    sbw_fail(error,"INVALID_REQUEST","Use a custom- group ID, a label, non-overlapping lowercase domains and executable names, and a valid node or default mode.");return NULL;
}

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
static bool health_node(const sbj *node) {
    const char *type = sbj_get_str(node, "type", "");
    return sbw_json_string(sbj_get(node, "server"), 1024, false) && strcmp(type, "direct") &&
        strcmp(type, "block") && strcmp(type, "selector") && strcmp(type, "urltest") &&
        strcmp(type, "dns") && strcmp(type, "wireguard");
}
static bool automatic_valid(const sbj *candidates) {
    if (!sbj_is_array(candidates) || !sbj_arr_len(candidates) || sbj_arr_len(candidates) > 32) return false;
    for (size_t i = 0; i < sbj_arr_len(candidates); ++i) {
        if (!sbw_json_string(sbj_arr_at(candidates, i), 512, false)) return false;
        for (size_t j = 0; j < i; ++j)
            if (sbj_equal(sbj_arr_at(candidates, i), sbj_arr_at(candidates, j))) return false;
    }
    return true;
}
static const char *automatic_target(const sbj *nodes, const sbj *candidates) {
    for (size_t i = 0; i < sbj_arr_len(candidates); ++i) {
        const char *tag = sbj_as_str(sbj_arr_at(candidates, i), "");
        if (health_node(named(nodes, tag))) return tag;
    }
    return "";
}
sbj *sbw_routing_automatic(const sbj *source, const sbj *identity, const sbj *params, sbw_error *error) {
    const sbj *candidates = sbj_get(params, "candidates");
    if (!source || !sbj_is_object(identity) || !sbj_is_object(params) || sbj_obj_len(params) != 2 ||
        !sbw_json_string(sbj_get(params, "group"), 64, false) || !automatic_valid(candidates)) goto invalid;
    sbj *policy = sbw_health_policy(identity);
    bool enabled = sbw_health_policy_valid(policy) && sbj_get_bool(policy, "enabled", false); sbj_free(policy);
    if (!enabled) { sbw_fail(error, "HEALTH_REQUIRED", "Enable health checks before configuring automatic groups."); return NULL; }
    sbj *config = sbj_parse_cstr(sbj_get_str(source, "content", ""));
    if (!config || sbw_subscriptions_merge(config, identity, error)) { sbj_free(config); goto invalid; }
    const sbj *nodes = sbj_get(config, "outbounds");
    for (size_t i = 0; i < sbj_arr_len(candidates); ++i)
        if (!health_node(named(nodes, sbj_as_str(sbj_arr_at(candidates, i), "")))) { sbj_free(config); goto invalid; }
    sbj_free(config);
    sbj *groups = sbw_routing_groups(source, identity); bool found = false;
    for (size_t i = 0; i < sbj_arr_len(groups); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(groups, i), "id"), sbj_get_str(params, "group", "")) &&
            sbj_get_bool(sbj_arr_at(groups, i), "editable", false)) found = true;
    sbj_free(groups); if (!found) goto invalid;
    sbj *result = sbj_clone(identity), *overrides = sbj_get_or_object(result, "windows_routing");
    sbj *preference = sbj_object(); sbj_set_str(preference, "mode", "automatic");
    sbj_set(preference, "automatic_candidates", sbj_clone(candidates));
    sbj_set(overrides, sbj_get_str(params, "group", ""), preference);
    size_t total = 0;
    for (size_t i = 0; i < sbj_obj_len(overrides); ++i)
        total += sbj_arr_len(sbj_get(sbj_obj_val(overrides, i), "automatic_candidates"));
    if (total > 128) { sbj_free(result); goto invalid; }
    if (sbj_string_is(sbj_get(params, "group"), "gpt")) {
        sbj_set_bool(result, "windows_gpt_use_default", false); sbj_del(result, "windows_gpt_outbound");
    }
    return result;
invalid:
    sbw_fail(error, "INVALID_REQUEST", "Choose an editable group and 1–32 distinct proxy nodes; direct, nested groups and unknown nodes are not automatic candidates (128 total maximum)."); return NULL;
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
        if (!strcmp(mode, "automatic")) target = automatic_target(nodes, sbj_get(p, "automatic_candidates"));
        if(!strcmp(mode,"default")) {
            const sbj *base=sbj_arr_at(groups,0); target=sbj_get_str(base,"outbound",server);
        }
        sbj_set_str(g,"id",id); sbj_set_str(g,"selector",selector);
        sbj_set_str(g,"label",!slot?"默认代理":!strcmp(id,"gpt")?"GPT / Codex":!strcmp(id,"claude")?"Claude":sbj_as_str(sbj_arr_at(domains,0),"服务分组"));
        sbj_set_str(g,"server_outbound",server); sbj_set_str(g,"outbound",target); sbj_set_str(g,"mode",mode);
        if (!strcmp(mode, "automatic")) sbj_set(g, "automatic_candidates", sbj_clone(sbj_get(p, "automatic_candidates")));
        sbj_set_bool(g,"editable",eligible);
        sbj_set_bool(g,"local",false);sbj_set(g,"domains",domains?sbj_clone(domains):sbj_array());sbj_set(g,"processes",sbj_array());
        sbj_set_str(g,"reason",eligible?"":"此规则或 DNS 结构暂不支持安全的本地覆盖");
        sbj_set_int(g,"route_index",slot?(long long)slot-1:-1);
        sbj_set_int(g,"dns_index",dns_index); sbj_set_str(g,"dns_tag",dns_tag);
        sbj_arr_push(groups,g); sbj_free(p);
    }
    const sbj *locals=sbj_get(identity,"windows_local_groups");
    for(size_t i=0;i<sbj_arr_len(locals);++i) {
        const sbj *saved=sbj_arr_at(locals,i);sbj *g=sbj_clone(saved);
        const char *id=sbj_get_str(saved,"id",""); char selector[96];
        sprintf_s(selector,sizeof(selector),"sb-easy-local-%s",id);
        const sbj *p=sbj_get(sbj_get(identity,"windows_routing"),id);if(!p)p=saved;
        const char *mode=sbj_get_str(p,"mode","default");
        const char *target=!strcmp(mode,"node")?sbj_get_str(p,"node",""):sbj_get_str(sbj_arr_at(groups,0),"outbound","");
        if (!strcmp(mode, "automatic")) target = automatic_target(nodes, sbj_get(p, "automatic_candidates"));
        if (!strcmp(mode, "automatic")) sbj_set(g, "automatic_candidates", sbj_clone(sbj_get(p, "automatic_candidates")));
        sbj_set_str(g,"mode",mode);sbj_set_str(g,"selector",selector);sbj_set_str(g,"outbound",target);
        sbj_set_str(g,"server_outbound",sbj_get_str(route,"final",""));sbj_set_bool(g,"local",true);
        bool eligible=!collision && remote_dns(named(servers,sbj_get_str(dns,"final","")));
        sbj_set_bool(g,"editable",eligible);sbj_set_str(g,"reason",eligible?"":"本地分组需要可隔离的远程 DNS 配置");
        sbj_set_str(g,"dns_tag",sbj_get_str(dns,"final",""));sbj_arr_push(groups,g);
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
    if(!source || !local_valid(sbj_get(identity,"windows_local_groups"))) return sbj_array();
    sbj *config=sbj_parse_cstr(sbj_get_str(source,"content",""));
    sbw_error ignored={0};if(sbw_subscriptions_merge(config,identity,&ignored)!=0){sbj_free(config);return sbj_array();}
    sbj *groups=discover(config,identity);sbj_free(config);return groups;
}
/* Safety/management rules always run before device overrides; all original
 * rule objects and their relative order within each tier remain intact. */
static bool protected_rule(const sbj *r,const sbj *config,bool dns_rule) {
    const char *action=sbj_get_str(r,"action","route");
    if(strcmp(action,"route"))return true;
    if(dns_rule) {
        const sbj *server=named(sbj_get(sbj_get(config,"dns"),"servers"),sbj_get_str(r,"server",""));
        if(named(sbj_get(config,"endpoints"),sbj_get_str(server,"detour","")))return true;
        return sbj_has(r,"domain") || sbj_has(r,"ip_cidr") || sbj_has(r,"source_ip_cidr") ||
            sbj_has(r,"ip_is_private") || sbj_has(r,"type") || contains(sbj_get(r,"rule_set"),"geosite-private");
    }
    const char *target=sbj_get_str(r,"outbound","");
    if(named(sbj_get(config,"endpoints"),target))return true;
    const sbj *node=named(sbj_get(config,"outbounds"),target);
    if(sbj_string_is(sbj_get(node,"type"),"wireguard"))return true;
    return sbj_has(r,"ip_cidr") || sbj_has(r,"source_ip_cidr") ||
        sbj_has(r,"ip_is_private") || sbj_has(r,"domain") || sbj_has(r,"type") || contains(sbj_get(r,"rule_set"),"geosite-private");
}
static void insert_local_rules(sbj *config,const sbj *routes,const sbj *dns_rules) {
    const char *sections[]={"route","dns"};const sbj *locals[]={routes,dns_rules};
    for(size_t k=0;k<2;++k) {
        if(!sbj_arr_len(locals[k]))continue;
        sbj *section=sbj_get(config,sections[k]), *original=sbj_get(section,"rules"), *rules=sbj_array();
        for(size_t i=0;i<sbj_arr_len(original);++i)if(protected_rule(sbj_arr_at(original,i),config,k==1))
            sbj_arr_push(rules,sbj_clone(sbj_arr_at(original,i)));
        for(size_t i=0;i<sbj_arr_len(locals[k]);++i)sbj_arr_push(rules,sbj_clone(sbj_arr_at(locals[k],i)));
        for(size_t i=0;i<sbj_arr_len(original);++i)if(!protected_rule(sbj_arr_at(original,i),config,k==1))
            sbj_arr_push(rules,sbj_clone(sbj_arr_at(original,i)));
        sbj_set(section,"rules",rules);
    }
}
sbj *sbw_routing_apply(const sbj *source,const sbj *identity,bool runtime,sbw_error *error) {
    if(!source)return NULL;
    if(!local_valid(sbj_get(identity,"windows_local_groups"))){sbw_fail(error,"ROUTING_UNSUPPORTED","The saved local groups are invalid.");return NULL;}
    sbj *health_policy = sbw_health_policy(identity);
    bool health_valid = sbw_health_policy_valid(health_policy), health_enabled = sbj_get_bool(health_policy, "enabled", false);
    sbj_free(health_policy);
    if (!health_valid) { sbw_fail(error, "HEALTH_POLICY_INVALID", "Saved health settings are invalid."); return NULL; }
    sbj *config=sbj_parse_cstr(sbj_get_str(source,"content",""));
    if(!config){sbw_fail(error,"ROUTING_UNSUPPORTED","Invalid routing source.");return NULL;}
    if(sbw_subscriptions_merge(config,identity,error)!=0){sbj_free(config);return NULL;}
    sbj *groups=discover(config,identity), *route=sbj_get(config,"route"), *dns=sbj_get(config,"dns");
    sbj *nodes=sbj_get(config,"outbounds"), *servers=sbj_get(dns,"servers");
    size_t node_count=sbj_arr_len(nodes);
    sbj *local_routes=sbj_array(), *local_dns_rules=sbj_array();
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
        bool custom_group=sbj_get_bool(g,"local",false);
        bool automatic = !strcmp(mode, "automatic");
        if (automatic && (!health_enabled || !automatic_valid(sbj_get(g, "automatic_candidates")))) goto unsupported;
        bool local=custom_group || strcmp(mode,"server")!=0, editable=sbj_get_bool(g,"editable",false);
        if(strcmp(mode,"server") && strcmp(mode,"node") && strcmp(mode,"default") && !automatic)goto unsupported;
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
                if (automatic ? (health_node(n) && contains(sbj_get(g, "automatic_candidates"), sbj_get_str(n, "tag", ""))) :
                    !sbj_string_is(sbj_get(n,"type"),"block")) sbj_arr_push(members,sbj_str(sbj_get_str(n,"tag","")));
            }
            if(!automatic && strcmp(id,"default") && sbj_get_bool(sbj_arr_at(groups,0),"editable",false))sbj_arr_push(members,sbj_str(SBW_DEFAULT_SELECTOR));
            sbj_set_str(s,"tag",selector);sbj_set_str(s,"type","selector");
            sbj_set(s,"outbounds",members);sbj_set_str(s,"default",selected);
            sbj_set_bool(s,"interrupt_exist_connections",false);sbj_arr_push(nodes,s);
        }
        sbj_set_str(copy,"detour",runtime?selector:target);sbj_arr_push(servers,copy);
        if(!strcmp(id,"default")) {
            sbj_set_str(route,"final",runtime?selector:target);sbj_set_str(dns,"final",dns_name);
        } else if(custom_group) {
            const char *keys[]={"domains","processes"}, *matches[]={"domain_suffix","process_name"};
            for(size_t k=0;k<2;++k)if(sbj_arr_len(sbj_get(g,keys[k]))) {
                sbj *r=sbj_object(), *dr=sbj_object();
                sbj_set(r,matches[k],sbj_clone(sbj_get(g,keys[k])));sbj_set_str(r,"outbound",runtime?selector:target);
                sbj_set(dr,matches[k],sbj_clone(sbj_get(g,keys[k])));sbj_set_str(dr,"server",dns_name);
                sbj_arr_push(local_routes,r);sbj_arr_push(local_dns_rules,dr);
            }
        } else {
            sbj *r=sbj_arr_at(sbj_get(route,"rules"),(size_t)sbj_get_int(g,"route_index",0));
            sbj *dr=sbj_arr_at(sbj_get(dns,"rules"),(size_t)sbj_get_int(g,"dns_index",0));
            sbj_set_str(r,"outbound",runtime?selector:target);sbj_set_str(dr,"server",dns_name);
        }
    }
    insert_local_rules(config,local_routes,local_dns_rules);
    sbj_free(local_routes);sbj_free(local_dns_rules);
    sbj *out=sbj_clone(source);sbj_set(out,"content",sbj_str_take(sbj_dump(config,-1)));
    sbj_free(groups);sbj_free(config);return out;
unavailable:
    sbw_fail(error, !sbj_get(identity,"windows_routing") && sbj_get_str(identity,"windows_gpt_outbound",NULL) ? "GPT_OUTBOUND_UNAVAILABLE" : "ROUTING_NODE_UNAVAILABLE","A locally selected node was removed. Choose another node or restore server routing.");
    sbj_free(local_routes);sbj_free(local_dns_rules);sbj_free(groups);sbj_free(config);return NULL;
unsupported:
    sbw_fail(error,"ROUTING_UNSUPPORTED","A locally overridden service or its DNS changed. Restore server routing for that group.");
    sbj_free(local_routes);sbj_free(local_dns_rules);sbj_free(groups);sbj_free(config);return NULL;
}
