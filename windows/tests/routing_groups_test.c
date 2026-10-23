#include "test_support.h"
#include "../service/routing.h"
#include "../service/health.h"
static const char *fixture=
"{\"outbounds\":[{\"type\":\"http\",\"tag\":\"a\"},{\"type\":\"http\",\"tag\":\"b\"}],"
"\"route\":{\"final\":\"a\",\"rules\":[{\"domain_suffix\":[\"chatgpt.com\",\"openai.com\"],\"outbound\":\"a\"},{\"domain_suffix\":[\"claude.ai\"],\"outbound\":\"b\"},{\"domain_suffix\":[\"other.test\"],\"outbound\":\"a\"}]},"
"\"dns\":{\"final\":\"shared\",\"servers\":[{\"type\":\"https\",\"tag\":\"shared\",\"server\":\"1.1.1.1\",\"detour\":\"a\"}],"
"\"rules\":[{\"domain_suffix\":[\"openai.com\",\"chatgpt.com\"],\"server\":\"shared\"},{\"domain_suffix\":[\"claude.ai\"],\"server\":\"shared\"},{\"domain_suffix\":[\"other.test\"],\"server\":\"shared\"}]}}";
static void choose(sbj *identity,const char *id,const char *mode,const char *node) {
    sbj *all=sbj_get(identity,"windows_routing");if(!all){all=sbj_object();sbj_set(identity,"windows_routing",all);}
    sbj *p=sbj_object();sbj_set_str(p,"mode",mode);if(node)sbj_set_str(p,"node",node);sbj_set(all,id,p);
}
int main(void) {
    sbj *source=sbj_object(),*identity=sbj_object();sbw_error error={0};
    sbj_set_str(source,"content",fixture);sbj *before=sbj_clone(source);
    sbj *groups=sbw_routing_groups(source,identity);CHECK(sbj_arr_len(groups)==4);
    for(size_t i=0;i<4;++i)CHECK(sbj_get_bool(sbj_arr_at(groups,i),"editable",false));
    char *other=sb_strdup(sbj_get_str(sbj_arr_at(groups,3),"id",""));sbj_free(groups);
    choose(identity,"default","node","b");choose(identity,"claude","default",NULL);choose(identity,other,"node","b");
    sbj_set_str(identity,"windows_gpt_outbound","b"); /* Upgrade preserves the former GPT preference. */
    sbj *runtime=sbw_routing_apply(source,identity,true,&error);CHECK(runtime && sbj_equal(source,before));
    sbj *cfg=sbj_parse_cstr(sbj_get_str(runtime,"content",""));
    sbj *dns=sbj_get(cfg,"dns"),*servers=sbj_get(dns,"servers"),*nodes=sbj_get(cfg,"outbounds");
    CHECK(sbj_arr_len(nodes)==6 && sbj_arr_len(servers)==5);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(servers,0),"detour"),"a"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(nodes,2),"default"),"b"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(nodes,3),"default"),"b"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(nodes,4),"default"),SBW_DEFAULT_SELECTOR));
    CHECK(sbj_string_is(sbj_get(sbj_get(cfg,"route"),"final"),SBW_DEFAULT_SELECTOR));
    for(size_t i=2;i<6;++i)CHECK(!sbj_get_bool(sbj_arr_at(nodes,i),"interrupt_exist_connections",true));
    for(size_t i=1;i<5;++i)CHECK(strstr(sbj_get_str(sbj_arr_at(servers,i),"detour",""),"sb-easy-local-")!=NULL);
    sbj_free(cfg);sbj_free(runtime);
    sbj *effective=sbw_routing_apply(source,identity,false,&error);CHECK(effective);
    cfg=sbj_parse_cstr(sbj_get_str(effective,"content",""));
    CHECK(sbj_string_is(sbj_get(sbj_get(cfg,"route"),"final"),"b"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(sbj_get(cfg,"route"),"rules"),1),"outbound"),"b"));
    sbj_free(cfg);sbj_free(effective);
    choose(identity,"claude","server",NULL);groups=sbw_routing_groups(source,identity);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(groups,2),"mode"),"server"));sbj_free(groups);
    choose(identity,"claude","node","removed");CHECK(!sbw_routing_apply(source,identity,true,&error));CHECK(!strcmp(error.code,"ROUTING_NODE_UNAVAILABLE"));
    choose(identity,"claude","node","a");cfg=sbj_parse_cstr(fixture);
    sbj_set_bool(sbj_arr_at(sbj_get(sbj_get(cfg,"route"),"rules"),1),"invert",true);
    sbj_set(source,"content",sbj_str_take(sbj_dump(cfg,-1)));sbj_free(cfg);
    CHECK(!sbw_routing_apply(source,identity,true,&error));CHECK(!strcmp(error.code,"ROUTING_UNSUPPORTED"));
    CHECK(sbj_string_is(sbj_get(before,"content"),fixture));
    sbj_set_str(source,"content",fixture);sbj_free(identity);identity=sbj_object();
    sbj *params=sbj_parse_cstr("{\"id\":\"custom-work\",\"label\":\"Work\",\"domains\":[\"work.example\"],\"processes\":[\"editor.exe\"],\"mode\":\"node\",\"node\":\"b\"}");
    sbj *changed=sbw_routing_change(identity,params,false,&error);CHECK(changed && !sbj_get(identity,"windows_local_groups"));
    sbj_free(identity);identity=changed;
    groups=sbw_routing_groups(source,identity);CHECK(sbj_arr_len(groups)==5);
    CHECK(sbj_get_bool(sbj_arr_at(groups,4),"local",false));sbj_free(groups);
    runtime=sbw_routing_apply(source,identity,true,&error);CHECK(runtime);
    cfg=sbj_parse_cstr(sbj_get_str(runtime,"content",""));
    sbj *rr=sbj_get(sbj_get(cfg,"route"),"rules"), *dr=sbj_get(sbj_get(cfg,"dns"),"rules");
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(rr,0),"outbound"),"sb-easy-local-custom-work"));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(rr,1),"process_name"),0),"editor.exe"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(dr,0),"server"),"sb-easy-local-custom-work-dns"));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(dr,1),"process_name"),0),"editor.exe"));
    sbj_free(cfg);sbj_free(runtime);
    /* Preserve protected WireGuard management and DNS rules ahead of overrides. */
    cfg=sbj_parse_cstr(fixture);sbj_set(cfg,"endpoints",sbj_parse_cstr("[{\"type\":\"wireguard\",\"tag\":\"management\"}]"));
    sbj_arr_push(sbj_get(sbj_get(cfg,"route"),"rules"),sbj_parse_cstr("{\"ip_cidr\":[\"10.42.0.0/16\"],\"outbound\":\"management\"}"));
    sbj_arr_push(sbj_get(sbj_get(cfg,"dns"),"rules"),sbj_parse_cstr("{\"domain\":[\"panel.test\"],\"server\":\"shared\"}"));
    sbj_set(source,"content",sbj_str_take(sbj_dump(cfg,-1)));sbj_free(cfg);
    runtime=sbw_routing_apply(source,identity,true,&error);CHECK(runtime);
    cfg=sbj_parse_cstr(sbj_get_str(runtime,"content",""));rr=sbj_get(sbj_get(cfg,"route"),"rules");dr=sbj_get(sbj_get(cfg,"dns"),"rules");
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(rr,0),"outbound"),"management"));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(rr,1),"outbound"),"sb-easy-local-custom-work"));
    CHECK(sbj_string_is(sbj_arr_at(sbj_get(sbj_arr_at(dr,0),"domain"),0),"panel.test"));
    sbj_free(cfg);sbj_free(runtime);
    sbj_set_str(params,"id","custom-two");sbj_set_str(params,"label","Other");
    CHECK(!sbw_routing_change(identity,params,false,&error)); /* overlaps domains/process */
    sbj_set_str(params,"id","custom-work");sbj_set(params,"domains",sbj_parse_cstr("[\"BAD.example\"]"));
    CHECK(!sbw_routing_change(identity,params,false,&error));
    sbj_set(params,"domains",sbj_parse_cstr("[\"changed.example\"]"));sbj_set(params,"processes",sbj_parse_cstr("[\"C:\\\\bad.exe\"]"));
    CHECK(!sbw_routing_change(identity,params,false,&error));
    sbj_set(params,"processes",sbj_array());sbj_set_str(params,"mode","default");sbj_del(params,"node");
    changed=sbw_routing_change(identity,params,false,&error);CHECK(changed);sbj_free(identity);identity=changed;
    runtime=sbw_routing_apply(source,identity,true,&error);CHECK(runtime);sbj_free(runtime);
    sbj_free(params);params=sbj_parse_cstr("{\"id\":\"custom-work\"}");
    changed=sbw_routing_change(identity,params,true,&error);CHECK(changed && !sbj_arr_len(sbj_get(changed,"windows_local_groups")));
    CHECK(!sbw_routing_change(changed,params,true,&error));sbj_free(changed);sbj_free(params);
    /* Automatic groups restrict both traffic and DNS to explicit leaf proxies. */
    sbj_free(identity); identity=sbj_object(); cfg=sbj_parse_cstr(fixture);
    nodes=sbj_get(cfg,"outbounds");
    sbj_set_str(sbj_arr_at(nodes,0),"server","a.example");
    sbj_set_str(sbj_arr_at(nodes,1),"server","b.example");
    sbj_arr_push(nodes,sbj_parse_cstr("{\"type\":\"direct\",\"tag\":\"direct\"}"));
    sbj_arr_push(nodes,sbj_parse_cstr("{\"type\":\"selector\",\"tag\":\"nested\",\"outbounds\":[\"a\",\"b\"]}"));
    sbj_set(source,"content",sbj_str_take(sbj_dump(cfg,-1))); sbj_free(cfg);
    params=sbj_parse_cstr("{\"group\":\"default\",\"candidates\":[\"a\",\"b\"]}");
    changed=sbw_routing_automatic(source,identity,params,&error); CHECK(changed);
    CHECK(!sbj_get(identity,"windows_routing")); sbj_free(identity); identity=changed;
    runtime=sbw_routing_apply(source,identity,true,&error); CHECK(runtime);
    cfg=sbj_parse_cstr(sbj_get_str(runtime,"content","")); nodes=sbj_get(cfg,"outbounds");
    bool selector_found=false,dns_found=false;
    for(size_t i=0;i<sbj_arr_len(nodes);++i) if(sbj_string_is(sbj_get(sbj_arr_at(nodes,i),"tag"),SBW_DEFAULT_SELECTOR)) {
        sbj *members=sbj_get(sbj_arr_at(nodes,i),"outbounds"); CHECK(sbj_arr_len(members)==2);
        CHECK(sbj_string_is(sbj_arr_at(members,0),"a") && sbj_string_is(sbj_arr_at(members,1),"b")); selector_found=true;
    }
    servers=sbj_get(sbj_get(cfg,"dns"),"servers");
    for(size_t i=0;i<sbj_arr_len(servers);++i) if(sbj_string_is(sbj_get(sbj_arr_at(servers,i),"tag"),"sb-easy-local-default-dns")) {
        CHECK(sbj_string_is(sbj_get(sbj_arr_at(servers,i),"detour"),SBW_DEFAULT_SELECTOR)); dns_found=true;
    }
    CHECK(selector_found && dns_found); sbj_free(cfg); sbj_free(runtime);
    const char *invalid_candidates[]={"[\"direct\"]","[\"nested\"]","[\"unknown\"]","[\"a\",\"a\"]","[]"};
    for(size_t i=0;i<sizeof invalid_candidates/sizeof *invalid_candidates;++i) {
        sbj_set(params,"candidates",sbj_parse_cstr(invalid_candidates[i])); CHECK(!sbw_routing_automatic(source,identity,params,&error));
    }
    sbj_set(params,"candidates",sbj_parse_cstr("[\"b\"]"));
    sbj *policy=sbw_health_policy(identity); sbj_set_bool(policy,"enabled",false);
    CHECK(!sbw_health_change(identity,policy,&error)); sbj_free(policy);
    /* Losing every allowed node rejects the candidate; caller keeps last good. */
    cfg=sbj_parse_cstr(sbj_get_str(source,"content",""));
    sbj_set(cfg,"outbounds",sbj_parse_cstr("[{\"type\":\"http\",\"tag\":\"unlisted\",\"server\":\"x.example\"}]"));
    sbj_set(source,"content",sbj_str_take(sbj_dump(cfg,-1))); sbj_free(cfg);
    CHECK(!sbw_routing_apply(source,identity,true,&error));
    sbj_free(params);
    free(other);sbj_free(source);sbj_free(before);sbj_free(identity);
    puts("Unified routing: default/Claude/GPT/custom groups, isolated DNS, migration and rejection passed.");return 0;
}
