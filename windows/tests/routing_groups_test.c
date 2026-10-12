#include "test_support.h"
#include "../service/routing.h"
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
    free(other);sbj_free(source);sbj_free(before);sbj_free(identity);
    puts("Unified routing: default/Claude/GPT/custom groups, isolated DNS, migration and rejection passed.");return 0;
}
