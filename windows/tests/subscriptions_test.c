#include "test_support.h"
#include "../service/subscriptions.h"
#include "../service/routing.h"
int main(void) {
    sbw_error error={0};sbj *identity=sbj_object();
    sbj *params=sbj_parse_cstr("{\"name\":\"Travel\",\"url\":\"https://example.invalid/?token=PRIVATE_SUB_TOKEN\",\"nodes\":[{\"type\":\"http\",\"tag\":\"same\",\"server\":\"127.0.0.1\",\"server_port\":8080,\"password\":\"PRIVATE_NODE_PASSWORD\"}]}");
    sbj *next=sbw_subscriptions_change(identity,params,false,&error);CHECK(next);
    CHECK(!sbj_get(identity,"local_subscriptions"));
    sbj *source=sbj_object();sbj_set_str(source,"content","{\"outbounds\":[{\"tag\":\"same\",\"type\":\"direct\"}],\"route\":{\"final\":\"same\"}}");
    sbj *runtime=sbw_routing_apply(source,next,false,&error);CHECK(runtime);
    sbj *config=sbj_parse_cstr(sbj_get_str(runtime,"content",""));CHECK(sbj_arr_len(sbj_get(config,"outbounds"))==2);
    const char *tag=sbj_get_str(sbj_arr_at(sbj_get(config,"outbounds"),1),"tag","");CHECK(!strncmp(tag,"local-",6));
    sbj *summary=sbw_subscriptions_summary(source,next);char *public_json=sbj_dump(summary,-1);
    CHECK(strstr(public_json,"Travel") && !strstr(public_json,"PRIVATE_") && !strstr(public_json,"example.invalid"));free(public_json);
    char *id=sb_strdup(sbj_get_str(sbj_arr_at(sbj_get(next,"local_subscriptions"),0),"id",""));
    sbj_set_str(params,"id",id);sbj_del(params,"url");
    sbj *updated=sbw_subscriptions_change(next,params,false,&error);CHECK(updated);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(updated,"local_subscriptions"),0),"url"),"https://example.invalid/?token=PRIVATE_SUB_TOKEN"));
    sbj *remove=sbj_object();sbj_set_str(remove,"id",id);sbj *removed=sbw_subscriptions_change(updated,remove,true,&error);CHECK(removed && !sbj_arr_len(sbj_get(removed,"local_subscriptions")));
    sbj *node=sbj_arr_at(sbj_get(params,"nodes"),0);sbj_set_str(node,"type","direct");CHECK(!sbw_subscriptions_change(next,params,false,&error));
    sbj_set_str(node,"type","http");sbj_set_str(node,"detour","same");CHECK(!sbw_subscriptions_change(next,params,false,&error));
    free(id);sbj_free(identity);sbj_free(params);sbj_free(next);sbj_free(updated);sbj_free(removed);sbj_free(remove);sbj_free(source);sbj_free(runtime);sbj_free(config);sbj_free(summary);
    puts("Subscription isolation, redaction, stable IDs, update and deletion passed.");return 0;
}
