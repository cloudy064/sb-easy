#include "test_support.h"
#include "../service/ip_check.h"
#include "../service/protocol.h"
#include "../service/extension_process.h"

static sbj *configuration(void) {
    return sbj_parse_cstr("{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"main-tun\"}],\"outbounds\":[{\"type\":\"selector\",\"tag\":\"default\",\"default\":\"Tokyo\",\"outbounds\":[\"Tokyo\"]},{\"type\":\"socks\",\"tag\":\"Tokyo\",\"server\":\"proxy.private.test\",\"server_port\":1080,\"password\":\"secret-proxy-value\"},{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{\"final\":\"default\"}}");
}
static void validation(void) {
    sbw_error error={0};sbj *config=configuration(),*before=sbj_clone(config);
    sbj *source=sbj_parse_cstr("{\"subscription_sources\":[{\"name\":\"Office subscription\",\"tags\":[\"Tokyo\"],\"url\":\"https://private.test/secret\"}]}");
    sbj *nodes=sbw_ipcheck_nodes(config,source,NULL,&error);CHECK(nodes&&sbj_arr_len(nodes)==1);
    CHECK(sbj_obj_len(sbj_arr_at(nodes,0))==3);CHECK(sbj_string_is(sbj_get(sbj_arr_at(nodes,0),"source"),"Office subscription"));
    char *redacted=sbj_dump(nodes,-1);CHECK(!strstr(redacted,"private.test")&&!strstr(redacted,"password")&&!strstr(redacted,"secret"));free(redacted);sbj_free(nodes);
    sbj_set_str(sbj_arr_at(sbj_get(source,"subscription_sources"),0),"name","Broken\nsource");
    sbj *unreadable=sbj_object();sbj_set_str(unreadable,"tag","Broken\nnode");sbj_set_str(unreadable,"type","socks");sbj_arr_push(sbj_get(config,"outbounds"),unreadable);
    nodes=sbw_ipcheck_nodes(config,source,NULL,&error);CHECK(nodes&&sbj_arr_len(nodes)==1);
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(nodes,0),"source"),"共享配置"));sbj_free(nodes);
    sbj_free(before);before=sbj_clone(config);
    sbj *interfaces=sbj_parse_cstr("[{\"name\":\"Wi-Fi\"},{\"name\":\"Ethernet\"}]");
    sbj *params=sbj_parse_cstr("{\"tags\":[\"Tokyo\"],\"interface\":\"Wi-Fi\",\"ipv6\":false}");
    CHECK(!sbw_ipcheck_validate(config,params,interfaces,&error));CHECK(sbj_equal(config,before));
    sbj_set_str(params,"interface","sb-easy");CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));CHECK(sb_streq(error.code,"IPCHECK_INTERFACE"));
    sbj_set_str(params,"interface","Wi-Fi");sbj_arr_push(sbj_get(params,"tags"),sbj_str("Tokyo"));CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));
    sbj *tags=sbj_array();sbj_arr_push(tags,sbj_str("default"));sbj_set(params,"tags",tags);CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));
    tags=sbj_array();sbj_arr_push(tags,sbj_str("missing"));sbj_set(params,"tags",tags);CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));
    tags=sbj_array();sbj_arr_push(tags,sbj_str("Tokyo"));sbj_set(params,"tags",tags);
    sbj_set_str(params,"url","https://arbitrary.test");CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));sbj_del(params,"url");
    sbj_set_str(params,"sing_box","C:\\untrusted.exe");CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));sbj_del(params,"sing_box");
    sbj_set_str(params,"ipv6","true");CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));sbj_set_bool(params,"ipv6",true);
    sbj_set(params,"tags",sbj_array());CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));
    for(int i=0;i<101;++i) {
        char tag[32];sprintf_s(tag,sizeof tag,"node-%d",i);sbj *node=sbj_object();sbj_set_str(node,"tag",tag);sbj_set_str(node,"type","socks");
        sbj_arr_push(sbj_get(config,"outbounds"),node);sbj_arr_push(sbj_get(params,"tags"),sbj_str(tag));
        if(i==99)CHECK(!sbw_ipcheck_validate(config,params,interfaces,&error));
    }
    CHECK(sbw_ipcheck_validate(config,params,interfaces,&error));
    sbj_free(params);sbj_free(interfaces);sbj_free(source);sbj_free(before);sbj_free(config);
}
static void failure_snapshot(void) {
    sbj *empty=sbw_ipcheck_failed_snapshot(NULL);CHECK(sbj_string_is(sbj_get(empty,"phase"),"failed"));
    CHECK(sbj_arr_len(sbj_get(empty,"results"))==0&&sbj_get_int(sbj_get(empty,"summary"),"processed_count",-1)==0);sbj_free(empty);
    sbj *previous=sbj_parse_cstr("{\"phase\":\"running\",\"cancel_requested\":true,\"results\":[{\"node\":\"Tokyo\",\"checked_at\":\"2026-10-13\",\"ipv6_requested\":false,\"ipv4\":{\"status\":\"ok\",\"ip\":\"8.8.8.8\"}}],\"summary\":{\"status\":\"partial\",\"node_count\":2,\"processed_count\":1,\"measured_count\":1,\"info_count\":0,\"complete_count\":0},\"error\":\"\"}");
    sbj *failed=sbw_ipcheck_failed_snapshot(previous);CHECK(sbj_string_is(sbj_get(failed,"phase"),"failed"));
    CHECK(!sbj_get_bool(failed,"cancel_requested",true));CHECK(sbj_string_is(sbj_get(failed,"error"),"probe_worker_stopped"));
    CHECK(sbj_equal(sbj_get(previous,"results"),sbj_get(failed,"results")));CHECK(sbj_equal(sbj_get(previous,"summary"),sbj_get(failed,"summary")));
    CHECK(sbj_string_is(sbj_get(previous,"phase"),"running"));test_redacted(failed);sbj_free(failed);sbj_free(previous);
}
static unsigned center_calls;
static int center_mock(void *context,const sbj *identity,const char *action,const sbj *params,HANDLE cancel,sbj **result,sbw_error *error) {
    (void)context;(void)cancel;(void)error;
    CHECK(sbj_string_is(sbj_get(identity,"agent_token"),"private-agent-token-never-returned"));
    CHECK(sbj_is_object(params));
    char *wire=sbj_dump(params,-1);CHECK(!strstr(wire,"secret")&&!strstr(wire,"config")&&!strstr(wire,"local-home"));free(wire);
    ++center_calls;
    if(sb_streq(action,"catalog")) *result=sbj_parse_cstr("{\"nodes\":[{\"tag\":\"Tokyo\",\"type\":\"socks\",\"source\":\"Center profile\"}],\"interfaces\":[],\"default_interface\":\"\"}");
    else {
        if(sb_streq(action,"start")){CHECK(sbj_obj_len(params)==2);CHECK(sbj_arr_len(sbj_get(params,"tags"))==1);}
        *result=sbj_parse_cstr("{\"phase\":\"idle\",\"results\":[]}");
    }
    return 0;
}
static void controller_readonly(void) {
    test_data data;test_data_init(&data);sbw_error error={0};
    data.saved=sbj_parse_cstr("{\"version\":1,\"identity\":{\"server\":\"https://example.test\",\"host_id\":\"device-1\",\"agent_token\":\"private-agent-token-never-returned\"},\"candidate\":null,\"last_good\":null}");
    sbj *candidate=sbj_object(),*config=configuration();char *raw=sbj_dump(config,-1);sbj_free(config);
    sbj_set_str(candidate,"content",raw);free(raw);sbj_set_str(candidate,"etag","ip-check-fixture");sbj_set_str(candidate,"rule_source","profile");
    sbj_set_str(candidate,"profile_id","");sbj_set_str(candidate,"profile_name","");
    sbj_set(data.saved,"candidate",candidate);
    sbj *identity=sbj_get(data.saved,"identity");
    sbj_set_str(identity,"host_name","");sbj_set_str(identity,"profile_id","");sbj_set_str(identity,"profile_name","");
    sbj_set(identity,"local_subscriptions",sbj_parse_cstr("[{\"id\":\"home\",\"name\":\"Local nodes\",\"url\":\"https://secret.test/sub\",\"nodes\":[{\"tag\":\"LA\",\"type\":\"socks\",\"server\":\"secret.test\",\"server_port\":1080}]}]"));
    sbw_control_plane *remote=sb_xcalloc(1,sizeof *remote);sbw_store *store=sb_xcalloc(1,sizeof *store);
    remote->context=&data;remote->enroll=test_enroll;remote->fetch_config=test_fetch;remote->ipcheck=center_mock;
    store->context=&data;store->load=test_load;store->save=test_save;store->clear=test_clear;
    sbw_controller *controller=sbw_controller_new(remote,store,NULL,NULL);CHECK(controller);sbj *saved=sbj_clone(data.saved),*empty=sbj_object();
    static const char *methods[]={"ipcheck.catalog","ipcheck.snapshot","ipcheck.start","ipcheck.cancel"};
    for(size_t i=0;i<sizeof(methods)/sizeof(methods[0]);++i) {
        CHECK(!sbw_controller_dispatch(controller,methods[i],empty,false,&error));CHECK(sb_streq(error.code,"FORBIDDEN"));
    }
    sbj *result=sbw_controller_dispatch(controller,"ipcheck.catalog",empty,true,&error);if(!result)fprintf(stderr,"Catalog: %s %s\n",error.code,error.message);CHECK(result);test_redacted(result);
    CHECK(sbj_arr_len(sbj_get(result,"nodes"))==1);CHECK(sbj_is_array(sbj_get(result,"interfaces")));
    CHECK(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(result,"nodes"),0),"tag"),"Tokyo"));sbj_free(result);
    result=sbw_controller_dispatch(controller,"ipcheck.snapshot",empty,true,&error);CHECK(result&&sbj_string_is(sbj_get(result,"phase"),"idle"));sbj_free(result);
    result=sbw_controller_dispatch(controller,"ipcheck.cancel",empty,true,&error);CHECK(result);sbj_free(result);
    sbj *start=sbj_parse_cstr("{\"tags\":[\"Tokyo\"],\"ipv6\":false}");
    result=sbw_controller_dispatch(controller,"ipcheck.start",start,true,&error);CHECK(result);sbj_free(result);sbj_free(start);
    CHECK(center_calls==4);
    result=sbw_controller_dispatch(controller,"status.get",empty,false,&error);CHECK(result&&!sbj_get_bool(result,"core_running",true));sbj_free(result);
    CHECK(sbj_equal(saved,data.saved));CHECK(!data.downloads&&!data.enrollments);
    sbj *bad=sbj_parse_cstr("{\"config\":{}}");CHECK(!sbw_controller_dispatch(controller,"ipcheck.catalog",bad,true,&error));CHECK(sb_streq(error.code,"INVALID_REQUEST"));sbj_free(bad);
    const char *request="{\"id\":\"hello\",\"version\":1,\"method\":\"protocol.hello\",\"params\":{}}";
    char *hello=sbw_handle_request(request,strlen(request),controller,false);CHECK(strstr(hello,"ipcheck.catalog")&&strstr(hello,"ipcheck.cancel"));free(hello);
    sbj_free(saved);sbj_free(empty);sbw_controller_free(controller);test_data_free(&data);
}
static void graceful_cleanup(void) {
    wchar_t temporary[32768],name[128];CHECK(GetTempPathW(32768,temporary)>0);
    swprintf_s(name,128,L"sb-easy-ipcheck-close-%lu-%llu",GetCurrentProcessId(),GetTickCount64());
    wchar_t *directory=sbw_path_join(temporary,name);CHECK(CreateDirectoryW(directory,NULL));
    for(int hang=0;hang<2;++hang) {
        wchar_t *marker=sbw_path_join(directory,hang?L"forced.txt":L"clean.txt");char *utf=sbw_utf8(marker,NULL);CHECK(utf);
        sbw_error error={0};sbw_extension_process *worker=sbw_extension_process_new(L"windows_ip_check_worker_fixture.exe",&error);
        CHECK(worker&&sbw_extension_process_running(worker));sbj *params=sbj_object();sbj_set_str(params,"marker",utf);sbj_set_bool(params,"hang",hang!=0);free(utf);
        sbj *reply=sbw_extension_process_call(worker,"start",params,&error);CHECK(reply);
        HANDLE process=OpenProcess(SYNCHRONIZE,FALSE,(DWORD)sbj_get_int(reply,"pid",0));CHECK(process);sbj_free(reply);sbj_free(params);
        ULONGLONG started=GetTickCount64();sbw_extension_process_free_graceful(worker);
        CHECK(GetTickCount64()-started<10000);CHECK(WaitForSingleObject(process,0)==WAIT_OBJECT_0);CloseHandle(process);
        if(!hang){CHECK(GetFileAttributesW(marker)!=INVALID_FILE_ATTRIBUTES);CHECK(DeleteFileW(marker));}
        else CHECK(GetFileAttributesW(marker)==INVALID_FILE_ATTRIBUTES);
        free(marker);
    }
    CHECK(RemoveDirectoryW(directory));free(directory);
}
int main(void) {
    validation();failure_snapshot();controller_readonly();graceful_cleanup();
    puts("IP detection: bounded node selection, physical-interface validation, redacted subscriptions, authorization and no active-core/config mutation passed.");return 0;
}
