#include "test_support.h"
#include "../service/preferences_cloud.h"
typedef struct fake { unsigned calls; bool conflict, expired; int64_t revision; sbj *envelope; bool deleted; } fake;
static int send(void *context, const char *server, const char *method, const char *path, const char *token,
    const char *cookie, const char *match, const sbj *body, HANDLE cancel, DWORD *status, sbj **response, char **flow_cookie, sbw_error *error) {
    (void)cancel; (void)error; fake *f=context; ++f->calls; CHECK(!strcmp(server,"https://panel.test"));
    *status=200; *response=sbj_object(); *flow_cookie=NULL;
    if(!strcmp(path,"/api/auth/login")) {
        CHECK(!token && !cookie && sbj_string_is(sbj_get(body,"password"),"ACCOUNT_PASSWORD"));
        sbj_set_bool(*response,"mfa_required",true);sbj_set_str(*response,"challenge","PRIVATE_CHALLENGE");
        *flow_cookie=sb_strdup("sb_auth_flow=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");return 0;
    }
    if(!strcmp(path,"/api/auth/login/mfa")) {
        CHECK(!token && cookie && strstr(cookie,"sb_auth_flow=") == cookie);
        CHECK(sbj_string_is(sbj_get(body,"challenge"),"PRIVATE_CHALLENGE") && sbj_string_is(sbj_get(body,"code"),"123456"));
        sbj_set_str(*response,"token","PRIVATE_PANEL_TOKEN");sbj_set_str(*response,"username","alice");return 0;
    }
    CHECK(token && !strcmp(token,"PRIVATE_PANEL_TOKEN") && !cookie);
    if(f->expired){*status=401;return 0;}
    if(!strcmp(path,"/api/auth/logout")){sbj_set_bool(*response,"success",true);return 0;}
    CHECK(!strcmp(path,"/api/auth/preferences/windows-personal"));
    if(!strcmp(method,"GET") && !f->revision){*status=404;return 0;}
    if(strcmp(method,"GET")) {
        char expected[32];sprintf_s(expected,sizeof expected,"\"%lld\"",(long long)f->revision);CHECK(match && !strcmp(match,expected));
        if(f->conflict){f->conflict=false;++f->revision;*status=409;return 0;}
        ++f->revision;
        if(!strcmp(method,"PUT")){CHECK(sbw_preferences_envelope_valid(body));sbj_free(f->envelope);f->envelope=sbj_clone(body);f->deleted=false;}
        else {CHECK(!strcmp(method,"DELETE"));sbj_free(f->envelope);f->envelope=NULL;f->deleted=true;}
    }
    sbj_set_int(*response,"revision",f->revision);sbj_set_int(*response,"updated_at",1780000000);
    sbj_set(*response,"envelope",f->envelope?sbj_clone(f->envelope):sbj_null());sbj_set_bool(*response,"deleted",f->deleted);return 0;
}
static void private_result(const sbj *result) {
    char *text=sbj_dump(result,-1);CHECK(!strstr(text,"PRIVATE_") && !strstr(text,"ACCOUNT_PASSWORD") && !strstr(text,"sb_auth_flow"));free(text);
}
int main(int argc,char **argv) {
    CHECK(argc==2); FILE *file=fopen(argv[1],"rb");CHECK(file);char raw[8192];size_t n=fread(raw,1,sizeof raw-1,file);fclose(file);raw[n]=0;
    sbj *vector=sbj_parse_cstr(raw);CHECK(vector);fake f={0};sbw_error error={0};
    sbw_preferences_cloud *cloud=sbw_preferences_cloud_new(send,&f);
    sbj *login=sbj_parse_cstr("{\"server\":\"https://panel.test\",\"username\":\"alice\",\"password\":\"ACCOUNT_PASSWORD\"}");
    sbj *result=sbw_preferences_cloud_call(cloud,"login",login,NULL,&error);CHECK(result && sbj_get_bool(result,"mfa_required",false));private_result(result);
    char *session=sb_strdup(sbj_get_str(result,"session_id",""));CHECK(strlen(session)==64);sbj_free(result);
    sbj *params=sbj_object();sbj_set_str(params,"session_id",session);sbj_set_str(params,"code","123456");
    result=sbw_preferences_cloud_call(cloud,"mfa",params,NULL,&error);CHECK(result && sbj_get_bool(result,"connected",false));private_result(result);sbj_free(result);sbj_del(params,"code");
    sbj *wrong=sbj_parse_cstr("{\"session_id\":\"another-console-window\"}");unsigned calls=f.calls;
    CHECK(!sbw_preferences_cloud_call(cloud,"get",wrong,NULL,&error) && f.calls==calls);sbj_free(wrong);
    result=sbw_preferences_cloud_call(cloud,"get",params,NULL,&error);CHECK(result && sbj_get_bool(result,"revision_known",false) && sbj_get_int(result,"revision",-1)==0);private_result(result);sbj_free(result);
    sbj_set_int(params,"revision",0);sbj_set(params,"envelope",sbj_clone(sbj_get(vector,"envelope")));
    result=sbw_preferences_cloud_call(cloud,"put",params,NULL,&error);CHECK(result && sbj_get_int(result,"revision",0)==1);private_result(result);sbj_free(result);
    sbj_set_int(params,"revision",1);f.conflict=true;CHECK(!sbw_preferences_cloud_call(cloud,"put",params,NULL,&error) && !strcmp(error.code,"PREFERENCES_CONFLICT"));
    calls=f.calls;CHECK(!sbw_preferences_cloud_call(cloud,"put",params,NULL,&error) && calls==f.calls);
    sbj_del(params,"envelope");sbj_del(params,"revision");result=sbw_preferences_cloud_call(cloud,"get",params,NULL,&error);CHECK(result && sbj_get_int(result,"revision",0)==2);sbj_free(result);
    sbj_set_int(params,"revision",2);result=sbw_preferences_cloud_call(cloud,"delete",params,NULL,&error);CHECK(result && sbj_get_bool(result,"deleted",false) && sbj_get_int(result,"revision",0)==3);private_result(result);sbj_free(result);
    sbj_set_int(params,"revision",0);sbj_set(params,"envelope",sbj_clone(sbj_get(vector,"envelope")));calls=f.calls;
    CHECK(!sbw_preferences_cloud_call(cloud,"put",params,NULL,&error) && f.calls==calls);
    sbj_set_int(params,"revision",3);result=sbw_preferences_cloud_call(cloud,"put",params,NULL,&error);CHECK(result && sbj_get_int(result,"revision",0)==4);sbj_free(result);
    sbj_del(params,"revision");sbj_del(params,"envelope");f.expired=true;
    CHECK(!sbw_preferences_cloud_call(cloud,"get",params,NULL,&error) && !strcmp(error.code,"PREFERENCES_AUTH_REQUIRED"));
    result=sbw_preferences_cloud_status(cloud);CHECK(!sbj_get_bool(result,"connected",true));private_result(result);sbj_free(result);
    /* Production transport rejects HTTP and arbitrary endpoints before I/O. */
    DWORD status=0;sbj *response=NULL;char *cookie=NULL;
    CHECK(sbw_panel_request(NULL,"http://127.0.0.1:1","POST","/api/auth/login",NULL,NULL,NULL,login,NULL,&status,&response,&cookie,&error));
    CHECK(!strcmp(error.code,"PREFERENCES_HTTPS_REQUIRED") && !response && !cookie);
    CHECK(sbw_panel_request(NULL,"https://panel.test","GET","/api/admin/backup",NULL,NULL,NULL,NULL,NULL,&status,&response,&cookie,&error));
    sbj_free(params);sbj_free(login);sbj_free(vector);sbj_free(f.envelope);free(session);sbw_preferences_cloud_free(cloud);
    puts("Preference cloud: private panel/MFA session, per-window capability, reviewed revisions, conflicts, tombstones and HTTPS boundary passed.");return 0;
}
