#include "subscriptions.h"
#include <winhttp.h>
#include <objbase.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

static bool node_valid(const sbj *node) {
    const char *type=sbj_get_str(node,"type","");
    const char *types[]={"shadowsocks","vmess","vless","trojan","hysteria2","tuic","http","socks"};
    bool supported=false;
    for(size_t i=0;i<sizeof(types)/sizeof(types[0]);++i) if(!strcmp(type,types[i]))supported=true;
    const sbj *tls=sbj_get(node,"tls");
    return supported && sbw_json_string(sbj_get(node,"tag"),80,false) &&
        sbw_json_string(sbj_get(node,"server"),253,false) && sbj_get_int(node,"server_port",0)>0 && sbj_get_int(node,"server_port",0)<=65535 &&
        !sbj_get(node,"plugin") && !sbj_get(node,"plugin_opts") && !sbj_get(node,"detour") && !sbj_get(node,"bind_interface") && !sbj_get(node,"routing_mark") &&
        !sbj_get(tls,"certificate_path") && !sbj_get(tls,"key_path") && !sbj_get(tls,"ech");
}
int sbw_subscriptions_merge(sbj *config,const sbj *identity,sbw_error *error) {
    sbj *out=sbj_get(config,"outbounds");
    const sbj *subs=sbj_get(identity,"local_subscriptions");
    if(!sbj_arr_len(subs))return 0;
    if(!sbj_is_array(out))return sbw_fail(error,"SUBSCRIPTION_INVALID","The base configuration has no outbounds.");
    for(size_t i=0;i<sbj_arr_len(subs);++i) {
        const sbj *sub=sbj_arr_at(subs,i),*nodes=sbj_get(sub,"nodes");
        for(size_t j=0;j<sbj_arr_len(nodes);++j) {
            const sbj *node=sbj_arr_at(nodes,j);
            if(!node_valid(node))return sbw_fail(error,"SUBSCRIPTION_INVALID","A saved subscription node is invalid.");
            char tag[128];sprintf_s(tag,sizeof tag,"local-%s/%s",sbj_get_str(sub,"id",""),sbj_get_str(node,"tag",""));
            for(size_t k=0;k<sbj_arr_len(out);++k)if(sbj_string_is(sbj_get(sbj_arr_at(out,k),"tag"),tag))
                return sbw_fail(error,"SUBSCRIPTION_CONFLICT","A local node name conflicts with another node.");
            sbj *copy=sbj_clone(node);sbj_set_str(copy,"tag",tag);sbj_arr_push(out,copy);
        }
    }
    if(sbj_arr_len(out)>1024)return sbw_fail(error,"SUBSCRIPTION_LIMIT","At most 1024 combined nodes are supported.");
    return 0;
}
sbj *sbw_subscriptions_summary(const sbj *source,const sbj *identity) {
    sbj *result=sbj_object(),*list=sbj_array(),*sources=sbj_get(source,"subscription_sources");
    sbj_set(result,"managed",sbj_is_array(sources)?sbj_clone(sources):sbj_array());
    sbj_set_bool(result,"sources_available",sbj_is_array(sources));
    const sbj *subs=sbj_get(identity,"local_subscriptions");
    for(size_t i=0;i<sbj_arr_len(subs);++i) {
        const sbj *sub=sbj_arr_at(subs,i),*nodes=sbj_get(sub,"nodes");
        sbj *item=sbj_object(),*tags=sbj_array();
        sbj_set_str(item,"id",sbj_get_str(sub,"id",""));sbj_set_str(item,"name",sbj_get_str(sub,"name",""));
        for(size_t j=0;j<sbj_arr_len(nodes);++j) {char tag[128];sprintf_s(tag,sizeof tag,"local-%s/%s",sbj_get_str(sub,"id",""),sbj_get_str(sbj_arr_at(nodes,j),"tag",""));sbj_arr_push(tags,sbj_str(tag));}
        sbj_set(item,"tags",tags);sbj_arr_push(list,item);
    }
    sbj_set(result,"local",list);return result;
}
sbj *sbw_subscriptions_change(const sbj *identity,const sbj *params,bool remove,sbw_error *error) {
    if(!identity){sbw_fail(error,"NOT_ENROLLED","Enroll this device first.");return NULL;}
    const char *id=sbj_get_str(params,"id","");
    const sbj *old=sbj_get(identity,"local_subscriptions"),*nodes=sbj_get(params,"nodes");
    if(strlen(id)>36 || (!remove && (!sbw_json_string(sbj_get(params,"name"),100,false) || !sbj_is_array(nodes) || !sbj_arr_len(nodes) || sbj_arr_len(nodes)>256)))goto invalid;
    const sbj *existing=NULL;
    for(size_t i=0;i<sbj_arr_len(old);++i)if(sbj_string_is(sbj_get(sbj_arr_at(old,i),"id"),id))existing=sbj_arr_at(old,i);
    if((*id && !existing) || (remove && !existing) || (!*id && sbj_arr_len(old)>=16))goto invalid;
    if(!remove) {
        const sbj *url=sbj_get(params,"url");
        if((!existing || url) && !sbw_json_string(url,8192,false))goto invalid;
        for(size_t i=0;i<sbj_arr_len(nodes);++i) {
            if(!node_valid(sbj_arr_at(nodes,i)))goto invalid;
            for(size_t j=0;j<i;++j)if(sbj_equal(sbj_get(sbj_arr_at(nodes,i),"tag"),sbj_get(sbj_arr_at(nodes,j),"tag")))goto invalid;
        }
    }
    sbj *copy=sbj_clone(identity),*list=sbj_array();
    for(size_t i=0;i<sbj_arr_len(old);++i)if(sbj_arr_at(old,i)!=existing)sbj_arr_push(list,sbj_clone(sbj_arr_at(old,i)));
    if(!remove) {
        char generated[37];GUID guid;
        if(!*id) {if(FAILED(CoCreateGuid(&guid))){sbj_free(copy);sbj_free(list);goto invalid;}
            sprintf_s(generated,sizeof generated,"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",guid.Data1,guid.Data2,guid.Data3,guid.Data4[0],guid.Data4[1],guid.Data4[2],guid.Data4[3],guid.Data4[4],guid.Data4[5],guid.Data4[6],guid.Data4[7]);id=generated;}
        sbj *sub=sbj_object();sbj_set_str(sub,"id",id);sbj_set_str(sub,"name",sbj_get_str(params,"name",""));
        sbj_set_str(sub,"url",sbj_get_str(params,"url",sbj_get_str(existing,"url","")));sbj_set(sub,"nodes",sbj_clone(nodes));sbj_arr_push(list,sub);
    }
    sbj_set(copy,"local_subscriptions",list);return copy;
invalid:sbw_fail(error,"SUBSCRIPTION_INVALID","Check the subscription name, address and node parameters.");return NULL;
}
sbj *sbw_subscription_fetch(const char *url,HANDLE cancel,sbw_error *error) {
    wchar_t *wide=NULL,*host=NULL,*path=NULL;HINTERNET session=NULL,connection=NULL,request=NULL;sbj *result=NULL;sb_buf body={0};
    if(!url || strlen(url)>8192 || strchr(url,'#'))goto done;
    wide=sbw_wide(url,error);if(!wide)goto done;
    URL_COMPONENTS parts={0};parts.dwStructSize=sizeof parts;parts.dwHostNameLength=parts.dwUrlPathLength=parts.dwExtraInfoLength=parts.dwUserNameLength=parts.dwPasswordLength=(DWORD)-1;
    if(!WinHttpCrackUrl(wide,0,0,&parts) || (parts.nScheme!=INTERNET_SCHEME_HTTPS && parts.nScheme!=INTERNET_SCHEME_HTTP) || parts.dwUserNameLength || parts.dwPasswordLength)goto done;
    host=sb_xcalloc((size_t)parts.dwHostNameLength+1,sizeof(wchar_t));wmemcpy(host,parts.lpszHostName,parts.dwHostNameLength);
    size_t length=(size_t)parts.dwUrlPathLength+parts.dwExtraInfoLength;
    path=sb_xcalloc(length+2,sizeof(wchar_t));if(length)wmemcpy(path,parts.lpszUrlPath,length);else path[0]=L'/';
    session=WinHttpOpen(L"sb-easy/1 subscription",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);if(!session)goto done;
    WinHttpSetTimeouts(session,5000,5000,10000,10000);
    connection=WinHttpConnect(session,host,parts.nPort,0);if(!connection)goto done;
    request=WinHttpOpenRequest(connection,L"GET",path,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,parts.nScheme==INTERNET_SCHEME_HTTPS?WINHTTP_FLAG_SECURE:0);if(!request)goto done;
    DWORD disabled=WINHTTP_DISABLE_AUTHENTICATION|WINHTTP_DISABLE_COOKIES;WinHttpSetOption(request,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof disabled);
    DWORD autologon=WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;WinHttpSetOption(request,WINHTTP_OPTION_AUTOLOGON_POLICY,&autologon,sizeof autologon);
    DWORD policy=WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;WinHttpSetOption(request,WINHTTP_OPTION_REDIRECT_POLICY,&policy,sizeof policy);
    if(!WinHttpSendRequest(request,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0) || !WinHttpReceiveResponse(request,NULL))goto done;
    DWORD status=0,size=sizeof status;if(!WinHttpQueryHeaders(request,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX)||status!=200)goto done;
    ULONGLONG deadline=GetTickCount64()+30000;
    for(;;) {char bytes[8192];DWORD read=0;
        if((cancel && WaitForSingleObject(cancel,0)==WAIT_OBJECT_0)||GetTickCount64()>deadline)goto done;
        if(!WinHttpReadData(request,bytes,sizeof bytes,&read))goto done;if(!read)break;
        if(body.len+read>256U*1024U)goto done;sb_buf_append(&body,bytes,read);
    }
    if(!body.len || memchr(body.p,0,body.len) || !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,body.p,(int)body.len,NULL,0))goto done;
    result=sbj_object();sbj_set(result,"body",sbj_strn(body.p,body.len));
done:
    if(request)WinHttpCloseHandle(request);if(connection)WinHttpCloseHandle(connection);if(session)WinHttpCloseHandle(session);
    free(wide);free(host);free(path);if(body.p)SecureZeroMemory(body.p,body.len);sb_buf_free(&body);
    if(!result)sbw_fail(error,"SUBSCRIPTION_FETCH_FAILED","Unable to download subscription (HTTP(S), maximum 256 KB). Check the address and network.");return result;
}
