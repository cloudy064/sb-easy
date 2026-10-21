#include "ipcheck_center.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

static size_t receive_center(char *data,size_t size,size_t count,void *context) {
    sb_buf *buffer=context;
    if(size && count>900U*1024U/size)return 0;
    size_t bytes=size*count;
    if(bytes>900U*1024U-buffer->len)return 0;
    sb_buf_append(buffer,data,bytes);return bytes;
}
int sb_ipcheck_center(const sbj *request,sb_http_resp *resp,sb_err *err) {
    char *payload=sbj_dump(request,-1);sb_buf buffer={0};long status=0;int rc=-1;
    CURL *curl=curl_easy_init();struct curl_slist *headers=NULL;
    if(!curl||!payload||strlen(payload)>2U*1024U*1024U)goto done;
    const char *socket=getenv("IPCHECK_SOCKET");
    headers=curl_slist_append(headers,"Content-Type: application/json");
    curl_easy_setopt(curl,CURLOPT_URL,"http://localhost/");
    curl_easy_setopt(curl,CURLOPT_UNIX_SOCKET_PATH,socket&&*socket?socket:"/run/sb-easy/ipcheck.sock");
    curl_easy_setopt(curl,CURLOPT_PROXY,"");
    curl_easy_setopt(curl,CURLOPT_POSTFIELDS,payload);
    curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,(long)strlen(payload));
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,10L);
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,2L);
    curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,receive_center);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buffer);
    if(curl_easy_perform(curl)!=CURLE_OK)goto done;
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    if(status!=200){sb_fail(err,status==409?SB_ERR_CONFLICT:SB_ERR_UNAVAILABLE,"Center IP check is busy or unavailable");goto cleanup;}
    sbj *result=sbj_parse(buffer.p,buffer.len,NULL,0);
    if(!sbj_is_object(result)){sbj_free(result);goto done;}
    sb_resp_json(resp,200,result);rc=0;goto cleanup;
done:sb_fail(err,SB_ERR_UNAVAILABLE,"Center IP check service is unavailable");
cleanup:
    if(payload){memset(payload,0,strlen(payload));free(payload);}
    sb_buf_free(&buffer);curl_slist_free_all(headers);if(curl)curl_easy_cleanup(curl);return rc;
}
