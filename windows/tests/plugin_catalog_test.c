#include "../service/plugin_catalog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int failures;
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);++failures;} } while(0)
static char *read_fixture(const char *directory,const char *name,size_t *length) {
    char path[4096];snprintf(path,sizeof path,"%s/%s",directory,name);FILE *file=fopen(path,"rb");if(!file)return NULL;
    fseek(file,0,SEEK_END);long size=ftell(file);rewind(file);if(size<0||size>1024*1024){fclose(file);return NULL;}
    char *text=sb_xmalloc((size_t)size+1);*length=fread(text,1,(size_t)size,file);fclose(file);text[*length]=0;return text;
}
int main(int argc,char **argv) {
    const char *directory=argc>1?argv[1]:"build/plugin-catalog-fixtures";size_t length=0,n=0;
    char *envelope=read_fixture(directory,"catalog.json",&length),*keytext=read_fixture(directory,"keys.json",&n);
    if(!envelope||!keytext){fprintf(stderr,"Generate fixtures with extensions/catalog/tests first.\n");return 2;}
    sbj *keys=sbj_parse_strict(keytext,n,NULL,0);free(keytext);
    char *info_text=read_fixture(directory,"test-info.json",&n);sbj *info=sbj_parse_strict(info_text,n,NULL,0);free(info_text);
    int64_t now=sbj_get_int(info,"now",0);char hash[65];sbw_error error={0};
    sbj *payload=sbw_plugin_catalog_verify(envelope,length,keys,now,false,hash,&error);
    if(!payload){fprintf(stderr,"Positive signature failed: %s %s\n",error.code,error.message);return 1;}
    CHECK(sbj_get_int(payload,"sequence",0)==42);CHECK(sb_streq(hash,sbj_get_str(info,"payload_sha256","")));
    sbj *state=sbw_plugin_catalog_accept(NULL,payload,hash,&error);CHECK(state!=NULL);
    CHECK(sbw_plugin_catalog_revoked(state,"http-debug","android",1));CHECK(!sbw_plugin_catalog_revoked(state,"http-debug","android",2));
    sbj *same=sbw_plugin_catalog_accept(state,payload,hash,&error);CHECK(same!=NULL);sbj_free(same);
    same=sbw_plugin_catalog_accept(state,payload,"0000000000000000000000000000000000000000000000000000000000000000",&error);CHECK(!same);sbj_free(same);
    sbj *later=sbj_clone(payload);sbj_set_int(later,"sequence",43);sbj_set(later,"revocations",sbj_array());
    same=sbw_plugin_catalog_accept(state,later,hash,&error);CHECK(same!=NULL);CHECK(sbw_plugin_catalog_revoked(same,"http-debug","android",1));
    sbj *rollback=sbw_plugin_catalog_accept(same,payload,hash,&error);CHECK(!rollback);sbj_free(rollback);sbj_free(same);sbj_free(later);
    const sbj *release=sbw_plugin_catalog_release(payload,"http-debug","android","x86_64",2);CHECK(release!=NULL);
    sbj *windows=sbj_clone(release);sbj_set_str(windows,"platform","windows");sbj_set_int(windows,"api",1);
    sbj_set_str(windows,"package","");sbj_set_str(windows,"signer_sha256","");sbj_set_str(windows,"min_host","0.6.9");sbj_set_int(windows,"min_os",10);
    CHECK(sbw_plugin_catalog_compatible(windows,"0.6.9","1.14.3",10,&error)==0);
    CHECK(sbw_plugin_catalog_compatible(windows,"0.6.8","1.14.3",10,&error)!=0);
    CHECK(sbw_plugin_catalog_compatible(windows,"0.6.9","1.15.0",10,&error)!=0);
    sbj_set_str(windows,"url","http://unsafe.example/plugin.sbe");CHECK(sbw_plugin_catalog_compatible(windows,"0.6.9","1.14.3",10,&error)!=0);sbj_free(windows);
    sbj *expired=sbw_plugin_catalog_verify(envelope,length,keys,now+2*86400,false,NULL,&error);CHECK(!expired);sbj_free(expired);
    expired=sbw_plugin_catalog_verify(envelope,length,keys,now+2*86400,true,NULL,&error);CHECK(expired!=NULL);sbj_free(expired);
    const char *bad[]={"wrong-salt.json","wrong-mgf.json","duplicate-key.json"};
    for(size_t i=0;i<sizeof bad/sizeof *bad;++i){char *input=read_fixture(directory,bad[i],&n);CHECK(input!=NULL);sbj *v=sbw_plugin_catalog_verify(input,n,keys,now,false,NULL,&error);CHECK(!v);sbj_free(v);free(input);}
    sbj *parsed=sbj_parse_strict(envelope,length,NULL,0);sbj_set_str(parsed,"key_id","unknown");char *input=sbj_dump(parsed,-1);
    sbj *invalid=sbw_plugin_catalog_verify(input,strlen(input),keys,now,false,NULL,&error);CHECK(!invalid);sbj_free(invalid);free(input);sbj_free(parsed);
    sbj *empty=sbj_parse_cstr("{\"format\":\"sb-easy.plugin-catalog.keys\",\"version\":1,\"keys\":{}}");
    invalid=sbw_plugin_catalog_verify(envelope,length,empty,now,false,NULL,&error);CHECK(!invalid);sbj_free(invalid);sbj_free(empty);
    sbj_free(state);sbj_free(payload);sbj_free(keys);sbj_free(info);free(envelope);
    printf("%s: cross-language RSA-PSS catalog, exact payload, salt/MGF, strict JSON, trust, expiry, rollback/revocation and compatibility\n",failures?"FAIL":"PASS");return failures?1:0;
}
