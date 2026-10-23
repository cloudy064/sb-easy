#include "plugin_catalog.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SBW_GENERATED_PLUGIN_TRUST
#include "plugin_trust_keys.h"
#endif
#ifndef SBW_PLUGIN_CATALOG_KEYS
#define SBW_PLUGIN_CATALOG_KEYS "{\"format\":\"sb-easy.plugin-catalog.keys\",\"version\":1,\"keys\":{}}"
#endif

#define ENVELOPE_MAX (1024U * 1024U)
#define PAYLOAD_MAX (512U * 1024U)
static int invalid(sbw_error *e) { return sbw_fail(e,"CATALOG_INVALID","The plugin catalog is invalid or is not signed by a trusted publisher."); }
static bool text(const sbj *v,size_t max,bool empty) { return sbw_json_string(v,max,empty); }
static bool integer(const sbj *v,int64_t min,int64_t max) { return sbj_is_integer(v)&&sbj_as_int(v,min-1)>=min&&sbj_as_int(v,min-1)<=max; }
static bool identifier(const sbj *v) {
    if(!text(v,64,false))return false;
    for(const char *p=v->v.str.ptr;*p;++p)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'))return false;
    return true;
}
static bool fields(const sbj *v,const char *const *names,size_t count) {
    if(!sbj_is_object(v)||sbj_obj_len(v)!=count)return false;
    for(size_t i=0;i<count;++i)if(!sbj_has(v,names[i]))return false;
    return true;
}
static bool platform(const sbj *v) { return sbj_string_is(v,"android")||sbj_string_is(v,"windows")||sbj_string_is(v,"linux")||sbj_string_is(v,"macos"); }
static bool digest(const sbj *v,bool empty) {
    if(empty&&sbj_string_is(v,""))return true;
    return text(v,64,false)&&v->v.str.len==64&&strspn(v->v.str.ptr,"0123456789abcdef")==64;
}
static bool version(const char *value,int result[3]) {
    if(!value||!*value)return false;
    const char *p=value;
    for(int i=0;i<3;++i) {
        const char *start=p;int n=0;
        while(*p>='0'&&*p<='9'){if(p-start>=6)return false;n=n*10+(*p++-'0');}
        if(p==start||(p-start>1&&*start=='0')||(i<2?*p!='.':*p!=0))return false;
        result[i]=n;if(i<2)++p;
    }
    return true;
}
static int version_compare(const int a[3],const int b[3]) {
    for(int i=0;i<3;++i)if(a[i]!=b[i])return a[i]<b[i]?-1:1;
    return 0;
}
static bool version_range(const sbj *release,const char *low,const char *high) {
    int a[3],b[3];return text(sbj_get(release,low),32,false)&&text(sbj_get(release,high),32,false)&&version(sbj_get_str(release,low,NULL),a)&&version(sbj_get_str(release,high,NULL),b)&&version_compare(a,b)<0;
}
static bool https_url(const sbj *v) {
    if(!text(v,4096,false))return false;
    for(const unsigned char *p=(const unsigned char*)v->v.str.ptr;*p;++p)if(*p<33||*p==127||*p=='#'||*p=='\\')return false;
    wchar_t *wide=sbw_wide(v->v.str.ptr,NULL);if(!wide)return false;
    URL_COMPONENTS url={0};url.dwStructSize=sizeof url;url.dwHostNameLength=(DWORD)-1;url.dwUserNameLength=(DWORD)-1;url.dwPasswordLength=(DWORD)-1;
    bool ok=WinHttpCrackUrl(wide,0,0,&url)&&url.nScheme==INTERNET_SCHEME_HTTPS&&url.dwHostNameLength>0&&!url.dwUserNameLength&&!url.dwPasswordLength&&url.nPort>0;
    free(wide);return ok;
}
static unsigned char *base64(const sbj *value,size_t maximum,size_t *length) {
    *length=0;if(!text(value,ENVELOPE_MAX,false)||value->v.str.len%4)return NULL;
    const char *s=value->v.str.ptr;size_t n=value->v.str.len,pad=(s[n-1]=='=')+(s[n-2]=='=');
    for(size_t i=0;i<n;++i)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||s[i]=='+'||s[i]=='/'||(i>=n-pad&&s[i]=='=')))return NULL;
    size_t bytes=n/4*3-pad;if(!bytes||bytes>maximum)return NULL;
    DWORD count=(DWORD)(n/4*3+1);unsigned char *out=sb_xmalloc(count);
    if(!CryptStringToBinaryA(s,(DWORD)n,CRYPT_STRING_BASE64,out,&count,NULL,NULL)||count!=bytes){free(out);return NULL;}
    DWORD encoded=(DWORD)n+8;char *again=sb_xmalloc(encoded);
    bool ok=CryptBinaryToStringA(out,count,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,again,&encoded)&&strlen(again)==n&&!memcmp(again,s,n);
    free(again);if(!ok){free(out);return NULL;}*length=count;return out;
}
static bool sha256(const void *data,size_t size,unsigned char hash[32]) {
    BCRYPT_ALG_HANDLE algorithm=NULL;if(size>ULONG_MAX||BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)return false;
    NTSTATUS status=BCryptHash(algorithm,NULL,0,(PUCHAR)data,(ULONG)size,hash,32);BCryptCloseAlgorithmProvider(algorithm,0);return status>=0;
}
static bool signature(const sbj *key,const unsigned char *payload,size_t length,const sbj *encoded_signature) {
    size_t der_length=0,sig_length=0;unsigned char *der=base64(key,4096,&der_length),*sig=base64(encoded_signature,512,&sig_length);
    CERT_PUBLIC_KEY_INFO *info=NULL;DWORD info_size=0;BCRYPT_KEY_HANDLE imported=NULL;bool ok=false;
    if(!der||!sig||!CryptDecodeObjectEx(X509_ASN_ENCODING,X509_PUBLIC_KEY_INFO,der,(DWORD)der_length,CRYPT_DECODE_ALLOC_FLAG,NULL,&info,&info_size)||
       !info->Algorithm.pszObjId||strcmp(info->Algorithm.pszObjId,szOID_RSA_RSA)||!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,info,0,NULL,&imported))goto done;
    unsigned char public_blob[1024];DWORD got=0;
    if(BCryptExportKey(imported,NULL,BCRYPT_RSAPUBLIC_BLOB,public_blob,sizeof public_blob,&got,0)<0||got<sizeof(BCRYPT_RSAKEY_BLOB))goto done;
    BCRYPT_RSAKEY_BLOB header;memcpy(&header,public_blob,sizeof header);
    if(header.Magic!=BCRYPT_RSAPUBLIC_MAGIC||header.BitLength<2048||header.BitLength>4096||header.cbModulus!=header.BitLength/8||
       header.cbPublicExp>8||got!=sizeof header+header.cbPublicExp+header.cbModulus||sig_length!=header.cbModulus)goto done;
    unsigned char hash[32];BCRYPT_PSS_PADDING_INFO padding={BCRYPT_SHA256_ALGORITHM,32};
    ok=sha256(payload,length,hash)&&BCryptVerifySignature(imported,&padding,hash,32,sig,(ULONG)sig_length,BCRYPT_PAD_PSS)>=0;
done:if(imported)BCryptDestroyKey(imported);if(info)LocalFree(info);free(der);free(sig);return ok;
}
static bool release_valid(const sbj *r) {
    static const char *const names[]={"id","platform","version","build","abi","api","min_host","max_host","min_core","max_core","min_os","url","sha256","bytes","package","signer_sha256","permissions"};
    int parsed[3];
    if(!fields(r,names,sizeof names/sizeof *names)||!identifier(sbj_get(r,"id"))||!platform(sbj_get(r,"platform"))||!identifier(sbj_get(r,"abi"))||
       !text(sbj_get(r,"version"),32,false)||!version(sbj_get_str(r,"version",NULL),parsed)||!integer(sbj_get(r,"build"),1,2100000000)||
       !integer(sbj_get(r,"api"),1,65535)||!integer(sbj_get(r,"min_os"),0,2100000000)||!integer(sbj_get(r,"bytes"),1,160LL*1024*1024)||
       !version_range(r,"min_host","max_host")||!version_range(r,"min_core","max_core")||!https_url(sbj_get(r,"url"))||!digest(sbj_get(r,"sha256"),false))return false;
    bool android=sbj_string_is(sbj_get(r,"platform"),"android");
    if(android?(!text(sbj_get(r,"package"),240,false)||!digest(sbj_get(r,"signer_sha256"),false)):
        (!sbj_string_is(sbj_get(r,"package"),"")||!sbj_string_is(sbj_get(r,"signer_sha256"),"")))return false;
    const sbj *permissions=sbj_get(r,"permissions");if(!sbj_is_array(permissions)||sbj_arr_len(permissions)>16)return false;
    for(size_t i=0;i<sbj_arr_len(permissions);++i) {
        const sbj *p=sbj_arr_at(permissions,i);if(!identifier(p))return false;
        for(size_t j=0;j<i;++j)if(sbj_equal(p,sbj_arr_at(permissions,j)))return false;
    }
    return true;
}
static bool revocation_valid(const sbj *r) {
    static const char *const names[]={"id","platform","build","reason"};
    if(!fields(r,names,4)||!identifier(sbj_get(r,"id"))||!platform(sbj_get(r,"platform"))||!integer(sbj_get(r,"build"),1,2100000000)||!text(sbj_get(r,"reason"),960,false))return false;
    const unsigned char *p=(const unsigned char*)sbj_get_str(r,"reason","");size_t characters=0;
    for(;*p;++p){if(*p<32||*p==127||(*p==0xc2&&p[1]>=0x80&&p[1]<=0x9f))return false;if((*p&0xc0)!=0x80)++characters;}
    return characters<=240;
}
static bool same_release(const sbj *a,const sbj *b,bool abi) {
    return sbj_equal(sbj_get(a,"id"),sbj_get(b,"id"))&&sbj_equal(sbj_get(a,"platform"),sbj_get(b,"platform"))&&
        sbj_get_int(a,"build",0)==sbj_get_int(b,"build",0)&&(!abi||sbj_equal(sbj_get(a,"abi"),sbj_get(b,"abi")));
}
sbj *sbw_plugin_catalog_verify(const char *envelope,size_t length,const sbj *trust,int64_t now,bool receipt,char hash_text[65],sbw_error *error) {
    sbj *parsed=NULL,*payload=NULL;unsigned char *bytes=NULL;size_t count=0;
    static const char *const env_fields[]={"format","version","algorithm","key_id","payload","signature"};
    static const char *const trust_fields[]={"format","version","keys"};
    static const char *const payload_fields[]={"sequence","issued_at","expires_at","releases","revocations"};
    if(!envelope||!length||length>ENVELOPE_MAX||now<=0||!fields(trust,trust_fields,3)||
       !sbj_string_is(sbj_get(trust,"format"),"sb-easy.plugin-catalog.keys")||!integer(sbj_get(trust,"version"),1,1)||
       !sbj_is_object(sbj_get(trust,"keys"))||sbj_obj_len(sbj_get(trust,"keys"))>16)goto fail;
    parsed=sbj_parse_strict(envelope,length,NULL,0);
    if(!fields(parsed,env_fields,6)||!sbj_string_is(sbj_get(parsed,"format"),"sb-easy.plugin-catalog")||
       !integer(sbj_get(parsed,"version"),1,1)||!sbj_string_is(sbj_get(parsed,"algorithm"),"rsa-pss-sha256")||!identifier(sbj_get(parsed,"key_id")))goto fail;
    bytes=base64(sbj_get(parsed,"payload"),PAYLOAD_MAX,&count);
    const sbj *key=sbj_get(sbj_get(trust,"keys"),sbj_get_str(parsed,"key_id",""));
    if(!bytes||!signature(key,bytes,count,sbj_get(parsed,"signature")))goto fail;
    payload=sbj_parse_strict((const char*)bytes,count,NULL,0);
    if(!fields(payload,payload_fields,5)||!integer(sbj_get(payload,"sequence"),1,INT64_C(9007199254740991))||
       !integer(sbj_get(payload,"issued_at"),1,INT64_C(4102444800))||!integer(sbj_get(payload,"expires_at"),1,INT64_C(4102444800)))goto fail;
    int64_t issued=sbj_get_int(payload,"issued_at",0),expires=sbj_get_int(payload,"expires_at",0);
    if(issued>now+300||expires<=issued||expires-issued>90LL*86400||(!receipt&&expires<=now))goto fail;
    const sbj *releases=sbj_get(payload,"releases"),*revocations=sbj_get(payload,"revocations");
    if(!sbj_is_array(releases)||sbj_arr_len(releases)>128||!sbj_is_array(revocations)||sbj_arr_len(revocations)>256)goto fail;
    for(size_t i=0;i<sbj_arr_len(releases);++i) {
        const sbj *r=sbj_arr_at(releases,i);if(!release_valid(r))goto fail;
        for(size_t j=0;j<i;++j)if(same_release(r,sbj_arr_at(releases,j),true))goto fail;
    }
    for(size_t i=0;i<sbj_arr_len(revocations);++i) {
        const sbj *r=sbj_arr_at(revocations,i);if(!revocation_valid(r))goto fail;
        for(size_t j=0;j<i;++j)if(same_release(r,sbj_arr_at(revocations,j),false))goto fail;
    }
    unsigned char hash[32];if(!sha256(bytes,count,hash))goto fail;
    if(hash_text)for(size_t i=0;i<32;++i)sprintf_s(hash_text+i*2,3,"%02x",hash[i]);
    free(bytes);sbj_free(parsed);return payload;
fail:free(bytes);sbj_free(parsed);sbj_free(payload);invalid(error);return NULL;
}
sbj *sbw_plugin_catalog_verify_trusted(const char *envelope,size_t length,int64_t now,bool receipt,char hash[65],sbw_error *error) {
    sbj *trust=sbj_parse_strict(SBW_PLUGIN_CATALOG_KEYS,strlen(SBW_PLUGIN_CATALOG_KEYS),NULL,0);
    sbj *out=sbw_plugin_catalog_verify(envelope,length,trust,now,receipt,hash,error);sbj_free(trust);return out;
}
bool sbw_plugin_catalog_has_trust(void) {
    sbj *trust=sbj_parse_strict(SBW_PLUGIN_CATALOG_KEYS,strlen(SBW_PLUGIN_CATALOG_KEYS),NULL,0);
    bool available=sbj_obj_len(sbj_get(trust,"keys"))>0;sbj_free(trust);return available;
}
bool sbw_plugin_catalog_revoked(const sbj *state,const char *id,const char *platform_name,int64_t build) {
    const sbj *list=sbj_get(state,"revocations");
    for(size_t i=0;i<sbj_arr_len(list);++i){const sbj *r=sbj_arr_at(list,i);if(sbj_string_is(sbj_get(r,"id"),id)&&sbj_string_is(sbj_get(r,"platform"),platform_name)&&sbj_get_int(r,"build",0)==build)return true;}
    return false;
}
sbj *sbw_plugin_catalog_accept(const sbj *previous,const sbj *payload,const char *hash,sbw_error *error) {
    int64_t sequence=sbj_get_int(payload,"sequence",0),old=sbj_get_int(previous,"sequence",0);
    if(!hash||strlen(hash)!=64||strspn(hash,"0123456789abcdef")!=64||sequence<1||sequence<old||
        (sequence==old&&!sbj_string_is(sbj_get(previous,"payload_hash"),hash))) {
        sbw_fail(error,"CATALOG_ROLLBACK","The plugin catalog is older than the accepted catalog or changes an existing sequence.");return NULL;
    }
    sbj *out=sbj_object(),*revocations=sbj_array();
    const sbj *lists[]={sbj_get(previous,"revocations"),sbj_get(payload,"revocations")};
    for(size_t n=0;n<2;++n)for(size_t i=0;i<sbj_arr_len(lists[n]);++i) {
        const sbj *r=sbj_arr_at(lists[n],i);bool exists=false;
        if(!revocation_valid(r)||sbj_arr_len(revocations)>=16384){sbj_free(out);sbj_free(revocations);invalid(error);return NULL;}
        for(size_t j=0;j<sbj_arr_len(revocations);++j)if(same_release(r,sbj_arr_at(revocations,j),false)){exists=true;break;}
        if(!exists)sbj_arr_push(revocations,sbj_clone(r));
    }
    sbj_set_int(out,"sequence",sequence);sbj_set_str(out,"payload_hash",hash);sbj_set(out,"revocations",revocations);return out;
}
const sbj *sbw_plugin_catalog_release(const sbj *payload,const char *id,const char *platform_name,const char *abi,int64_t build) {
    const sbj *list=sbj_get(payload,"releases"),*result=NULL;
    for(size_t i=0;i<sbj_arr_len(list);++i) {
        const sbj *r=sbj_arr_at(list,i);int64_t candidate=sbj_get_int(r,"build",0);
        if(sbj_string_is(sbj_get(r,"id"),id)&&sbj_string_is(sbj_get(r,"platform"),platform_name)&&sbj_string_is(sbj_get(r,"abi"),abi)&&
           (!build||build==candidate)&&(!result||candidate>sbj_get_int(result,"build",0)))result=r;
    }
    return result;
}
int sbw_plugin_catalog_compatible(const sbj *r,const char *host,const char *core,int64_t os,sbw_error *error) {
    int h[3],c[3],minimum[3],maximum[3];bool ok=release_valid(r)&&version(host,h)&&version(core,c)&&
        sbj_string_is(sbj_get(r,"platform"),"windows")&&sbj_string_is(sbj_get(r,"abi"),"x86_64")&&sbj_get_int(r,"api",0)==1&&os>=sbj_get_int(r,"min_os",0);
    if(ok){version(sbj_get_str(r,"min_host",""),minimum);version(sbj_get_str(r,"max_host",""),maximum);ok=version_compare(h,minimum)>=0&&version_compare(h,maximum)<0;}
    if(ok){version(sbj_get_str(r,"min_core",""),minimum);version(sbj_get_str(r,"max_core",""),maximum);ok=version_compare(c,minimum)>=0&&version_compare(c,maximum)<0;}
    const sbj *permissions=sbj_get(r,"permissions");const char *id=sbj_get_str(r,"id","");
    const char *capture[]={"private-files","packet-capture","kernel-driver-broker"};
    const char *statistics[]={"private-files","traffic-metadata"};
    const char *http[]={"private-files","internet","tls-intercept"};
    const char *const *required=sb_streq(id,"capture")?capture:sb_streq(id,"statistics")?statistics:sb_streq(id,"http-debug")?http:NULL;
    size_t count=sb_streq(id,"statistics")?2:3;ok=ok&&required&&sbj_arr_len(permissions)==count;
    for(size_t i=0;ok&&i<count;++i) {
        bool found=false;for(size_t j=0;j<sbj_arr_len(permissions);++j)if(sbj_string_is(sbj_arr_at(permissions,j),required[i]))found=true;
        ok=found;
    }
    return ok?0:sbw_fail(error,"CATALOG_INCOMPATIBLE","This plugin release is incompatible with this host, core or permission boundary.");
}
