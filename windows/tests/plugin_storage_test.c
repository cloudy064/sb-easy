#include "../service/plugin_storage.h"
#include "../service/secure_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"line %d: %s (%s: %s)\n",__LINE__,#c,error.code,error.message);exit(1);}}while(0)
static sbw_error error;
static unsigned char *fixture(const char *root,const char *name,size_t *length){char p[4096];snprintf(p,sizeof p,"%s/%s",root,name);FILE *f=fopen(p,"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>0&&n<1024*1024);rewind(f);unsigned char *out=sb_xmalloc((size_t)n+1);*length=fread(out,1,(size_t)n,f);fclose(f);CHECK(*length==(size_t)n);out[n]=0;return out;}
static void accept(sbw_plugin_storage *s,const char *root,const char *name){size_t n=0;unsigned char *env=fixture(root,name,&n);memset(&error,0,sizeof error);CHECK(!sbw_plugin_storage_catalog(s,(const char*)env,n,&error));free(env);}
static void install(sbw_plugin_storage *s,const char *root,int build){char name[80];snprintf(name,sizeof name,"package-%d.sbe",build);size_t n=0;unsigned char *data=fixture(root,name,&n);CHECK(!sbw_plugin_storage_check_package(s,"statistics",data,n,&error));CHECK(!sbw_plugin_storage_publish(s,"statistics",data,n,&error));free(data);CHECK(sbw_plugin_storage_verified(s,"statistics",&error));}
static void version(sbw_plugin_storage *s,int build){sbj *v=sbw_plugin_storage_status(s,"statistics");if(sbj_get_int(v,"build",0)!=build){char *text=sbj_dump(v,-1);fprintf(stderr,"expected build %d; got %s\n",build,text);free(text);}CHECK(sbj_get_int(v,"build",0)==build);CHECK(sbj_get_bool(v,"verified",false));sbj_free(v);}
/* Simulate a process ending after each publication rename, using the same
 * durable journal. Recovery runs only through the production open API. */
static void interrupted(const wchar_t *root,int step){
    wchar_t *trust=sbw_path_join(root,L".plugin-trust");sbw_store *raw=sbw_secure_store_new(trust,&error);CHECK(raw);sbj *state=NULL;CHECK(!raw->load(raw->context,&state,&error));
    sbj *pending=sbj_object();sbj_set_str(pending,"id","statistics");sbj_set_bool(pending,"had_old",true);sbj_set_bool(pending,"committed",false);sbj_set(state,"pending",pending);CHECK(!raw->save(raw->context,state,&error));sbj_free(state);sbw_store_free(raw);
    wchar_t *dest=sbw_path_join(root,L"extensions\\statistics"),*view=sbw_path_join(root,L"ui\\extensions\\statistics"),*old=sbw_path_join(trust,L"old"),*oldview=sbw_path_join(trust,L"old-view"),*stage=sbw_path_join(trust,L"new"),*stageview=sbw_path_join(trust,L"new-view");
    CHECK(CreateDirectoryW(stage,NULL));CHECK(CreateDirectoryW(stageview,NULL));
    if(step>=1)CHECK(MoveFileW(dest,old));if(step>=2)CHECK(MoveFileW(view,oldview));if(step>=3)CHECK(MoveFileW(stageview,view));if(step>=4)CHECK(MoveFileW(stage,dest));
    sbw_plugin_storage *s=sbw_plugin_storage_open(root,&error);CHECK(s);version(s,2);sbw_plugin_storage_close(s);
    CHECK(GetFileAttributesW(old)==INVALID_FILE_ATTRIBUTES);CHECK(GetFileAttributesW(oldview)==INVALID_FILE_ATTRIBUTES);free(trust);free(dest);free(view);free(old);free(oldview);free(stage);free(stageview);
}
int main(int argc,char **argv){
    CHECK(argc==2);wchar_t temp[MAX_PATH],root[MAX_PATH];CHECK(GetTempPathW(MAX_PATH,temp));CHECK(GetTempFileNameW(temp,L"spg",0,root));CHECK(DeleteFileW(root));CHECK(CreateDirectoryW(root,NULL));
    sbw_plugin_storage *s=sbw_plugin_storage_open(root,&error);CHECK(s);CHECK(!sbw_plugin_storage_release(s,"statistics",&error));accept(s,argv[1],"catalog-2.json");
    size_t n=0;unsigned char *data=fixture(argv[1],"package-2.sbe",&n);data[n-1]^=1;CHECK(sbw_plugin_storage_publish(s,"statistics",data,n,&error)!=0);data[n-1]^=1;CHECK(!sbw_plugin_storage_publish(s,"statistics",data,n,&error));free(data);version(s,2);
    wchar_t *marker=sbw_path_join(root,L"extensions\\statistics\\enabled");CHECK(GetFileAttributesW(marker)==INVALID_FILE_ATTRIBUTES);free(marker);CHECK(!sbw_plugin_storage_confirm(s,"statistics",&error));sbw_plugin_storage_close(s);
    for(int step=0;step<=4;++step){printf("recover step %d\n",step);interrupted(root,step);}
    s=sbw_plugin_storage_open(root,&error);CHECK(s);version(s,2);accept(s,argv[1],"catalog-3.json");
    /* A worker holding a file blocks publication; the old code survives. */
    wchar_t *exe=sbw_path_join(root,L"extensions\\statistics\\sb-easy-statistics.exe");wchar_t *held_directory=sbw_path_join(root,L"extensions\\statistics");HANDLE held=CreateFileW(held_directory,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);free(held_directory);CHECK(held!=INVALID_HANDLE_VALUE);
    data=fixture(argv[1],"package-3.sbe",&n);CHECK(sbw_plugin_storage_publish(s,"statistics",data,n,&error)!=0);CloseHandle(held);free(data);version(s,2);
    install(s,argv[1],3);version(s,3);CHECK(!sbw_plugin_storage_rollback(s,"statistics",&error));version(s,2);install(s,argv[1],3);
    HANDLE changed=CreateFileW(exe,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);CHECK(changed!=INVALID_HANDLE_VALUE);DWORD wrote=0;CHECK(WriteFile(changed,"tampered",8,&wrote,NULL));CloseHandle(changed);CHECK(!sbw_plugin_storage_verified(s,"statistics",&error));CHECK(!sbw_plugin_storage_rollback(s,"statistics",&error));version(s,2);free(exe);
    install(s,argv[1],3);accept(s,argv[1],"catalog-4.json");CHECK(!sbw_plugin_storage_verified(s,"statistics",&error));CHECK(!sbw_plugin_storage_rollback(s,"statistics",&error));version(s,2);
    CHECK(sbw_plugin_storage_rollback(s,"statistics",&error)!=0);accept(s,argv[1],"catalog-5.json");CHECK(!sbw_plugin_storage_release(s,"statistics",&error));
    data=fixture(argv[1],"catalog-3.json",&n);CHECK(sbw_plugin_storage_catalog(s,(const char*)data,n,&error)!=0);free(data);sbw_plugin_storage_close(s);
    s=sbw_plugin_storage_open(root,&error);CHECK(s);version(s,2);CHECK(sbw_plugin_storage_rollback(s,"statistics",&error)!=0);accept(s,argv[1],"catalog-6.json");CHECK(!sbw_plugin_storage_release(s,"statistics",&error));sbw_plugin_storage_close(s);
    /* A signed replacement can repair a revoked active release while keeping
     * the last non-revoked cached version available for recovery. */
    CHECK(GetTempFileNameW(temp,L"spg",0,root));CHECK(DeleteFileW(root));CHECK(CreateDirectoryW(root,NULL));s=sbw_plugin_storage_open(root,&error);CHECK(s);
    accept(s,argv[1],"catalog-2.json");install(s,argv[1],2);CHECK(!sbw_plugin_storage_confirm(s,"statistics",&error));accept(s,argv[1],"catalog-3.json");install(s,argv[1],3);accept(s,argv[1],"catalog-4.json");CHECK(!sbw_plugin_storage_verified(s,"statistics",&error));install(s,argv[1],4);version(s,4);CHECK(!sbw_plugin_storage_rollback(s,"statistics",&error));version(s,2);sbw_plugin_storage_close(s);
    puts("PASS: signed install/update, all interrupted publication stages, locked files, tampering, rollback, durable revocation and downgrade prevention");return 0;
}
