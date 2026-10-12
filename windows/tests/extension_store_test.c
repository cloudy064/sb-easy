#include "test_support.h"
#include "../service/extension_store.h"

int main(int argc,char **argv) {
    const char *id=argc>2?argv[2]:"capture";const sbw_extension_release *release=sbw_extension_release_find(id);CHECK(release);
    sbw_error error={0};unsigned char *data=sb_xcalloc(release->bytes,1);
    CHECK(sbw_store_publish(id,L"Z:\\not-used",data,4,&error)!=0);
    CHECK(sb_streq(error.code,"STORE_INTEGRITY"));
    memcpy(data,"SBECP001",8);
    CHECK(sbw_store_publish(id,L"Z:\\not-used",data,release->bytes,&error)!=0);
    CHECK(sb_streq(error.code,"STORE_INTEGRITY"));
    if(argc>1) {
        FILE *f=NULL;CHECK(!fopen_s(&f,argv[1],"rb"));CHECK(fread(data,1,release->bytes,f)==release->bytes);fclose(f);
        wchar_t temp[MAX_PATH],root[MAX_PATH];CHECK(GetTempPathW(MAX_PATH,temp));CHECK(GetTempFileNameW(temp,L"sbs",0,root));CHECK(DeleteFileW(root));CHECK(CreateDirectoryW(root,NULL));
        data[release->bytes-1]^=1;
        CHECK(sbw_store_publish(id,root,data,release->bytes,&error)!=0&&sb_streq(error.code,"STORE_INTEGRITY"));
        wchar_t relative[128];swprintf_s(relative,128,L"extensions\\%S",id);wchar_t *dest=sbw_path_join(root,relative);CHECK(GetFileAttributesW(dest)==INVALID_FILE_ATTRIBUTES);
        data[release->bytes-1]^=1;
        /* A blocked UI destination must not publish any executable files. */
        wchar_t *ui=sbw_path_join(root,L"ui");CHECK(CreateDirectoryW(ui,NULL));free(ui);
        ui=sbw_path_join(root,L"ui\\extensions");CHECK(CreateDirectoryW(ui,NULL));free(ui);
        swprintf_s(relative,128,L"ui\\extensions\\%S",id);ui=sbw_path_join(root,relative);CHECK(CreateDirectoryW(ui,NULL));
        CHECK(sbw_store_publish(id,root,data,release->bytes,&error)!=0&&sb_streq(error.code,"STORE_EXISTS"));
        CHECK(GetFileAttributesW(dest)==INVALID_FILE_ATTRIBUTES);CHECK(RemoveDirectoryW(ui));free(ui);
        CHECK(!sbw_store_publish(id,root,data,release->bytes,&error));
        CHECK(GetFileAttributesW(dest)!=INVALID_FILE_ATTRIBUTES);
        wchar_t *marker=sbw_path_join(dest,L"enabled");CHECK(GetFileAttributesW(marker)==INVALID_FILE_ATTRIBUTES);free(marker);
        CHECK(sbw_store_publish(id,root,data,release->bytes,&error)!=0&&sb_streq(error.code,"STORE_EXISTS"));
        free(dest);
    }
    free(data);puts("Store rejects corrupt packages and unsafe layouts; trusted install is atomic, disabled and non-overwriting.");return 0;
}
