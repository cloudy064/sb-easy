#include "test_support.h"
#include "../service/capture.h"
#include <wchar.h>

int main(void) {
    wchar_t temp[MAX_PATH], root[MAX_PATH];
    CHECK(GetTempPathW(MAX_PATH,temp)&&GetTempFileNameW(temp,L"sbc",0,root));
    CHECK(DeleteFileW(root)&&CreateDirectoryW(root,NULL));
    sbj *identity=sbj_object();sbj_set_str(identity,"server","https://capture.example");sbj_set_str(identity,"host_id","device-one");
    sbw_error error={0};sbw_capture *capture=sbw_capture_new(root,identity,&error);CHECK(capture);
    sbj *config=sbj_parse_cstr("{\"enabled\":true,\"domains\":[\"example.com\"],\"bpf\":\"udp dst port 18443 and src net 127.0.0.0/8\"}");
    CHECK(sbw_capture_configure(capture,config,&error)==0);
    unsigned char packet[32]={0x45,0,0,32,0,1,0,0,64,17,0,0,127,0,0,1,198,18,255,2,0xd4,0x31,0x48,0x0b,0,12,0,0,1,2,3,4};
    CHECK(sbw_capture_test_packet(capture,packet,sizeof packet,"browser.exe","unmatched.test",&error)==0);
    CHECK(sbw_capture_test_packet(capture,packet,sizeof packet,"browser.exe","api.example.com",&error)==0);
    packet[23]=12;CHECK(sbw_capture_test_packet(capture,packet,sizeof packet,"browser.exe","api.example.com",&error)==0);packet[23]=11;
    CHECK(sbw_capture_rotate(capture,&error)==0);
    sbj *snapshot=sbw_capture_snapshot(capture);const sbj *files=sbj_get(snapshot,"files");CHECK(sbj_arr_len(files)==1);CHECK(sbj_get_int(snapshot,"packets",0)==1);
    char *digest=sb_strdup(sbj_get_str(sbj_arr_at(files,0),"digest",""));unsigned char *bytes=NULL;size_t length=0;
    CHECK(sbw_capture_read(capture,digest,&bytes,&length,&error)==0&&length==24+16+sizeof packet);
    CHECK(bytes[0]==0xd4&&bytes[20]==101&&!memcmp(bytes+40,packet,sizeof packet));free(bytes);sbj_free(snapshot);
    sbj_set_str(config,"bpf","tcp.port == 443");CHECK(sbw_capture_configure(capture,config,&error)!=0);
    snapshot=sbw_capture_snapshot(capture);CHECK(strstr(sbj_get_str(sbj_get(snapshot,"config"),"bpf",""),"udp dst"));sbj_free(snapshot);
    CHECK(!sbw_capture_digest_valid("../device-state.dat"));CHECK(sbw_capture_read(capture,"../state.lock",&bytes,&length,&error)!=0);
    CHECK(sbw_capture_mark_uploaded(capture,digest,&error)==0);
    sbw_capture_free(capture);capture=sbw_capture_new(root,identity,&error);CHECK(capture);
    snapshot=sbw_capture_snapshot(capture);CHECK(sbj_get_bool(sbj_arr_at(sbj_get(snapshot,"files"),0),"uploaded",false));sbj_free(snapshot);
    sbj_set_str(identity,"host_id","device-two");sbw_capture *other=sbw_capture_new(root,identity,&error);CHECK(other);
    snapshot=sbw_capture_snapshot(other);CHECK(sbj_arr_len(sbj_get(snapshot,"files"))==0);CHECK(!sbj_get_bool(sbj_get(snapshot,"config"),"enabled",true));sbj_free(snapshot);sbw_capture_free(other);
    CHECK(sbw_capture_delete(capture,digest,&error)==0);free(digest);sbj_free(config);sbj_free(identity);sbw_capture_free(capture);
    test_remove_capture_dirs(root);CHECK(RemoveDirectoryW(root));
    puts("Capture BPF, scope, raw PCAP, invalid-update preservation, persistence and device isolation passed.");return 0;
}
