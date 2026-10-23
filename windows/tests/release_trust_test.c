#include "../service/release_trust.h"
#include "../service/control_plane.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char publisher[] = "0123456789ABCDEF0123456789ABCDEF01234567";
static const char manifest[] = "{\"schema\":2,\"version\":\"0.7.0\",\"created_at\":\"2026-10-23T12:00:00Z\","
    "\"publisher_thumbprint\":\"0123456789ABCDEF0123456789ABCDEF01234567\",\"platform\":\"windows\",\"architecture\":\"x64\","
    "\"core_version\":\"1.14.3\",\"minimum_app_version\":\"0.6.9\",\"protocol_version\":1,\"channel\":\"stable\",\"rollout_percent\":30,"
    "\"files\":[{\"name\":\"sb-easy-0.7.0-windows-x64.msi\",\"bytes\":3,\"sha256\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}]}";
static void changed(const char *field, sbj *value) {
    sbj *json = sbj_parse(manifest, strlen(manifest), NULL, 0); sbj_set(json, field, value);
    char *text = sbj_dump(json, -1); sbw_error error = {0}; sbw_release release;
    assert(sbw_release_parse(text, strlen(text), publisher, &release, &error) < 0);
    assert(!release.id[0]); free(text); sbj_free(json);
}
static void parse_tests(void) {
    sbw_error error = {0}; sbw_release release; unsigned parts[3];
    assert(sbw_release_version("0.6.9", parts) && parts[2] == 9);
    assert(!sbw_release_version("00.6.9", parts) && !sbw_release_version("1.2.3-dev", parts));
    assert(!sbw_release_version("256.1.1", parts) && !sbw_release_version("1.1.65536", parts));
    assert(sbw_release_compare("0.6.10", "0.6.9") == 1);
    assert(sbw_release_parse(manifest, strlen(manifest), publisher, &release, &error) == 0);
    assert(!strcmp(release.core_version, "1.14.3") && release.bytes == 3 && strlen(release.id) == 64);
    assert(sbw_release_eligible(&release, "0.6.9", 29, &error) == 0);
    assert(sbw_release_eligible(&release, "0.6.9", 30, &error) < 0 && !strcmp(error.code, "UPDATE_ROLLOUT_PENDING"));
    assert(sbw_release_eligible(&release, "0.7.0", 0, &error) < 0 && !strcmp(error.code, "UPDATE_NOT_NEWER"));
    assert(sbw_release_eligible(&release, "0.6.8", 0, &error) < 0);
    assert(sbw_release_parse(manifest, strlen(manifest), "", &release, &error) < 0);
    changed("schema", sbj_int(1)); changed("architecture", sbj_str("arm64")); changed("platform", sbj_str("linux"));
    changed("channel", sbj_str("preview")); changed("protocol_version", sbj_int(2)); changed("rollout_percent", sbj_int(101));
    changed("rollout_percent", sbj_float(1.5)); changed("rollout_percent", sbj_int(-1)); changed("version", sbj_str("0.6.9.1"));
    changed("extra", sbj_bool(true)); changed("files", sbj_array());
    sbj *json = sbj_parse(manifest, strlen(manifest), NULL, 0), *entry = sbj_arr_at(sbj_get(json, "files"), 0);
    sbj_set_str(entry, "name", "../escape.msi"); char *text = sbj_dump(json, -1);
    assert(sbw_release_parse(text, strlen(text), publisher, &release, &error) < 0); free(text);
    sbj_set_str(entry, "name", "package.msi"); sbj_set_int(entry, "bytes", (int64_t)SBW_RELEASE_PACKAGE_LIMIT + 1);
    text = sbj_dump(json, -1); assert(sbw_release_parse(text, strlen(text), publisher, &release, &error) < 0); free(text);
    sbj_set_int(entry, "bytes", 3); sbj_arr_push(sbj_get(json, "files"), sbj_clone(entry));
    text = sbj_dump(json, -1); assert(sbw_release_parse(text, strlen(text), publisher, &release, &error) < 0); free(text); sbj_free(json);
    sb_buf duplicate = {0}; sb_buf_puts(&duplicate, "{\"schema\":2,"); sb_buf_puts(&duplicate, manifest + 1);
    assert(sbw_release_parse(duplicate.p, duplicate.len, publisher, &release, &error) < 0); sb_buf_free(&duplicate);
    assert(sbw_release_verify_manifest(manifest, strlen(manifest), "junk", 4, publisher, &release, &error) < 0);
    assert(!strcmp(error.code, "UPDATE_SIGNATURE_INVALID"));
    assert(sbw_release_verify_manifest(manifest, strlen(manifest), "junk", 4, "", &release, &error) < 0);
    assert(!strcmp(error.code, "UPDATE_PUBLISHER_UNCONFIGURED"));
}
static int unexpected_sink(void *context, const void *data, size_t length, sbw_error *error) {
    (void)context; (void)data; (void)length; (void)error; assert(false); return -1;
}
static void transport_tests(void) {
    assert(sbw_https_release_url("https://downloads.example.test/releases/current.json"));
    assert(!sbw_https_release_url("http://downloads.example.test/current.json"));
    assert(!sbw_https_release_url("https://user@downloads.example.test/current.json"));
    assert(!sbw_https_release_url("https://downloads.example.test/../current.json"));
    assert(!sbw_https_release_url("https://downloads.example.test/current.json?token=secret"));
    assert(!sbw_https_release_url("https://downloads.example.test"));
    sbw_error error = {0}; uint64_t received = 99;
    assert(sbw_https_download("http://127.0.0.1:1/file", 100, 1000, NULL, unexpected_sink, NULL, &received, &error) < 0);
    assert(!received && !strcmp(error.code, "invalid_server"));
    HANDLE cancelled = CreateEventW(NULL, TRUE, TRUE, NULL); assert(cancelled);
    assert(sbw_https_download("https://127.0.0.1:1/file", 100, 1000, cancelled, unexpected_sink, NULL, &received, &error) < 0);
    assert(!strcmp(error.code, "cancelled")); CloseHandle(cancelled);
}
static void file_tests(void) {
    char digest[65]; sbw_error error = {0};
    assert(sbw_release_hash("abc", 3, digest, &error) == 0 && !strcmp(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    wchar_t directory[MAX_PATH], path[MAX_PATH]; assert(GetTempPathW(MAX_PATH, directory)); assert(GetTempFileNameW(directory, L"sbu", 0, path));
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(file != INVALID_HANDLE_VALUE); DWORD count = 0; assert(WriteFile(file, "abc", 3, &count, NULL) && count == 3);
    assert(sbw_release_hash_file(file, 3, digest, &error) == 0);
    assert(sbw_release_hash_file(file, 4, digest, &error) < 0);
    digest[0] = 'f'; assert(sbw_release_hash_file(file, 3, digest, &error) < 0);
    assert(sbw_release_verify_file(path, file, publisher, true, &error) < 0);
    CloseHandle(file); assert(DeleteFileW(path));
}
int main(void) { parse_tests(); transport_tests(); file_tests(); puts("Windows release trust tests passed"); return 0; }
