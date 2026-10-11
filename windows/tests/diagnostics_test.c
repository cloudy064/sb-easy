#include "test_support.h"
#include "../service/diagnostics.h"
int main(void) {
    const char json[] = "{\"outbounds\":[{\"password\":\"fixture-private-value\",\"username\":\"alice-sensitive\",\"tls\":{\"private_key\":\"hidden-key-value\"}}],\"experimental\":{\"clash_api\":{\"secret\":\"fixture-api-value\"}}}";
    sbj *config = sbj_parse_cstr(json);
    char *safe = sbw_diagnostics_redact("dial alice-sensitive fixture-private-value fixture-api-value hidden-key-value: i/o timeout", config);
    CHECK(!strstr(safe, "sensitive") && !strstr(safe, "fixture-") && !strstr(safe, "secret-key"));
    CHECK(strstr(safe, "i/o timeout")); free(safe);
    safe = sbw_diagnostics_redact("Authorization: Basic unknown-credential", config);
    CHECK(!strstr(safe, "unknown-credential")); free(safe);
    safe = sbw_diagnostics_redact("GET https://example.com/path?code=one-time-value", config);
    CHECK(!strstr(safe, "one-time-value") && strstr(safe, "example.com")); free(safe);
    safe = sbw_diagnostics_redact("DNS api.openai.com outbound/http[Tokyo]: unexpected status: 407", config);
    CHECK(strstr(safe, "api.openai.com") && strstr(safe, "407")); free(safe); sbj_free(config);
    wchar_t temp[MAX_PATH], directory[MAX_PATH];
    CHECK(GetTempPathW(MAX_PATH, temp) && GetTempFileNameW(temp, L"sbd", 0, directory));
    CHECK(DeleteFileW(directory) && CreateDirectoryW(directory, NULL));
    sbw_diagnostics *log = sbw_diagnostics_new(directory);
    HANDLE reader, writer; CHECK(CreatePipe(&reader, &writer, NULL, 0));
    sbw_log_stream *capture = sbw_diagnostics_capture(log, reader, json); CHECK(capture);
    DWORD written;
    const char first[] = "DNS api.openai.com fixture-private-";
    const char last[] = "value i/o timeout\n";
    CHECK(WriteFile(writer, first, sizeof first - 1, &written, NULL));
    CHECK(WriteFile(writer, last, sizeof last - 1, &written, NULL));
    CloseHandle(writer); sbw_diagnostics_finish(capture); sbw_diagnostics_free(log);
    wchar_t *path = sbw_path_join(directory, L"diagnostic-0.log");
    FILE *file = NULL; CHECK(!_wfopen_s(&file, path, L"rb") && file);
    char data[4096] = {0}; CHECK(fread(data, 1, sizeof data - 1, file) > 0); fclose(file);
    CHECK(strstr(data, "api.openai.com") && strstr(data, "i/o timeout") && !strstr(data, "fixture-private"));
    /* Retention is bounded, and survives opening the logger again. */
    log = sbw_diagnostics_new(directory);
    char bulk[16000]; memset(bulk, 'x', sizeof bulk - 1); bulk[sizeof bulk - 1] = 0;
    for (int i = 0; i < 1200; ++i) sbw_diagnostics_event(log, "rotation", bulk);
    sbw_diagnostics_free(log);
    for (int i = 0; i < 4; ++i) {
        wchar_t name[40]; swprintf_s(name, 40, L"diagnostic-%d.log", i);
        wchar_t *item = sbw_path_join(directory, name); WIN32_FILE_ATTRIBUTE_DATA attr;
        CHECK(GetFileAttributesExW(item, GetFileExInfoStandard, &attr));
        CHECK(!attr.nFileSizeHigh && attr.nFileSizeLow <= 4U * 1024U * 1024U);
        CHECK(DeleteFileW(item)); free(item);
    }
    CHECK(RemoveDirectoryW(directory)); free(path);
    puts("Diagnostics redaction, split pipe lines, persistence and bounded rotation passed."); return 0;
}
