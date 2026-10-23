#include "test_support.h"
#include "../service/preferences.h"
#include "../service/independent.h"

int main(int argc, char **argv) {
    CHECK(argc == 2); FILE *file = fopen(argv[1], "rb"); CHECK(file);
    char bytes[8192]; size_t count = fread(bytes, 1, sizeof bytes - 1, file); CHECK(!ferror(file)); fclose(file); bytes[count] = 0;
    sbj *vector = sbj_parse_cstr(bytes); CHECK(vector); sbw_error error = {0};
    const char *password = sbj_get_str(vector, "passphrase", "");
    sbj *plain = sbw_preferences_decrypt(sbj_get(vector, "envelope"), password, &error);
    if (!plain) fprintf(stderr, "Vector decrypt: %s\n", error.code);
    CHECK(plain && sbj_equal(plain, sbj_get(vector, "payload")));
    sbj *one = sbw_preferences_encrypt(plain, password, &error), *two = sbw_preferences_encrypt(plain, password, &error);
    CHECK(one && two && !sbj_equal(one, two) && sbw_preferences_envelope_valid(one));
    sbj *roundtrip = sbw_preferences_decrypt(one, password, &error); CHECK(sbj_equal(roundtrip, plain)); sbj_free(roundtrip);
    CHECK(!sbw_preferences_decrypt(one, "incorrect-password", &error) && !strcmp(error.code, "ARCHIVE_DECRYPT_FAILED"));
    CHECK(!sbw_preferences_encrypt(plain, "short", &error) && !strcmp(error.code, "ARCHIVE_PASSWORD"));
    sbj *bad = sbj_clone(one); sbj_set_int(bad, "iterations", 1); CHECK(!sbw_preferences_envelope_valid(bad)); sbj_free(bad);
    bad = sbj_clone(one); sbj_set_str(bad, "salt", "AAECAwQFBgcICQoLDA0ODw"); CHECK(!sbw_preferences_envelope_valid(bad)); sbj_free(bad);
    bad = sbj_clone(one); sbj_set_bool(bad, "extra", true); CHECK(!sbw_preferences_envelope_valid(bad)); sbj_free(bad);
    bad = sbj_clone(one); char *cipher = sb_strdup(sbj_get_str(bad, "ciphertext", "")); cipher[0] = cipher[0] == 'A' ? 'B' : 'A';
    sbj_set_str(bad, "ciphertext", cipher); free(cipher); CHECK(!sbw_preferences_decrypt(bad, password, &error)); sbj_free(bad);
    sbj *identity = sbw_independent_identity();
    sbj_set_str(identity, "agent_token", "DEVICE_SECRET_MUST_NOT_ROAM");
    sbj_set_bool(identity, "windows_gpt_use_default", true);
    sbj_set(identity, "windows_local_groups", sbj_parse_cstr("[{\"id\":\"custom-device\",\"processes\":[\"private.exe\"]}]"));
    sbj_set(identity, "windows_routing", sbj_parse_cstr("{\"default\":{\"mode\":\"node\",\"node\":\"local-11111111-1111-1111-1111-111111111111/Office\"},\"custom-device\":{\"mode\":\"default\"}}"));
    sbj_set(identity, "local_subscriptions", sbj_parse_cstr("[{\"id\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"Private source\",\"url\":\"https://sub.test/private-token\",\"nodes\":[{\"tag\":\"Office\",\"type\":\"http\",\"server\":\"proxy.test\",\"server_port\":8080,\"password\":\"ENCRYPTED_PROXY_SECRET\"}],\"refresh_interval_minutes\":360,\"last_error\":\"IGNORED_HISTORY\"}]"));
    sbj *payload = sbw_preferences_payload(identity, &error); CHECK(payload);
    CHECK(sbj_string_is(sbj_get(sbj_get(sbj_get(sbj_get(payload, "preferences"), "routing"), "gpt"), "mode"), "default"));
    char *serialized = sbj_dump(payload, -1);
    CHECK(!strstr(serialized, "DEVICE_SECRET") && !strstr(serialized, "private.exe") && !strstr(serialized, "custom-device") && !strstr(serialized, "IGNORED_HISTORY"));
    CHECK(strstr(serialized, "ENCRYPTED_PROXY_SECRET") && strstr(serialized, "private-token")); sbw_secret_free(serialized);
    sbj *destination = sbw_independent_identity(); sbj_set_str(destination, "agent_token", "DESTINATION_DEVICE_SECRET");
    sbj_set(destination, "windows_local_groups", sbj_clone(sbj_get(identity, "windows_local_groups")));
    sbj_set(destination, "windows_routing", sbj_parse_cstr("{\"custom-device\":{\"mode\":\"default\"}}"));
    sbj *merged = sbw_preferences_merge(destination, payload, &error); CHECK(merged);
    CHECK(sbj_string_is(sbj_get(merged, "agent_token"), "DESTINATION_DEVICE_SECRET"));
    CHECK(sbj_equal(sbj_get(merged, "windows_local_groups"), sbj_get(destination, "windows_local_groups")));
    CHECK(sbj_has(sbj_get(merged, "windows_routing"), "custom-device"));
    sbj *preview = sbw_preferences_preview(merged); serialized = sbj_dump(preview, -1);
    CHECK(!strstr(serialized, "SECRET") && !strstr(serialized, "private-token")); free(serialized); sbj_free(preview);
    bad = sbj_clone(payload); sbj_set_str(bad, "platform", "android"); CHECK(!sbw_preferences_merge(destination, bad, &error) && !strcmp(error.code, "ARCHIVE_PLATFORM")); sbj_free(bad);
    bad = sbj_clone(payload); sbj_set_str(sbj_get(bad, "preferences"), "agent_token", "ATTACK"); CHECK(!sbw_preferences_merge(destination, bad, &error)); sbj_free(bad);
    bad = sbj_clone(payload); sbj *node = sbj_arr_at(sbj_get(sbj_arr_at(sbj_get(sbj_get(bad, "preferences"), "local_subscriptions"), 0), "nodes"), 0);
    sbj_set_str(node, "certificate_path", "C:\\private"); CHECK(!sbw_preferences_merge(destination, bad, &error)); sbj_free(bad);
    sbj_free(merged); sbj_free(destination); sbj_free(payload); sbj_free(identity); sbj_free(plain); sbj_free(one); sbj_free(two); sbj_free(vector);
    puts("Preferences: shared Unicode vector, randomized AES-GCM, tamper rejection, strict envelope and device-state exclusions passed."); return 0;
}
