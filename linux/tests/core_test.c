#include "desktop.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x)                                                                     \
    do {                                                                               \
        if (!(x)) {                                                                    \
            fprintf(stderr, "%s:%d: %s (%s)\n", __FILE__, __LINE__, #x, err.msg);      \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)
static sb_err err;
static size_t rule_with(const sbj* rules, const char* key) {
    for (size_t i = 0; i < sbj_arr_len(rules); ++i)
        if (sbj_get(sbj_arr_at(rules, i), key))
            return i;
    return SIZE_MAX;
}
static sbj* sample_profile(int port) {
    sbj* profile = sbl_new_profile("Fixture");
    char* raw =
        sb_asprintf("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"One\",\"server\":"
                    "\"127.0.0.1\",\"server_port\":%d},{\"type\":\"http\",\"tag\":"
                    "\"Two\",\"server\":\"127.0.0.1\",\"server_port\":%d}]}",
                    port, port);
    REQUIRE(sbl_import(profile, "Fixture subscription", "", raw, &err) == 0);
    free(raw);
    return profile;
}
static void unit_contract(void) {
    sbj *state = sbl_new_state(), *profile = sample_profile(12345);
    char* secret = sbl_secret();
    REQUIRE(secret);
    sbj_arr_push(sbj_get(state, "profiles"), profile);
    sbj_set_str(state, "selected_id", sbj_get_str(profile, "id", ""));
    REQUIRE(sbl_validate_state(state, &err) == 0);
    char* config = sbl_build(profile, false, getuid(), 23451, 23452, secret,
                             "/tmp/fixture-cache", &err);
    REQUIRE(config);
    sbj* parsed = sbl_parse(config, SBL_MAX_STATE, &err);
    REQUIRE(sbj_arr_len(sbj_get(parsed, "inbounds")) == 1);
    REQUIRE(sbj_string_is(sbj_get(sbj_arr_at(sbj_get(parsed, "inbounds"), 0), "type"),
                          "mixed"));
    REQUIRE(!strstr(config, "sb-easy-apple"));
    sbj_free(parsed);
    free(config);
    REQUIRE(
        !sbl_build(profile, true, 0, 23451, 23452, secret, "/tmp/fixture-cache", &err));
    REQUIRE(sbl_url("https://example.com/sub?secret=private", false, &err));
    REQUIRE(!sbl_url("https://user:password@example.com/sub", false, &err));
    REQUIRE(!sbl_url("http://example.com/sub", true, &err));
    REQUIRE(sbl_url("http://127.0.0.1:1234/sub", true, &err));
    REQUIRE(!sbl_parse("{\"x\":1,\"x\":2}", 100, &err));
    sbj* managed = sbj_clone(profile);
    sbj_set_str(managed, "mode", "managed");
    sbj_set_str(managed, "server", "https://center.example.com");
    sbj_set_str(managed, "source",
                "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"route\":{"
                "\"final\":\"direct\"},\"dns\":{}}");
    config = sbl_build(managed, false, getuid(), 23451, 23452, secret,
                       "/tmp/fixture-cache", &err);
    REQUIRE(config);
    free(config);
    sbj_set_str(managed, "source",
                "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],"
                "\"route\":{\"final\":\"direct\",\"rules\":[{\"domain\":[\"protected.example\"],"
                "\"outbound\":\"direct\"},{\"ip_cidr\":[\"10.0.0.0/8\"],\"outbound\":\"direct\"}]},"
                "\"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"protected-dns\",\"server\":\"1.1.1.1\"}],"
                "\"rules\":[{\"domain\":[\"protected.example\"],\"server\":\"protected-dns\"}]}}");
    sbj_set(managed, "settings", sbl_parse(
                "{\"local_groups\":[{\"id\":\"work\",\"name\":\"Work\",\"domains\":[\"example.org\"],"
                "\"outbound\":\"direct\"}],\"process_rules\":[{\"process_name\":[\"curl\"],\"outbound\":\"direct\"}]}",
                SBL_MAX_STATE, &err));
    config = sbl_build(managed, true, 1000, 23451, 23452, secret,
                       "/tmp/fixture-cache", &err);
    REQUIRE(config);
    parsed = sbl_parse(config, SBL_MAX_STATE, &err);
    const sbj *route_rules = sbj_get(sbj_get(parsed, "route"), "rules"),
              *dns_rules = sbj_get(sbj_get(parsed, "dns"), "rules"),
              *tun = sbj_arr_at(sbj_get(parsed, "inbounds"), 0);
    REQUIRE(rule_with(route_rules, "domain") < rule_with(route_rules, "process_name"));
    REQUIRE(rule_with(route_rules, "ip_cidr") < rule_with(route_rules, "process_name"));
    REQUIRE(rule_with(dns_rules, "domain") < rule_with(dns_rules, "process_name"));
    REQUIRE(rule_with(dns_rules, "process_name") != SIZE_MAX);
    REQUIRE(!sbj_get_bool(tun, "auto_redirect", true));
    REQUIRE(sbj_get_int(tun, "iproute2_table_index", 0) == 42041);
    REQUIRE(sbj_get_int(tun, "iproute2_rule_index", 0) == 12040);
    REQUIRE(sbj_as_int(sbj_arr_at(sbj_get(tun, "include_uid"), 0), 0) == 1000);
    const sbj* servers = sbj_get(sbj_get(parsed, "dns"), "servers");
    for (size_t i = 0; i < sbj_arr_len(servers); ++i) {
        const sbj* server = sbj_arr_at(servers, i);
        if (sbj_string_is(sbj_get(server, "tag"), "sb-easy-linux-process-0"))
            REQUIRE(!sbj_get(server, "detour"));
    }
    sbj_free(parsed);
    free(config);
    sbj_set_str(managed, "source",
                "{\"outbounds\":[{\"type\":\"ssh\",\"tag\":\"direct\",\"private_key_"
                "path\":\"/etc/shadow\"}],\"route\":{\"final\":\"direct\"}}");
    REQUIRE(!sbl_build(managed, false, getuid(), 23451, 23452, secret,
                       "/tmp/fixture-cache", &err));
    sbj_free(managed);
    char path[] = "/tmp/sb-linux-vault-XXXXXX";
    REQUIRE(mkdtemp(path));
    unsigned char key[32];
    memset(key, 19, sizeof key);
    sbl_vault vault, locked;
    REQUIRE(sbl_vault_open(&vault, path, key, &err) == 0);
    REQUIRE(sbl_vault_open(&locked, path, key, &err) == -1);
    sbj* fresh = sbl_vault_load(&vault, &err);
    REQUIRE(fresh);
    sbj_free(fresh);
    REQUIRE(sbl_vault_save(&vault, state, &err) == 0);
    REQUIRE(sbj_get_int(state, "revision", 0) == 1);
    sbj* copy = sbl_vault_load(&vault, &err);
    REQUIRE(copy);
    char *dump1 = sbj_dump(state, -1), *dump2 = sbj_dump(copy, -1);
    REQUIRE(!strcmp(dump1, dump2));
    free(dump1);
    free(dump2);
    sbj_set_int(copy, "revision", 0);
    REQUIRE(sbl_vault_save(&vault, copy, &err) == -1);
    sbj_free(copy);
    int fd = openat(vault.dirfd, "vault.bin", O_RDWR);
    REQUIRE(fd >= 0);
    unsigned char byte;
    REQUIRE(pread(fd, &byte, 1, 48) == 1);
    byte ^= 1;
    REQUIRE(pwrite(fd, &byte, 1, 48) == 1);
    close(fd);
    REQUIRE(!sbl_vault_load(&vault, &err));
    unlinkat(vault.dirfd, "vault.bin", 0);
    unlinkat(vault.dirfd, "vault.lock", 0);
    sbl_vault_close(&vault);
    rmdir(path);
    sbj_free(state);
    free(secret);
}
static void live_contract(int proxy_port, int target_port) {
    char path[] = "/tmp/sb-linux-runtime-XXXXXX";
    REQUIRE(mkdtemp(path));
    sbl_runtime runtime;
    REQUIRE(sbl_runtime_init(&runtime, path, &err) == 0);
    sbj* profile = sample_profile(proxy_port);
    REQUIRE(sbl_runtime_start(&runtime, profile, false, getuid(), &err) == 0);
    char* url = sb_asprintf("http://127.0.0.1:%d/slow", target_port);
    sbj* probe = sbl_runtime_probe(&runtime, url, &err);
    REQUIRE(probe);
    char* probe_text = sbj_dump(probe, -1);
    puts(probe_text);
    free(probe_text);
    REQUIRE(sbj_get_bool(probe, "success", false));
    REQUIRE(sbj_get_int(probe, "http_status", 0) == 200);
    REQUIRE(sbj_get_bool(probe, "route_observed", false));
    sbj_free(probe);
    sbj* sub = sbj_arr_at(sbj_get(profile, "subscriptions"), 0);
    char* tag = sb_asprintf("local-%s/Two", sbj_get_str(sub, "id", ""));
    sbj* selected = sbl_runtime_select(&runtime, SBL_DEFAULT, tag, &err);
    REQUIRE(selected);
    sbj_free(selected);
    sbj_set_str(sbj_get_or_object(sbj_get(profile, "settings"), "selector_choices"),
                SBL_DEFAULT, tag);
    REQUIRE(sbl_runtime_start(&runtime, profile, false, getuid(), &err) == 0);
    probe = sbl_runtime_probe(&runtime, url, &err);
    REQUIRE(probe);
    REQUIRE(sbj_get_bool(probe, "success", false));
    bool found = false;
    const sbj* chain = sbj_get(probe, "chains");
    for (size_t i = 0; i < sbj_arr_len(chain); ++i)
        if (sbj_string_is(sbj_arr_at(chain, i), tag))
            found = true;
    REQUIRE(found);
    sbj_free(probe);
    sbj* bad = sbj_clone(profile);
    sbj_set_str(sbj_get_or_object(sbj_get(bad, "settings"), "selector_choices"),
                SBL_DEFAULT, "removed-node");
    REQUIRE(sbl_runtime_start(&runtime, bad, false, getuid(), &err) == -1);
    sbj_free(bad);
    probe = sbl_runtime_probe(&runtime, url, &err);
    REQUIRE(probe);
    REQUIRE(sbj_get_bool(probe, "success", false));
    sbj_free(probe);
    char *sub_url =
             sb_asprintf("http://127.0.0.1:%d/invalid-subscription", target_port),
         *old_nodes = sbj_dump(sbj_get(sub, "nodes"), -1);
    sbj_set_str(sub, "url", sub_url);
    REQUIRE(sbl_refresh_subscription(profile, sbj_get_str(sub, "id", ""), &err) == -1);
    char* nodes = sbj_dump(sbj_get(sub, "nodes"), -1);
    REQUIRE(!strcmp(nodes, old_nodes));
    free(nodes);
    free(old_nodes);
    free(sub_url);
    sbl_runtime_stop(&runtime);
    REQUIRE(access(runtime.path, F_OK) != 0);
    sbl_runtime_clear(&runtime);
    GDir* dir = g_dir_open(path, 0, NULL);
    const char* entry;
    while ((entry = g_dir_read_name(dir))) {
        char* file = g_build_filename(path, entry, NULL);
        unlink(file);
        g_free(file);
    }
    g_dir_close(dir);
    rmdir(path);
    free(tag);
    free(url);
    sbj_free(profile);
}
int main(int argc, char** argv) {
    umask(0077);
    unit_contract();
    if (argc == 3)
        live_contract(atoi(argv[1]), atoi(argv[2]));
    puts("Linux desktop contracts passed");
    return 0;
}
