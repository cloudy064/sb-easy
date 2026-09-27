/* Port of cpp/tests/wireguard_test.cpp plus golden checks. Every expected
 * config text, JSON dump, command log and error message below was produced by
 * the C++ implementation (cpp/src/wireguard.cpp) for the same fixture, so these
 * tests pin byte-for-byte parity. "@DIR@" stands for the fixture directory.
 *
 * Safety: the real wg / ip / iptables / sysctl are never reachable. PATH points
 * at a nonexistent directory from process start, and each fixture replaces it
 * with only its own directory of fake tools (shell builtins only), which log
 * their argv and exit as the FAKE_* environment variables say. */
#include "test.h"

#include <ftw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sb/database.h"
#include "sb/json.h"
#include "sb/store.h"
#include "sb/util.h"
#include "sb/wireguard.h"

/* ---- fixed key material (standard base64 of raw 32-byte keys) ---------- */

#define SERVER_PRIV "JTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBciLThDTllkb3o="
#define SERVER_PUB "nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo="
#define P1_PRIV "SlVga3aBjJeirbjDztnk7/oFEBsmMTxHUl1oc36JlJ8="
#define P2_PRIV "b3qFkJumsbzH0t3o8/4JFB8qNUBLVmFsd4KNmKOuucQ="
#define P3_PRIV "lJ+qtcDL1uHs9wINGCMuOURPWmVwe4aRnKeyvcjT3uk="
#define P4_PRIV "ucTP2uXw+wYRHCcyPUhTXml0f4qVoKu2wczX4u34Aw4="
#define P5_PRIV "3un0/woVICs2QUxXYm14g46ZpK+6xdDb5vH8BxIdKDM="
#define P6_PRIV "Aw4ZJC86RVBbZnF8h5KdqLO+ydTf6vUACxYhLDdCTVg="
#define P7_PRIV "KDM+SVRfanWAi5ahrLfCzdjj7vkEDxolMDtGUVxncn0="
#define P10_PRIV "l6KtuMPO2eTv+gUQGyYxPEdSXWhzfomUn6q1wMvW4ew="
#define P11_PRIV "vMfS3ejz/gkUHyo1QEtWYWx3go2Yo665xM/a5fD7BhE="
#define P12_PRIV "4ez3Ag0YIy45RE9aZXB7hpGcp7K9yNPe6fT/ChUgKzY="
#define P13_PRIV "BhEcJzI9SFNeaXR/ipWgq7bBzNfi7fgDDhkkLzpFUFs="
#define P1_PUB "dYCLlqGst8LN2OPu+QQPGiUwO0ZRXGdyfYiTnqm0v8o="
#define P2_PUB "mqWwu8bR3Ofy/QgTHik0P0pVYGt2gYyXoq24w87Z5O8="
#define P3_PUB "v8rV4Ov2AQwXIi04Q05ZZG96hZCbprG8x9Ld6PP+CRQ="
#define P4_PUB "5O/6BRAbJjE8R1JdaHN+iZSfqrXAy9bh7PcCDRgjLjk="
#define P5_PUB "CRQfKjVAS1ZhbHeCjZijrrnEz9rl8PsGERwnMj1IU14="
#define P6_PUB "LjlET1plcHuGkZynsr3I097p9P8KFSArNkFMV2JteIM="
#define P7_PUB "U15pdH+KlaCrtsHM1+Lt+AMOGSQvOkVQW2ZxfIeSnag="
#define P10_PUB "ws3Y4+75BA8aJTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBc="
#define P11_PUB "5/L9CBMeKTQ/SlVga3aBjJeirbjDztnk7/oFEBsmMTw="
#define P12_PUB "DBciLThDTllkb3qFkJumsbzH0t3o8/4JFB8qNUBLVmE="
#define P13_PUB "MTxHUl1oc36JlJ+qtcDL1uHs9wINGCMuOURPWmVwe4Y="
#define P1_PSK "oKu2wczX4u34Aw4ZJC86RVBbZnF8h5KdqLO+ydTf6vU="
#define P3_PSK "6vUACxYhLDdCTVhjbnmEj5qlsLvG0dzn8v0IEx4pND8="
#define P4_PSK "DxolMDtGUVxncn2Ik56ptL/K1eDr9gEMFyItOENOWWQ="
#define P5_PSK "ND9KVWBrdoGMl6KtuMPO2eTv+gUQGyYxPEdSXWhzfok="
#define P7_PSK "fomUn6q1wMvW4ez3Ag0YIy45RE9aZXB7hpGcp7K9yNM="
#define P10_PSK "7fgDDhkkLzpFUFtmcXyHkp2os77J1N/q9QALFiEsN0I="
#define P12_PSK "N0JNWGNueYSPmqWwu8bR3Ofy/QgTHik0P0pVYGt2gYw="
#define P13_PSK "XGdyfYiTnqm0v8rV4Ov2AQwXIi04Q05ZZG96hZCbprE="
#define H1_PUB "y9bh7PcCDRgjLjlET1plcHuGkZynsr3I097p9P8KFSA="
#define H2_PUB "8PsGERwnMj1IU15pdH+KlaCrtsHM1+Lt+AMOGSQvOkU="
/* RFC 7748 section 6.1 (Alice). */
#define ALICE_PRIV "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
#define ALICE_PUB "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="

#define TYPE_ERROR_STRING_NUMBER "[json.exception.type_error.302] type must be string, but is number"

/* ---- fixture ------------------------------------------------------------ */

__attribute__((constructor)) static void isolate_path(void) {
    setenv("PATH", "/nonexistent/sb-easy-wireguard-test", 1);
}

#define LOG_ARGV                                                                          \
    "{ printf '%s' \"${0##*/}\"; for a in \"$@\"; do printf '|%s' \"$a\"; done; "         \
    "printf '\\n'; } >> \"$FAKE_LOG\"\n"

static const char FAKE_WG[] = "#!/bin/sh\n" LOG_ARGV
                              "case \"$1\" in\n"
                              "  show) printf '%s' \"$FAKE_WG_DUMP\"; exit \"${FAKE_WG_SHOW_EXIT:-0}\";;\n"
                              "  syncconf) printf '%s' \"$FAKE_WG_SYNC_OUTPUT\"; "
                              "exit \"${FAKE_WG_SYNC_EXIT:-0}\";;\n"
                              "esac\n"
                              "exit 0\n";
static const char FAKE_IP[] = "#!/bin/sh\n" LOG_ARGV
                              "case \"$1 $2\" in\n"
                              "  'link show') exit \"${FAKE_IP_LINK_SHOW_EXIT:-1}\";;\n"
                              "esac\n"
                              "exit 0\n";
static const char FAKE_IPTABLES[] = "#!/bin/sh\n" LOG_ARGV
                                    "case \"$1\" in -C) exit \"${FAKE_IPT_CHECK_EXIT:-1}\";; esac\n"
                                    "case \"$3\" in -C) exit \"${FAKE_IPT_CHECK_EXIT:-1}\";; esac\n"
                                    "exit 0\n";
static const char FAKE_SYSCTL[] = "#!/bin/sh\n" LOG_ARGV "exit 0\n";

static const char *const FAKE_ENV[] = {"FAKE_WG_DUMP",        "FAKE_WG_SHOW_EXIT",
                                       "FAKE_WG_SYNC_EXIT",   "FAKE_WG_SYNC_OUTPUT",
                                       "FAKE_IP_LINK_SHOW_EXIT", "FAKE_IPT_CHECK_EXIT",
                                       "FAKE_LOG"};

typedef struct {
    char *dir;      /* mkdtemp root, removed by fixture_close */
    char *bin;      /* fake tools: the only PATH entry */
    char *log;      /* argv log appended to by the fake tools */
    sb_store *store;
} fixture;

static void write_tool(const fixture *f, const char *name, const char *script) {
    char *path = sb_path_join(f->bin, name);
    if (sb_write_file(path, script, strlen(script)) != 0 || chmod(path, 0755) != 0) abort();
    free(path);
}

static void remove_tool(const fixture *f, const char *name) {
    char *path = sb_path_join(f->bin, name);
    unlink(path);
    free(path);
}

static int remove_entry(const char *path, const struct stat *info, int flag, struct FTW *walk) {
    (void)info;
    (void)flag;
    (void)walk;
    return remove(path);
}

static void clear_fake_env(void) {
    for (size_t i = 0; i < sizeof FAKE_ENV / sizeof FAKE_ENV[0]; ++i) unsetenv(FAKE_ENV[i]);
}

static bool fixture_open(fixture *f) {
    memset(f, 0, sizeof *f);
    clear_fake_env();
    char pattern[] = "/tmp/sb-easy-wireguard-XXXXXX";
    if (!mkdtemp(pattern)) return false;
    f->dir = sb_strdup(pattern);
    f->bin = sb_path_join(f->dir, "bin");
    f->log = sb_path_join(f->dir, "commands.log");
    if (sb_mkdirs(f->bin, 0755) != 0) return false;
    write_tool(f, "wg", FAKE_WG);
    write_tool(f, "ip", FAKE_IP);
    write_tool(f, "iptables", FAKE_IPTABLES);
    write_tool(f, "sysctl", FAKE_SYSCTL);
    setenv("PATH", f->bin, 1);
    setenv("FAKE_LOG", f->log, 1);
    if (sb_write_file(f->log, "", 0) != 0) return false;
    char *database = sb_path_join(f->dir, "store.db");
    sb_err err = {0};
    f->store = sb_store_open(database, sb_getenv_or("SB_EASY_MIGRATIONS", "migrations"), &err);
    free(database);
    if (!f->store) fprintf(stderr, "  store: %s\n", err.msg);
    return f->store != NULL;
}

static void fixture_close(fixture *f) {
    sb_store_free(f->store);
    if (f->dir) nftw(f->dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
    setenv("PATH", "/nonexistent/sb-easy-wireguard-test", 1);
    clear_fake_env();
    free(f->dir);
    free(f->bin);
    free(f->log);
    memset(f, 0, sizeof *f);
}

static char *replace_all(const char *text, const char *from, const char *to) {
    sb_buf out = {0};
    size_t n = strlen(from);
    const char *p = text;
    for (;;) {
        const char *hit = n ? strstr(p, from) : NULL;
        if (!hit) {
            sb_buf_puts(&out, p);
            break;
        }
        sb_buf_append(&out, p, (size_t)(hit - p));
        sb_buf_puts(&out, to);
        p = hit + n;
    }
    return sb_buf_detach(&out);
}

/* Returns (and clears) the fake tools' argv log, fixture dir as "@DIR@". */
static char *take_log(const fixture *f) {
    char *text = sb_read_file(f->log, NULL);
    if (sb_write_file(f->log, "", 0) != 0) abort();
    char *out = replace_all(text ? text : "", f->dir, "@DIR@");
    free(text);
    return out;
}

static void discard_log(const fixture *f) { free(take_log(f)); }

#define CHECK_LOG(f, expected)                                                               \
    do {                                                                                     \
        char *_log = take_log(f);                                                            \
        CHECK_STR(_log, expected);                                                           \
        free(_log);                                                                          \
    } while (0)

/* Checks a malloc'd result against expected and frees it. */
#define CHECK_TAKE_STR(expr, expected)                                                       \
    do {                                                                                     \
        char *_got = (expr);                                                                 \
        CHECK_STR(_got, expected);                                                           \
        free(_got);                                                                          \
    } while (0)

#define CHECK_ERR(err, kind, message)                                                        \
    do {                                                                                     \
        CHECK_EQ_INT((err).code, (kind));                                                    \
        CHECK_STR((err).msg, message);                                                       \
    } while (0)

static void set_setting(sb_store *store, const char *key, const char *json_text) {
    sbj *value = sbj_parse_cstr(json_text);
    sb_err err = {0};
    if (!value || sb_store_set_app_setting(store, key, value, &err) != 0) {
        fprintf(stderr, "set_app_setting(%s): %s\n", key, err.msg);
        abort();
    }
    sbj_free(value);
}

static void peer_make(sb_wireguard_peer *p, const char *id, const char *name, const char *private_key,
                      const char *public_key, const char *preshared_key, const char *address) {
    sb_wireguard_peer_init(p);
    sb_str_set(&p->id, id);
    sb_str_set(&p->name, name);
    p->name_len = strlen(p->name);
    sb_str_set(&p->private_key, private_key);
    sb_str_set(&p->public_key, public_key);
    p->preshared_key = sb_strdup(preshared_key);
    sb_str_set(&p->address, address);
}

/* Creates the peer and releases *p. */
static void peer_create(sb_store *store, sb_wireguard_peer *p) {
    sb_wireguard_peer created;
    sb_wireguard_peer_init(&created);
    sb_err err = {0};
    if (sb_store_create_wireguard_peer(store, p, &created, &err) != 0) {
        fprintf(stderr, "create_wireguard_peer: %s\n", err.msg);
        abort();
    }
    sb_wireguard_peer_free(&created);
    sb_wireguard_peer_free(p);
}

static bool find_peer(sb_store *store, const char *id, sb_wireguard_peer *out) {
    sb_err err = {0};
    return sb_store_find_wireguard_peer(store, id, out, &err) == 1;
}

static size_t peer_count(sb_store *store) {
    sb_wireguard_peer_vec peers = {0};
    sb_err err = {0};
    if (sb_store_list_wireguard_peers(store, &peers, &err) != 0) abort();
    size_t count = peers.len;
    sb_wireguard_peer_vec_free(&peers);
    return count;
}

/* The C++ fixtures' WireGuardOptions{wg-opt, 1111, 10.1.0.1/24, ...}. */
static void base_options(sb_wireguard_options *o, const char *config_directory) {
    sb_wireguard_options_init(o);
    sb_str_set(&o->interface, "wg-opt");
    o->port = 1111;
    sb_str_set(&o->address, "10.1.0.1/24");
    sb_str_set(&o->dns, "10.1.0.1");
    o->mtu = 1000;
    sb_str_set(&o->external_hostname, "vpn.example.com");
    sb_str_set(&o->egress_interface, "eth9");
    sb_str_set(&o->config_directory, config_directory);
}

static sb_wireguard *service_new(const fixture *f, bool enabled, const char *config_subdir) {
    char *directory = config_subdir ? sb_path_join(f->dir, config_subdir) : sb_strdup(f->dir);
    sb_wireguard_options options;
    base_options(&options, directory);
    options.enabled = enabled;
    sb_wireguard *wg = sb_wireguard_new(f->store, &options);
    sb_wireguard_options_free(&options);
    free(directory);
    return wg;
}

static char *dump_json(const sbj *value) { return sbj_dump(value, -1); }

static char *sha256_hex(const char *text) { return sb_sha256_hex(text, strlen(text)); }

static char *repeat(char c, size_t n) {
    char *text = sb_xmalloc(n + 1);
    memset(text, c, n);
    text[n] = '\0';
    return text;
}

static const char kSettings[] =
    "{\"interface\":\"wgt\",\"listen_port\":51999,\"address\":\"10.60.0.1/24\","
    "\"dns\":\"10.60.0.1\",\"mtu\":1380}";

/* ======================================================================
 * Ported from cpp/tests/wireguard_test.cpp
 * ====================================================================== */

TEST(keys_configs_stats_and_peer_repository_are_compatible) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    sb_wireguard_keypair keys;
    REQUIRE(sb_wireguard_generate_keypair(&keys, &err) == 0);
    char *derived = sb_wireguard_public_key_from_private(keys.private_key, &err);
    /* X25519 WireGuard public keys must derive from the persisted private key */
    CHECK(strlen(keys.private_key) == 44U && strlen(keys.public_key) == 44U);
    CHECK_STR(derived, keys.public_key);
    free(derived);

    sb_wireguard_peer peer, stored;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&stored);
    sb_str_set(&peer.name, "Phone client");
    peer.name_len = strlen(peer.name);
    sb_str_set(&peer.private_key, keys.private_key);
    sb_str_set(&peer.public_key, keys.public_key);
    peer.preshared_key = sb_wireguard_generate_preshared_key(&err);
    REQUIRE(peer.preshared_key);
    free(peer.address);
    peer.address = sb_store_next_wireguard_address(f.store, "10.59.32.1/24", &err);
    REQUIRE(peer.address);
    sb_str_set(&peer.dns, "10.59.32.1");
    peer.enabled = true;
    peer.persistent_keepalive = 25;
    sb_str_set(&peer.allowed_ips, "0.0.0.0/0, ::/0");
    peer.notes = sb_strdup("fixture");
    peer.notes_len = strlen(peer.notes);
    REQUIRE(sb_store_create_wireguard_peer(f.store, &peer, &stored, &err) == 0);
    /* peer allocation should skip addresses already used in the /24 */
    CHECK_STR(stored.address, "10.59.32.2/24");
    CHECK_TAKE_STR(sb_store_next_wireguard_address(f.store, "10.59.32.1/24", &err), "10.59.32.3/24");

    sb_wireguard_options options;
    sb_wireguard_options_init(&options);
    options.enabled = false;
    sb_str_set(&options.interface, "wg-test");
    options.port = 51820;
    sb_str_set(&options.address, "10.59.32.1/24");
    sb_str_set(&options.dns, "10.59.32.1");
    options.mtu = 1380;
    sb_str_set(&options.external_hostname, "vpn.example.com");
    sb_str_set(&options.config_directory, f.dir);
    sb_wireguard *service = sb_wireguard_new(f.store, &options);
    sb_wireguard_options_free(&options);

    /* client configs should contain peer credentials and runtime endpoint */
    char *client = sb_wireguard_client_config(service, &stored, &err);
    REQUIRE(client);
    char *expected_key = sb_asprintf("PrivateKey = %s", keys.private_key);
    CHECK_CONTAINS(client, expected_key);
    CHECK_CONTAINS(client, "Endpoint = vpn.example.com:51820");
    CHECK_CONTAINS(client, "MTU = 1420");
    free(expected_key);
    free(client);

    /* WireGuard QR responses should be real SVG matrices */
    char *qr = sb_wireguard_qr_svg(service, &stored, &err);
    REQUIRE(qr);
    CHECK(sb_starts_with(qr, "<?xml"));
    CHECK_CONTAINS(qr, "<svg");
    CHECK_CONTAINS(qr, "<path");
    free(qr);

    /* server configs should include peers and persist the server keypair */
    char *server = sb_wireguard_server_config(service, &err);
    REQUIRE(server);
    char *expected_peer = sb_asprintf("PublicKey = %s", keys.public_key);
    CHECK_CONTAINS(server, expected_peer);
    free(expected_peer);
    free(server);
    sb_wireguard_options defaults;
    sb_wireguard_options_init(&defaults);
    sb_wireguard *other = sb_wireguard_new(f.store, &defaults);
    sb_wireguard_options_free(&defaults);
    char *first = sb_wireguard_server_public_key(service, &err);
    char *second = sb_wireguard_server_public_key(other, &err);
    CHECK_STR(first, second);
    free(first);
    free(second);
    sb_wireguard_free(other);

    /* WireGuard peer updates should round-trip */
    stored.enabled = false;
    sb_str_set(&stored.notes, "updated");
    stored.notes_len = strlen(stored.notes);
    sb_wireguard_peer updated;
    sb_wireguard_peer_init(&updated);
    REQUIRE(sb_store_update_wireguard_peer(f.store, &stored, &updated, &err) == 0);
    CHECK(!updated.enabled);
    CHECK_STR(updated.notes, "updated");
    /* WireGuard enable toggles should persist */
    REQUIRE(sb_store_set_wireguard_peer_enabled(f.store, updated.id, true, &err) == 0);
    sb_wireguard_peer found;
    sb_wireguard_peer_init(&found);
    CHECK(find_peer(f.store, updated.id, &found) && found.enabled);
    sb_wireguard_peer_free(&found);

    /* wg dump parser should expose peer endpoint, handshake, and counters */
    sb_wireguard_peer_stats_vec stats = {0};
    REQUIRE(sb_wireguard_parse_stats("server-private\tserver-public\t51820\toff\n"
                                     "peer-public\tpsk\t198.51.100.1:1234\t10.0.0.2/32\t"
                                     "1700000000\t123\t456\t25\n",
                                     &stats, &err) == 0);
    REQUIRE(stats.len == 1U);
    CHECK_STR(stats.items[0].public_key, "peer-public");
    CHECK_STR(stats.items[0].endpoint, "198.51.100.1:1234");
    CHECK(stats.items[0].has_latest_handshake && stats.items[0].latest_handshake == 1700000000);
    CHECK_EQ_INT(stats.items[0].transfer_rx, 123);
    CHECK_EQ_INT(stats.items[0].transfer_tx, 456);
    sb_wireguard_peer_stats_vec_free(&stats);

    /* WireGuard peer deletion should persist */
    REQUIRE(sb_store_delete_wireguard_peer(f.store, updated.id, &err) == 0);
    CHECK_EQ_INT(peer_count(f.store), 0);

    sb_wireguard_peer_free(&updated);
    sb_wireguard_peer_free(&stored);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_keypair_free(&keys);
    sb_wireguard_free(service);
    fixture_close(&f);
}

TEST(nul_names_match_exact_peers_and_export_complete_configs) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    sb_wireguard *service = service_new(&f, false, NULL);
    REQUIRE(service);
    sb_wireguard_peer peer;
    peer_make(&peer, "prefix", "Phone", P1_PRIV, P1_PUB, NULL, "10.1.0.2/32");
    peer_create(f.store, &peer);
    peer_make(&peer, "exact", "Phone", P2_PRIV, P2_PUB, NULL, "10.1.0.3/32");
    sb_str_setn(&peer.name, "Phone\0client", 12);
    peer.name_len = 12;
    peer_create(f.store, &peer);

    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_setn(&host.name, "Phone\0client", 12);
    host.name_len = 12;
    REQUIRE(sb_store_create_host(f.store, &host, &created, &err) == 0);
    REQUIRE(sb_wireguard_provision_host(service, &created, false, &created, &err) == 0);
    CHECK_STR(created.wg_public_key, P2_PUB);
    CHECK_EQ_INT(created.name_len, 12);
    CHECK(memcmp(created.name, "Phone\0client", 12) == 0);
    sb_wireguard_peer_init(&peer);
    REQUIRE(find_peer(f.store, "prefix", &peer));
    CHECK(peer.host_id == NULL);
    REQUIRE(find_peer(f.store, "exact", &peer));
    CHECK_STR(peer.host_id, created.id);
    size_t len = 0;
    char *config = sb_wireguard_client_config_n(service, &peer, &len, &err);
    REQUIRE(config);
    const char client_prefix[] = "# Client: Phone\0client\n[Interface]\n";
    CHECK(len >= sizeof client_prefix - 1);
    CHECK(memcmp(config, client_prefix, sizeof client_prefix - 1) == 0);
    CHECK_CONTAINS(config + strlen(config) + 1, "PrivateKey = ");
    free(config);
    config = sb_wireguard_host_config_n(service, &created, &len, &err);
    REQUIRE(config);
    const char host_prefix[] = "# sb-easy managed host: Phone\0client\n[Interface]\n";
    CHECK(len >= sizeof host_prefix - 1);
    CHECK(memcmp(config, host_prefix, sizeof host_prefix - 1) == 0);
    CHECK_CONTAINS(config + strlen(config) + 1, "# Hub (central server)");
    free(config);
    config = sb_wireguard_server_config_n(service, &len, &err);
    REQUIRE(config);
    CHECK(len > strlen(config));
    CHECK_CONTAINS(config + strlen(config) + 1, "PublicKey = " P2_PUB);
    free(config);
    sb_wireguard_peer_free(&peer);
    sb_host_free(&created);

    /* A third full name must allocate a new peer, not take the prefix peer. */
    sb_str_setn(&host.name, "Phone\0other", 11);
    host.name_len = 11;
    REQUIRE(sb_store_create_host(f.store, &host, &created, &err) == 0);
    REQUIRE(sb_wireguard_provision_host(service, &created, false, &created, &err) == 0);
    CHECK_EQ_INT(peer_count(f.store), 3);
    REQUIRE(find_peer(f.store, "prefix", &peer));
    CHECK(peer.host_id == NULL);
    sb_wireguard_peer_vec all = {0};
    REQUIRE(sb_store_list_wireguard_peers(f.store, &all, &err) == 0);
    size_t named = 0;
    for (size_t i = 0; i < all.len; ++i) {
        if (sb_streq(all.items[i].host_id, created.id)) {
            ++named;
            CHECK_EQ_INT(all.items[i].name_len, 17);
            CHECK(memcmp(all.items[i].name, "host: Phone\0other", 17) == 0);
        }
    }
    CHECK_EQ_INT(named, 1);
    sb_wireguard_peer_vec_free(&all);
    /* The fake-tool sync must write every byte, including after both NULs. */
    sb_wireguard *enabled = service_new(&f, true, "names");
    REQUIRE(enabled);
    config = sb_wireguard_server_config_n(enabled, &len, &err);
    REQUIRE(config);
    REQUIRE(sb_wireguard_sync(enabled, &err) == 0);
    char *file = sb_path_join(f.dir, "names/wg0.conf");
    size_t written_len = 0;
    char *written = sb_read_file(file, &written_len);
    REQUIRE(written);
    CHECK_EQ_INT(written_len, len);
    CHECK(written_len == len && memcmp(written, config, len) == 0);
    free(written);
    free(file);
    free(config);
    sb_wireguard_free(enabled);
    sb_wireguard_peer_free(&peer);
    sb_host_free(&created);
    sb_host_free(&host);
    sb_wireguard_free(service);
    fixture_close(&f);
}

TEST(managed_devices_reuse_standalone_peers_as_singbox_endpoints) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    sb_host host, created;
    sb_host_init(&host);
    sb_host_init(&created);
    sb_str_set(&host.name, "Phone client");
    host.name_len = strlen(host.name);
    sbj_free(host.capabilities);
    host.capabilities = sbj_parse_cstr("{\"platform\":\"android\",\"runs_singbox\":true}");
    REQUIRE(sb_store_create_host(f.store, &host, &created, &err) == 0);

    sb_wireguard_keypair keys;
    REQUIRE(sb_wireguard_generate_keypair(&keys, &err) == 0);
    sb_wireguard_peer peer, stored;
    sb_wireguard_peer_init(&stored);
    peer_make(&peer, "", created.name, keys.private_key, keys.public_key, NULL, "10.59.32.4/24");
    free(peer.preshared_key);
    peer.preshared_key = sb_wireguard_generate_preshared_key(&err);
    REQUIRE(sb_store_create_wireguard_peer(f.store, &peer, &stored, &err) == 0);

    sb_wireguard_options options;
    sb_wireguard_options_init(&options);
    options.enabled = false;
    options.port = 51820;
    sb_str_set(&options.address, "10.59.32.1/24");
    options.mtu = 1420;
    sb_str_set(&options.external_hostname, "vpn.example.com");
    sb_str_set(&options.config_directory, f.dir);
    sb_wireguard *service = sb_wireguard_new(f.store, &options);
    sb_wireguard_options_free(&options);

    /* host = service.provision_host(std::move(host), false) (in/out aliased) */
    REQUIRE(sb_wireguard_provision_host(service, &created, false, &created, &err) == 0);
    sb_wireguard_peer_vec peers = {0};
    REQUIRE(sb_store_list_wireguard_peers(f.store, &peers, &err) == 0);
    /* unified enrollment should link the existing peer without changing keys */
    REQUIRE(peers.len == 1U);
    CHECK_STR(peers.items[0].id, stored.id);
    CHECK_STR(peers.items[0].host_id, created.id);
    CHECK_STR(peers.items[0].allowed_ips, "10.59.32.0/24");
    CHECK_STR(peers.items[0].public_key, keys.public_key);
    CHECK_STR(created.wg_address, "10.59.32.4/24");
    CHECK_STR(created.wg_public_key, keys.public_key);
    CHECK(created.clash_api == NULL);

    /* sing-box endpoint should carry the linked peer and intranet route */
    sbj *endpoint = NULL;
    REQUIRE(sb_wireguard_client_endpoint(service, &created, &endpoint, &err) == 1);
    CHECK_STR(sbj_get_str(endpoint, "type", NULL), "wireguard");
    CHECK_TAKE_STR(dump_json(sbj_get(endpoint, "address")), "[\"10.59.32.4/24\"]");
    const sbj *remote = sbj_arr_at(sbj_get(endpoint, "peers"), 0);
    CHECK_STR(sbj_get_str(remote, "address", NULL), "vpn.example.com");
    CHECK_TAKE_STR(dump_json(sbj_get(remote, "allowed_ips")), "[\"10.59.32.0/24\"]");
    sbj_free(endpoint);

    sb_wireguard_peer_vec_free(&peers);
    sb_wireguard_peer_free(&stored);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_keypair_free(&keys);
    sb_host_free(&created);
    sb_host_free(&host);
    sb_wireguard_free(service);
    fixture_close(&f);
}

/* ======================================================================
 * Keys, parsers and options
 * ====================================================================== */

TEST(public_keys_derive_like_cpp_and_invalid_keys_are_rejected) {
    sb_err err = {0};
    CHECK_TAKE_STR(sb_wireguard_public_key_from_private(ALICE_PRIV, &err), ALICE_PUB);
    CHECK_TAKE_STR(sb_wireguard_public_key_from_private(SERVER_PRIV, &err), SERVER_PUB);
    CHECK_TAKE_STR(
        sb_wireguard_public_key_from_private("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &err),
        "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=");
    /* EVP_DecodeBlock quirks: "==" padding still yields 33 bytes. */
    CHECK_TAKE_STR(
        sb_wireguard_public_key_from_private("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", &err),
        "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=");

    static const struct {
        const char *key;
        const char *message;
    } invalid[] = {
        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Invalid WireGuard key"},
        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "WireGuard key must encode 32 bytes"},
        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "WireGuard key must encode 32 bytes"},
        {"", "WireGuard key must encode 32 bytes"},
        {" AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "Invalid WireGuard key"},
        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-A=", "Invalid WireGuard key"},
        {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", "Invalid WireGuard key"},
        {"short", "WireGuard key must encode 32 bytes"},
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        sb_err_clear(&err);
        char *result = sb_wireguard_public_key_from_private(invalid[i].key, &err);
        CHECK(result == NULL);
        free(result);
        CHECK_ERR(err, SB_ERR_VALIDATION, invalid[i].message);
    }
    sb_err_clear(&err);
    CHECK(sb_wireguard_public_key_from_private(NULL, &err) == NULL);
    CHECK_ERR(err, SB_ERR_VALIDATION, "WireGuard key must encode 32 bytes");

    sb_wireguard_keypair first, second;
    REQUIRE(sb_wireguard_generate_keypair(&first, &err) == 0);
    REQUIRE(sb_wireguard_generate_keypair(&second, &err) == 0);
    CHECK(strcmp(first.private_key, second.private_key) != 0);
    CHECK_TAKE_STR(sb_wireguard_public_key_from_private(second.private_key, &err), second.public_key);
    char *psk = sb_wireguard_generate_preshared_key(&err);
    REQUIRE(psk);
    size_t decoded_len = 0;
    unsigned char *decoded = sb_base64_decode_strict(psk, strlen(psk), &decoded_len);
    CHECK(strlen(psk) == 44U && decoded && decoded_len == 32U);
    free(decoded);
    free(psk);
    sb_wireguard_keypair_free(&first);
    sb_wireguard_keypair_free(&second);
}

TEST(parse_stats_reads_wg_dump_like_cpp) {
    static const struct {
        const char *dump;
        const char *json;
    } cases[] = {
        {"priv\tpub\t51820\toff\n"
         "k1\tpsk\t(none)\t10.0.0.2/32\t0\t0\t0\toff\n"
         "k2\t(none)\t\t10.0.0.3/32\t-5\t-7\t-9\t25\n"
         "k3\tpsk\t[2001:db8::1]:51820\t10.0.0.4/32\t1700000000\t123abc\t99999999999999999999\t25\n",
         "[{\"endpoint\":null,\"latest_handshake\":null,\"public_key\":\"k1\",\"transfer_rx\":0,"
         "\"transfer_tx\":0},{\"endpoint\":null,\"latest_handshake\":null,\"public_key\":\"k2\","
         "\"transfer_rx\":-7,\"transfer_tx\":-9},{\"endpoint\":\"[2001:db8::1]:51820\","
         "\"latest_handshake\":1700000000,\"public_key\":\"k3\",\"transfer_rx\":123,"
         "\"transfer_tx\":0}]"},
        {"k4\ta\tb\tc\t+5\t 5\t-9223372036854775808\td\te\tf\n"
         "\n"
         "short\tline\n"
         "k5\tp\te:1\ta\t9223372036854775807\t-9223372036854775809\t0x10\toff\r\n"
         "k6\tp\te\ta\t1\t2\t3",
         "[{\"endpoint\":\"b\",\"latest_handshake\":null,\"public_key\":\"k4\",\"transfer_rx\":0,"
         "\"transfer_tx\":-9223372036854775808},{\"endpoint\":\"e:1\",\"latest_handshake\":"
         "9223372036854775807,\"public_key\":\"k5\",\"transfer_rx\":0,\"transfer_tx\":0}]"},
        {"", "[]"},
        {"\n\n\n", "[]"},
        {"\t\t\t\t\t\t\t",
         "[{\"endpoint\":null,\"latest_handshake\":null,\"public_key\":\"\",\"transfer_rx\":0,"
         "\"transfer_tx\":0}]"},
        {"k7\tp\t(none) \ta\t-\t--1\t-0\t\t\n"
         "k8\tp\t(NONE)\ta\t00012\t1e5\t12.5\t1\n"
         "k9\tp\t(none)\ta\t1700000000\t1\t2\t3",
         "[{\"endpoint\":\"(none) \",\"latest_handshake\":null,\"public_key\":\"k7\","
         "\"transfer_rx\":0,\"transfer_tx\":0},{\"endpoint\":\"(NONE)\",\"latest_handshake\":12,"
         "\"public_key\":\"k8\",\"transfer_rx\":1,\"transfer_tx\":12},{\"endpoint\":null,"
         "\"latest_handshake\":1700000000,\"public_key\":\"k9\",\"transfer_rx\":1,"
         "\"transfer_tx\":2}]"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        sb_err err = {0};
        sb_wireguard_peer_stats_vec stats = {0};
        CHECK(sb_wireguard_parse_stats(cases[i].dump, &stats, &err) == 0);
        sbj *json = sb_wireguard_peer_stats_vec_to_json(&stats);
        CHECK_TAKE_STR(dump_json(json), cases[i].json);
        sbj_free(json);
        sb_wireguard_peer_stats_vec_free(&stats);
    }
}

static char *utc_text(time_t t, const char *suffix) {
    char text[32];
    struct tm parts;
    gmtime_r(&t, &parts);
    strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%S", &parts);
    return sb_asprintf("%s%s", text, suffix);
}

static bool expired(const char *expire_at) {
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    peer.expire_at = sb_strdup(expire_at);
    bool result = sb_wireguard_peer_expired(&peer);
    sb_wireguard_peer_free(&peer);
    return result;
}

TEST(peer_expiry_parses_timestamps_like_cpp) {
    static const struct {
        const char *expire_at;
        bool expired;
    } cases[] = {
        {"", false},
        {"2000-01-01T00:00:00Z", true},
        {"2000-01-01T00:00:00", true},
        {"2099-01-01T00:00:00Z", false},
        {"2099-01-01T00:00:00+02:00", false},
        {"garbage", false},
        {"2000-13-01T00:00:00Z", false},
        {"2000-02-30T00:00:00Z", true},
        {"2000-01-01t00:00:00Z", true},             /* literals compare case-insensitively */
        {"  2000-01-01T00:00:00Z", false},          /* only 19 characters are parsed */
        {"               2025abc", true},           /* input ending after %Y is not a failure */
        {"2000-01-01 00:00:00", false},
        {"2000-1-1T1:1:1Z......", true},
        {"2000-01-01T24:00:00Z", false},
        {"2000-01-01T23:59:60Z", true},
        {"2000-01-01T23:59:61Z", false},
        {"2000-01- 1T00:00:00Z", true},             /* %d skips one space */
        {"\t2000-01-01T00:00:00", true},
        {"2000-01-01T00:00:0", false},
        {"2000-01-01T00:00:00.123456Z", true},
        {"99-1-1T1:1:1XXXXXXX", true},
        /* system_clock::from_time_t overflows int64 nanoseconds outside
         * 1677..2262; the C++ build wraps, and so does the port. */
        {"2262-04-11T23:47:16Z", false},
        {"2262-04-11T23:47:17Z", true},
        {"2800-01-01T00:00:00Z", false},
        {"2999-01-01T00:00:00Z", true},
        {"1677-09-21T00:12:43Z", false},
        {"1677-09-21T00:12:44Z", true},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (expired(cases[i].expire_at) != cases[i].expired)
            SB_FAIL_AT("peer_expired(\"%s\") != %d", cases[i].expire_at, cases[i].expired);
    }
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    CHECK(!sb_wireguard_peer_expired(&peer));
    sb_wireguard_peer_free(&peer);

    time_t now = time(NULL);
    static const struct {
        long offset;
        const char *suffix;
        bool expired;
    } relative[] = {
        {86400, "Z", false},       {-86400, "Z", true},       {86400, "+48:00", true},
        {-86400, "-48:00", false}, {86400, "+4800", false},   {86400, "+48:0x", false},
        {-86400, "+-1:00", true},  {86400, ".5+48:00", true}, {86400, "Z+48:00", false},
        {10800, "+05:00", true},   {10800, "+01:00", false},  {-10800, "-05:00", false},
        {86400, "+48:", false},
    };
    for (size_t i = 0; i < sizeof relative / sizeof relative[0]; ++i) {
        char *text = utc_text(now + relative[i].offset, relative[i].suffix);
        if (expired(text) != relative[i].expired)
            SB_FAIL_AT("peer_expired(\"%s\") != %d", text, relative[i].expired);
        free(text);
    }
}

static char *describe_options(const sb_wireguard_options *o) {
    return sb_asprintf("interface=%s port=%u address=%s dns=%s mtu=%u external=%s egress=%s dir=%s "
                       "enabled=%d",
                       o->interface, (unsigned)o->port, o->address, o->dns, (unsigned)o->mtu,
                       o->external_hostname, o->egress_interface, o->config_directory,
                       o->enabled ? 1 : 0);
}

#define OPTS(interface, port, address, dns, mtu)                                              \
    "interface=" interface " port=" port " address=" address " dns=" dns " mtu=" mtu          \
    " external=vpn.example.com egress=eth9 dir=/unused enabled=0"
#define DEFAULT_OPTS OPTS("wg-opt", "1111", "10.1.0.1/24", "10.1.0.1", "1000")

TEST(runtime_options_merge_the_saved_interface_setting_like_cpp) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_wireguard_options options;
    base_options(&options, "/unused");
    sb_wireguard *service = sb_wireguard_new(f.store, &options);
    sb_wireguard_options_free(&options);

    static const struct {
        const char *setting;
        const char *expected; /* describe_options() or the error message */
    } cases[] = {
        {"{\"interface\":\"wgx\",\"listen_port\":51999,\"address\":\"10.9.0.1/16\",\"dns\":\"1.1.1.1\","
         "\"mtu\":1280}",
         OPTS("wgx", "51999", "10.9.0.1/16", "1.1.1.1", "1280")},
        {"{}", DEFAULT_OPTS},
        {"{\"listen_port\":0,\"mtu\":0}", OPTS("wg-opt", "1111", "10.1.0.1/24", "10.1.0.1", "0")},
        {"{\"listen_port\":65535,\"mtu\":65535}",
         OPTS("wg-opt", "65535", "10.1.0.1/24", "10.1.0.1", "65535")},
        {"{\"listen_port\":65536,\"mtu\":65536}", DEFAULT_OPTS},
        {"{\"listen_port\":-1,\"mtu\":-1}", DEFAULT_OPTS},
        {"{\"listen_port\":1.9,\"mtu\":1400.7}", OPTS("wg-opt", "1", "10.1.0.1/24", "10.1.0.1", "1400")},
        {"{\"listen_port\":-0.5,\"mtu\":-0.5}", OPTS("wg-opt", "1111", "10.1.0.1/24", "10.1.0.1", "0")},
        {"{\"mtu\":9.3e18}", DEFAULT_OPTS},
        {"{\"listen_port\":-9223372036854775808,\"mtu\":-9223372036854775807}", DEFAULT_OPTS},
        {"{\"mtu\":18446744073709551615}", DEFAULT_OPTS},
#if defined(__aarch64__)
        {"{\"listen_port\":-1.5,\"mtu\":-1.5}", OPTS("wg-opt", "1111", "10.1.0.1/24", "10.1.0.1", "0")},
        {"{\"mtu\":1e20}", DEFAULT_OPTS},
        {"{\"mtu\":-1e30}", OPTS("wg-opt", "1111", "10.1.0.1/24", "10.1.0.1", "0")},
#else
        {"{\"listen_port\":-1.5,\"mtu\":-1.5}", DEFAULT_OPTS},
        {"{\"mtu\":1e20}", OPTS("wg-opt", "1111", "10.1.0.1/24", "10.1.0.1", "0")},
        {"{\"mtu\":-1e30}", DEFAULT_OPTS},
#endif
        {"{\"interface\":\"\",\"address\":\"\",\"dns\":\"\"}", OPTS("", "1111", "", "", "1000")},
        {"{\"unrelated\":1,\"external_hostname\":\"x\",\"config_directory\":\"/y\",\"enabled\":true}",
         DEFAULT_OPTS},
        {"[1,2]", DEFAULT_OPTS},
        {"\"str\"", DEFAULT_OPTS},
        {"null", DEFAULT_OPTS},
        {"{\"interface\":5}", TYPE_ERROR_STRING_NUMBER},
        {"{\"interface\":null}", "[json.exception.type_error.302] type must be string, but is null"},
        {"{\"address\":true}", "[json.exception.type_error.302] type must be string, but is boolean"},
        {"{\"dns\":[]}", "[json.exception.type_error.302] type must be string, but is array"},
        {"{\"listen_port\":\"51820\"}", "[json.exception.type_error.302] type must be number, but is string"},
        {"{\"mtu\":true}", "[json.exception.type_error.302] type must be number, but is boolean"},
        {"{\"mtu\":null}", "[json.exception.type_error.302] type must be number, but is null"},
        {"{\"listen_port\":\"x\",\"interface\":1}", TYPE_ERROR_STRING_NUMBER},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        set_setting(f.store, "wireguard_interface", cases[i].setting);
        sb_err err = {0};
        sb_wireguard_options runtime;
        if (sb_wireguard_runtime_options(service, &runtime, &err) == 0) {
            char *described = describe_options(&runtime);
            if (strcmp(described, cases[i].expected) != 0)
                SB_FAIL_AT("%s:\n    got:      %s\n    expected: %s", cases[i].setting, described,
                           cases[i].expected);
            free(described);
            sb_wireguard_options_free(&runtime);
        } else {
            if (err.code != SB_ERR_BAD_JSON || strcmp(err.msg, cases[i].expected) != 0)
                SB_FAIL_AT("%s:\n    error:    %s\n    expected: %s", cases[i].setting, err.msg,
                           cases[i].expected);
        }
    }
    sb_wireguard_free(service);
    fixture_close(&f);
}

TEST(server_keypair_is_generated_once_and_persisted) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    sb_wireguard *service = service_new(&f, false, NULL);

    /* No key yet: generate and persist {"private_key","public_key"}. */
    char *generated = sb_wireguard_server_public_key(service, &err);
    REQUIRE(generated);
    sbj *saved = NULL;
    REQUIRE(sb_store_app_setting(f.store, "wg_server_key", &saved, &err) == 1);
    CHECK_EQ_INT(sbj_obj_len(saved), 2);
    CHECK_STR(sbj_get_str(saved, "public_key", NULL), generated);
    CHECK_TAKE_STR(sb_wireguard_public_key_from_private(sbj_get_str(saved, "private_key", ""), &err),
                   generated);
    sbj_free(saved);
    CHECK_TAKE_STR(sb_wireguard_server_public_key(service, &err), generated);
    free(generated);

    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\"}");
    CHECK_TAKE_STR(sb_wireguard_server_public_key(service, &err), SERVER_PUB);
    set_setting(f.store, "wg_server_key",
                "{\"private_key\":\"" SERVER_PRIV "\",\"public_key\":\"custom-public\"}");
    CHECK_TAKE_STR(sb_wireguard_server_public_key(service, &err), "custom-public");
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\",\"public_key\":\"\"}");
    CHECK_TAKE_STR(sb_wireguard_server_public_key(service, &err), SERVER_PUB);

    /* An empty private key means "no key": a new pair replaces the setting. */
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"\",\"public_key\":\"ignored\"}");
    char *replaced = sb_wireguard_server_public_key(service, &err);
    CHECK(replaced && strlen(replaced) == 44U && strcmp(replaced, "ignored") != 0);
    REQUIRE(sb_store_app_setting(f.store, "wg_server_key", &saved, &err) == 1);
    CHECK_STR(sbj_get_str(saved, "public_key", NULL), replaced);
    sbj_free(saved);
    free(replaced);

    sb_err_clear(&err);
    set_setting(f.store, "wg_server_key", "{\"private_key\":5}");
    CHECK(sb_wireguard_server_public_key(service, &err) == NULL);
    CHECK_ERR(err, SB_ERR_BAD_JSON, TYPE_ERROR_STRING_NUMBER);
    sb_err_clear(&err);
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"\",\"public_key\":5}");
    CHECK(sb_wireguard_server_public_key(service, &err) == NULL);
    CHECK_ERR(err, SB_ERR_BAD_JSON, TYPE_ERROR_STRING_NUMBER);
    sb_err_clear(&err);
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"short\"}");
    CHECK(sb_wireguard_server_public_key(service, &err) == NULL);
    CHECK_ERR(err, SB_ERR_VALIDATION, "WireGuard key must encode 32 bytes");

    sb_wireguard_free(service);
    fixture_close(&f);
}

/* ======================================================================
 * Generated configs (goldens from the C++ implementation)
 * ====================================================================== */

static const char GOLDEN_CLIENT_PHONE[] =
    "# Client: Phone\n"
    "[Interface]\n"
    "PrivateKey = SlVga3aBjJeirbjDztnk7/oFEBsmMTxHUl1oc36JlJ8=\n"
    "Address = 10.60.0.2/24\n"
    "DNS = 10.60.0.1\n"
    "MTU = 1380\n"
    "\n"
    "[Peer]\n"
    "PublicKey = nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\n"
    "PresharedKey = oKu2wczX4u34Aw4ZJC86RVBbZnF8h5KdqLO+ydTf6vU=\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "Endpoint = vpn.example.com:51999\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_CLIENT_LAPTOP[] =
    "# Client: Laptop\n"
    "[Interface]\n"
    "PrivateKey = b3qFkJumsbzH0t3o8/4JFB8qNUBLVmFsd4KNmKOuucQ=\n"
    "Address = 10.60.0.3/24\n"
    "DNS = \n"
    "MTU = 1380\n"
    "\n"
    "[Peer]\n"
    "PublicKey = nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\n"
    "AllowedIPs = 10.60.0.0/24\n"
    "Endpoint = vpn.example.com:51999\n";

static const char GOLDEN_SERVER_CONFIG[] =
    "# Generated by sb-easy\n"
    "\n"
    "[Interface]\n"
    "PrivateKey = JTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBciLThDTllkb3o=\n"
    "ListenPort = 51999\n"
    "\n"
    "# Client: Phone\n"
    "[Peer]\n"
    "PublicKey = dYCLlqGst8LN2OPu+QQPGiUwO0ZRXGdyfYiTnqm0v8o=\n"
    "PresharedKey = oKu2wczX4u34Aw4ZJC86RVBbZnF8h5KdqLO+ydTf6vU=\n"
    "AllowedIPs = 10.60.0.2/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Client: Laptop\n"
    "[Peer]\n"
    "PublicKey = mqWwu8bR3Ofy/QgTHik0P0pVYGt2gYyXoq24w87Z5O8=\n"
    "AllowedIPs = 10.60.0.3/32\n"
    "\n"
    "# Client: Quota ok\n"
    "[Peer]\n"
    "PublicKey = LjlET1plcHuGkZynsr3I097p9P8KFSArNkFMV2JteIM=\n"
    "AllowedIPs = 10.60.0.7/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Client: Future\n"
    "[Peer]\n"
    "PublicKey = U15pdH+KlaCrtsHM1+Lt+AMOGSQvOkVQW2ZxfIeSnag=\n"
    "PresharedKey = fomUn6q1wMvW4ez3Ag0YIy45RE9aZXB7hpGcp7K9yNM=\n"
    "AllowedIPs = 10.60.0.8/32\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_STATS_JSON[] =
    "[{\"endpoint\":\"198.51.100.1:1000\",\"latest_handshake\":1700000000,\"public_key\":"
    "\"CRQfKjVAS1ZhbHeCjZijrrnEz9rl8PsGERwnMj1IU14=\",\"transfer_rx\":700,\"transfer_tx\":300},"
    "{\"endpoint\":null,\"latest_handshake\":null,\"public_key\":"
    "\"LjlET1plcHuGkZynsr3I097p9P8KFSArNkFMV2JteIM=\",\"transfer_rx\":100,\"transfer_tx\":100}]";

static const char GOLDEN_SERVER_CONFIG_NO_STATS[] =
    "# Generated by sb-easy\n"
    "\n"
    "[Interface]\n"
    "PrivateKey = JTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBciLThDTllkb3o=\n"
    "ListenPort = 51999\n"
    "\n"
    "# Client: Phone\n"
    "[Peer]\n"
    "PublicKey = dYCLlqGst8LN2OPu+QQPGiUwO0ZRXGdyfYiTnqm0v8o=\n"
    "PresharedKey = oKu2wczX4u34Aw4ZJC86RVBbZnF8h5KdqLO+ydTf6vU=\n"
    "AllowedIPs = 10.60.0.2/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Client: Laptop\n"
    "[Peer]\n"
    "PublicKey = mqWwu8bR3Ofy/QgTHik0P0pVYGt2gYyXoq24w87Z5O8=\n"
    "AllowedIPs = 10.60.0.3/32\n"
    "\n"
    "# Client: Quota hit\n"
    "[Peer]\n"
    "PublicKey = CRQfKjVAS1ZhbHeCjZijrrnEz9rl8PsGERwnMj1IU14=\n"
    "PresharedKey = ND9KVWBrdoGMl6KtuMPO2eTv+gUQGyYxPEdSXWhzfok=\n"
    "AllowedIPs = 10.60.0.6/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Client: Quota ok\n"
    "[Peer]\n"
    "PublicKey = LjlET1plcHuGkZynsr3I097p9P8KFSArNkFMV2JteIM=\n"
    "AllowedIPs = 10.60.0.7/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Client: Future\n"
    "[Peer]\n"
    "PublicKey = U15pdH+KlaCrtsHM1+Lt+AMOGSQvOkVQW2ZxfIeSnag=\n"
    "PresharedKey = fomUn6q1wMvW4ez3Ag0YIy45RE9aZXB7hpGcp7K9yNM=\n"
    "AllowedIPs = 10.60.0.8/32\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_WG_DUMP[] =
    "srv-private\tsrv-public\t51999\toff\n" P5_PUB
    "\t(none)\t198.51.100.1:1000\t10.60.0.6/32\t1700000000\t700\t300\t25\n" P6_PUB
    "\tpsk\t(none)\t10.60.0.7/32\t0\t100\t100\toff\n";

/* Peers of the "configs" C++ golden fixture. */
static void seed_config_peers(sb_store *store) {
    sb_wireguard_peer p;
    peer_make(&p, "peer-a", "Phone", P1_PRIV, P1_PUB, P1_PSK, "10.60.0.2/24");
    sb_str_set(&p.dns, "10.60.0.1");
    peer_create(store, &p);
    peer_make(&p, "peer-b", "Laptop", P2_PRIV, P2_PUB, NULL, "10.60.0.3/24");
    sb_str_set(&p.dns, "");
    p.persistent_keepalive = 0;
    sb_str_set(&p.allowed_ips, "10.60.0.0/24");
    peer_create(store, &p);
    peer_make(&p, "peer-c", "Disabled", P3_PRIV, P3_PUB, P3_PSK, "10.60.0.4/24");
    p.enabled = false;
    peer_create(store, &p);
    peer_make(&p, "peer-d", "Expired", P4_PRIV, P4_PUB, P4_PSK, "10.60.0.5/24");
    p.expire_at = sb_strdup("2001-01-01T00:00:00Z");
    peer_create(store, &p);
    peer_make(&p, "peer-e", "Quota hit", P5_PRIV, P5_PUB, P5_PSK, "10.60.0.6/24");
    p.quota_bytes = 1000;
    peer_create(store, &p);
    peer_make(&p, "peer-f", "Quota ok", P6_PRIV, P6_PUB, "", "10.60.0.7/24");
    p.quota_bytes = 5000;
    peer_create(store, &p);
    peer_make(&p, "peer-g", "Future", P7_PRIV, P7_PUB, P7_PSK, "10.60.0.8/24");
    p.expire_at = sb_strdup("2099-01-01T00:00:00+02:00");
    peer_create(store, &p);
}

TEST(client_and_server_configs_match_cpp) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\"}");
    set_setting(f.store, "wireguard_interface", kSettings);
    seed_config_peers(f.store);
    setenv("FAKE_WG_DUMP", GOLDEN_WG_DUMP, 1);
    sb_wireguard *service = service_new(&f, false, NULL);

    sb_wireguard_peer phone, laptop;
    sb_wireguard_peer_init(&phone);
    sb_wireguard_peer_init(&laptop);
    REQUIRE(find_peer(f.store, "peer-a", &phone) && find_peer(f.store, "peer-b", &laptop));
    CHECK_TAKE_STR(sb_wireguard_client_config(service, &phone, &err), GOLDEN_CLIENT_PHONE);
    CHECK_TAKE_STR(sb_wireguard_client_config(service, &laptop, &err), GOLDEN_CLIENT_LAPTOP);
    /* quota (rx + tx >= quota), expiry and disabled peers are left out */
    CHECK_TAKE_STR(sb_wireguard_server_config(service, &err), GOLDEN_SERVER_CONFIG);

    sb_wireguard_peer_stats_vec stats = {0};
    REQUIRE(sb_wireguard_stats(service, &stats, &err) == 0);
    sbj *json = sb_wireguard_peer_stats_vec_to_json(&stats);
    CHECK_TAKE_STR(dump_json(json), GOLDEN_STATS_JSON);
    sbj_free(json);
    sb_wireguard_peer_stats_vec_free(&stats);

    /* Without live counters quotas cannot be enforced (errors are ignored). */
    setenv("FAKE_WG_SHOW_EXIT", "1", 1);
    CHECK_TAKE_STR(sb_wireguard_server_config(service, &err), GOLDEN_SERVER_CONFIG_NO_STATS);
    CHECK_LOG(&f, "wg|show|wgt|dump\nwg|show|wgt|dump\nwg|show|wgt|dump\n");

    char *svg = sb_wireguard_qr_svg(service, &phone, &err);
    REQUIRE(svg);
    CHECK_EQ_INT(strlen(svg), 37446);
    CHECK_TAKE_STR(sha256_hex(svg), "0bd3f2ee378c108c010627a1c52589367d4d06dc65a976cf6a42323153308e7c");
    free(svg);

    sb_wireguard_peer_free(&phone);
    sb_wireguard_peer_free(&laptop);
    sb_wireguard_free(service);
    fixture_close(&f);
}

static const char GOLDEN_HOST_ALPHA[] =
    "# sb-easy managed host: Alpha\n"
    "[Interface]\n"
    "PrivateKey = l6KtuMPO2eTv+gUQGyYxPEdSXWhzfomUn6q1wMvW4ew=\n"
    "Address = 10.60.0.20/32\n"
    "MTU = 1380\n"
    "ListenPort = 51820\n"
    "\n"
    "# Hub (central server)\n"
    "[Peer]\n"
    "PublicKey = nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\n"
    "PresharedKey = 7fgDDhkkLzpFUFtmcXyHkp2os77J1N/q9QALFiEsN0I=\n"
    "AllowedIPs = 10.60.0.0/24\n"
    "Endpoint = vpn.example.com:51999\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Beta\n"
    "[Peer]\n"
    "PublicKey = 5/L9CBMeKTQ/SlVga3aBjJeirbjDztnk7/oFEBsmMTw=\n"
    "AllowedIPs = 10.60.0.21/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Gamma\n"
    "[Peer]\n"
    "PublicKey = DBciLThDTllkb3qFkJumsbzH0t3o8/4JFB8qNUBLVmE=\n"
    "AllowedIPs = 10.60.0.22/32\n"
    "Endpoint = [2001:db8::1]:4500\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Epsilon\n"
    "[Peer]\n"
    "PublicKey = MTxHUl1oc36JlJ+qtcDL1uHs9wINGCMuOURPWmVwe4Y=\n"
    "AllowedIPs = 10.60.0.24/32\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_HOST_BETA[] =
    "# sb-easy managed host: Beta\n"
    "[Interface]\n"
    "PrivateKey = vMfS3ejz/gkUHyo1QEtWYWx3go2Yo665xM/a5fD7BhE=\n"
    "Address = 10.60.0.21/32\n"
    "MTU = 1380\n"
    "\n"
    "# Hub (central server)\n"
    "[Peer]\n"
    "PublicKey = nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\n"
    "AllowedIPs = 10.60.0.0/24\n"
    "Endpoint = vpn.example.com:51999\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Alpha\n"
    "[Peer]\n"
    "PublicKey = ws3Y4+75BA8aJTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBc=\n"
    "AllowedIPs = 10.60.0.20/32\n"
    "Endpoint = 203.0.113.5:51820\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Gamma\n"
    "[Peer]\n"
    "PublicKey = DBciLThDTllkb3qFkJumsbzH0t3o8/4JFB8qNUBLVmE=\n"
    "AllowedIPs = 10.60.0.22/32\n"
    "Endpoint = [2001:db8::1]:4500\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_HOST_EPSILON[] =
    "# sb-easy managed host: host: Epsilon\n"
    "[Interface]\n"
    "PrivateKey = BhEcJzI9SFNeaXR/ipWgq7bBzNfi7fgDDhkkLzpFUFs=\n"
    "Address = 10.60.0.24/32\n"
    "MTU = 1380\n"
    "\n"
    "# Hub (central server)\n"
    "[Peer]\n"
    "PublicKey = nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\n"
    "PresharedKey = XGdyfYiTnqm0v8rV4Ov2AQwXIi04Q05ZZG96hZCbprE=\n"
    "AllowedIPs = 10.60.0.0/24\n"
    "Endpoint = vpn.example.com:51999\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Alpha\n"
    "[Peer]\n"
    "PublicKey = ws3Y4+75BA8aJTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBc=\n"
    "AllowedIPs = 10.60.0.20/32\n"
    "Endpoint = 203.0.113.5:51820\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Gamma\n"
    "[Peer]\n"
    "PublicKey = DBciLThDTllkb3qFkJumsbzH0t3o8/4JFB8qNUBLVmE=\n"
    "AllowedIPs = 10.60.0.22/32\n"
    "Endpoint = [2001:db8::1]:4500\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_ENDPOINT_ALPHA[] =
    "{\"address\":[\"10.60.0.20/32\"],\"mtu\":1380,\"peers\":[{\"address\":\"vpn.example.com\","
    "\"allowed_ips\":[\"10.60.0.0/24\"],\"persistent_keepalive_interval\":25,\"port\":51999,"
    "\"pre_shared_key\":\"7fgDDhkkLzpFUFtmcXyHkp2os77J1N/q9QALFiEsN0I=\",\"public_key\":"
    "\"nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\"}],\"private_key\":"
    "\"l6KtuMPO2eTv+gUQGyYxPEdSXWhzfomUn6q1wMvW4ew=\",\"tag\":\"sb-easy-network\","
    "\"type\":\"wireguard\"}";

static const char GOLDEN_ENDPOINT_BETA[] =
    "{\"address\":[\"10.60.0.21/32\"],\"mtu\":1380,\"peers\":[{\"address\":\"vpn.example.com\","
    "\"allowed_ips\":[\"10.60.0.0/24\"],\"persistent_keepalive_interval\":0,\"port\":51999,"
    "\"public_key\":\"nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\"}],\"private_key\":"
    "\"vMfS3ejz/gkUHyo1QEtWYWx3go2Yo665xM/a5fD7BhE=\",\"tag\":\"sb-easy-network\","
    "\"type\":\"wireguard\"}";

static const char GOLDEN_HOST_ALPHA_MTU0[] =
    "# sb-easy managed host: Alpha\n"
    "[Interface]\n"
    "PrivateKey = l6KtuMPO2eTv+gUQGyYxPEdSXWhzfomUn6q1wMvW4ew=\n"
    "Address = 10.60.0.20/32\n"
    "ListenPort = 51820\n"
    "\n"
    "# Hub (central server)\n"
    "[Peer]\n"
    "PublicKey = nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\n"
    "PresharedKey = 7fgDDhkkLzpFUFtmcXyHkp2os77J1N/q9QALFiEsN0I=\n"
    "AllowedIPs = 10.61.0.9/16\n"
    "Endpoint = vpn.example.com:1111\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Beta\n"
    "[Peer]\n"
    "PublicKey = 5/L9CBMeKTQ/SlVga3aBjJeirbjDztnk7/oFEBsmMTw=\n"
    "AllowedIPs = 10.60.0.21/32\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Gamma\n"
    "[Peer]\n"
    "PublicKey = DBciLThDTllkb3qFkJumsbzH0t3o8/4JFB8qNUBLVmE=\n"
    "AllowedIPs = 10.60.0.22/32\n"
    "Endpoint = [2001:db8::1]:4500\n"
    "PersistentKeepalive = 25\n"
    "\n"
    "# Mesh: Epsilon\n"
    "[Peer]\n"
    "PublicKey = MTxHUl1oc36JlJ+qtcDL1uHs9wINGCMuOURPWmVwe4Y=\n"
    "AllowedIPs = 10.60.0.24/32\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_ENDPOINT_ALPHA_MTU0[] =
    "{\"address\":[\"10.60.0.20/32\"],\"peers\":[{\"address\":\"vpn.example.com\",\"allowed_ips\":"
    "[\"10.61.0.9/16\"],\"persistent_keepalive_interval\":25,\"port\":1111,\"pre_shared_key\":"
    "\"7fgDDhkkLzpFUFtmcXyHkp2os77J1N/q9QALFiEsN0I=\",\"public_key\":"
    "\"nHydJOz6F47m+3a3NVL1zVONO+fcvus79vmX+yk1yTo=\"}],\"private_key\":"
    "\"l6KtuMPO2eTv+gUQGyYxPEdSXWhzfomUn6q1wMvW4ew=\",\"tag\":\"sb-easy-network\","
    "\"type\":\"wireguard\"}";

static void find_host(sb_store *store, const char *id, sb_host *out) {
    sb_err err = {0};
    if (sb_store_find_host(store, id, out, &err) != 1) abort();
}

TEST(host_configs_and_endpoints_match_cpp) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\"}");
    set_setting(f.store, "wireguard_interface", kSettings);
    static const struct {
        const char *id, *name, *endpoint, *address, *public_key;
        bool enabled;
    } specs[] = {
        {"host-alpha", "Alpha", "203.0.113.5:51820", "10.60.0.20/32", P10_PUB, true},
        {"host-beta", "Beta", NULL, "10.60.0.21/32", P11_PUB, true},
        {"host-gamma", "Gamma", "[2001:db8::1]:4500", "10.60.0.22/32", P12_PUB, true},
        {"host-delta", "Delta", "198.51.100.9:51820", "10.60.0.23/32", H1_PUB, false},
        {"host-eps", "Epsilon", "host:0", "10.60.0.24/32", P13_PUB, true},
        {"host-zeta", "Zeta", "198.51.100.10:51820", NULL, H2_PUB, true},
    };
    for (size_t i = 0; i < sizeof specs / sizeof specs[0]; ++i) {
        sb_host host, created;
        sb_host_init(&host);
        sb_host_init(&created);
        sb_str_set(&host.id, specs[i].id);
        sb_str_set(&host.name, specs[i].name);
        host.name_len = strlen(host.name);
        host.wg_endpoint = sb_strdup(specs[i].endpoint);
        host.wg_endpoint_len = host.wg_endpoint ? strlen(host.wg_endpoint) : 0;
        host.wg_address = sb_strdup(specs[i].address);
        host.wg_address_len = host.wg_address ? strlen(host.wg_address) : 0;
        host.wg_public_key = sb_strdup(specs[i].public_key);
        host.wg_public_key_len = host.wg_public_key ? strlen(host.wg_public_key) : 0;
        host.enabled = specs[i].enabled;
        REQUIRE(sb_store_create_host(f.store, &host, &created, &err) == 0);
        /* Distinct creation times keep list_hosts() ordering deterministic. */
        char *sql = sb_asprintf("UPDATE hosts SET created_at = '2024-01-0%zu 00:00:00' WHERE id = '%s'",
                                i + 1, specs[i].id);
        REQUIRE(sb_database_execute(sb_store_database(f.store), sql, &err) == 0);
        free(sql);
        sb_host_free(&host);
        sb_host_free(&created);
    }
    sb_wireguard_peer p;
    peer_make(&p, "peer-alpha", "host: Alpha", P10_PRIV, P10_PUB, P10_PSK, "10.60.0.20/32");
    p.host_id = sb_strdup("host-alpha");
    sb_str_set(&p.allowed_ips, "10.60.0.0/24");
    sb_str_set(&p.dns, "");
    peer_create(f.store, &p);
    peer_make(&p, "peer-beta", "host: Beta", P11_PRIV, P11_PUB, NULL, "10.60.0.21/32");
    p.host_id = sb_strdup("host-beta");
    p.persistent_keepalive = 0;
    peer_create(f.store, &p);
    peer_make(&p, "peer-gamma", "Gamma", P12_PRIV, P12_PUB, P12_PSK, "10.60.0.22/32");
    p.host_id = sb_strdup("host-gamma");
    p.enabled = false;
    peer_create(f.store, &p);
    peer_make(&p, "peer-eps", "host: host: Epsilon", P13_PRIV, P13_PUB, P13_PSK, "10.60.0.24/32");
    p.host_id = sb_strdup("host-eps");
    p.expire_at = sb_strdup("2001-01-01T00:00:00Z");
    peer_create(f.store, &p);

    sb_wireguard *service = service_new(&f, false, NULL);
    sb_host alpha, beta, gamma, delta, eps;
    sb_host_init(&alpha);
    sb_host_init(&beta);
    sb_host_init(&gamma);
    sb_host_init(&delta);
    sb_host_init(&eps);
    find_host(f.store, "host-alpha", &alpha);
    find_host(f.store, "host-beta", &beta);
    find_host(f.store, "host-gamma", &gamma);
    find_host(f.store, "host-delta", &delta);
    find_host(f.store, "host-eps", &eps);

    CHECK_TAKE_STR(sb_wireguard_host_config(service, &alpha, &err), GOLDEN_HOST_ALPHA);
    CHECK_TAKE_STR(sb_wireguard_host_config(service, &beta, &err), GOLDEN_HOST_BETA);
    CHECK_TAKE_STR(sb_wireguard_host_config(service, &eps, &err), GOLDEN_HOST_EPSILON);
    sb_err_clear(&err);
    CHECK(sb_wireguard_host_config(service, &delta, &err) == NULL);
    CHECK_ERR(err, SB_ERR_NOT_FOUND, "Host has no WireGuard peer");

    sbj *endpoint = NULL;
    REQUIRE(sb_wireguard_client_endpoint(service, &alpha, &endpoint, &err) == 1);
    CHECK_TAKE_STR(dump_json(endpoint), GOLDEN_ENDPOINT_ALPHA);
    sbj_free(endpoint);
    REQUIRE(sb_wireguard_client_endpoint(service, &beta, &endpoint, &err) == 1);
    CHECK_TAKE_STR(dump_json(endpoint), GOLDEN_ENDPOINT_BETA);
    sbj_free(endpoint);
    endpoint = NULL;
    /* disabled, expired and missing peers have no endpoint */
    CHECK_EQ_INT(sb_wireguard_client_endpoint(service, &gamma, &endpoint, &err), 0);
    CHECK_EQ_INT(sb_wireguard_client_endpoint(service, &eps, &endpoint, &err), 0);
    CHECK_EQ_INT(sb_wireguard_client_endpoint(service, &delta, &endpoint, &err), 0);
    CHECK(endpoint == NULL);

    /* MTU 0 drops the MTU line/member; a non-/24 subnet keeps its host part. */
    set_setting(f.store, "wireguard_interface", "{\"address\":\"10.61.0.9/16\",\"mtu\":0,\"listen_port\":0}");
    CHECK_TAKE_STR(sb_wireguard_host_config(service, &alpha, &err), GOLDEN_HOST_ALPHA_MTU0);
    REQUIRE(sb_wireguard_client_endpoint(service, &alpha, &endpoint, &err) == 1);
    CHECK_TAKE_STR(dump_json(endpoint), GOLDEN_ENDPOINT_ALPHA_MTU0);
    sbj_free(endpoint);

    sb_host_free(&alpha);
    sb_host_free(&beta);
    sb_host_free(&gamma);
    sb_host_free(&delta);
    sb_host_free(&eps);
    sb_wireguard_free(service);
    fixture_close(&f);
}

/* ======================================================================
 * QR codes
 * ====================================================================== */

static const char GOLDEN_QR_HELLO[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 "
    "0 29 29\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/><pa"
    "th d=\"M4,4h1v1h-1zM5,4h1v1h-1zM6,4h1v1h-1zM7,4h1v1h-1zM8,4h1v1h-1zM9,4h1v1h-1zM10,4h1v1h-1zM16,"
    "4h1v1h-1zM18,4h1v1h-1zM19,4h1v1h-1zM20,4h1v1h-1zM21,4h1v1h-1zM22,4h1v1h-1zM23,4h1v1h-1zM24,4h1v1"
    "h-1zM4,5h1v1h-1zM10,5h1v1h-1zM18,5h1v1h-1zM24,5h1v1h-1zM4,6h1v1h-1zM6,6h1v1h-1zM7,6h1v1h-1zM8,6h"
    "1v1h-1zM10,6h1v1h-1zM12,6h1v1h-1zM13,6h1v1h-1zM15,6h1v1h-1zM18,6h1v1h-1zM20,6h1v1h-1zM21,6h1v1h-"
    "1zM22,6h1v1h-1zM24,6h1v1h-1zM4,7h1v1h-1zM6,7h1v1h-1zM7,7h1v1h-1zM8,7h1v1h-1zM10,7h1v1h-1zM12,7h1"
    "v1h-1zM14,7h1v1h-1zM18,7h1v1h-1zM20,7h1v1h-1zM21,7h1v1h-1zM22,7h1v1h-1zM24,7h1v1h-1zM4,8h1v1h-1z"
    "M6,8h1v1h-1zM7,8h1v1h-1zM8,8h1v1h-1zM10,8h1v1h-1zM14,8h1v1h-1zM15,8h1v1h-1zM16,8h1v1h-1zM18,8h1v"
    "1h-1zM20,8h1v1h-1zM21,8h1v1h-1zM22,8h1v1h-1zM24,8h1v1h-1zM4,9h1v1h-1zM10,9h1v1h-1zM14,9h1v1h-1zM"
    "18,9h1v1h-1zM24,9h1v1h-1zM4,10h1v1h-1zM5,10h1v1h-1zM6,10h1v1h-1zM7,10h1v1h-1zM8,10h1v1h-1zM9,10h"
    "1v1h-1zM10,10h1v1h-1zM12,10h1v1h-1zM14,10h1v1h-1zM16,10h1v1h-1zM18,10h1v1h-1zM19,10h1v1h-1zM20,1"
    "0h1v1h-1zM21,10h1v1h-1zM22,10h1v1h-1zM23,10h1v1h-1zM24,10h1v1h-1zM13,11h1v1h-1zM14,11h1v1h-1zM15"
    ",11h1v1h-1zM7,12h1v1h-1zM8,12h1v1h-1zM10,12h1v1h-1zM11,12h1v1h-1zM13,12h1v1h-1zM14,12h1v1h-1zM15"
    ",12h1v1h-1zM21,12h1v1h-1zM22,12h1v1h-1zM4,13h1v1h-1zM6,13h1v1h-1zM9,13h1v1h-1zM11,13h1v1h-1zM13,"
    "13h1v1h-1zM14,13h1v1h-1zM18,13h1v1h-1zM19,13h1v1h-1zM20,13h1v1h-1zM21,13h1v1h-1zM22,13h1v1h-1zM4"
    ",14h1v1h-1zM5,14h1v1h-1zM7,14h1v1h-1zM9,14h1v1h-1zM10,14h1v1h-1zM12,14h1v1h-1zM13,14h1v1h-1zM15,"
    "14h1v1h-1zM17,14h1v1h-1zM19,14h1v1h-1zM22,14h1v1h-1zM23,14h1v1h-1zM24,14h1v1h-1zM4,15h1v1h-1zM5,"
    "15h1v1h-1zM8,15h1v1h-1zM9,15h1v1h-1zM11,15h1v1h-1zM13,15h1v1h-1zM16,15h1v1h-1zM17,15h1v1h-1zM19,"
    "15h1v1h-1zM20,15h1v1h-1zM22,15h1v1h-1zM5,16h1v1h-1zM8,16h1v1h-1zM9,16h1v1h-1zM10,16h1v1h-1zM11,1"
    "6h1v1h-1zM12,16h1v1h-1zM18,16h1v1h-1zM19,16h1v1h-1zM20,16h1v1h-1zM21,16h1v1h-1zM23,16h1v1h-1zM12"
    ",17h1v1h-1zM14,17h1v1h-1zM16,17h1v1h-1zM17,17h1v1h-1zM18,17h1v1h-1zM21,17h1v1h-1zM23,17h1v1h-1zM"
    "4,18h1v1h-1zM5,18h1v1h-1zM6,18h1v1h-1zM7,18h1v1h-1zM8,18h1v1h-1zM9,18h1v1h-1zM10,18h1v1h-1zM12,1"
    "8h1v1h-1zM14,18h1v1h-1zM18,18h1v1h-1zM22,18h1v1h-1zM4,19h1v1h-1zM10,19h1v1h-1zM13,19h1v1h-1zM14,"
    "19h1v1h-1zM15,19h1v1h-1zM17,19h1v1h-1zM21,19h1v1h-1zM22,19h1v1h-1zM23,19h1v1h-1zM24,19h1v1h-1zM4"
    ",20h1v1h-1zM6,20h1v1h-1zM7,20h1v1h-1zM8,20h1v1h-1zM10,20h1v1h-1zM12,20h1v1h-1zM14,20h1v1h-1zM16,"
    "20h1v1h-1zM20,20h1v1h-1zM21,20h1v1h-1zM23,20h1v1h-1zM24,20h1v1h-1zM4,21h1v1h-1zM6,21h1v1h-1zM7,2"
    "1h1v1h-1zM8,21h1v1h-1zM10,21h1v1h-1zM12,21h1v1h-1zM14,21h1v1h-1zM15,21h1v1h-1zM16,21h1v1h-1zM17,"
    "21h1v1h-1zM20,21h1v1h-1zM4,22h1v1h-1zM6,22h1v1h-1zM7,22h1v1h-1zM8,22h1v1h-1zM10,22h1v1h-1zM14,22"
    "h1v1h-1zM15,22h1v1h-1zM17,22h1v1h-1zM18,22h1v1h-1zM19,22h1v1h-1zM20,22h1v1h-1zM21,22h1v1h-1zM22,"
    "22h1v1h-1zM23,22h1v1h-1zM24,22h1v1h-1zM4,23h1v1h-1zM10,23h1v1h-1zM13,23h1v1h-1zM14,23h1v1h-1zM15"
    ",23h1v1h-1zM16,23h1v1h-1zM17,23h1v1h-1zM18,23h1v1h-1zM19,23h1v1h-1zM20,23h1v1h-1zM21,23h1v1h-1zM"
    "22,23h1v1h-1zM23,23h1v1h-1zM24,23h1v1h-1zM4,24h1v1h-1zM5,24h1v1h-1zM6,24h1v1h-1zM7,24h1v1h-1zM8,"
    "24h1v1h-1zM9,24h1v1h-1zM10,24h1v1h-1zM14,24h1v1h-1zM17,24h1v1h-1z\" fill=\"#000\"/></svg>";

TEST(qr_svgs_match_cpp) {
    sb_err err = {0};
    CHECK_TAKE_STR(sb_qr_svg_for_text("hello", &err), GOLDEN_QR_HELLO);
    static const struct {
        char c;
        size_t repeat; /* 0: the empty text */
        size_t length;
        const char *sha256;
    } fitting[] = {
        {'x', 0, 3231, "629fa7f02b4b59f5c7666ffecec351ec24d6307dbd4720be90f1b0166a902c5c"},
        {'x', 2331, 237899, "2ae80e6cecc70a38b1df3da2f4f34eacacb34adb706d8a01a4100ff4eb7745b0"},
        {'7', 5596, 225613, "94dfbfd1ed336e2e7327aa5e188112ac899218a919e45b98aad077b1460f028a"},
        {'A', 3391, 230545, "817936a07320d1ce29f7fb0963ffe15d9c56113893f303fc5111e2a1101b3be1"},
    };
    for (size_t i = 0; i < sizeof fitting / sizeof fitting[0]; ++i) {
        char *text = repeat(fitting[i].c, fitting[i].repeat);
        char *svg = sb_qr_svg_for_text(text, &err);
        CHECK(svg && strlen(svg) == fitting[i].length);
        if (svg) CHECK_TAKE_STR(sha256_hex(svg), fitting[i].sha256);
        free(svg);
        free(text);
    }
    static const struct {
        char c;
        size_t repeat;
        const char *message; /* qrcodegen::data_too_long::what() */
    } too_long[] = {
        {'x', 2332, "Data length = 18676 bits, Max capacity = 18672 bits"},
        {'7', 5597, "Data length = 18675 bits, Max capacity = 18672 bits"},
        {'A', 3392, "Data length = 18673 bits, Max capacity = 18672 bits"},
        {'B', 8000, "Data length = 44017 bits, Max capacity = 18672 bits"},
        {'x', 20000, "Data length = 160020 bits, Max capacity = 18672 bits"},
        {'B', 9000, "Segment too long"},
        {'1', 20000, "Segment too long"},
        {'x', 70000, "Segment too long"},
    };
    for (size_t i = 0; i < sizeof too_long / sizeof too_long[0]; ++i) {
        char *text = repeat(too_long[i].c, too_long[i].repeat);
        sb_err_clear(&err);
        char *svg = sb_qr_svg_for_text(text, &err);
        CHECK(svg == NULL);
        free(svg);
        CHECK_ERR(err, SB_ERR_GENERIC, too_long[i].message);
        free(text);
    }
}

/* ======================================================================
 * Provisioning
 * ====================================================================== */

TEST(provisioning_allocates_links_and_removes_host_peers) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\"}");
    set_setting(f.store, "wireguard_interface", kSettings);
    sb_wireguard *service = service_new(&f, false, NULL);

    /* A new host gets a fresh identity: "host: <name>", next /24 address as a
     * /32, no DNS, keepalive 25, the hub subnet as AllowedIPs and a PSK. */
    sb_host omega, sigma, provisioned;
    sb_host_init(&omega);
    sb_host_init(&sigma);
    sb_host_init(&provisioned);
    sb_str_set(&omega.id, "host-omega");
    sb_str_set(&omega.name, "Omega");
    omega.name_len = strlen(omega.name);
    REQUIRE(sb_store_create_host(f.store, &omega, &omega, &err) == 0);
    REQUIRE(sb_wireguard_provision_host(service, &omega, true, &provisioned, &err) == 0);
    CHECK_STR(provisioned.wg_address, "10.60.0.2/32");
    CHECK_STR(provisioned.clash_api, "http://10.60.0.2:9090");
    sb_wireguard_peer_vec peers = {0};
    REQUIRE(sb_store_list_wireguard_peers(f.store, &peers, &err) == 0);
    REQUIRE(peers.len == 1U);
    const sb_wireguard_peer *created = &peers.items[0];
    CHECK_STR(created->name, "host: Omega");
    CHECK_STR(created->address, "10.60.0.2/32");
    CHECK_STR(created->dns, "");
    CHECK_STR(created->allowed_ips, "10.60.0.0/24");
    CHECK_STR(created->host_id, "host-omega");
    CHECK(created->enabled && created->persistent_keepalive == 25 && created->quota_bytes == 0);
    CHECK(created->preshared_key && strlen(created->preshared_key) == 44U);
    CHECK(created->expire_at == NULL && created->notes == NULL);
    CHECK_STR(provisioned.wg_public_key, created->public_key);
    CHECK_TAKE_STR(sb_wireguard_public_key_from_private(created->private_key, &err), created->public_key);
    char *first_id = sb_strdup(created->id);
    sb_wireguard_peer_vec_free(&peers);

    /* Provisioning again reuses the linked peer. */
    REQUIRE(sb_wireguard_provision_host(service, &provisioned, false, &provisioned, &err) == 0);
    CHECK_EQ_INT(peer_count(f.store), 1);
    CHECK_STR(provisioned.wg_address, "10.60.0.2/32");
    free(first_id);

    /* An explicit Clash API is kept. */
    sb_str_set(&sigma.id, "host-sigma");
    sb_str_set(&sigma.name, "Sigma");
    sigma.name_len = strlen(sigma.name);
    sigma.clash_api = sb_strdup("http://custom:9090");
    sigma.clash_api_len = sigma.clash_api ? strlen(sigma.clash_api) : 0;
    REQUIRE(sb_store_create_host(f.store, &sigma, &sigma, &err) == 0);
    REQUIRE(sb_wireguard_provision_host(service, &sigma, true, &sigma, &err) == 0);
    CHECK_STR(sigma.clash_api, "http://custom:9090");
    CHECK_STR(sigma.wg_address, "10.60.0.3/32");

    /* An unlinked peer with exactly the host's name is adopted: enabled,
     * linked and routed to the hub subnet, keys and address unchanged. */
    sb_wireguard_peer standalone;
    peer_make(&standalone, "peer-laptop", "Laptop", P2_PRIV, P2_PUB, NULL, "10.60.0.40/24");
    standalone.enabled = false;
    sb_str_set(&standalone.allowed_ips, "0.0.0.0/0");
    peer_create(f.store, &standalone);
    sb_host laptop;
    sb_host_init(&laptop);
    sb_str_set(&laptop.id, "host-laptop");
    sb_str_set(&laptop.name, "Laptop");
    laptop.name_len = strlen(laptop.name);
    REQUIRE(sb_store_create_host(f.store, &laptop, &laptop, &err) == 0);
    REQUIRE(sb_wireguard_provision_host(service, &laptop, false, &laptop, &err) == 0);
    CHECK_STR(laptop.wg_address, "10.60.0.40/24");
    CHECK_STR(laptop.wg_public_key, P2_PUB);
    CHECK(laptop.clash_api == NULL);
    sb_wireguard_peer adopted;
    sb_wireguard_peer_init(&adopted);
    REQUIRE(find_peer(f.store, "peer-laptop", &adopted));
    CHECK_STR(adopted.host_id, "host-laptop");
    CHECK_STR(adopted.allowed_ips, "10.60.0.0/24");
    CHECK_STR(adopted.dns, "10.59.32.1");
    CHECK_STR(adopted.private_key, P2_PRIV);
    CHECK(adopted.enabled && adopted.preshared_key == NULL);
    sb_wireguard_peer_free(&adopted);

    /* A host missing from the store fails in update_host, after the peer was
     * created (as in C++). */
    sb_host ghost, untouched;
    sb_host_init(&ghost);
    sb_host_init(&untouched);
    sb_str_set(&ghost.id, "host-ghost");
    sb_str_set(&ghost.name, "Ghost");
    ghost.name_len = strlen(ghost.name);
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_provision_host(service, &ghost, false, &untouched, &err), -1);
    CHECK_ERR(err, SB_ERR_NOT_FOUND, "Host not found");
    CHECK_STR(untouched.id, "");
    CHECK_EQ_INT(peer_count(f.store), 4);

    /* Deprovisioning removes the kernel peer (enabled services only) and the
     * stored peer; unknown hosts are a no-op. */
    sb_wireguard *enabled = service_new(&f, true, NULL);
    discard_log(&f);
    CHECK_EQ_INT(sb_wireguard_deprovision_host(enabled, "host-laptop", &err), 0);
    CHECK_LOG(&f, "wg|set|wgt|peer|" P2_PUB "|remove\n");
    sb_wireguard_peer gone;
    sb_wireguard_peer_init(&gone);
    CHECK(!find_peer(f.store, "peer-laptop", &gone));
    sb_wireguard_peer_free(&gone);
    CHECK_EQ_INT(sb_wireguard_deprovision_host(enabled, "host-laptop", &err), 0);
    CHECK_EQ_INT(sb_wireguard_deprovision_host(service, "host-ghost", &err), 0);
    CHECK_LOG(&f, "");
    CHECK_EQ_INT(peer_count(f.store), 2);

    sb_host_free(&omega);
    sb_host_free(&sigma);
    sb_host_free(&provisioned);
    sb_host_free(&laptop);
    sb_host_free(&ghost);
    sb_host_free(&untouched);
    sb_wireguard_free(enabled);
    sb_wireguard_free(service);
    fixture_close(&f);
}

/* ======================================================================
 * Kernel interface
 * ====================================================================== */

static const char GOLDEN_STARTUP_FRESH_LOG[] =
    "wg|show|wgp|dump\n"
    "ip|link|show|wgp\n"
    "ip|link|add|wgp|type|wireguard\n"
    "ip|link|set|wgp|mtu|1380\n"
    "ip|address|add|10.60.0.1/24|dev|wgp\n"
    "ip|link|set|up|wgp\n"
    "wg|setconf|wgp|@DIR@/etc/nested/wgp.conf\n"
    "sysctl|-w|net.ipv4.ip_forward=1\n"
    "iptables|-t|nat|-C|POSTROUTING|-s|10.60.0.0/24|-o|eth9|-j|MASQUERADE\n"
    "iptables|-t|nat|-A|POSTROUTING|-s|10.60.0.0/24|-o|eth9|-j|MASQUERADE\n"
    "iptables|-C|FORWARD|-i|wgp|-j|ACCEPT\n"
    "iptables|-A|FORWARD|-i|wgp|-j|ACCEPT\n"
    "iptables|-C|FORWARD|-o|wgp|-j|ACCEPT\n"
    "iptables|-A|FORWARD|-o|wgp|-j|ACCEPT\n";

static const char GOLDEN_STARTUP_CONF[] =
    "# Generated by sb-easy\n"
    "\n"
    "[Interface]\n"
    "PrivateKey = JTA7RlFcZ3J9iJOeqbS/ytXg6/YBDBciLThDTllkb3o=\n"
    "ListenPort = 51999\n"
    "\n"
    "# Client: Phone\n"
    "[Peer]\n"
    "PublicKey = dYCLlqGst8LN2OPu+QQPGiUwO0ZRXGdyfYiTnqm0v8o=\n"
    "PresharedKey = oKu2wczX4u34Aw4ZJC86RVBbZnF8h5KdqLO+ydTf6vU=\n"
    "AllowedIPs = 10.60.0.2/32\n"
    "PersistentKeepalive = 25\n";

static const char GOLDEN_STARTUP_EXISTING_LOG[] =
    "wg|show|wgp|dump\n"
    "ip|link|show|wgp\n"
    "wg|syncconf|wgp|@DIR@/etc/nested/wgp.conf\n"
    "sysctl|-w|net.ipv4.ip_forward=1\n"
    "iptables|-t|nat|-C|POSTROUTING|-s|10.60.0.0/24|-o|eth9|-j|MASQUERADE\n"
    "iptables|-C|FORWARD|-i|wgp|-j|ACCEPT\n"
    "iptables|-C|FORWARD|-o|wgp|-j|ACCEPT\n";

static const char GOLDEN_SYNC_LOG[] =
    "wg|show|wgp|dump\n"
    "wg|syncconf|wgp|@DIR@/etc/nested/wgp.conf\n";

static const char GOLDEN_SHUTDOWN_LOG[] =
    "iptables|-t|nat|-D|POSTROUTING|-s|10.60.0.0/24|-o|eth9|-j|MASQUERADE\n"
    "iptables|-D|FORWARD|-i|wgp|-j|ACCEPT\n"
    "iptables|-D|FORWARD|-o|wgp|-j|ACCEPT\n"
    "ip|link|delete|wgp\n";

static const char GOLDEN_STARTUP_MTU0_LOG[] =
    "wg|show|wgm|dump\n"
    "ip|link|show|wgm\n"
    "ip|link|add|wgm|type|wireguard\n"
    "ip|address|add|10.70.1.1/16|dev|wgm\n"
    "ip|link|set|up|wgm\n"
    "wg|setconf|wgm|@DIR@/etc/nested/wgm.conf\n"
    "sysctl|-w|net.ipv4.ip_forward=1\n"
    "iptables|-t|nat|-C|POSTROUTING|-s|10.70.1.1/16|-o|eth9|-j|MASQUERADE\n"
    "iptables|-t|nat|-A|POSTROUTING|-s|10.70.1.1/16|-o|eth9|-j|MASQUERADE\n"
    "iptables|-C|FORWARD|-i|wgm|-j|ACCEPT\n"
    "iptables|-A|FORWARD|-i|wgm|-j|ACCEPT\n"
    "iptables|-C|FORWARD|-o|wgm|-j|ACCEPT\n"
    "iptables|-A|FORWARD|-o|wgm|-j|ACCEPT\n";

static const char GOLDEN_STARTUP_NO_SYSCTL_LOG[] =
    "wg|show|wgm|dump\n"
    "ip|link|show|wgm\n"
    "ip|link|add|wgm|type|wireguard\n"
    "ip|address|add|10.70.1.1/16|dev|wgm\n"
    "ip|link|set|up|wgm\n"
    "wg|setconf|wgm|@DIR@/etc/nested/wgm.conf\n";

TEST(startup_sync_and_shutdown_run_the_cpp_commands) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\"}");
    set_setting(f.store, "wireguard_interface",
                "{\"interface\":\"wgp\",\"listen_port\":51999,\"address\":\"10.60.0.1/24\","
                "\"dns\":\"10.60.0.1\",\"mtu\":1380}");
    sb_wireguard_peer p;
    peer_make(&p, "peer-a", "Phone", P1_PRIV, P1_PUB, P1_PSK, "10.60.0.2/24");
    peer_create(f.store, &p);
    sb_wireguard *service = service_new(&f, true, "etc/nested");
    char *conf = sb_path_join(f.dir, "etc/nested/wgp.conf");

    /* No interface yet: create, configure, then NAT and forwarding rules. */
    CHECK_EQ_INT(sb_wireguard_startup(service, &err), 0);
    CHECK_LOG(&f, GOLDEN_STARTUP_FRESH_LOG);
    char *written = sb_read_file(conf, NULL);
    CHECK_STR(written, GOLDEN_STARTUP_CONF);
    free(written);
    struct stat info;
    CHECK(stat(conf, &info) == 0 && (info.st_mode & 0777) == 0600);

    /* Existing interface and rules: syncconf, rules only checked. */
    setenv("FAKE_IP_LINK_SHOW_EXIT", "0", 1);
    setenv("FAKE_IPT_CHECK_EXIT", "0", 1);
    CHECK_EQ_INT(sb_wireguard_startup(service, &err), 0);
    CHECK_LOG(&f, GOLDEN_STARTUP_EXISTING_LOG);
    CHECK_EQ_INT(sb_wireguard_sync(service, &err), 0);
    CHECK_LOG(&f, GOLDEN_SYNC_LOG);

    /* Checked commands fail with their exit code and combined output. */
    setenv("FAKE_WG_SYNC_EXIT", "3", 1);
    setenv("FAKE_WG_SYNC_OUTPUT", "boom\n", 1);
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_sync(service, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "wg exited with code 3: boom\n");
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_startup(service, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "wg exited with code 3: boom\n");
    unsetenv("FAKE_WG_SYNC_EXIT");
    unsetenv("FAKE_WG_SYNC_OUTPUT");
    discard_log(&f);

    sb_wireguard_remove_peer(service, P1_PUB);
    CHECK_LOG(&f, "wg|set|wgp|peer|" P1_PUB "|remove\n");
    sb_wireguard_shutdown(service);
    CHECK_LOG(&f, GOLDEN_SHUTDOWN_LOG);
    unsetenv("FAKE_IP_LINK_SHOW_EXIT");
    unsetenv("FAKE_IPT_CHECK_EXIT");

    /* MTU 0 skips `ip link set mtu`; non-/24 subnets are used as given. */
    set_setting(f.store, "wireguard_interface",
                "{\"interface\":\"wgm\",\"mtu\":0,\"address\":\"10.70.1.1/16\"}");
    CHECK_EQ_INT(sb_wireguard_startup(service, &err), 0);
    CHECK_LOG(&f, GOLDEN_STARTUP_MTU0_LOG);

    /* A missing tool is a spawn failure, even for unchecked commands. */
    remove_tool(&f, "sysctl");
    remove_tool(&f, "iptables");
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_startup(service, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "sysctl: No such file or directory");
    CHECK_LOG(&f, GOLDEN_STARTUP_NO_SYSCTL_LOG);
    /* shutdown() stops silently at the first failure (noexcept in C++). */
    sb_wireguard_shutdown(service);
    CHECK_LOG(&f, "");

    free(conf);
    sb_wireguard_free(service);
    fixture_close(&f);
}

TEST(kernel_helpers_fail_and_skip_like_cpp) {
    fixture f;
    REQUIRE(fixture_open(&f));
    sb_err err = {0};
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"" SERVER_PRIV "\"}");

    /* Disabled services never touch the kernel. */
    sb_wireguard *disabled = service_new(&f, false, "never");
    CHECK_EQ_INT(sb_wireguard_startup(disabled, &err), 0);
    CHECK_EQ_INT(sb_wireguard_sync(disabled, &err), 0);
    sb_wireguard_remove_peer(disabled, P1_PUB);
    sb_wireguard_shutdown(disabled);
    CHECK_LOG(&f, "");
    char *never = sb_path_join(f.dir, "never");
    CHECK(!sb_file_exists(never));
    free(never);

    /* stats() is a checked command. */
    setenv("FAKE_WG_SHOW_EXIT", "1", 1);
    setenv("FAKE_WG_DUMP", "partial\n", 1);
    sb_wireguard_peer_stats_vec stats = {0};
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_stats(disabled, &stats, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "wg exited with code 1: partial\n");
    CHECK_EQ_INT(stats.len, 0);
    unsetenv("FAKE_WG_SHOW_EXIT");
    unsetenv("FAKE_WG_DUMP");

    /* Configuration directories are created like create_directories(). */
    char *file = sb_path_join(f.dir, "a-file");
    REQUIRE(sb_write_file(file, "x", 1) == 0);
    sb_wireguard_options options;
    base_options(&options, file);
    options.enabled = true;
    sb_wireguard *into_file = sb_wireguard_new(f.store, &options);
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_sync(into_file, &err), -1);
    char *expected = sb_asprintf("filesystem error: cannot create directories: Not a directory [%s]", file);
    CHECK_ERR(err, SB_ERR_IO, expected);
    free(expected);
    sb_wireguard_free(into_file);
    sb_str_set(&options.config_directory, "");
    sb_wireguard *empty = sb_wireguard_new(f.store, &options);
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_startup(empty, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "filesystem error: cannot create directories: Invalid argument []");
    sb_wireguard_free(empty);
    char *trailing = sb_asprintf("%s/trailing/", f.dir);
    sb_str_set(&options.config_directory, trailing);
    sb_wireguard *slash = sb_wireguard_new(f.store, &options);
    discard_log(&f);
    /* The migration's default wireguard_interface setting names "wg0". */
    CHECK_EQ_INT(sb_wireguard_sync(slash, &err), 0);
    CHECK_LOG(&f, "wg|show|wg0|dump\nwg|syncconf|wg0|@DIR@/trailing/wg0.conf\n");
    sb_wireguard_free(slash);
    free(trailing);

    /* A missing `wg`: stats fail, server_config ignores it, sync fails. */
    remove_tool(&f, "wg");
    sb_str_set(&options.config_directory, f.dir);
    sb_wireguard *enabled = sb_wireguard_new(f.store, &options);
    sb_wireguard_options_free(&options);
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_stats(enabled, &stats, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "wg: No such file or directory");
    char *server = sb_wireguard_server_config(enabled, &err);
    CHECK(server && sb_starts_with(server, "# Generated by sb-easy\n"));
    free(server);
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_sync(enabled, &err), -1);
    CHECK_ERR(err, SB_ERR_IO, "wg: No such file or directory");
    sb_wireguard_remove_peer(enabled, P1_PUB); /* noexcept: swallowed */

    /* Mistyped settings surface nlohmann's type_error; the noexcept
     * helpers give up silently. */
    set_setting(f.store, "wireguard_interface", "{\"interface\":7}");
    sb_err_clear(&err);
    CHECK_EQ_INT(sb_wireguard_startup(enabled, &err), -1);
    CHECK_ERR(err, SB_ERR_BAD_JSON, TYPE_ERROR_STRING_NUMBER);
    sb_err_clear(&err);
    CHECK(sb_wireguard_server_config(enabled, &err) == NULL);
    CHECK_ERR(err, SB_ERR_BAD_JSON, TYPE_ERROR_STRING_NUMBER);
    sb_wireguard_peer peer;
    peer_make(&peer, "peer-a", "Phone", P1_PRIV, P1_PUB, P1_PSK, "10.60.0.2/24");
    sb_err_clear(&err);
    CHECK(sb_wireguard_client_config(enabled, &peer, &err) == NULL);
    CHECK_ERR(err, SB_ERR_BAD_JSON, TYPE_ERROR_STRING_NUMBER);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_shutdown(enabled);
    sb_wireguard_remove_peer(enabled, P1_PUB);
    CHECK_LOG(&f, "");

    /* An invalid persisted server key is a validation error. */
    set_setting(f.store, "wireguard_interface", kSettings);
    set_setting(f.store, "wg_server_key", "{\"private_key\":\"bad\"}");
    sb_err_clear(&err);
    CHECK(sb_wireguard_server_config(enabled, &err) == NULL);
    CHECK_ERR(err, SB_ERR_VALIDATION, "WireGuard key must encode 32 bytes");

    free(file);
    sb_wireguard_free(enabled);
    sb_wireguard_free(disabled);
    fixture_close(&f);
}
