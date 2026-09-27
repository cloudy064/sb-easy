/* Contract tests for the admin route group (c/src/http_routes_admin.c):
 * /api/health, /api/system/..., /api/auth/..., /api/users*, /api/settings*,
 * /api/wireguard/..., /api/config/sing-box/...
 *
 * Ports every assertion of cpp/tests/http_server_test.cpp that concerns these
 * routes (the C service reports "sb-easy-c" from /api/health) and adds the
 * validation / not-found edge cases of the C++ handlers.
 *
 * Safety: the WireGuard service shells out to `wg` (e.g. `wg show wg0 dump`
 * for live stats) even when WireGuard is disabled. A constructor below puts
 * fake `wg`/`ip`/`iptables`/`sysctl` scripts first on PATH so the tests never
 * execute the real tools; the fake `wg show` prints a scripted dump file when
 * one exists (used to test the live-stats merge) and fails otherwise. */
#include "test.h"
#include "http_test_support.h"

#include <ctype.h>
#include <sqlite3.h>
#include <sys/stat.h>

#define ADMIN NULL /* default admin bearer token */
#define NO_AUTH "" /* no Authorization header */

/* ---- fake WireGuard tooling ------------------------------------------- */

static char *fake_bin_dir;
static char *fake_wg_dump; /* when this file exists, `wg show ...` prints it */

static void remove_fake_tools(void) {
    if (!fake_bin_dir) return;
    char *cmd = sb_asprintf("rm -rf '%s'", fake_bin_dir);
    if (system(cmd) != 0) {
    }
    free(cmd);
    free(fake_bin_dir);
    free(fake_wg_dump);
    fake_bin_dir = fake_wg_dump = NULL;
}

static void write_script(const char *name, const char *text) {
    char *path = sb_path_join(fake_bin_dir, name);
    if (sb_write_file(path, text, strlen(text)) != 0 || chmod(path, 0755) != 0) abort();
    free(path);
}

__attribute__((constructor)) static void install_fake_wireguard_tools(void) {
    char tmpl[] = "/tmp/sb-easy-c-admin-bin-XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) abort();
    fake_bin_dir = sb_strdup(dir);
    fake_wg_dump = sb_path_join(fake_bin_dir, "wg-dump.txt");
    char *wg = sb_asprintf("#!/bin/sh\n"
                           "if [ \"$1\" = show ] && [ -f '%s' ]; then cat '%s'; exit 0; fi\n"
                           "echo 'fake wg: the real tool is never run by tests' >&2\n"
                           "exit 1\n",
                           fake_wg_dump, fake_wg_dump);
    write_script("wg", wg);
    free(wg);
    static const char *const others[] = {"ip", "iptables", "sysctl", "wg-quick"};
    for (size_t i = 0; i < sizeof others / sizeof *others; ++i)
        write_script(others[i], "#!/bin/sh\necho 'fake tool: refusing to touch the network' >&2\nexit 1\n");
    const char *path = getenv("PATH");
    char *new_path = sb_asprintf("%s:%s", fake_bin_dir, path && *path ? path : "/usr/bin:/bin");
    setenv("PATH", new_path, 1);
    free(new_path);
    atexit(remove_fake_tools);
}

/* ---- request helpers -------------------------------------------------- */

/* Releases the previous response held in *r and performs a new request.
 * token: ADMIN (NULL), NO_AUTH ("") or an explicit bearer token. */
static void call_h(sb_test_server *t, sb_test_response *r, const char *method, const char *path,
                   const char *body, const char *token, const char *const *headers) {
    sb_test_response_free(r);
    sb_test_request_ex(t, method, path, body, token, headers, r);
}

static void call(sb_test_server *t, sb_test_response *r, const char *method, const char *path,
                 const char *body, const char *token) {
    call_h(t, r, method, path, body, token, NULL);
}

static const char *error_of(const sb_test_response *r) { return sbj_get_str(r->json, "error", NULL); }
static const char *str_of(const sbj *object, const char *key) { return sbj_get_str(object, key, NULL); }

#define CHECK_ERROR(resp, code, message)                                                   \
    do {                                                                                   \
        CHECK_EQ_INT((resp).status, (code));                                               \
        CHECK_STR(error_of(&(resp)), (message));                                           \
    } while (0)

#define CHECK_SUCCESS(resp)                                                                \
    do {                                                                                   \
        CHECK_EQ_INT((resp).status, 200);                                                  \
        CHECK(sbj_get_bool((resp).json, "success", false));                                \
    } while (0)

/* "YYYY-MM-DDTHH:MM:SSZ" */
static bool is_utc_timestamp(const char *s) {
    static const char pattern[] = "dddd-dd-ddTdd:dd:ddZ";
    if (!s || strlen(s) != sizeof pattern - 1) return false;
    for (size_t i = 0; pattern[i]; ++i) {
        if (pattern[i] == 'd' ? !isdigit((unsigned char)s[i]) : s[i] != pattern[i]) return false;
    }
    return true;
}

static bool is_lower_hex(const char *s, size_t len) {
    if (!s || strlen(s) != len) return false;
    for (size_t i = 0; i < len; ++i)
        if (!isdigit((unsigned char)s[i]) && !(s[i] >= 'a' && s[i] <= 'f')) return false;
    return true;
}

static size_t str_len(const char *s) { return s ? strlen(s) : 0; }

/* Store fixtures ---------------------------------------------------------- */

static char *store_peer(sb_test_server *t, const char *name, const char *public_key, const char *address,
                        const char *host_id, const char *expire_at) {
    sb_wireguard_peer peer, created;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&created);
    sb_str_set(&peer.name, name);
    peer.name_len = strlen(peer.name);
    sb_str_set(&peer.private_key, "cHJpdmF0ZS1rZXktZml4dHVyZS1wcml2YXRlLWtleQ=");
    sb_str_set(&peer.public_key, public_key);
    sb_str_set(&peer.preshared_key, "cHJlc2hhcmVkLWtleS1maXh0dXJlLXByZXNoYXJlZA=");
    sb_str_set(&peer.address, address);
    if (host_id) sb_str_set(&peer.host_id, host_id);
    if (expire_at) sb_str_set(&peer.expire_at, expire_at);
    sb_err err = {0};
    char *id = NULL;
    if (sb_store_create_wireguard_peer(t->store, &peer, &created, &err) == 0) id = sb_strdup(created.id);
    else fprintf(stderr, "store peer failed: %s\n", err.msg);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_free(&created);
    return id;
}

static char *store_node(sb_test_server *t, const char *tag, const char *type, bool enabled, const char *config) {
    sb_proxy_record node, created;
    sb_proxy_record_init(&node);
    sb_proxy_record_init(&created);
    sb_str_set(&node.tag, tag);
    node.tag_len = strlen(node.tag);
    sb_str_set(&node.node_type, type);
    node.node_type_len = strlen(node.node_type);
    node.enabled = enabled;
    sb_str_set(&node.server, "proxy.example.com");
    node.server_len = strlen(node.server);
    node.server_port = 443;
    sbj_free(node.protocol_config);
    node.protocol_config = sbj_parse_cstr(config);
    sb_err err = {0};
    char *id = NULL;
    if (sb_store_create_proxy_node(t->store, &node, &created, &err) == 0) id = sb_strdup(created.id);
    else fprintf(stderr, "store node failed: %s\n", err.msg);
    sb_proxy_record_free(&node);
    sb_proxy_record_free(&created);
    return id;
}

static bool peer_enabled(sb_test_server *t, const char *id) {
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    sb_err err = {0};
    bool enabled = sb_store_find_wireguard_peer(t->store, id, &peer, &err) == 1 && peer.enabled;
    sb_wireguard_peer_free(&peer);
    return enabled;
}

static char *admin_id(sb_test_server *t) {
    sb_user_account admin;
    sb_user_account_init(&admin);
    sb_err err = {0};
    char *id = sb_store_find_user_by_username(t->store, "admin", &admin, &err) == 1 ? sb_strdup(admin.id) : NULL;
    sb_user_account_free(&admin);
    return id;
}

/* Number of one_time_links rows for (token, peer_id). */
static int one_time_link_rows(sb_test_server *t, const char *token, const char *peer_id) {
    sb_database *db = sb_store_database(t->store);
    sb_database_lock(db);
    sqlite3_stmt *stmt = NULL;
    int count = -1;
    if (sqlite3_prepare_v2(sb_database_handle(db),
                           "SELECT COUNT(*) FROM one_time_links WHERE id = ?1 AND peer_id = ?2 AND used = 0",
                           -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, peer_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sb_database_unlock(db);
    return count;
}

/* ======================================================================
 * /api/health, /api/system/...
 * ====================================================================== */

TEST(health_and_public_system_routes) {
    sb_test_server t;
    sb_test_response r = {0};
    REQUIRE(sb_test_server_start(&t) == 0);

    /* "health endpoint should identify the C++ service" -> the C service. */
    call(&t, &r, "GET", "/api/health", NULL, NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "service"), "sb-easy-c");
    CHECK_STR(str_of(r.json, "status"), "ok");
    CHECK_EQ_INT(sbj_obj_len(r.json), 2);
    CHECK(r.content_type && sb_starts_with(r.content_type, "application/json"));

    /* CORS on the health route (policy "https://allowed.example"). */
    const char *const allowed[] = {"Origin: https://allowed.example", NULL};
    call_h(&t, &r, "GET", "/api/health", NULL, ADMIN, allowed);
    CHECK_STR(r.allow_origin, "https://allowed.example");
    const char *const rejected[] = {"Origin: https://rejected.example", NULL};
    call_h(&t, &r, "GET", "/api/health", NULL, ADMIN, rejected);
    CHECK(r.allow_origin == NULL);

    /* "system status must remain public for health dashboards" */
    call(&t, &r, "GET", "/api/system/status", NULL, NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "status"), "running");
    CHECK_STR(str_of(r.json, "version"), "1.0.0");
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "wireguard"), "peer_count", -1), 0);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "sing_box"), "node_count", -1), 0);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "subscriptions"), "count", -1), 0);
    CHECK_EQ_INT(sbj_obj_len(r.json), 5);

    /* Administrative APIs reject requests without a JWT. */
    call(&t, &r, "GET", "/api/users", NULL, NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid or expired token");
    call(&t, &r, "GET", "/api/system/logs", NULL, NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid or expired token");
    call(&t, &r, "POST", "/api/system/migrate/wg-easy", NULL, NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid or expired token");

    /* "the legacy wg-easy migration placeholder must preserve its contract" */
    call(&t, &r, "POST", "/api/system/migrate/wg-easy", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "status"), "not_implemented");
    CHECK_STR(str_of(r.json, "message"),
              "wg-easy migration coming in a future update. Use manual import for now.");

    /* "system logs must expose the bounded server log buffer" */
    call(&t, &r, "GET", "/api/system/logs", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    const sbj *lines = sbj_get(r.json, "lines");
    CHECK(sbj_is_array(lines));
    CHECK(sbj_arr_len(lines) > 0);
    const sbj *line;
    SBJ_ARR_FOREACH(lines, i, line) CHECK(sbj_is_string(line) && line->v.str.len > 0);

    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ======================================================================
 * /api/auth/...
 * ====================================================================== */

TEST(auth_login_and_session) {
    sb_test_server t;
    sb_test_response r = {0};
    char *token = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    /* "the seeded administrator must be able to log in" */
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"admin\",\"password\":\"contract-admin-password\"}",
         NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "role"), "admin");
    CHECK_STR(str_of(r.json, "username"), "admin");
    CHECK(sbj_is_string(sbj_get(r.json, "token")));
    CHECK_EQ_INT(sbj_obj_len(r.json), 3);
    token = sb_strdup(str_of(r.json, "token"));
    sb_auth_claims claims = {0};
    CHECK(token && sb_auth_verify_token("contract-jwt-secret", token, &claims));
    CHECK_STR(claims.username, "admin");
    CHECK_STR(claims.role, "admin");
    sb_auth_claims_free(&claims);

    /* Username defaults to "admin" when absent or null. */
    call(&t, &r, "POST", "/api/auth/login", "{\"password\":\"contract-admin-password\"}", NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "username"), "admin");
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":null,\"password\":\"contract-admin-password\"}",
         NO_AUTH);
    CHECK_EQ_INT(r.status, 200);

    /* Credential and validation failures. */
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"admin\",\"password\":\"wrong\"}", NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid credentials");
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"nobody\",\"password\":\"contract-admin-password\"}",
         NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid credentials");
    call(&t, &r, "POST", "/api/auth/login", "[]", NO_AUTH);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", "/api/auth/login", "not json", NO_AUTH);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", "/api/auth/login", NULL, NO_AUTH);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":5,\"password\":\"x\"}", NO_AUTH);
    CHECK_ERROR(r, 400, "username must be a string");
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"admin\"}", NO_AUTH);
    CHECK_ERROR(r, 400, "password must be a non-empty string");
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"admin\",\"password\":\"\"}", NO_AUTH);
    CHECK_ERROR(r, 400, "password must be a non-empty string");
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"admin\",\"password\":7}", NO_AUTH);
    CHECK_ERROR(r, 400, "password must be a non-empty string");

    /* "session inspection must return verified JWT claims" */
    call(&t, &r, "GET", "/api/auth/session", NULL, token);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(r.json, "authenticated", false));
    CHECK_STR(str_of(r.json, "username"), "admin");
    CHECK_STR(str_of(r.json, "role"), "admin");
    CHECK_EQ_INT(sbj_obj_len(r.json), 3);
    call(&t, &r, "GET", "/api/auth/session", NULL, NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid or expired token");
    call(&t, &r, "GET", "/api/auth/session", NULL, "not-a-jwt");
    CHECK_ERROR(r, 401, "Invalid or expired token");
    char *foreign = sb_auth_create_token("another-secret", "id", "admin", "admin");
    call(&t, &r, "GET", "/api/auth/session", NULL, foreign);
    CHECK_ERROR(r, 401, "Invalid or expired token");
    free(foreign);
    const char *const basic[] = {"Authorization: Basic YWRtaW46YWRtaW4=", NULL};
    call_h(&t, &r, "GET", "/api/auth/session", NULL, NO_AUTH, basic);
    CHECK_ERROR(r, 401, "Invalid or expired token");

    free(token);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ======================================================================
 * /api/users*
 * ====================================================================== */

TEST(passwords_with_nul_create_login_and_reset) {
    sb_test_server t;
    sb_test_response r = {0};
    REQUIRE(sb_test_server_start(&t) == 0);
    call(&t, &r, "POST", "/api/users",
         "{\"username\":\"nul-password\",\"password\":\"pass\\u0000word\"}", ADMIN);
    REQUIRE(r.status == 200);
    char *path = sb_asprintf("/api/users/%s/password", str_of(r.json, "id"));
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"nul-password\",\"password\":\"pass\\u0000word\"}", NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"nul-password\",\"password\":\"pass\"}", NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid credentials");
    call(&t, &r, "POST", path, "{\"password\":\"new\\u0000password\"}", ADMIN);
    CHECK_SUCCESS(r);
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"nul-password\",\"password\":\"new\\u0000password\"}", NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"nul-password\",\"password\":\"new\"}", NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid credentials");
    free(path);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

TEST(usernames_with_nul_preserve_identity_session_and_audit) {
    sb_test_server t;
    sb_test_response r = {0};
    REQUIRE(sb_test_server_start(&t) == 0);
    const char *create = "{\"username\":\"admin\\u0000other\",\"password\":\"other-password\",\"role\":\"admin\"}";
    call(&t, &r, "POST", "/api/users", create, ADMIN);
    REQUIRE(r.status == 200);
    sbj *expected = sbj_strn("admin\0other", 11);
    CHECK(sbj_equal(sbj_get(r.json, "username"), expected));
    call(&t, &r, "POST", "/api/users", create, ADMIN);
    CHECK_ERROR(r, 409, "Username already exists");
    call(&t, &r, "POST", "/api/auth/login", create, NO_AUTH);
    REQUIRE(r.status == 200);
    CHECK(sbj_equal(sbj_get(r.json, "username"), expected));
    char *token = sb_strdup(str_of(r.json, "token"));
    call(&t, &r, "GET", "/api/auth/session", NULL, token);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_equal(sbj_get(r.json, "username"), expected));
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"admin\",\"password\":\"other-password\"}", NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid credentials");
    call(&t, &r, "GET", "/api/users", NULL, ADMIN);
    size_t matches = 0;
    const sbj *item;
    SBJ_ARR_FOREACH(r.json, i, item) {
        if (sbj_equal(sbj_get(item, "username"), expected)) ++matches;
    }
    CHECK_EQ_INT(matches, 1);
    call(&t, &r, "PUT", "/api/settings", "{\"general\":{\"app_name\":\"NUL actor\"}}", token);
    CHECK_EQ_INT(r.status, 200);
    call(&t, &r, "GET", "/api/users/audit", NULL, ADMIN);
    matches = 0;
    SBJ_ARR_FOREACH(r.json, i, item) {
        if (sbj_equal(sbj_get(item, "actor"), expected)) ++matches;
    }
    CHECK_EQ_INT(matches, 1);
    call(&t, &r, "POST", "/api/users",
         "{\"username\":\"\\u0000\",\"password\":\"leading-nul\"}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"\\u0000\",\"password\":\"leading-nul\"}", NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    sbj_free(expected);
    free(token);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

TEST(user_administration) {
    sb_test_server t;
    sb_test_response r = {0};
    char *viewer_id = NULL, *viewer_token = NULL, *self_id = NULL, *path = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    /* "administrators must be able to create viewers without leaking hashes" */
    call(&t, &r, "POST", "/api/users",
         "{\"username\":\"contract-viewer\",\"password\":\"viewer-password\",\"role\":\"viewer\"}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "role"), "viewer");
    CHECK_STR(str_of(r.json, "username"), "contract-viewer");
    CHECK(!sbj_has(r.json, "password_hash"));
    CHECK(sbj_is_string(sbj_get(r.json, "created_at")));
    CHECK_EQ_INT(sbj_obj_len(r.json), 4);
    viewer_id = sb_strdup(str_of(r.json, "id"));
    REQUIRE(viewer_id && *viewer_id);

    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"contract-viewer\",\"password\":\"viewer-password\"}",
         NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "role"), "viewer");
    viewer_token = sb_strdup(str_of(r.json, "token"));
    REQUIRE(viewer_token);

    /* Viewers keep read access but are blocked before mutations run (the
     * C++ contract uses /api/proxy/nodes; the admin group has equivalents). */
    call(&t, &r, "GET", "/api/settings", NULL, viewer_token);
    CHECK_EQ_INT(r.status, 200);
    call(&t, &r, "PUT", "/api/settings", "{\"general\":{\"app_name\":\"viewer\"}}", viewer_token);
    CHECK_ERROR(r, 403, "Viewer role is read-only");
    call(&t, &r, "POST", "/api/wireguard/peers", "{}", viewer_token);
    CHECK_ERROR(r, 403, "Viewer role is read-only");

    /* "user administration must require the admin role" */
    call(&t, &r, "GET", "/api/users", NULL, viewer_token);
    CHECK_ERROR(r, 403, "Admin role required");
    call(&t, &r, "GET", "/api/users/audit", NULL, viewer_token);
    CHECK_ERROR(r, 403, "Admin role required");

    call(&t, &r, "GET", "/api/users", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(r.json));
    CHECK_EQ_INT(sbj_arr_len(r.json), 2);
    const sbj *user;
    SBJ_ARR_FOREACH(r.json, i, user) {
        CHECK(!sbj_has(user, "password_hash"));
        CHECK_EQ_INT(sbj_obj_len(user), 4);
    }

    /* Creation validation, in the C++ order. */
    call(&t, &r, "POST", "/api/users", "[1]", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", "/api/users", "{\"password\":\"long-enough\"}", ADMIN);
    CHECK_ERROR(r, 400, "username must be a non-empty string");
    call(&t, &r, "POST", "/api/users", "{\"username\":\"someone\"}", ADMIN);
    CHECK_ERROR(r, 400, "password must be a non-empty string");
    call(&t, &r, "POST", "/api/users", "{\"username\":\"someone\",\"password\":\"long-enough\",\"role\":1}",
         ADMIN);
    CHECK_ERROR(r, 400, "role must be a string");
    call(&t, &r, "POST", "/api/users", "{\"username\":\"someone\",\"password\":\"abc\"}", ADMIN);
    CHECK_ERROR(r, 400, "Username required, password must be at least 4 characters");
    call(&t, &r, "POST", "/api/users", "{\"username\":\"  \\t \",\"password\":\"long-enough\"}", ADMIN);
    CHECK_ERROR(r, 400, "Username required, password must be at least 4 characters");
    call(&t, &r, "POST", "/api/users", "{\"username\":\"someone\",\"password\":\"long-enough\",\"role\":\"root\"}",
         ADMIN);
    CHECK_ERROR(r, 400, "Role must be admin or viewer");
    call(&t, &r, "POST", "/api/users", "{\"username\":\"contract-viewer\",\"password\":\"long-enough\"}", ADMIN);
    CHECK_ERROR(r, 409, "Username already exists");
    /* Role defaults to viewer; null role too. */
    call(&t, &r, "POST", "/api/users", "{\"username\":\"defaulted\",\"password\":\"long-enough\",\"role\":null}",
         ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "role"), "viewer");

    /* "administrators must be able to reset another user's password" */
    free(path);
    path = sb_asprintf("/api/users/%s/password", viewer_id);
    call(&t, &r, "POST", path, "{\"password\":\"replacement-password\"}", ADMIN);
    CHECK_SUCCESS(r);
    CHECK_EQ_INT(sbj_obj_len(r.json), 1);
    call(&t, &r, "POST", "/api/auth/login",
         "{\"username\":\"contract-viewer\",\"password\":\"replacement-password\"}", NO_AUTH);
    CHECK_EQ_INT(r.status, 200);
    call(&t, &r, "POST", "/api/auth/login", "{\"username\":\"contract-viewer\",\"password\":\"viewer-password\"}",
         NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid credentials");
    call(&t, &r, "POST", path, "{\"password\":\"abc\"}", ADMIN);
    CHECK_ERROR(r, 400, "Password must be at least 4 characters");
    call(&t, &r, "POST", path, "{}", ADMIN);
    CHECK_ERROR(r, 400, "password must be a non-empty string");
    call(&t, &r, "POST", path, "\"text\"", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", path, "{\"password\":\"replacement-password\"}", viewer_token);
    CHECK_ERROR(r, 403, "Viewer role is read-only");
    call(&t, &r, "POST", "/api/users/missing-user/password", "{\"password\":\"replacement-password\"}", ADMIN);
    CHECK_ERROR(r, 404, "User not found");

    /* "administrators must not delete their own account" */
    self_id = admin_id(&t);
    REQUIRE(self_id);
    free(path);
    path = sb_asprintf("/api/users/%s", self_id);
    call(&t, &r, "DELETE", path, NULL, ADMIN);
    CHECK_ERROR(r, 400, "You cannot delete your own account");

    /* "administrators must be able to remove another user" */
    free(path);
    path = sb_asprintf("/api/users/%s", viewer_id);
    call(&t, &r, "DELETE", path, NULL, ADMIN);
    CHECK_SUCCESS(r);
    call(&t, &r, "DELETE", "/api/users/does-not-exist", NULL, ADMIN);
    CHECK_SUCCESS(r);

    /* A second admin cannot remove the last remaining admin. */
    call(&t, &r, "POST", "/api/users", "{\"username\":\"second-admin\",\"password\":\"second-pass\",\"role\":\"admin\"}",
         ADMIN);
    CHECK_EQ_INT(r.status, 200);
    char *second_id = sb_strdup(str_of(r.json, "id"));
    char *second_token = sb_test_token(&t, second_id, "second-admin", "admin");
    free(path);
    path = sb_asprintf("/api/users/%s", self_id);
    call(&t, &r, "DELETE", path, NULL, second_token);
    CHECK_SUCCESS(r);
    call(&t, &r, "DELETE", "/api/users/unknown", NULL, second_token);
    CHECK_SUCCESS(r);
    free(path);
    path = sb_asprintf("/api/users/%s", second_id);
    char *other_token = sb_test_token(&t, "someone-else", "ghost", "admin");
    call(&t, &r, "DELETE", path, NULL, other_token);
    CHECK_ERROR(r, 400, "Cannot delete the last admin");
    free(other_token);
    free(second_token);
    free(second_id);

    /* "successful administrative mutations must be audit logged" */
    call(&t, &r, "GET", "/api/users/audit", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(r.json));
    bool created_logged = false, deleted_logged = false, failure_logged = false;
    const sbj *entry;
    SBJ_ARR_FOREACH(r.json, i, entry) {
        CHECK_EQ_INT(sbj_obj_len(entry), 5);
        CHECK(sbj_is_integer(sbj_get(entry, "id")));
        CHECK(sbj_is_string(sbj_get(entry, "ts")));
        if (sb_streq(str_of(entry, "actor"), "admin") && sb_streq(str_of(entry, "action"), "POST") &&
            sb_streq(str_of(entry, "target"), "/api/users"))
            created_logged = true;
        if (sb_streq(str_of(entry, "action"), "DELETE") &&
            sb_starts_with(str_of(entry, "target"), "/api/users/"))
            deleted_logged = true;
        if (sb_streq(str_of(entry, "target"), "/api/users/missing-user/password")) failure_logged = true;
    }
    CHECK(created_logged);
    CHECK(deleted_logged);
    CHECK(!failure_logged); /* only 2xx mutations are audited */

    free(path);
    free(self_id);
    free(viewer_id);
    free(viewer_token);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ======================================================================
 * /api/settings*
 * ====================================================================== */

TEST(settings_merge_and_mutation) {
    sb_test_server t;
    sb_test_response r = {0};
    REQUIRE(sb_test_server_start(&t) == 0);

    /* "settings must merge persisted values with runtime defaults" */
    call(&t, &r, "GET", "/api/settings", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    const sbj *wg = sbj_get(r.json, "wireguard_interface");
    CHECK_STR(str_of(wg, "interface"), "wg0");
    CHECK_EQ_INT(sbj_get_int(wg, "listen_port", -1), 51820);
    CHECK_STR(str_of(wg, "address"), "10.59.32.1/24");
    CHECK_STR(str_of(wg, "dns"), "10.59.32.1");
    CHECK_EQ_INT(sbj_get_int(wg, "mtu", -1), 1420);
    CHECK_STR(str_of(sbj_get(r.json, "general"), "app_name"), "sb-easy");
    CHECK(sbj_is_object(sbj_get(r.json, "singbox_connection")));

    /* "settings mutations must persist supported sections" */
    call(&t, &r, "PUT", "/api/settings", "{\"general\":{\"app_name\":\"contract-panel\"}}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(sbj_get(r.json, "general"), "app_name"), "contract-panel");
    CHECK_STR(str_of(sbj_get(r.json, "wireguard_interface"), "interface"), "wg0");

    /* Saved wireguard_interface members override the runtime values except
     * nulls; unknown sections are ignored. */
    call(&t, &r, "PUT", "/api/settings",
         "{\"wireguard_interface\":{\"listen_port\":51999,\"dns\":null,\"extra\":\"kept\"},\"bogus\":{\"x\":1}}",
         ADMIN);
    CHECK_EQ_INT(r.status, 200);
    wg = sbj_get(r.json, "wireguard_interface");
    CHECK_EQ_INT(sbj_get_int(wg, "listen_port", -1), 51999);
    CHECK_STR(str_of(wg, "dns"), "10.59.32.1");
    CHECK_STR(str_of(wg, "interface"), "wg0");
    CHECK_STR(str_of(wg, "extra"), "kept");
    CHECK(!sbj_has(r.json, "bogus"));
    call(&t, &r, "GET", "/api/settings", NULL, ADMIN);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "wireguard_interface"), "listen_port", -1), 51999);
    CHECK_STR(str_of(sbj_get(r.json, "general"), "app_name"), "contract-panel");

    /* A non-object saved section is replaced by the runtime view. */
    call(&t, &r, "PUT", "/api/settings", "{\"wireguard_interface\":[1,2]}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "wireguard_interface"), "listen_port", -1), 51820);

    call(&t, &r, "PUT", "/api/settings", "[]", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "PUT", "/api/settings", "", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");

    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

TEST(backup_restore_and_config_downloads) {
    sb_test_server t;
    sb_test_response r = {0};
    char *peer_id = NULL, *enabled_a = NULL, *enabled_b = NULL, *disabled = NULL, *path = NULL, *backup = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    /* Seed the same sections the C++ contract created over other routes:
     * three nodes (one disabled), one subscription, one WireGuard peer. */
    enabled_a = store_node(&t, "Node A", "shadowsocks", true, "{\"method\":\"aes-256-gcm\",\"password\":\"a\"}");
    enabled_b = store_node(&t, "Node B", "trojan", true, "{\"password\":\"b\"}");
    disabled = store_node(&t, "Node C", "shadowsocks", false, "{\"method\":\"aes-128-gcm\",\"password\":\"c\"}");
    REQUIRE(enabled_a && enabled_b && disabled);
    sb_subscription sub, created_sub;
    sb_subscription_init(&sub);
    sb_subscription_init(&created_sub);
    sb_str_set(&sub.name, "Fixture");
    sub.name_len = strlen(sub.name);
    sb_str_set(&sub.url, "http://127.0.0.1:9/fixture");
    sub.url_len = strlen(sub.url);
    sb_err err = {0};
    CHECK(sb_store_create_subscription(t.store, &sub, &created_sub, &err) == 0);
    sb_subscription_free(&sub);
    sb_subscription_free(&created_sub);
    peer_id = store_peer(&t, "Backup peer", "YmFja3VwLXB1YmxpYy1rZXktYmFja3VwLXB1YmxpYy0=", "10.59.32.2/24", NULL,
                         NULL);
    REQUIRE(peer_id);

    call(&t, &r, "GET", "/api/system/status", NULL, NO_AUTH);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "wireguard"), "peer_count", -1), 1);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "sing_box"), "node_count", -1), 3);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "subscriptions"), "count", -1), 1);

    /* "settings backup must export nodes, peers, subscriptions, and settings" */
    call(&t, &r, "GET", "/api/settings/backup", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_get_int(r.json, "version", -1), 1);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "proxy_nodes")), 3);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "wireguard_peers")), 1);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "subscriptions")), 1);
    CHECK(sbj_is_object(sbj_get(r.json, "app_settings")));
    CHECK(is_utc_timestamp(str_of(r.json, "exported_at")));
    CHECK_EQ_INT(sbj_obj_len(r.json), 6);
    backup = sb_strndup(r.body, r.body_len);

    /* "backup restore must idempotently upsert every exported data section" */
    call(&t, &r, "POST", "/api/settings/restore", backup, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    const sbj *restored = sbj_get(r.json, "restored");
    CHECK_EQ_INT(sbj_get_int(restored, "proxy_nodes", -1), 3);
    CHECK_EQ_INT(sbj_get_int(restored, "wireguard_peers", -1), 1);
    CHECK_EQ_INT(sbj_get_int(restored, "subscriptions", -1), 1);
    CHECK_EQ_INT(sbj_get_int(restored, "app_settings", -1), 3);
    call(&t, &r, "GET", "/api/system/status", NULL, NO_AUTH);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "sing_box"), "node_count", -1), 3);

    call(&t, &r, "POST", "/api/settings/restore", "{\"proxy_nodes\":{}}", ADMIN);
    CHECK_ERROR(r, 400, "backup row sections must be arrays");
    call(&t, &r, "POST", "/api/settings/restore", "{\"app_settings\":[]}", ADMIN);
    CHECK_ERROR(r, 400, "backup app_settings must be an object");
    call(&t, &r, "POST", "/api/settings/restore", "[]", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", "/api/settings/restore", "{}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_obj_len(sbj_get(r.json, "restored")), 4);
    /* nlohmann value() type errors surface as "Invalid JSON request". */
    call(&t, &r, "POST", "/api/settings/restore", "{\"subscriptions\":[{\"id\":\"s\",\"url\":\"u\",\"name\":5}]}",
         ADMIN);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number");

    /* "config download must render enabled proxy outbounds and auto group" */
    call(&t, &r, "GET", "/api/config/sing-box/outbounds", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(r.json));
    CHECK_EQ_INT(sbj_arr_len(r.json), 3);

    /* "full config must render the self profile with runtime Clash settings" */
    call(&t, &r, "GET", "/api/config/sing-box/full", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(sbj_get(r.json, "outbounds")));
    const sbj *clash = sbj_get(sbj_get(r.json, "experimental"), "clash_api");
    CHECK_STR(str_of(clash, "external_controller"), "127.0.0.1:9/local");
    CHECK_STR(str_of(clash, "secret"), "local-secret");

    /* Single outbound download. */
    free(path);
    path = sb_asprintf("/api/config/sing-box/outbound/%s", enabled_b);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "tag"), "Node B");
    CHECK_STR(str_of(r.json, "type"), "trojan");
    CHECK_STR(str_of(r.json, "server"), "proxy.example.com");
    CHECK_EQ_INT(sbj_get_int(r.json, "server_port", -1), 443);
    free(path);
    path = sb_asprintf("/api/config/sing-box/outbound/%s", disabled);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "tag"), "Node C");
    call(&t, &r, "GET", "/api/config/sing-box/outbound/missing", NULL, ADMIN);
    CHECK_ERROR(r, 404, "Node not found");

    free(path);
    free(backup);
    free(peer_id);
    free(enabled_a);
    free(enabled_b);
    free(disabled);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ======================================================================
 * /api/wireguard/...
 * ====================================================================== */

TEST(wireguard_peer_contract) {
    sb_test_server t;
    sb_test_response r = {0};
    char *peer_id = NULL, *second_id = NULL, *path = NULL, *private_key = NULL, *token = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    /* "WireGuard peer creation must generate keys and allocate an address" */
    call(&t, &r, "POST", "/api/wireguard/peers",
         "{\"name\":\"Contract phone\",\"notes\":\"created over HTTP\",\"quota_bytes\":1000000}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "address"), "10.59.32.2/24");
    CHECK_EQ_INT(str_len(str_of(r.json, "private_key")), 44);
    CHECK_EQ_INT(str_len(str_of(r.json, "public_key")), 44);
    CHECK_EQ_INT(str_len(str_of(r.json, "preshared_key")), 44);
    CHECK_STR(str_of(r.json, "name"), "Contract phone");
    CHECK_STR(str_of(r.json, "notes"), "created over HTTP");
    CHECK_EQ_INT(sbj_get_int(r.json, "quota_bytes", -1), 1000000);
    CHECK_STR(str_of(r.json, "dns"), "10.59.32.1");
    CHECK_STR(str_of(r.json, "allowed_ips"), "0.0.0.0/0, ::/0");
    CHECK_EQ_INT(sbj_get_int(r.json, "persistent_keepalive", -1), 25);
    CHECK(sbj_get_bool(r.json, "enabled", false));
    CHECK(sbj_is_null(sbj_get(r.json, "expire_at")) && sbj_has(r.json, "expire_at"));
    CHECK(sbj_is_null(sbj_get(r.json, "host_id")) && sbj_has(r.json, "host_id"));
    CHECK_EQ_INT(sbj_obj_len(r.json), 16);
    peer_id = sb_strdup(str_of(r.json, "id"));
    private_key = sb_strdup(str_of(r.json, "private_key"));
    REQUIRE(peer_id && *peer_id);

    /* "WireGuard peer listing must merge classification and expiry state" */
    call(&t, &r, "GET", "/api/wireguard/peers", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(sbj_arr_len(r.json), 1);
    const sbj *listed = sbj_arr_at(r.json, 0);
    CHECK_STR(str_of(listed, "kind"), "wg");
    CHECK(sbj_is_bool(sbj_get(listed, "expired")) && !sbj_get_bool(listed, "expired", true));
    CHECK(!sbj_has(listed, "host_name"));
    CHECK(!sbj_has(listed, "endpoint")); /* no live stats: `wg` is unavailable */
    CHECK_EQ_INT(sbj_obj_len(listed), 18);

    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s", peer_id);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "id"), peer_id);
    CHECK(!sbj_has(r.json, "kind"));

    /* "WireGuard peer updates must preserve omitted credentials" */
    call(&t, &r, "PUT", path, "{\"name\":\"Renamed phone\",\"persistent_keepalive\":15,\"allowed_ips\":\"10.0.0.0/8\"}",
         ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "name"), "Renamed phone");
    CHECK_EQ_INT(sbj_get_int(r.json, "persistent_keepalive", -1), 15);
    CHECK_STR(str_of(r.json, "allowed_ips"), "10.0.0.0/8");
    CHECK_STR(str_of(r.json, "private_key"), private_key);
    CHECK_STR(str_of(r.json, "notes"), "created over HTTP");
    CHECK_EQ_INT(sbj_get_int(r.json, "quota_bytes", -1), 1000000);

    /* "WireGuard disable/enable must persist" */
    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s/disable", peer_id);
    call(&t, &r, "POST", path, NULL, ADMIN);
    CHECK_SUCCESS(r);
    CHECK(!peer_enabled(&t, peer_id));
    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s/enable", peer_id);
    call(&t, &r, "POST", path, NULL, ADMIN);
    CHECK_SUCCESS(r);
    CHECK(peer_enabled(&t, peer_id));

    /* "WireGuard config download must contain the deployment endpoint" */
    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s/config", peer_id);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_CONTAINS(r.body, "Endpoint = vpn.example.com:51820");
    CHECK_CONTAINS(r.body, "# Client: Renamed phone\n");
    CHECK_CONTAINS(r.content_disposition, "Renamed_phone.conf");
    CHECK_STR(r.content_disposition, "attachment; filename=\"Renamed_phone.conf\"");
    CHECK(r.content_type && sb_starts_with(r.content_type, "application/octet-stream"));

    /* "WireGuard QR endpoint must return an SVG QR code" */
    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s/qr", peer_id);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(r.content_type && sb_starts_with(r.content_type, "image/svg+xml"));
    CHECK_CONTAINS(r.body, "<svg");

    /* "WireGuard one-time links must be persisted with a bounded expiry" */
    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s/one-time-link", peer_id);
    call(&t, &r, "POST", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    const char *url = str_of(r.json, "url");
    CHECK(url && sb_starts_with(url, "https://vpn.example.com/api/one-time/"));
    const char *expires = str_of(r.json, "expires_at");
    CHECK(is_utc_timestamp(expires));
    int64_t expires_unix = 0;
    CHECK(expires && sb_parse_datetime(expires, &expires_unix) == 0);
    int64_t delta = expires_unix - sb_unix_now();
    CHECK(delta >= 290 && delta <= 301);
    CHECK_EQ_INT(sbj_obj_len(r.json), 2);
    if (url && sb_starts_with(url, "https://vpn.example.com/api/one-time/")) {
        token = sb_strdup(url + strlen("https://vpn.example.com/api/one-time/"));
        CHECK(is_lower_hex(token, 32));
        CHECK_EQ_INT(one_time_link_rows(&t, token, peer_id), 1);
    }

    /* "disabled WireGuard runtime should expose empty stats and safe sync" */
    call(&t, &r, "GET", "/api/wireguard/stats", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(sbj_get(r.json, "peers")));
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "peers")), 0);
    call(&t, &r, "POST", "/api/wireguard/sync", NULL, ADMIN);
    CHECK_SUCCESS(r);

    /* "system status must report persisted WireGuard peers" */
    call(&t, &r, "GET", "/api/system/status", NULL, NO_AUTH);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "wireguard"), "peer_count", -1), 1);

    /* Explicit fields on create; the next free address is allocated. */
    call(&t, &r, "POST", "/api/wireguard/peers",
         "{\"name\":\"  Tablet  \",\"dns\":\"1.1.1.1\",\"persistent_keepalive\":0,\"allowed_ips\":\"10.59.32.0/24\","
         "\"expire_at\":\"2999-01-01T00:00:00Z\",\"notes\":7}",
         ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "name"), "Tablet");
    CHECK_STR(str_of(r.json, "address"), "10.59.32.3/24");
    CHECK_STR(str_of(r.json, "dns"), "1.1.1.1");
    CHECK_EQ_INT(sbj_get_int(r.json, "persistent_keepalive", -1), 0);
    CHECK_STR(str_of(r.json, "allowed_ips"), "10.59.32.0/24");
    CHECK_STR(str_of(r.json, "expire_at"), "2999-01-01T00:00:00Z");
    CHECK(sbj_is_null(sbj_get(r.json, "notes")));
    second_id = sb_strdup(str_of(r.json, "id"));
    call(&t, &r, "POST", "/api/wireguard/peers", "{\"name\":\"Fixed\",\"address\":\"10.59.32.3/24\"}", ADMIN);
    CHECK_ERROR(r, 409, "WireGuard address already exists");
    call(&t, &r, "POST", "/api/wireguard/peers", "{\"name\":\"Negative\",\"quota_bytes\":-1}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid WireGuard keepalive or quota");

    /* Delete removes the peer. */
    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s", second_id);
    call(&t, &r, "DELETE", path, NULL, ADMIN);
    CHECK_SUCCESS(r);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_ERROR(r, 404, "Peer not found");
    call(&t, &r, "DELETE", path, NULL, ADMIN);
    CHECK_ERROR(r, 404, "Peer not found");
    call(&t, &r, "GET", "/api/system/status", NULL, NO_AUTH);
    CHECK_EQ_INT(sbj_get_int(sbj_get(r.json, "wireguard"), "peer_count", -1), 1);

    free(token);
    free(path);
    free(peer_id);
    free(second_id);
    free(private_key);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

TEST(wireguard_validation_and_missing_peers) {
    sb_test_server t;
    sb_test_response r = {0};
    char *peer_id = NULL, *path = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    static const char *const missing[][2] = {
        {"GET", "/api/wireguard/peers/missing"},
        {"PUT", "/api/wireguard/peers/missing"},
        {"DELETE", "/api/wireguard/peers/missing"},
        {"POST", "/api/wireguard/peers/missing/enable"},
        {"POST", "/api/wireguard/peers/missing/disable"},
        {"GET", "/api/wireguard/peers/missing/config"},
        {"GET", "/api/wireguard/peers/missing/qr"},
        {"POST", "/api/wireguard/peers/missing/one-time-link"},
    };
    for (size_t i = 0; i < sizeof missing / sizeof *missing; ++i) {
        call(&t, &r, missing[i][0], missing[i][1], strcmp(missing[i][0], "PUT") == 0 ? "{}" : NULL, ADMIN);
        CHECK_ERROR(r, 404, "Peer not found");
    }

    /* The body is validated first on create. */
    call(&t, &r, "POST", "/api/wireguard/peers", "[]", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "POST", "/api/wireguard/peers", "{}", ADMIN);
    CHECK_ERROR(r, 400, "name must be a non-empty string");
    call(&t, &r, "POST", "/api/wireguard/peers", "{\"name\":\"x\",\"dns\":5}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number");
    call(&t, &r, "POST", "/api/wireguard/peers", "{\"name\":\"x\",\"persistent_keepalive\":\"25\"}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be number, but is string");
    call(&t, &r, "POST", "/api/wireguard/peers", "{\"name\":\"x\",\"allowed_ips\":null}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is null");

    /* Update validation on an existing peer (created through the store so
     * this does not depend on key generation). */
    peer_id = store_peer(&t, "Stored", "c3RvcmVkLXB1YmxpYy1rZXktc3RvcmVkLXB1YmxpYy0=", "10.59.32.7/24", NULL, NULL);
    REQUIRE(peer_id);
    path = sb_asprintf("/api/wireguard/peers/%s", peer_id);
    call(&t, &r, "PUT", path, "[]", ADMIN);
    CHECK_ERROR(r, 400, "Request body must be a JSON object");
    call(&t, &r, "PUT", path, "{\"name\":5}", ADMIN);
    CHECK_ERROR(r, 400, "name must be a string");
    call(&t, &r, "PUT", path, "{\"dns\":[]}", ADMIN);
    CHECK_ERROR(r, 400, "dns must be a string");
    call(&t, &r, "PUT", path, "{\"enabled\":\"yes\"}", ADMIN);
    CHECK_ERROR(r, 400, "enabled must be a boolean");
    call(&t, &r, "PUT", path, "{\"allowed_ips\":1}", ADMIN);
    CHECK_ERROR(r, 400, "allowed_ips must be a string");
    call(&t, &r, "PUT", path, "{\"persistent_keepalive\":\"x\"}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be number, but is string");
    call(&t, &r, "PUT", path, "{\"quota_bytes\":true}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be number, but is boolean");
    call(&t, &r, "PUT", path, "{\"persistent_keepalive\":70000}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid WireGuard peer");
    call(&t, &r, "PUT", path, "{\"name\":\"\"}", ADMIN);
    CHECK_ERROR(r, 400, "Invalid WireGuard peer");

    /* Nulls are ignored, non-string expire_at/notes leave values untouched,
     * booleans/floats convert like nlohmann get<int32_t>(). */
    call(&t, &r, "PUT", path,
         "{\"name\":null,\"dns\":null,\"enabled\":false,\"persistent_keepalive\":true,\"quota_bytes\":12.9,"
         "\"expire_at\":\"2000-01-01T00:00:00Z\",\"notes\":\"n\"}",
         ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "name"), "Stored");
    CHECK_STR(str_of(r.json, "dns"), "10.59.32.1");
    CHECK(!sbj_get_bool(r.json, "enabled", true));
    CHECK_EQ_INT(sbj_get_int(r.json, "persistent_keepalive", -1), 1);
    CHECK_EQ_INT(sbj_get_int(r.json, "quota_bytes", -1), 12);
    CHECK_STR(str_of(r.json, "expire_at"), "2000-01-01T00:00:00Z");
    CHECK_STR(str_of(r.json, "notes"), "n");
    call(&t, &r, "PUT", path, "{\"expire_at\":null,\"notes\":5,\"persistent_keepalive\":null}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(str_of(r.json, "expire_at"), "2000-01-01T00:00:00Z");
    CHECK_STR(str_of(r.json, "notes"), "n");
    CHECK_EQ_INT(sbj_get_int(r.json, "persistent_keepalive", -1), 1);

    call(&t, &r, "GET", "/api/wireguard/peers", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_get_bool(sbj_arr_at(r.json, 0), "expired", false));

    free(path);
    free(peer_id);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

TEST(wireguard_live_stats_and_agent_peers) {
    sb_test_server t;
    sb_test_response r = {0};
    char *wg_id = NULL, *agent_id = NULL, *orphan_id = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    static const char key_a[] = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
    static const char key_b[] = "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=";
    static const char key_c[] = "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=";
    wg_id = store_peer(&t, "Laptop", key_a, "10.59.32.2/24", NULL, NULL);
    agent_id = store_peer(&t, "Self agent", key_b, "10.59.32.3/24", "self", "2000-01-01T00:00:00Z");
    orphan_id = store_peer(&t, "Orphan", key_c, "10.59.32.4/24", "deleted-host", NULL);
    REQUIRE(wg_id && agent_id && orphan_id);

    /* `wg show wg0 dump`: interface line, then peer lines. */
    char *dump = sb_asprintf("c2VydmVy\tc2VydmVyLXB1Yg==\t51820\toff\n"
                             "%s\t(none)\t203.0.113.7:51820\t10.59.32.2/32\t1700000000\t1234\t5678\t25\n"
                             "%s\t(none)\t(none)\t10.59.32.3/32\t0\t0\t0\toff\n"
                             "unknown-key\t(none)\t198.51.100.1:1\t10.59.32.99/32\t1\t2\t3\toff\n",
                             key_a, key_b);
    REQUIRE(sb_write_file(fake_wg_dump, dump, strlen(dump)) == 0);
    free(dump);

    call(&t, &r, "GET", "/api/wireguard/peers", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    REQUIRE(sbj_arr_len(r.json) == 3);
    const sbj *a = sbj_arr_at(r.json, 0), *b = sbj_arr_at(r.json, 1), *c = sbj_arr_at(r.json, 2);
    CHECK_STR(str_of(a, "kind"), "wg");
    CHECK(!sbj_has(a, "host_name"));
    CHECK_STR(str_of(a, "endpoint"), "203.0.113.7:51820");
    CHECK_EQ_INT(sbj_get_int(a, "latest_handshake", -1), 1700000000);
    CHECK_EQ_INT(sbj_get_int(a, "transfer_rx", -1), 1234);
    CHECK_EQ_INT(sbj_get_int(a, "transfer_tx", -1), 5678);
    CHECK_STR(str_of(b, "kind"), "agent");
    CHECK_STR(str_of(b, "host_name"), "This server");
    CHECK(sbj_get_bool(b, "expired", false));
    CHECK(sbj_has(b, "endpoint") && sbj_is_null(sbj_get(b, "endpoint")));
    CHECK(sbj_has(b, "latest_handshake") && sbj_is_null(sbj_get(b, "latest_handshake")));
    CHECK_EQ_INT(sbj_get_int(b, "transfer_rx", -1), 0);
    CHECK_STR(str_of(c, "kind"), "agent");
    CHECK(sbj_has(c, "host_name") && sbj_is_null(sbj_get(c, "host_name")));
    CHECK(!sbj_has(c, "endpoint"));

    call(&t, &r, "GET", "/api/wireguard/stats", NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    const sbj *peers = sbj_get(r.json, "peers");
    CHECK_EQ_INT(sbj_arr_len(peers), 3);
    const sbj *first = sbj_arr_at(peers, 0);
    CHECK_STR(str_of(first, "public_key"), key_a);
    CHECK_STR(str_of(first, "endpoint"), "203.0.113.7:51820");
    CHECK_EQ_INT(sbj_get_int(first, "latest_handshake", -1), 1700000000);
    CHECK_EQ_INT(sbj_obj_len(first), 5);

    remove(fake_wg_dump);
    call(&t, &r, "GET", "/api/wireguard/stats", NULL, ADMIN);
    CHECK_EQ_INT(sbj_arr_len(sbj_get(r.json, "peers")), 0);

    free(wg_id);
    free(agent_id);
    free(orphan_id);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

TEST(wireguard_client_config_is_exact) {
    sb_test_server t;
    sb_test_response r = {0};
    char *peer_id = NULL, *path = NULL;
    REQUIRE(sb_test_server_start(&t) == 0);

    sbj *server_key = sbj_parse_cstr("{\"private_key\":\"c2VydmVyLXByaXZhdGU=\","
                                     "\"public_key\":\"U0VSVkVSLVBVQkxJQy1LRVktU0VSVkVSLVBVQkxJQy0=\"}");
    sb_err err = {0};
    CHECK(sb_store_set_app_setting(t.store, "wg_server_key", server_key, &err) == 0);
    sbj_free(server_key);
    peer_id = store_peer(&t, "Fixed peer one", "Zml4ZWQtcHVibGljLWtleS1maXhlZC1wdWJsaWMta2U=", "10.59.32.9/24", NULL,
                         NULL);
    REQUIRE(peer_id);

    path = sb_asprintf("/api/wireguard/peers/%s/config", peer_id);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "# Client: Fixed peer one\n"
                      "[Interface]\n"
                      "PrivateKey = cHJpdmF0ZS1rZXktZml4dHVyZS1wcml2YXRlLWtleQ=\n"
                      "Address = 10.59.32.9/24\n"
                      "DNS = 10.59.32.1\n"
                      "MTU = 1420\n"
                      "\n"
                      "[Peer]\n"
                      "PublicKey = U0VSVkVSLVBVQkxJQy1LRVktU0VSVkVSLVBVQkxJQy0=\n"
                      "PresharedKey = cHJlc2hhcmVkLWtleS1maXh0dXJlLXByZXNoYXJlZA=\n"
                      "AllowedIPs = 0.0.0.0/0, ::/0\n"
                      "Endpoint = vpn.example.com:51820\n"
                      "PersistentKeepalive = 25\n");
    CHECK_STR(r.content_disposition, "attachment; filename=\"Fixed_peer_one.conf\"");

    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s/qr", peer_id);
    call(&t, &r, "GET", path, NULL, ADMIN);
    CHECK_EQ_INT(r.status, 200);
    CHECK(r.content_type && sb_starts_with(r.content_type, "image/svg+xml"));
    CHECK_CONTAINS(r.body, "<svg");
    CHECK_CONTAINS(r.body, "</svg>");

    free(path);
    path = sb_asprintf("/api/wireguard/peers/%s", peer_id);
    call(&t, &r, "PUT", path, "{\"name\":\"Fixed\\u0000peer\"}", ADMIN);
    CHECK_EQ_INT(r.status, 200);
    sbj *expected_name = sbj_strn("Fixed\0peer", 10);
    CHECK(sbj_equal(sbj_get(r.json, "name"), expected_name));
    sbj_free(expected_name);
    /* libcurl rejects NUL in the filename header (also emitted by C++).
     * The byte-exact body/header contract is checked by control_plane_e2e. */

    free(path);
    free(peer_id);
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* The C++ server registers no /api/one-time/... handler: those paths get the
 * JWT advice and then the structured API 404. */
TEST(one_time_paths_are_not_routed) {
    sb_test_server t;
    sb_test_response r = {0};
    REQUIRE(sb_test_server_start(&t) == 0);

    call(&t, &r, "GET", "/api/one-time/0123456789abcdef0123456789abcdef", NULL, ADMIN);
    CHECK_ERROR(r, 404, "API route not found");
    call(&t, &r, "GET", "/api/one-time/0123456789abcdef0123456789abcdef", NULL, NO_AUTH);
    CHECK_ERROR(r, 401, "Invalid or expired token");

    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}
