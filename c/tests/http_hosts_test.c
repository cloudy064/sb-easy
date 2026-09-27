/* Contract tests for the panel's /api/hosts*, /api/devices/... and
 * /api/agent/... routes (c/src/http_routes_hosts.c). The first test ports the
 * hosts/profile/agent assertions of cpp/tests/http_server_test.cpp in their
 * original order; the rest pin the C++ validation messages, status codes and
 * edge cases handler by handler. */
#include "test.h"

#include "http_test_support.h"
#include "sb/config_etag.h"
#include "sb/wireguard.h"

/* ---- helpers ------------------------------------------------------------ */

/* Dotted JSON path lookup: "route.rules.0.outbound". Borrowed or NULL. */
static const sbj *jpath(const sbj *root, const char *path) {
    const sbj *current = root;
    char *copy = sb_strdup(path);
    char *save = NULL;
    for (char *segment = strtok_r(copy, ".", &save); segment && current; segment = strtok_r(NULL, ".", &save)) {
        if (sbj_is_array(current)) {
            char *end = NULL;
            unsigned long index = strtoul(segment, &end, 10);
            current = (end && *end == '\0') ? sbj_arr_at(current, index) : NULL;
        } else {
            current = sbj_get(current, segment);
        }
    }
    free(copy);
    return current;
}

static const char *jstr(const sbj *root, const char *path) {
    const sbj *value = jpath(root, path);
    return sbj_is_string(value) ? value->v.str.ptr : NULL;
}

static long long jint(const sbj *root, const char *path) {
    const sbj *value = jpath(root, path);
    return sbj_is_number(value) ? (long long)sbj_as_int(value, -1) : -999999;
}

static int jbool(const sbj *root, const char *path) {
    const sbj *value = jpath(root, path);
    return sbj_is_bool(value) ? (value->v.b ? 1 : 0) : -1;
}

static size_t jlen(const sbj *root, const char *path) {
    const sbj *value = path ? jpath(root, path) : root;
    return sbj_is_array(value) ? sbj_arr_len(value) : (size_t)-1;
}

/* Compact dump of a JSON value at `path` (malloc'd, "(missing)" if absent). */
static char *jdump(const sbj *root, const char *path) {
    const sbj *value = path ? jpath(root, path) : root;
    return value ? sbj_dump(value, -1) : sb_strdup("(missing)");
}

#define CHECK_JSON(root, path, expected)                                   \
    do {                                                                   \
        char *_dumped = jdump((root), (path));                             \
        CHECK_STR(_dumped, (expected));                                    \
        free(_dumped);                                                     \
    } while (0)

/* Admin request (default token). */
static sb_test_response call(sb_test_server *t, const char *method, const char *path, const char *body) {
    sb_test_response r;
    sb_test_request_ex(t, method, path, body, NULL, NULL, &r);
    return r;
}

/* Request with an explicit bearer token ("" -> no Authorization header). */
static sb_test_response call_as(sb_test_server *t, const char *token, const char *method, const char *path,
                                const char *body) {
    sb_test_response r;
    sb_test_request_ex(t, method, path, body, token, NULL, &r);
    return r;
}

/* Request with one extra header line. */
static sb_test_response call_with(sb_test_server *t, const char *token, const char *header, const char *method,
                                  const char *path, const char *body) {
    const char *headers[] = {header, NULL};
    sb_test_response r;
    sb_test_request_ex(t, method, path, body, token, headers, &r);
    return r;
}

#define CHECK_ERROR(resp, code, message)                                   \
    do {                                                                   \
        CHECK_EQ_INT((resp).status, (code));                               \
        CHECK_STR(jstr((resp).json, "error"), (message));                  \
    } while (0)

static int find_host(sb_test_server *t, const char *id, sb_host *out) {
    sb_err err = {0};
    return sb_store_find_host(t->store, id, out, &err);
}

static char *host_token(sb_test_server *t, const char *id) {
    sb_host host;
    sb_host_init(&host);
    char *token = find_host(t, id, &host) == 1 ? sb_strdup(host.agent_token) : NULL;
    sb_host_free(&host);
    return token;
}

static size_t peer_count(sb_test_server *t) {
    sb_wireguard_peer_vec peers = {0};
    sb_err err = {0};
    size_t count = sb_store_list_wireguard_peers(t->store, &peers, &err) == 0 ? peers.len : (size_t)-1;
    sb_wireguard_peer_vec_free(&peers);
    return count;
}

static size_t pending_commands(sb_test_server *t, const char *host_id) {
    sb_host_command_vec commands = {0};
    sb_err err = {0};
    size_t count = sb_store_list_host_commands(t->store, host_id, true, &commands, &err) == 0 ? commands.len
                                                                                              : (size_t)-1;
    sb_host_command_vec_free(&commands);
    return count;
}

static int execute_sql(sb_test_server *t, const char *sql) {
    sb_err err = {0};
    int rc = sb_database_execute(sb_store_database(t->store), sql, &err);
    if (rc != 0) fprintf(stderr, "  SQL failed: %s\n", err.msg);
    return rc;
}

/* Creates a host through the API and returns its id (malloc'd). */
static char *create_host(sb_test_server *t, const char *body) {
    sb_test_response r = call(t, "POST", "/api/hosts", body);
    char *id = r.status == 200 ? sb_strdup(jstr(r.json, "id")) : NULL;
    if (!id) fprintf(stderr, "  host creation failed: %ld %s\n", r.status, r.body ? r.body : "");
    sb_test_response_free(&r);
    return id;
}

/* The "Contract phone" peer the C++ contract created over
 * /api/wireguard/peers before exercising hosts (it owns 10.59.32.2). */
static void prepare_contract_peer(sb_store *store, void *user) {
    (void)user;
    sb_err err = {0};
    sb_wireguard_keypair keys = {0};
    if (sb_wireguard_generate_keypair(&keys, &err) != 0) {
        fprintf(stderr, "  keypair generation failed: %s\n", err.msg);
        return;
    }
    sb_wireguard_peer peer, created;
    sb_wireguard_peer_init(&peer);
    sb_wireguard_peer_init(&created);
    sb_str_set(&peer.name, "Contract phone");
    peer.name_len = strlen(peer.name);
    sb_str_set(&peer.private_key, keys.private_key);
    sb_str_set(&peer.public_key, keys.public_key);
    sb_str_set(&peer.address, "10.59.32.2/24");
    peer.quota_bytes = 1000000;
    if (sb_store_create_wireguard_peer(store, &peer, &created, &err) != 0)
        fprintf(stderr, "  peer creation failed: %s\n", err.msg);
    sb_wireguard_peer_free(&peer);
    sb_wireguard_peer_free(&created);
    sb_wireguard_keypair_free(&keys);
}

static const char *const contract_rule_script =
    "\nfunction buildRules(context) {\n"
    "  return [{\n"
    "    domain_suffix: [\".example.com\"],\n"
    "    outbound: context.outboundTags.includes(\"direct\") ? \"direct\" : \"block\"\n"
    "  }];\n"
    "}\n";

/* {"rule_script": <script>, ...extra}: JSON-escapes the script. */
static char *with_script(const char *prefix, const char *script, const char *suffix) {
    sbj *value = sbj_str(script);
    char *escaped = sbj_dump(value, -1);
    sbj_free(value);
    char *out = sb_asprintf("%s%s%s", prefix, escaped, suffix);
    free(escaped);
    return out;
}

/* ---- the C++ contract (hosts / profiles / devices / agent) --------------- */

TEST(hosts_contract) {
    sb_test_server t;
    REQUIRE(sb_test_server_start_ex(&t, prepare_contract_peer, NULL, NULL) == 0);
    REQUIRE(peer_count(&t) == 1);
    sb_test_response r;

    r = call_as(&t, "", "GET", "/api/hosts", NULL);
    CHECK_EQ_INT(r.status, 401); /* administrative APIs must reject requests without a JWT */
    sb_test_response_free(&r);
    {
        const char *preflight[] = {"Origin: https://allowed.example", "Access-Control-Request-Method: GET",
                                   "Access-Control-Request-Headers: authorization,content-type", NULL};
        sb_test_request_ex(&t, "OPTIONS", "/api/hosts", NULL, NULL, preflight, &r);
        CHECK_EQ_INT(r.status, 204); /* CORS preflight completes before JWT authentication */
        CHECK_STR(r.allow_origin, "https://allowed.example");
        sb_test_response_free(&r);
    }

    r = call(&t, "GET", "/api/hosts/profiles", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(r.json) && sbj_arr_len(r.json) > 0); /* profile list includes the seeded default */
    CHECK(sbj_is_string(jpath(r.json, "0.template")));      /* Rust string template contract */
    sb_test_response_free(&r);

    char *body = with_script("{\"rule_script\":", contract_rule_script,
                             ",\"context\":{\"host\":{\"id\":\"preview\",\"name\":\"Preview\"},"
                             "\"outboundTags\":[\"direct\",\"block\"],\"currentRules\":[]}}");
    r = call(&t, "POST", "/api/hosts/rule-script/test", body);
    free(body);
    CHECK_EQ_INT(r.status, 200); /* rule script preview executes unsaved QuickJS source */
    CHECK_EQ_INT(jbool(r.json, "success"), 1);
    CHECK_EQ_INT(jint(r.json, "count"), 1);
    CHECK_STR(jstr(r.json, "rules.0.outbound"), "direct");
    sb_test_response_free(&r);

    r = call(&t, "POST", "/api/hosts/rule-script/test",
             "{\"rule_script\":\"function buildRules() { throw new Error('bad'); }\"}");
    CHECK_EQ_INT(r.status, 422); /* preview exposes bounded execution errors */
    CHECK_STR(jstr(r.json, "kind"), "rule_script");
    sb_test_response_free(&r);

    body = with_script("{\"name\":\"Scripted profile\",\"template\":{\"route\":{\"rules\":[],\"final\":\"direct\"}},"
                       "\"rule_script\":",
                       contract_rule_script, ",\"rule_script_enabled\":true}");
    r = call(&t, "POST", "/api/hosts/profiles", body);
    free(body);
    CHECK_EQ_INT(r.status, 200); /* profile creation succeeds */
    char *profile_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(profile_id);

    char *path = sb_asprintf("/api/hosts/profiles/%s", profile_id);
    r = call(&t, "PUT", path,
             "{\"name\":\"Renamed scripted profile\",\"template\":{\"route\":{\"rules\":[],\"final\":\"direct\"}}}");
    free(path);
    CHECK_EQ_INT(r.status, 200); /* updates preserve omitted script fields */
    CHECK_EQ_INT(jbool(r.json, "rule_script_enabled"), 1);
    CHECK_STR(jstr(r.json, "rule_script"), contract_rule_script);
    sb_test_response_free(&r);

    body = sb_asprintf("{\"name\":\"HTTP test host\",\"capabilities\":{\"runs_singbox\":true,\"is_wg_member\":false,"
                       "\"is_wg_hub\":false,\"is_self\":false},\"profile_id\":\"%s\",\"clash_secret\":\"hidden\"}",
                       profile_id);
    r = call(&t, "POST", "/api/hosts", body);
    free(body);
    CHECK_EQ_INT(r.status, 200);
    CHECK(!sbj_has(r.json, "agent_token")); /* device creation must not expose its credential */
    CHECK(!sbj_has(r.json, "clash_secret")); /* nor the Clash secret */
    char *host_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(host_id);
    char *original_token = host_token(&t, host_id);
    REQUIRE(original_token && *original_token);

    path = sb_asprintf("/api/devices/%s/enrollment-codes", host_id);
    r = call(&t, "POST", path, NULL);
    free(path);
    CHECK_EQ_INT(r.status, 200); /* complete device enrollment payload */
    CHECK_STR(jstr(r.json, "server"), "https://panel.example.com");
    CHECK(jstr(r.json, "code") && strlen(jstr(r.json, "code")) == 64);
    CHECK(sb_starts_with(jstr(r.json, "enrollment_uri"), "sbeasy://enroll?server=https%3A%2F%2F"));
    CHECK_CONTAINS(jstr(r.json, "qr_svg"), "<svg");
    char *enrollment_code = sb_strdup(jstr(r.json, "code"));
    sb_test_response_free(&r);
    REQUIRE(enrollment_code);

    body = sb_asprintf("{\"code\":\"%s\",\"device\":{\"platform\":\"linux\",\"agent_version\":\"sb-easy-cpp-agent/test\","
                       "\"core_version\":\"1.13.12\",\"install_id\":\"device-contract\",\"hostname\":\"Contract Device\"}}",
                       enrollment_code);
    r = call_as(&t, "", "POST", "/api/devices/enroll", body);
    free(body);
    CHECK_EQ_INT(r.status, 200); /* devices redeem without admin auth */
    CHECK_STR(jstr(r.json, "host_id"), host_id);
    CHECK_STR(jstr(r.json, "agent_token"), original_token);
    CHECK_STR(jstr(r.json, "profile.id"), profile_id);
    sb_test_response_free(&r);

    body = sb_asprintf("{\"code\":\"%s\",\"device\":{}}", enrollment_code);
    r = call_as(&t, "", "POST", "/api/devices/enroll", body);
    free(body);
    CHECK_EQ_INT(r.status, 400); /* codes are single use */
    sb_test_response_free(&r);

    sb_host host;
    sb_host_init(&host);
    CHECK(find_host(&t, host_id, &host) == 1); /* enrollment persists device metadata */
    CHECK_STR(sbj_get_str(host.capabilities, "platform", NULL), "linux");
    CHECK_STR(sbj_get_str(host.capabilities, "install_id", NULL), "device-contract");
    sb_host_free(&host);

    path = sb_asprintf("/api/hosts/%s/enrollment-codes", host_id);
    r = call(&t, "POST", path, NULL);
    free(path);
    CHECK_EQ_INT(r.status, 200); /* the previous enrollment-code path stays compatible */
    char *legacy_code = sb_strdup(jstr(r.json, "code"));
    sb_test_response_free(&r);
    REQUIRE(legacy_code);
    body = sb_asprintf("{\"code\":\"%s\",\"device\":{\"platform\":\"android\"}}", legacy_code);
    r = call_as(&t, "", "POST", "/api/agent/enroll", body);
    free(body);
    CHECK_EQ_INT(r.status, 200); /* released Android apps keep their enrollment alias */
    sb_test_response_free(&r);

    /* Android agents receive their intranet endpoint through the same
     * authenticated config API with a direct control-plane route. */
    r = call_as(&t, original_token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "endpoints.0.type"), "wireguard");
    CHECK(!jpath(r.json, "experimental.clash_api"));
    CHECK_STR(jstr(r.json, "route.rules.0.outbound"), "direct");
    CHECK_JSON(r.json, "route.rules.0.domain", "[\"panel.example.com\"]");
    CHECK(jstr(r.json, "endpoints.0.tag") &&
          sb_streq(jstr(r.json, "route.rules.1.outbound"), jstr(r.json, "endpoints.0.tag")));
    CHECK_JSON(r.json, "route.rules.1.ip_cidr", "[\"10.59.32.0/24\"]");
    sb_test_response_free(&r);
    sb_host_init(&host);
    CHECK(find_host(&t, host_id, &host) == 1 && host.wg_address); /* one device identity provisioned */
    sb_host_free(&host);

    path = sb_asprintf("/api/hosts/%s", host_id);
    r = call(&t, "PUT", path,
             "{\"capabilities\":{\"runs_singbox\":true,\"is_wg_member\":true,\"is_wg_hub\":false,\"is_self\":false}}");
    CHECK_EQ_INT(r.status, 200); /* enabling WG membership provisions reachback identity */
    CHECK(jstr(r.json, "wg_address") != NULL);
    CHECK(jstr(r.json, "wg_public_key") != NULL);
    CHECK(sb_starts_with(jstr(r.json, "clash_api"), "http://10.59.32."));
    sb_test_response_free(&r);

    char *wg_path = sb_asprintf("/api/hosts/%s/wg-config", host_id);
    r = call(&t, "GET", wg_path, NULL);
    free(wg_path);
    CHECK_EQ_INT(r.status, 200); /* managed hosts download their intranet config */
    CHECK_CONTAINS(r.body, "# Hub (central server)");
    CHECK_CONTAINS(r.body, "Endpoint = vpn.example.com:51820");
    sb_test_response_free(&r);

    r = call(&t, "PUT", path,
             "{\"capabilities\":{\"runs_singbox\":true,\"is_wg_member\":false,\"is_wg_hub\":false,\"is_self\":false}}");
    CHECK_EQ_INT(r.status, 200); /* disabling WG membership deprovisions its peer */
    CHECK_EQ_INT(peer_count(&t), 1);
    sb_test_response_free(&r);

    r = call(&t, "GET", "/api/hosts", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_array(r.json));
    bool found_public_host = false;
    const sbj *listed;
    SBJ_ARR_FOREACH(r.json, i, listed) {
        if (!sb_streq(sbj_get_str(listed, "id", NULL), host_id)) continue;
        found_public_host = true;
        CHECK(!sbj_has(listed, "agent_token"));                  /* host list hides the agent token */
        CHECK(sbj_is_object(sbj_get(listed, "capabilities")));   /* capabilities are a JSON object */
    }
    CHECK(found_public_host);
    sb_test_response_free(&r);

    REQUIRE(execute_sql(&t, "INSERT INTO proxy_nodes (id, tag, node_type, enabled, server, server_port, "
                            "protocol_config, fingerprint) VALUES ('http-node', 'http-node', 'shadowsocks', "
                            "TRUE, '127.0.0.1', 8388, '{\"method\":\"aes-128-gcm\",\"password\":\"secret\"}', "
                            "'http-node')") == 0);
    char *outbounds_path = sb_asprintf("/api/hosts/%s/outbounds", host_id);
    r = call(&t, "PUT", outbounds_path, "{\"node_ids\":[\"http-node\"]}");
    CHECK_EQ_INT(r.status, 200); /* outbound assignment succeeds */
    sb_test_response_free(&r);
    r = call(&t, "GET", outbounds_path, NULL);
    CHECK_JSON(r.json, "node_ids", "[\"http-node\"]"); /* and round-trips */
    sb_test_response_free(&r);
    free(outbounds_path);

    char *config_path = sb_asprintf("/api/hosts/%s/config", host_id);
    r = call(&t, "GET", config_path, NULL);
    CHECK_EQ_INT(r.status, 200); /* config preview executes the profile rule script */
    CHECK_STR(jstr(r.json, "route.rules.0.outbound"), "direct");
    sb_test_response_free(&r);

    r = call(&t, "GET", "/api/agent/health", NULL);
    CHECK_EQ_INT(r.status, 200); /* agent health stays unauthenticated */
    sb_test_response_free(&r);
    r = call(&t, "GET", "/api/agent/config", NULL); /* the admin JWT is no agent credential */
    CHECK_EQ_INT(r.status, 401);
    sb_test_response_free(&r);

    r = call_as(&t, original_token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200); /* authenticated agents receive config and ETag */
    CHECK(r.etag && *r.etag);
    CHECK_STR(r.rule_source, "quickjs");
    CHECK_STR(r.profile_id, profile_id);
    CHECK_STR(r.profile_name, "Renamed scripted profile");
    CHECK_STR(jstr(r.json, "route.rules.0.outbound"), "direct");
    char *agent_etag = sb_strdup(r.etag);
    sb_test_response_free(&r);
    REQUIRE(agent_etag);

    char *if_none_match = sb_asprintf("If-None-Match: %s", agent_etag);
    r = call_with(&t, original_token, if_none_match, "GET", "/api/agent/config", NULL);
    free(if_none_match);
    CHECK_EQ_INT(r.status, 304); /* matching ETags produce an empty 304 */
    CHECK_EQ_INT(r.body_len, 0);
    CHECK_STR(r.etag, agent_etag);
    CHECK_STR(r.rule_source, "quickjs");
    CHECK_STR(r.profile_id, profile_id);
    CHECK_STR(r.profile_name, "Renamed scripted profile");
    sb_test_response_free(&r);
    sb_host_init(&host);
    CHECK(find_host(&t, host_id, &host) == 1 && host.last_seen); /* config polls update liveness */
    sb_host_free(&host);

    {
        sbj *status = sbj_object();
        sbj_set_str(status, "singbox_version", "1.12.0");
        sbj_set_bool(status, "singbox_running", true);
        sbj_set_str(status, "config_etag", agent_etag);
        body = sbj_dump(status, -1);
        sbj_free(status);
    }
    r = call_as(&t, original_token, "POST", "/api/agent/status", body);
    free(body);
    CHECK_EQ_INT(r.status, 200); /* agent status reports succeed */
    CHECK_EQ_INT(jbool(r.json, "ok"), 1);
    sb_test_response_free(&r);
    sb_host_init(&host);
    CHECK(find_host(&t, host_id, &host) == 1 && host.singbox_state);
    if (host.singbox_state) {
        sbj *state = sbj_parse_cstr(host.singbox_state);
        CHECK_STR(jstr(state, "etag"), agent_etag); /* the reported ETag is persisted */
        sbj_free(state);
    }
    sb_host_free(&host);

    char *commands_path = sb_asprintf("/api/hosts/%s/commands", host_id);
    r = call(&t, "POST", commands_path, "{\"command\":\" RELOAD \"}");
    CHECK_EQ_INT(r.status, 200); /* normalized agent commands are enqueued */
    CHECK_STR(jstr(r.json, "status"), "pending");
    CHECK_STR(jstr(r.json, "command"), "reload");
    char *command_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(command_id);

    r = call_as(&t, original_token, "GET", "/api/agent/commands", NULL);
    CHECK_EQ_INT(r.status, 200); /* agents only pull their pending commands */
    CHECK_EQ_INT(jlen(r.json, NULL), 1);
    CHECK_STR(jstr(r.json, "0.id"), command_id);
    sb_test_response_free(&r);

    char *ack_path = sb_asprintf("/api/agent/commands/%s/ack", command_id);
    r = call_as(&t, "legacy-self-token", "POST", ack_path, "{\"status\":\"done\",\"result\":\"wrong host\"}");
    CHECK_EQ_INT(r.status, 200); /* cross-host acknowledgements do not leak existence */
    sb_test_response_free(&r);
    CHECK_EQ_INT(pending_commands(&t, host_id), 1); /* ...and do not acknowledge */
    r = call_as(&t, original_token, "POST", ack_path, "{\"status\":\"done\",\"result\":\"reloaded\"}");
    CHECK_EQ_INT(r.status, 200); /* the owning agent acknowledges */
    sb_test_response_free(&r);
    free(ack_path);
    r = call(&t, "GET", commands_path, NULL);
    CHECK_STR(jstr(r.json, "0.status"), "done"); /* admins see the acknowledged history */
    CHECK_STR(jstr(r.json, "0.result"), "reloaded");
    sb_test_response_free(&r);
    free(commands_path);
    r = call(&t, "POST", "/api/hosts/self/commands", "{\"command\":\"reload\"}");
    CHECK_EQ_INT(r.status, 400); /* the built-in self host rejects remote commands */
    sb_test_response_free(&r);

    sb_buf telemetry = {0};
    sb_buf_puts(&telemetry, "{\"up\":10,\"down\":20,\"up_total\":100,\"down_total\":200,\"conn_count\":1,"
                            "\"connections\":[{\"id\":\"connection\"}],\"domain_stats\":[{\"domain\":\"example.com\","
                            "\"outbound\":\"direct\",\"outbound_type\":\"direct\",\"rule\":\"domain_suffix=example.com\","
                            "\"chain\":[\"direct\"],\"connection_count\":3,\"uplink_total\":120,\"downlink_total\":800,"
                            "\"first_seen\":1000,\"last_seen\":2000}],\"logs\":[");
    for (int i = 0; i < 502; ++i) sb_buf_printf(&telemetry, "%s\"%d\"", i ? "," : "", i);
    sb_buf_puts(&telemetry, "]}");
    r = call_as(&t, original_token, "POST", "/api/agent/telemetry", telemetry.p);
    sb_buf_free(&telemetry);
    CHECK_EQ_INT(r.status, 200); /* agents relay telemetry */
    sb_test_response_free(&r);
    char *telemetry_path = sb_asprintf("/api/hosts/%s/telemetry", host_id);
    r = call(&t, "GET", telemetry_path, NULL);
    free(telemetry_path);
    CHECK_EQ_INT(jint(r.json, "up"), 10); /* latest snapshot with capped logs */
    CHECK_EQ_INT(jlen(r.json, "logs"), 500);
    CHECK_STR(jstr(r.json, "logs.0"), "2");
    CHECK_STR(jstr(r.json, "domain_stats.0.domain"), "example.com");
    CHECK_EQ_INT(jint(r.json, "domain_stats.0.connection_count"), 3);
    sb_test_response_free(&r);
    r = call_as(&t, original_token, "POST", "/api/agent/telemetry", "{\"domain_stats\":[{\"domain\":\"\"}]}");
    CHECK_EQ_INT(r.status, 400); /* malformed domain telemetry is rejected */
    sb_test_response_free(&r);

    r = call_as(&t, "", "POST", "/api/agent/diagnostics", "{\"reason\":\"manual\",\"logs\":[]}");
    CHECK_EQ_INT(r.status, 401); /* diagnostic uploads require a device credential */
    sb_test_response_free(&r);
    sb_buf diagnostics = {0};
    sb_buf_puts(&diagnostics, "{\"reason\":\"manual\",\"app_version\":\"1.1.2\",\"core_version\":\"1.13.12\","
                              "\"device\":{\"model\":\"Contract Phone\"},\"vpn\":{\"phase\":\"CONNECTED\"},"
                              "\"network\":{\"active_network\":\"cellular\"},\"config\":{\"profile_name\":\"Managed Device\"},"
                              "\"runtime_log_count\":1502,\"connection_count\":3,"
                              "\"untrusted_extra\":\"must not be persisted\",\"logs\":[");
    for (int i = 0; i < 1502; ++i) sb_buf_printf(&diagnostics, "%s\"diagnostic-%d\"", i ? "," : "", i);
    sb_buf_puts(&diagnostics, "]}");
    r = call_as(&t, original_token, "POST", "/api/agent/diagnostics", diagnostics.p);
    sb_buf_free(&diagnostics);
    CHECK_EQ_INT(r.status, 200); /* agents explicitly upload a diagnostic report */
    CHECK(jstr(r.json, "report_id") != NULL);
    sb_test_response_free(&r);
    char *diagnostics_path = sb_asprintf("/api/hosts/%s/diagnostics", host_id);
    r = call(&t, "GET", diagnostics_path, NULL);
    free(diagnostics_path);
    CHECK_EQ_INT(r.status, 200); /* bounded, whitelisted device diagnostics */
    CHECK_EQ_INT(jlen(r.json, NULL), 1);
    CHECK_EQ_INT(jlen(r.json, "0.logs"), 1500);
    CHECK_STR(jstr(r.json, "0.logs.0"), "diagnostic-2");
    CHECK_STR(jstr(r.json, "0.app_version"), "1.1.2");
    CHECK(!jpath(r.json, "0.untrusted_extra"));
    sb_test_response_free(&r);

    r = call_as(&t, original_token, "POST", "/api/agent/proxy-latency",
                "{\"results\":{\"http-node\":42.5,\"missing-node\":null}}");
    CHECK_EQ_INT(r.status, 200); /* latency reports update matching proxy tags */
    CHECK_EQ_INT(jint(r.json, "updated"), 1);
    sb_test_response_free(&r);

    char *token_path = sb_asprintf("/api/hosts/%s/token", host_id);
    r = call(&t, "GET", token_path, NULL);
    free(token_path);
    CHECK_STR(jstr(r.json, "agent_token"), original_token); /* token reveal contract */
    CHECK_STR(jstr(r.json, "server"), "https://panel.example.com");
    sb_test_response_free(&r);
    char *rotate_path = sb_asprintf("/api/hosts/%s/rotate-token", host_id);
    r = call(&t, "POST", rotate_path, NULL);
    free(rotate_path);
    CHECK(jstr(r.json, "agent_token") && !sb_streq(jstr(r.json, "agent_token"), original_token));
    sb_test_response_free(&r);
    r = call_as(&t, original_token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 401); /* rotation immediately revokes the old credential */
    sb_test_response_free(&r);

    r = call(&t, "PUT", path, "{\"name\":\"Disabled preview host\",\"enabled\":false}");
    CHECK_STR(jstr(r.json, "name"), "Disabled preview host"); /* partial host updates */
    CHECK_EQ_INT(jbool(r.json, "enabled"), 0);
    sb_test_response_free(&r);
    r = call(&t, "GET", config_path, NULL);
    CHECK_EQ_INT(r.status, 200); /* admin config preview works for disabled hosts */
    sb_test_response_free(&r);
    free(config_path);

    r = call(&t, "POST", "/api/hosts/profiles", "{\"name\":\"invalid\",\"template\":[]}");
    CHECK_EQ_INT(r.status, 400); /* invalid templates are structured 400s */
    CHECK(jstr(r.json, "error") != NULL);
    sb_test_response_free(&r);
    r = call(&t, "GET", "/api/hosts/missing", NULL);
    CHECK_EQ_INT(r.status, 404);
    sb_test_response_free(&r);
    r = call(&t, "GET", "/api/hosts/missing/config", NULL);
    CHECK_EQ_INT(r.status, 404);
    sb_test_response_free(&r);
    r = call(&t, "DELETE", "/api/hosts/profiles/default", NULL);
    CHECK_EQ_INT(r.status, 400); /* the default profile is protected */
    sb_test_response_free(&r);

    r = call(&t, "DELETE", path, NULL);
    CHECK_EQ_INT(jbool(r.json, "success"), 1); /* host deletion succeeds */
    sb_test_response_free(&r);

    free(path);
    free(command_id);
    free(agent_etag);
    free(legacy_code);
    free(enrollment_code);
    free(original_token);
    free(host_id);
    free(profile_id);
    sb_test_server_stop(&t);
}

/* ---- profiles / rule-script preview ------------------------------------- */

TEST(profile_validation) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    static const struct {
        const char *body;
        const char *error;
    } cases[] = {
        {"", "Request body must be a JSON object"},
        {"[]", "Request body must be a JSON object"},
        {"{\"template\":{}}", "name must be a non-empty string"},
        {"{\"name\":\"\"}", "name must be a non-empty string"},
        {"{\"name\":5,\"template\":{}}", "name must be a non-empty string"},
        {"{\"name\":\"x\"}", "template must be a JSON object"},
        {"{\"name\":\"x\",\"template\":[]}", "template must be a JSON object"},
        {"{\"name\":\"x\",\"template\":{},\"mode\":5}",
         "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number"},
        {"{\"name\":\"x\",\"template\":{},\"mode\":null}",
         "Invalid JSON request: [json.exception.type_error.302] type must be string, but is null"},
        {"{\"name\":\"x\",\"template\":{},\"rule_script\":5}", "rule_script must be a string"},
        {"{\"name\":\"x\",\"template\":{},\"rule_script\":null}", "rule_script must be a string"},
        {"{\"name\":\"x\",\"template\":{},\"rule_script_enabled\":\"yes\"}", "rule_script_enabled must be a boolean"},
        {"{\"name\":\"x\",\"template\":{},\"rule_script_enabled\":true}",
         "rule_script must not be empty when rule_script_enabled is true"},
        {"{\"name\":\"x\",\"template\":{},\"rule_script\":\" \\n\\t \",\"rule_script_enabled\":true}",
         "rule_script must not be empty when rule_script_enabled is true"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
        sb_test_response r = call(&t, "POST", "/api/hosts/profiles", cases[i].body);
        CHECK_ERROR(r, 400, cases[i].error);
        sb_test_response_free(&r);
    }

    /* A NUL is not whitespace: the script counts as non-empty. Unknown modes
     * fall back to managed. */
    sb_test_response r = call(&t, "POST", "/api/hosts/profiles",
                              "{\"name\":\"x\",\"template\":{},\"rule_script\":\"\\u0000\",\"rule_script_enabled\":true,"
                              "\"mode\":\"x\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "mode"), "managed");
    CHECK_EQ_INT(jbool(r.json, "rule_script_enabled"), 1);
    sb_test_response_free(&r);

    r = call(&t, "POST", "/api/hosts/profiles",
             "{\"name\":\"Full one\",\"template\":{\"a\":[1,2.5,null,true]},\"mode\":\"full\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "mode"), "full");
    CHECK_STR(jstr(r.json, "template"), "{\"a\":[1,2.5,null,true]}");
    CHECK_STR(jstr(r.json, "rule_script"), "");
    CHECK_EQ_INT(jbool(r.json, "rule_script_enabled"), 0);
    char *full_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);

    /* PUT keeps omitted fields but re-validates the stored script. */
    char *path = sb_asprintf("/api/hosts/profiles/%s", full_id);
    r = call(&t, "PUT", path, "{\"name\":\"Renamed\",\"template\":{\"b\":1}}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "mode"), "managed"); /* mode is not optional: absent -> managed */
    CHECK_STR(jstr(r.json, "template"), "{\"b\":1}");
    sb_test_response_free(&r);
    r = call(&t, "GET", path, NULL);
    CHECK_STR(jstr(r.json, "name"), "Renamed");
    sb_test_response_free(&r);
    r = call(&t, "DELETE", path, NULL);
    CHECK_EQ_INT(jbool(r.json, "success"), 1);
    sb_test_response_free(&r);
    r = call(&t, "GET", path, NULL);
    CHECK_ERROR(r, 404, "Profile not found");
    sb_test_response_free(&r);
    free(path);
    free(full_id);

    r = call(&t, "PUT", "/api/hosts/profiles/missing", "{\"name\":\"x\",\"template\":{}}");
    CHECK_ERROR(r, 404, "Profile not found");
    sb_test_response_free(&r);
    r = call(&t, "PUT", "/api/hosts/profiles/default", "{\"name\":\"x\"}");
    CHECK_ERROR(r, 400, "template must be a JSON object");
    sb_test_response_free(&r);
    r = call(&t, "PUT", "/api/hosts/profiles/default",
             "{\"name\":\"Default renamed\",\"template\":{},\"rule_script_enabled\":true}");
    CHECK_ERROR(r, 400, "rule_script must not be empty when rule_script_enabled is true");
    sb_test_response_free(&r);
    r = call(&t, "DELETE", "/api/hosts/profiles/missing", NULL);
    CHECK_ERROR(r, 404, "Profile not found");
    sb_test_response_free(&r);
    r = call(&t, "DELETE", "/api/hosts/profiles/default", NULL);
    CHECK_ERROR(r, 400, "Cannot delete the default profile");
    sb_test_response_free(&r);
    r = call(&t, "GET", "/api/hosts/profiles/default", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "name"), "Default (tun + mixed)");
    CHECK(sbj_is_string(jpath(r.json, "template")));
    sb_test_response_free(&r);

    /* Deleting a profile moves its hosts back to the default profile. */
    r = call(&t, "POST", "/api/hosts/profiles", "{\"name\":\"Temp\",\"template\":{}}");
    char *temp_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    char *body = sb_asprintf("{\"name\":\"On temp\",\"capabilities\":{},\"profile_id\":\"%s\"}", temp_id);
    char *host_id = create_host(&t, body);
    free(body);
    REQUIRE(host_id);
    path = sb_asprintf("/api/hosts/profiles/%s", temp_id);
    r = call(&t, "DELETE", path, NULL);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    free(path);
    path = sb_asprintf("/api/hosts/%s", host_id);
    r = call(&t, "GET", path, NULL);
    CHECK_STR(jstr(r.json, "profile_id"), "default");
    sb_test_response_free(&r);
    free(path);
    free(host_id);
    free(temp_id);
    sb_test_server_stop(&t);
}

TEST(rule_script_preview) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    static const struct {
        const char *body;
        const char *error;
    } invalid[] = {
        {"{}", "rule_script must be a non-empty string"},
        {"{\"rule_script\":\"\"}", "rule_script must be a non-empty string"},
        {"{\"rule_script\":\"x\",\"context\":[]}", "context must be a JSON object"},
        {"{\"rule_script\":\"x\",\"context\":null}", "context must be a JSON object"},
        {"{\"rule_script\":\"x\",\"context\":{\"host\":null}}", "context host/outboundTags/currentRules have invalid types"},
        {"{\"rule_script\":\"x\",\"context\":{\"outboundTags\":\"x\"}}",
         "context host/outboundTags/currentRules have invalid types"},
        {"{\"rule_script\":\"x\",\"context\":{\"currentRules\":{}}}",
         "context host/outboundTags/currentRules have invalid types"},
    };
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        sb_test_response r = call(&t, "POST", "/api/hosts/rule-script/test", invalid[i].body);
        CHECK_ERROR(r, 400, invalid[i].error);
        sb_test_response_free(&r);
    }
    /* Missing context members get the C++ defaults. */
    sb_test_response r = call(&t, "POST", "/api/hosts/rule-script/test",
                              "{\"rule_script\":\"function buildRules(c) { return [{domain: [c.host.id, c.host.name, "
                              "String(Object.keys(c.host.capabilities).length)], outbound: c.outboundTags.join(','), "
                              "rule_set: [String(c.currentRules.length)]}]; }\",\"context\":{\"extra\":1}}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jint(r.json, "count"), 1);
    CHECK_JSON(r.json, "rules.0.domain", "[\"preview\",\"QuickJS preview\",\"0\"]");
    CHECK_STR(jstr(r.json, "rules.0.outbound"), "Proxy,direct,block");
    CHECK_JSON(r.json, "rules.0.rule_set", "[\"0\"]");
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/hosts/rule-script/test", "{\"rule_script\":\"function buildRules(c) { return {}; }\"}");
    CHECK_ERROR(r, 422, "buildRules(context) must return an array");
    CHECK_STR(jstr(r.json, "kind"), "rule_script");
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/hosts/rule-script/test", "{\"rule_script\":\"function buildRules(c) { return [1]; }\"}");
    CHECK_ERROR(r, 422, "each generated rule must be a JSON object");
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/hosts/rule-script/test", "{\"rule_script\":\"function buildRules(c) { return []; }\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "{\"count\":0,\"rules\":[],\"success\":true}");
    sb_test_response_free(&r);
    sb_test_server_stop(&t);
}

/* ---- hosts --------------------------------------------------------------- */

static size_t host_count(sb_test_server *t) {
    sb_host_vec hosts = {0};
    sb_err err = {0};
    size_t count = sb_store_list_hosts(t->store, &hosts, &err) == 0 ? hosts.len : (size_t)-1;
    sb_host_vec_free(&hosts);
    return count;
}

TEST(host_validation_and_provisioning) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    static const struct {
        const char *body;
        int status;
        const char *error;
    } invalid[] = {
        {"{}", 400, "name must be a non-empty string"},
        {"{\"name\":\"\"}", 400, "name must be a non-empty string"},
        {"{\"name\":\"n\",\"capabilities\":[]}", 400, "capabilities must be a JSON object"},
        {"{\"name\":\"n\",\"profile_id\":5}", 400, "profile_id must be a string"},
        {"{\"name\":\"n\",\"capabilities\":{},\"wg_address\":1}", 400, "wg_address must be a string"},
        {"{\"name\":\"n\",\"capabilities\":{},\"wg_endpoint\":true}", 400, "wg_endpoint must be a string"},
        {"{\"name\":\"n\",\"capabilities\":{},\"clash_api\":{}}", 400, "clash_api must be a string"},
        {"{\"name\":\"n\",\"capabilities\":{},\"clash_secret\":1}", 400, "clash_secret must be a string"},
        {"{\"name\":\"n\",\"capabilities\":{},\"profile_id\":\"missing-profile\"}", 500, "Internal server error"},
    };
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        sb_test_response r = call(&t, "POST", "/api/hosts", invalid[i].body);
        CHECK_ERROR(r, invalid[i].status, invalid[i].error);
        sb_test_response_free(&r);
    }
    CHECK_EQ_INT(host_count(&t), 1); /* only self */

    /* The membership check runs after the insert: the host exists anyway. */
    sb_test_response r = call(&t, "POST", "/api/hosts", "{\"name\":\"n\",\"capabilities\":{\"is_wg_member\":\"yes\"}}");
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is string");
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/hosts", "{\"name\":\"n\",\"capabilities\":{\"is_wg_member\":null}}");
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is null");
    sb_test_response_free(&r);
    CHECK_EQ_INT(host_count(&t), 3);

    /* Nulls leave defaults; an empty wg_endpoint is dropped on create. */
    r = call(&t, "POST", "/api/hosts",
             "{\"name\":\"plain\",\"capabilities\":{},\"wg_endpoint\":\"\",\"clash_secret\":null,\"profile_id\":null,"
             "\"clash_api\":\"http://x:9090\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK(sbj_is_null(jpath(r.json, "wg_endpoint")));
    CHECK_STR(jstr(r.json, "profile_id"), "default");
    CHECK_STR(jstr(r.json, "clash_api"), "http://x:9090");
    CHECK_EQ_INT(jbool(r.json, "has_token"), 1);
    CHECK_EQ_INT(jint(r.json, "assigned_outbounds"), 0);
    CHECK(sbj_is_null(jpath(r.json, "last_seen")));
    CHECK(!sbj_has(r.json, "agent_token") && !sbj_has(r.json, "clash_secret"));
    sb_test_response_free(&r);

    /* Default capabilities make the host a WireGuard member: it gets a peer
     * and a default Clash API on its intranet address... */
    r = call(&t, "POST", "/api/hosts", "{\"name\":\"Default caps host\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_JSON(r.json, "capabilities",
               "{\"is_self\":false,\"is_wg_hub\":false,\"is_wg_member\":true,\"runs_singbox\":true}");
    CHECK_STR(jstr(r.json, "wg_address"), "10.59.32.2/32");
    CHECK_STR(jstr(r.json, "clash_api"), "http://10.59.32.2:9090");
    CHECK(jstr(r.json, "wg_public_key") != NULL);
    sb_test_response_free(&r);
    /* ...unless the request mentions clash_api at all (even as null). */
    r = call(&t, "POST", "/api/hosts", "{\"name\":\"Clash null host\",\"clash_api\":null}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "wg_address"), "10.59.32.3/32");
    CHECK(sbj_is_null(jpath(r.json, "clash_api")));
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/hosts",
             "{\"name\":\"Endpoint host\",\"capabilities\":{\"is_wg_member\":true},\"wg_endpoint\":\"203.0.113.5:51820\","
             "\"clash_api\":\"http://custom:9090\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "wg_endpoint"), "203.0.113.5:51820");
    CHECK_STR(jstr(r.json, "clash_api"), "http://custom:9090");
    char *endpoint_host = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    CHECK_EQ_INT(peer_count(&t), 3);

    /* Updates. */
    char *plain = create_host(&t, "{\"name\":\"Plain\",\"capabilities\":{}}");
    REQUIRE(plain);
    char *path = sb_asprintf("/api/hosts/%s", plain);
    static const struct {
        const char *body;
        const char *error;
    } bad_updates[] = {
        {"x", "Request body must be a JSON object"},
        {"{\"name\":\"\"}", "name must be a non-empty string"},
        {"{\"name\":5}", "name must be a non-empty string"},
        {"{\"capabilities\":\"x\"}", "capabilities must be a JSON object"},
        {"{\"enabled\":\"no\"}", "enabled must be a boolean"},
        {"{\"wg_public_key\":5}", "wg_public_key must be a string"},
        {"{\"clash_secret\":5}", "clash_secret must be a string"},
    };
    for (size_t i = 0; i < sizeof bad_updates / sizeof *bad_updates; ++i) {
        r = call(&t, "PUT", path, bad_updates[i].body);
        CHECK_ERROR(r, 400, bad_updates[i].error);
        sb_test_response_free(&r);
    }
    r = call(&t, "PUT", path, "{\"name\":null,\"capabilities\":null,\"enabled\":null}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "name"), "Plain");
    sb_test_response_free(&r);
    /* Update keeps an empty wg_endpoint (no create-time normalisation). */
    r = call(&t, "PUT", path, "{\"wg_endpoint\":\"\",\"clash_api\":\"http://changed\",\"wg_public_key\":\"pk\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "wg_endpoint"), "");
    CHECK_STR(jstr(r.json, "wg_public_key"), "pk");
    sb_test_response_free(&r);
    r = call(&t, "PUT", path, "{\"profile_id\":\"missing-profile\"}");
    CHECK_ERROR(r, 500, "Internal server error");
    sb_test_response_free(&r);
    /* A malformed membership flag is persisted before the check fails, and
     * then blocks further updates (the stored value is read first). */
    r = call(&t, "PUT", path, "{\"capabilities\":{\"is_wg_member\":\"x\"}}");
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is string");
    sb_test_response_free(&r);
    r = call(&t, "PUT", path, "{\"enabled\":false}");
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is string");
    sb_test_response_free(&r);
    sb_host host;
    sb_host_init(&host);
    CHECK(find_host(&t, plain, &host) == 1 && host.enabled);
    CHECK_STR(sbj_get_str(host.capabilities, "is_wg_member", NULL), "x");
    sb_host_free(&host);
    free(path);

    r = call(&t, "PUT", "/api/hosts/missing", "{\"name\":\"x\"}");
    CHECK_ERROR(r, 404, "Host not found");
    sb_test_response_free(&r);
    /* self never gets provisioned, even when it becomes a member. */
    r = call(&t, "PUT", "/api/hosts/self", "{\"name\":\"Renamed self\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "name"), "Renamed self");
    CHECK(sbj_is_null(jpath(r.json, "wg_address")));
    CHECK_EQ_INT(jbool(r.json, "has_token"), 0);
    sb_test_response_free(&r);
    r = call(&t, "DELETE", "/api/hosts/self", NULL);
    CHECK_ERROR(r, 400, "Cannot delete the built-in self host");
    sb_test_response_free(&r);
    r = call(&t, "DELETE", "/api/hosts/missing", NULL);
    CHECK_ERROR(r, 404, "Host not found");
    sb_test_response_free(&r);

    /* Deleting a member host removes its peer. */
    path = sb_asprintf("/api/hosts/%s", endpoint_host);
    r = call(&t, "DELETE", path, NULL);
    CHECK_STR(r.body, "{\"success\":true}");
    sb_test_response_free(&r);
    CHECK_EQ_INT(peer_count(&t), 2);
    r = call(&t, "GET", path, NULL);
    CHECK_ERROR(r, 404, "Host not found");
    sb_test_response_free(&r);
    free(path);
    free(endpoint_host);
    free(plain);
    sb_test_server_stop(&t);
}

TEST(host_subresources) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    static const char *const missing[][2] = {
        {"GET", "/telemetry"},  {"GET", "/diagnostics"}, {"GET", "/commands"},   {"POST", "/commands"},
        {"GET", "/outbounds"},  {"PUT", "/outbounds"},   {"GET", "/config"},     {"GET", "/wg-config"},
        {"GET", "/token"},      {"POST", "/rotate-token"}, {"POST", "/enrollment-codes"},
    };
    for (size_t i = 0; i < sizeof missing / sizeof *missing; ++i) {
        char *path = sb_asprintf("/api/hosts/missing%s", missing[i][1]);
        const char *body = strcmp(missing[i][0], "GET") ? "{\"command\":\"reload\",\"node_ids\":[]}" : NULL;
        sb_test_response r = call(&t, missing[i][0], path, body);
        CHECK_ERROR(r, 404, "Host not found");
        sb_test_response_free(&r);
        free(path);
    }
    sb_test_response r = call(&t, "POST", "/api/devices/missing/enrollment-codes", NULL);
    CHECK_ERROR(r, 404, "Host not found");
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/devices/self/enrollment-codes", NULL);
    CHECK_ERROR(r, 400, "Enrollment requires an enabled remote host");
    sb_test_response_free(&r);

    char *id = create_host(&t, "{\"name\":\"Sub host\",\"capabilities\":{}}");
    REQUIRE(id);
    char *path = sb_asprintf("/api/hosts/%s/telemetry", id);
    r = call(&t, "GET", path, NULL);
    CHECK_STR(r.body, "{\"at\":\"\",\"conn_count\":0,\"connections\":null,\"domain_stats\":[],\"down\":0,"
                      "\"down_total\":0,\"logs\":[],\"up\":0,\"up_total\":0}");
    sb_test_response_free(&r);
    free(path);
    path = sb_asprintf("/api/hosts/%s/diagnostics", id);
    r = call(&t, "GET", path, NULL);
    CHECK_STR(r.body, "[]");
    sb_test_response_free(&r);
    free(path);

    /* commands */
    path = sb_asprintf("/api/hosts/%s/commands", id);
    static const struct {
        const char *body;
        const char *error;
    } bad_commands[] = {
        {"", "Request body must be a JSON object"},
        {"{}", "command must be a non-empty string"},
        {"{\"command\":5}", "command must be a non-empty string"},
        {"{\"command\":\"\"}", "command must be a non-empty string"},
        {"{\"command\":\"Stop\"}", "Unknown command: stop"},
        {"{\"command\":\"   \"}", "Unknown command: "},
        /* only ASCII whitespace is trimmed; U+00A0 survives */
        {"{\"command\":\"\\tRELOAD\\u00a0\"}", "Unknown command: reload\xc2\xa0"},
        /* what() stops at an embedded NUL */
        {"{\"command\":\"x\\u0000y\"}", "Unknown command: x"},
    };
    for (size_t i = 0; i < sizeof bad_commands / sizeof *bad_commands; ++i) {
        r = call(&t, "POST", path, bad_commands[i].body);
        CHECK_ERROR(r, 400, bad_commands[i].error);
        sb_test_response_free(&r);
    }
    /* Long unknown commands are echoed in full. */
    sb_buf longer = {0};
    sb_buf_puts(&longer, "{\"command\":\"");
    for (int i = 0; i < 3000; ++i) sb_buf_putc(&longer, 'Z');
    sb_buf_puts(&longer, "\"}");
    r = call(&t, "POST", path, longer.p);
    sb_buf_free(&longer);
    CHECK_EQ_INT(r.status, 400);
    CHECK(jstr(r.json, "error") && strlen(jstr(r.json, "error")) == 17 + 3000);
    CHECK(sb_starts_with(jstr(r.json, "error"), "Unknown command: zzzz"));
    sb_test_response_free(&r);
    r = call(&t, "POST", path, "{\"command\":\" ReStArT\\n\"}");
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "command"), "restart");
    CHECK_STR(jstr(r.json, "status"), "pending");
    CHECK_EQ_INT(sbj_obj_len(r.json), 3);
    sb_test_response_free(&r);
    r = call(&t, "GET", path, NULL);
    CHECK_EQ_INT(jlen(r.json, NULL), 1);
    CHECK_STR(jstr(r.json, "0.command"), "restart");
    CHECK(sbj_is_null(jpath(r.json, "0.result")) && sbj_is_null(jpath(r.json, "0.acked_at")));
    CHECK_STR(jstr(r.json, "0.host_id"), id);
    sb_test_response_free(&r);
    free(path);

    /* outbounds: the PUT echoes the request order, GET reads the stored set */
    path = sb_asprintf("/api/hosts/%s/outbounds", id);
    r = call(&t, "PUT", path, "{}");
    CHECK_ERROR(r, 400, "node_ids must be an array");
    sb_test_response_free(&r);
    r = call(&t, "PUT", path, "{\"node_ids\":\"x\"}");
    CHECK_ERROR(r, 400, "node_ids must be an array");
    sb_test_response_free(&r);
    r = call(&t, "PUT", path, "{\"node_ids\":[1]}");
    CHECK_ERROR(r, 400, "node_ids must contain only strings");
    sb_test_response_free(&r);
    REQUIRE(execute_sql(&t, "INSERT INTO proxy_nodes (id, tag, node_type, server, server_port, fingerprint) VALUES "
                            "('a', 'A', 'shadowsocks', 'a.example', 1, 'fa'), "
                            "('b', 'B', 'shadowsocks', 'b.example', 1, 'fb')") == 0);
    r = call(&t, "PUT", path, "{\"node_ids\":[\"b\",\"a\",\"b\"]}");
    CHECK_EQ_INT(r.status, 200);
    char *expected = sb_asprintf("{\"host_id\":\"%s\",\"node_ids\":[\"b\",\"a\",\"b\"]}", id);
    CHECK_STR(r.body, expected);
    free(expected);
    sb_test_response_free(&r);
    r = call(&t, "GET", path, NULL);
    expected = sb_asprintf("{\"host_id\":\"%s\",\"node_ids\":[\"a\",\"b\"],\"uses_all_when_empty\":true}", id);
    CHECK_STR(r.body, expected);
    free(expected);
    sb_test_response_free(&r);
    free(path);
    path = sb_asprintf("/api/hosts/%s", id);
    r = call(&t, "GET", path, NULL);
    CHECK_EQ_INT(jint(r.json, "assigned_outbounds"), 2);
    sb_test_response_free(&r);
    free(path);

    /* token reveal / rotation */
    path = sb_asprintf("/api/hosts/%s/token", id);
    char *token = host_token(&t, id);
    r = call(&t, "GET", path, NULL);
    expected = sb_asprintf("{\"agent_token\":\"%s\",\"host_id\":\"%s\",\"server\":\"https://panel.example.com\"}",
                           token, id);
    CHECK_STR(r.body, expected);
    free(expected);
    sb_test_response_free(&r);
    free(path);
    path = sb_asprintf("/api/hosts/%s/rotate-token", id);
    r = call(&t, "POST", path, NULL);
    char *rotated = host_token(&t, id);
    expected = sb_asprintf("{\"agent_token\":\"%s\",\"host_id\":\"%s\"}", rotated, id);
    CHECK_STR(r.body, expected);
    CHECK(strlen(rotated) == 64 && strcmp(rotated, token) != 0);
    free(expected);
    sb_test_response_free(&r);
    free(path);
    free(rotated);
    free(token);

    /* wg-config needs a peer */
    path = sb_asprintf("/api/hosts/%s/wg-config", id);
    r = call(&t, "GET", path, NULL);
    CHECK_ERROR(r, 404, "Host has no WireGuard peer");
    sb_test_response_free(&r);
    free(path);

    /* enrollment codes need an enabled remote host */
    path = sb_asprintf("/api/hosts/%s", id);
    r = call(&t, "PUT", path, "{\"enabled\":false}");
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    free(path);
    path = sb_asprintf("/api/devices/%s/enrollment-codes", id);
    r = call(&t, "POST", path, NULL);
    CHECK_ERROR(r, 400, "Enrollment requires an enabled remote host");
    sb_test_response_free(&r);
    free(path);

    /* viewers read, but cannot mutate */
    char *viewer = sb_test_token(&t, "viewer-id", "viewer", "viewer");
    r = call_as(&t, viewer, "GET", "/api/hosts", NULL);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    r = call_as(&t, viewer, "POST", "/api/hosts", "{\"name\":\"x\"}");
    CHECK_ERROR(r, 403, "Viewer role is read-only");
    sb_test_response_free(&r);
    free(viewer);
    free(id);
    sb_test_server_stop(&t);
}

TEST(wg_config_download) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    char *id = create_host(&t, "{\"name\":\"My Office Box\",\"capabilities\":{\"is_wg_member\":true},"
                               "\"wg_endpoint\":\"203.0.113.9:51999\"}");
    REQUIRE(id);
    char *path = sb_asprintf("/api/hosts/%s/wg-config", id);
    sb_test_response r = call(&t, "GET", path, NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.content_type, "application/octet-stream");
    CHECK_STR(r.content_disposition, "attachment; filename=\"My_Office_Box-wg.conf\"");
    CHECK(sb_starts_with(r.body, "# sb-easy managed host: My Office Box\n[Interface]\n"));
    CHECK_CONTAINS(r.body, "ListenPort = 51999\n");
    CHECK_CONTAINS(r.body, "AllowedIPs = 10.59.32.0/24\n");
    CHECK_CONTAINS(r.body, "Endpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n");
    sb_test_response_free(&r);
    free(path);
    free(id);
    sb_test_server_stop(&t);
}

/* ---- agent API ----------------------------------------------------------- */

TEST(agent_authentication) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    char *id = create_host(&t, "{\"name\":\"Agent host\",\"capabilities\":{\"runs_singbox\":true}}");
    REQUIRE(id);
    char *token = host_token(&t, id);
    static const char *const routes[][2] = {
        {"GET", "/api/agent/config"},      {"POST", "/api/agent/status"},
        {"GET", "/api/agent/commands"},    {"POST", "/api/agent/commands/x/ack"},
        {"POST", "/api/agent/proxy-latency"}, {"POST", "/api/agent/telemetry"},
        {"POST", "/api/agent/diagnostics"},
    };
    char *lower = sb_asprintf("Authorization: bearer %s", token);
    char *padded = sb_asprintf("Authorization: Bearer   %s  ", token);
    const char *missing[] = {NULL, "Authorization: Bearer", "Authorization: Bearer    ", lower, "Authorization: Basic x"};
    for (size_t i = 0; i < sizeof routes / sizeof *routes; ++i) {
        const char *body = strcmp(routes[i][0], "POST") == 0 ? "nope" : NULL;
        for (size_t k = 0; k < sizeof missing / sizeof *missing; ++k) {
            sb_test_response r = call_with(&t, "", missing[k], routes[i][0], routes[i][1], body);
            CHECK_ERROR(r, 401, "Missing agent token");
            sb_test_response_free(&r);
        }
        sb_test_response r = call_as(&t, "wrong", routes[i][0], routes[i][1], body);
        CHECK_ERROR(r, 401, "Invalid agent token");
        sb_test_response_free(&r);
        /* The admin JWT is no agent credential either. */
        r = call(&t, routes[i][0], routes[i][1], body);
        CHECK_ERROR(r, 401, "Invalid agent token");
        sb_test_response_free(&r);
        /* Authentication precedes body validation; the token is trimmed. */
        r = call_with(&t, "", padded, routes[i][0], routes[i][1], body);
        if (body)
            CHECK_ERROR(r, 400, "Request body must be a JSON object");
        else
            CHECK_EQ_INT(r.status, 200);
        sb_test_response_free(&r);
    }
    free(lower);
    free(padded);

    /* The legacy AGENT_TOKEN acts as the self host. */
    sb_test_response r = call_as(&t, "legacy-self-token", "GET", "/api/agent/commands", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.body, "[]");
    sb_test_response_free(&r);
    r = call_as(&t, "legacy-self-token", "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.profile_id, "default");
    sb_test_response_free(&r);

    /* Disabled hosts lose agent access. */
    char *path = sb_asprintf("/api/hosts/%s", id);
    r = call(&t, "PUT", path, "{\"enabled\":false}");
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    free(path);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_ERROR(r, 401, "Invalid agent token");
    sb_test_response_free(&r);
    free(token);
    free(id);
    sb_test_server_stop(&t);
}

TEST(agent_reports) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    char *id = create_host(&t, "{\"name\":\"Reporter\",\"capabilities\":{}}");
    REQUIRE(id);
    char *token = host_token(&t, id);
    static const struct {
        const char *path, *body;
        int status;
        const char *error;
    } cases[] = {
        {"/api/agent/status", "", 400, "Request body must be a JSON object"},
        {"/api/agent/status", "{\"singbox_version\":5}", 400, "singbox_version must be a string or null"},
        {"/api/agent/status", "{\"app_version\":true}", 400, "app_version must be a string or null"},
        {"/api/agent/status", "{\"singbox_running\":\"yes\"}", 400, "singbox_running must be a boolean or null"},
        {"/api/agent/status", "{\"config_etag\":1}", 400, "config_etag must be a string or null"},
        {"/api/agent/status", "{\"last_error\":[]}", 400, "last_error must be a string or null"},
        /* fields are checked in declaration order */
        {"/api/agent/status", "{\"last_error\":1,\"singbox_running\":1}", 400, "singbox_running must be a boolean or null"},
        {"/api/agent/proxy-latency", "{\"results\":null}", 400, "results must be a JSON object"},
        {"/api/agent/proxy-latency", "{\"results\":[]}", 400, "results must be a JSON object"},
        {"/api/agent/proxy-latency", "{\"results\":{\"a\":\"x\"}}", 400, "proxy latency values must be numbers or null"},
        {"/api/agent/proxy-latency", "{\"results\":{\"a\":true}}", 400, "proxy latency values must be numbers or null"},
        {"/api/agent/telemetry", "{\"up\":1.5}", 400, "up must be an integer"},
        {"/api/agent/telemetry", "{\"conn_count\":-1}", 400, "conn_count must not be negative"},
        {"/api/agent/telemetry", "{\"logs\":[1]}", 400, "logs must contain only strings"},
        {"/api/agent/diagnostics", "{\"reason\":5}", 400, "reason must be a string"},
        {"/api/agent/diagnostics", "{\"device\":[]}", 400, "device must be a JSON object"},
        {"/api/agent/diagnostics", "{\"runtime_log_count\":-1}", 400, "runtime_log_count must not be negative"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
        sb_test_response r = call_as(&t, token, "POST", cases[i].path, cases[i].body);
        CHECK_ERROR(r, cases[i].status, cases[i].error);
        sb_test_response_free(&r);
    }

    sb_test_response r = call_as(&t, token, "POST", "/api/agent/status", "{}");
    CHECK_STR(r.body, "{\"ok\":true}");
    sb_test_response_free(&r);
    sb_host host;
    sb_host_init(&host);
    CHECK(find_host(&t, id, &host) == 1 && host.last_seen);
    CHECK_STR(host.singbox_state, "{\"app_version\":null,\"etag\":null,\"last_error\":null,\"running\":null,\"version\":null}");
    sb_host_free(&host);
    r = call_as(&t, token, "POST", "/api/agent/status",
                "{\"singbox_version\":\"1\",\"app_version\":\"2\",\"singbox_running\":false,\"config_etag\":\"e\","
                "\"last_error\":\"boom\\u0000!\",\"extra\":1}");
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    sb_host_init(&host);
    CHECK(find_host(&t, id, &host) == 1);
    CHECK_STR(host.singbox_state,
              "{\"app_version\":\"2\",\"etag\":\"e\",\"last_error\":\"boom\\u0000!\",\"running\":false,\"version\":\"1\"}");
    sb_host_free(&host);

    /* acknowledgements */
    char *path = sb_asprintf("/api/hosts/%s/commands", id);
    r = call(&t, "POST", path, "{\"command\":\"restart\"}");
    char *command = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(command);
    char *ack = sb_asprintf("/api/agent/commands/%s/ack", command);
    r = call_as(&t, token, "POST", ack, "{\"status\":5}");
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number");
    sb_test_response_free(&r);
    r = call_as(&t, token, "POST", ack, "{\"status\":null}");
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is null");
    sb_test_response_free(&r);
    r = call_as(&t, token, "POST", ack, "{\"status\":\"done\",\"result\":5}");
    CHECK_ERROR(r, 400, "result must be a string or null");
    sb_test_response_free(&r);
    CHECK_EQ_INT(pending_commands(&t, id), 1);
    r = call_as(&t, token, "POST", ack, "{\"status\":\"nope\"}");
    CHECK_STR(r.body, "{\"ok\":true}");
    sb_test_response_free(&r);
    r = call(&t, "GET", path, NULL);
    CHECK_STR(jstr(r.json, "0.status"), "failed"); /* anything but "done" is a failure */
    CHECK(sbj_is_null(jpath(r.json, "0.result")));
    CHECK(jstr(r.json, "0.acked_at") != NULL);
    sb_test_response_free(&r);
    r = call_as(&t, token, "POST", "/api/agent/commands/unknown/ack", "{\"status\":\"done\"}");
    CHECK_STR(r.body, "{\"ok\":true}"); /* unknown ids are not revealed */
    sb_test_response_free(&r);
    free(ack);
    free(command);
    free(path);

    /* latency updates */
    REQUIRE(execute_sql(&t, "INSERT INTO proxy_nodes (id, tag, node_type, server, server_port, fingerprint) VALUES "
                            "('n1', 'Tag One', 'shadowsocks', 'a.example', 1, 'f1')") == 0);
    r = call_as(&t, token, "POST", "/api/agent/proxy-latency", "{}");
    CHECK_STR(r.body, "{\"ok\":true,\"updated\":0}");
    sb_test_response_free(&r);
    r = call_as(&t, token, "POST", "/api/agent/proxy-latency", "{\"results\":{\"Tag One\":12,\"Other\":null}}");
    CHECK_STR(r.body, "{\"ok\":true,\"updated\":1}");
    sb_test_response_free(&r);

    /* telemetry snapshot replaces the previous one */
    r = call_as(&t, token, "POST", "/api/agent/telemetry", "{\"connections\":{\"any\":\"thing\"},\"up\":5}");
    CHECK_STR(r.body, "{\"ok\":true}");
    sb_test_response_free(&r);
    path = sb_asprintf("/api/hosts/%s/telemetry", id);
    r = call(&t, "GET", path, NULL);
    CHECK_EQ_INT(jint(r.json, "up"), 5);
    CHECK_JSON(r.json, "connections", "{\"any\":\"thing\"}");
    CHECK(jstr(r.json, "at") && strlen(jstr(r.json, "at")) == 20);
    sb_test_response_free(&r);
    r = call_as(&t, token, "POST", "/api/agent/telemetry", "{\"up\":\"x\"}");
    CHECK_ERROR(r, 400, "up must be an integer");
    sb_test_response_free(&r);
    r = call(&t, "GET", path, NULL);
    CHECK_EQ_INT(jint(r.json, "up"), 5); /* a rejected report keeps the last snapshot */
    sb_test_response_free(&r);
    free(path);

    /* diagnostics: the size limit applies before authentication */
    sb_buf big = {0};
    sb_buf_puts(&big, "{\"logs\":[\"");
    for (int i = 0; i < 1000000; ++i) sb_buf_putc(&big, 'a');
    sb_buf_puts(&big, "\"]}");
    r = call_as(&t, "", "POST", "/api/agent/diagnostics", big.p);
    CHECK_ERROR(r, 400, "Diagnostic report exceeds 1 MB");
    sb_test_response_free(&r);
    sb_buf_free(&big);
    r = call_as(&t, token, "POST", "/api/agent/diagnostics",
                "{\"reason\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\","
                "\"device\":null,\"connection_count\":2}");
    CHECK_EQ_INT(r.status, 200);
    CHECK(jstr(r.json, "report_id") && strlen(jstr(r.json, "report_id")) == 36);
    CHECK_EQ_INT(jbool(r.json, "ok"), 1);
    sb_test_response_free(&r);
    path = sb_asprintf("/api/hosts/%s/diagnostics", id);
    r = call(&t, "GET", path, NULL);
    CHECK_EQ_INT(jlen(r.json, NULL), 1);
    CHECK(jstr(r.json, "0.reason") && strlen(jstr(r.json, "0.reason")) == 80); /* truncated to 80 bytes */
    CHECK_JSON(r.json, "0.device", "{}");
    CHECK_EQ_INT(jint(r.json, "0.connection_count"), 2);
    sb_test_response_free(&r);
    free(path);
    free(token);
    free(id);
    sb_test_server_stop(&t);
}

TEST(enrollment_redeem) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    char *id = create_host(&t, "{\"name\":\"Enrolling host\",\"capabilities\":{\"runs_singbox\":true}}");
    REQUIRE(id);
    char *path = sb_asprintf("/api/devices/%s/enrollment-codes", id);
    sb_test_response r = call(&t, "POST", path, NULL);
    free(path);
    CHECK_EQ_INT(r.status, 200);
    char *code = sb_strdup(jstr(r.json, "code"));
    char *uri = sb_asprintf("sbeasy://enroll?server=https%%3A%%2F%%2Fpanel.example.com&code=%s", code);
    CHECK_STR(jstr(r.json, "enrollment_uri"), uri);
    CHECK_STR(jstr(r.json, "host_id"), id);
    CHECK(sb_starts_with(jstr(r.json, "qr_svg"), "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg "));
    CHECK(jstr(r.json, "expires_at") && strlen(jstr(r.json, "expires_at")) == 19);
    CHECK_EQ_INT(sbj_obj_len(r.json), 6);
    free(uri);
    sb_test_response_free(&r);

    char *with_nul = sb_asprintf("{\"code\":\"%s\\u0000\"}", code);
    char *device_array = sb_asprintf("{\"code\":\"%s\",\"device\":[]}", code);
    char *device_null = sb_asprintf("{\"code\":\"%s\",\"device\":null}", code);
    const struct {
        const char *body;
        const char *error;
    } invalid[] = {
        {"", "Request body must be a JSON object"},
        {"{}", "code must be a non-empty string"},
        {"{\"code\":5}", "code must be a non-empty string"},
        {"{\"code\":\"short\"}", "A valid enrollment code and device are required"},
        {device_array, "A valid enrollment code and device are required"},
        {device_null, "A valid enrollment code and device are required"},
        {"{\"code\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"}",
         "Enrollment code is invalid or expired"},
        /* the full byte string is hashed: a NUL suffix never matches */
        {with_nul, "Enrollment code is invalid or expired"},
        {"{\"code\":\"a\\u0000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}", "Enrollment code is invalid or expired"},
        {"{\"code\":\"a\\u0000b\"}", "A valid enrollment code and device are required"},
    };
    for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        r = call_as(&t, "", "POST", "/api/devices/enroll", invalid[i].body);
        CHECK_ERROR(r, 400, invalid[i].error);
        sb_test_response_free(&r);
    }
    free(with_nul);
    free(device_array);
    free(device_null);

    char *body = sb_asprintf("{\"code\":\"%s\",\"device\":{\"platform\":\"linux\",\"model\":7,\"hostname\":\"\"}}", code);
    r = call_as(&t, "", "POST", "/api/agent/enroll", body);
    free(body);
    CHECK_EQ_INT(r.status, 200);
    char *token = host_token(&t, id);
    char *expected = sb_asprintf("{\"agent_token\":\"%s\",\"host_id\":\"%s\",\"host_name\":\"Enrolling host\","
                                 "\"profile\":{\"id\":\"default\",\"name\":\"Default (tun + mixed)\"},"
                                 "\"server\":\"https://panel.example.com\"}",
                                 token, id);
    CHECK_STR(r.body, expected);
    free(expected);
    free(token);
    sb_test_response_free(&r);
    sb_host host;
    sb_host_init(&host);
    CHECK(find_host(&t, id, &host) == 1);
    /* only non-empty whitelisted strings are merged */
    CHECK_JSON(host.capabilities, NULL, "{\"platform\":\"linux\",\"runs_singbox\":true}");
    CHECK(host.last_seen != NULL);
    sb_host_free(&host);
    free(code);
    free(id);
    sb_test_server_stop(&t);
}

/* ---- /api/agent/config, /api/hosts/{id}/config --------------------------- */

TEST(agent_config_etag_and_headers) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    sb_test_response r = call_as(&t, "legacy-self-token", "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.content_type, "application/json; charset=utf-8");
    CHECK_STR(r.rule_source, "profile");
    CHECK_STR(r.profile_id, "default");
    CHECK_STR(r.profile_name, "Default (tun + mixed)");
    /* ETag = SHA256(host id || pretty body || seed), quoted. */
    char *expected_etag = sb_config_etag("self", r.body, "contract-seed");
    CHECK_STR(r.etag, expected_etag);
    free(expected_etag);
    /* The body is the dump(2) of the same config the admin preview returns. */
    CHECK(r.body_len > 2 && r.body[0] == '{' && r.body[1] == '\n' && r.body[2] == ' ');
    char *pretty = r.json ? sbj_dump(r.json, 2) : NULL;
    CHECK_STR(pretty, r.body);
    free(pretty);
    char *compact = r.json ? sbj_dump(r.json, -1) : NULL;
    char *etag = sb_strdup(r.etag);
    sb_test_response_free(&r);
    r = call(&t, "GET", "/api/hosts/self/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.content_type, "application/json; charset=utf-8");
    CHECK_STR(r.body, compact);
    CHECK(r.etag == NULL);
    CHECK(r.rule_source == NULL);
    sb_test_response_free(&r);
    free(compact);

    sb_host host;
    sb_host_init(&host);
    CHECK(find_host(&t, "self", &host) == 1 && host.last_seen); /* polls touch the host */
    sb_host_free(&host);

    char *header = sb_asprintf("If-None-Match: %s", etag);
    r = call_with(&t, "legacy-self-token", header, "GET", "/api/agent/config", NULL);
    free(header);
    CHECK_EQ_INT(r.status, 304);
    CHECK_EQ_INT(r.body_len, 0);
    CHECK_STR(r.etag, etag);
    CHECK_STR(r.rule_source, "profile");
    CHECK_STR(r.profile_id, "default");
    CHECK_STR(r.profile_name, "Default (tun + mixed)");
    sb_test_response_free(&r);
    /* Only an exact match counts. */
    header = sb_asprintf("If-None-Match: W/%s", etag);
    r = call_with(&t, "legacy-self-token", header, "GET", "/api/agent/config", NULL);
    free(header);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.etag, etag);
    sb_test_response_free(&r);
    r = call_with(&t, "legacy-self-token", "If-None-Match: *", "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    free(etag);

    /* Profile headers follow the host's profile; a disabled script is
     * "profile", an enabled one "quickjs"; script failures are 422. */
    r = call(&t, "POST", "/api/hosts/profiles",
             "{\"name\":\"Script off\",\"template\":{\"route\":{\"rules\":[],\"final\":\"direct\"}},"
             "\"rule_script\":\"function buildRules() { throw new Error('never'); }\"}");
    char *off_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    r = call(&t, "POST", "/api/hosts/profiles",
             "{\"name\":\"Script bad\",\"template\":{\"route\":{\"rules\":[],\"final\":\"direct\"}},"
             "\"rule_script\":\"function buildRules() { return [{ outbound: 'nope' }]; }\",\"rule_script_enabled\":true}");
    char *bad_id = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(off_id && bad_id);
    char *body = sb_asprintf("{\"name\":\"Off host\",\"capabilities\":{},\"profile_id\":\"%s\"}", off_id);
    char *off_host = create_host(&t, body);
    free(body);
    body = sb_asprintf("{\"name\":\"Bad host\",\"capabilities\":{},\"profile_id\":\"%s\"}", bad_id);
    char *bad_host = create_host(&t, body);
    free(body);
    REQUIRE(off_host && bad_host);
    char *token = host_token(&t, off_host);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(r.rule_source, "profile");
    CHECK_STR(r.profile_id, off_id);
    CHECK_STR(r.profile_name, "Script off");
    expected_etag = sb_config_etag(off_host, r.body, "contract-seed");
    CHECK_STR(r.etag, expected_etag);
    free(expected_etag);
    sb_test_response_free(&r);
    free(token);
    token = host_token(&t, bad_host);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_ERROR(r, 422, "generated rule references unknown outbound tag: nope");
    CHECK_STR(jstr(r.json, "kind"), "rule_script");
    CHECK(r.etag == NULL);
    sb_test_response_free(&r);
    char *path = sb_asprintf("/api/hosts/%s/config", bad_host);
    r = call(&t, "GET", path, NULL);
    CHECK_ERROR(r, 422, "generated rule references unknown outbound tag: nope");
    sb_test_response_free(&r);
    free(path);
    /* A failed render does not count as a poll. */
    sb_host_init(&host);
    CHECK(find_host(&t, bad_host, &host) == 1 && host.last_seen == NULL);
    sb_host_free(&host);
    free(token);
    free(off_host);
    free(bad_host);
    free(off_id);
    free(bad_id);
    sb_test_server_stop(&t);
}

TEST(embedded_managed_network) {
    sb_test_server t;
    REQUIRE(sb_test_server_start(&t) == 0);
    /* A template that already uses the endpoint tag and a Clash controller. */
    sb_test_response r = call(&t, "POST", "/api/hosts/profiles",
                              "{\"name\":\"Embedded\",\"mode\":\"full\",\"template\":{"
                              "\"endpoints\":[{\"type\":\"wireguard\",\"tag\":\"sb-easy-network\",\"peers\":[]},7],"
                              "\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],"
                              "\"route\":{\"rules\":[],\"final\":\"direct\"},"
                              "\"experimental\":{\"clash_api\":{\"external_controller\":\"0.0.0.0:9090\"},"
                              "\"cache_file\":{\"enabled\":true}}}}");
    CHECK_EQ_INT(r.status, 200);
    char *profile = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(profile);
    char *body = sb_asprintf("{\"name\":\"Phone\",\"capabilities\":{\"platform\":\"android\"},\"profile_id\":\"%s\"}",
                             profile);
    char *phone = create_host(&t, body);
    free(body);
    REQUIRE(phone);
    char *token = host_token(&t, phone);
    char *config_path = sb_asprintf("/api/hosts/%s/config", phone);

    /* The admin preview never provisions: no identity, no endpoint, but the
     * control-plane route and the Clash removal already apply. */
    r = call(&t, "GET", config_path, NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jlen(r.json, "endpoints"), 2);
    CHECK(!jpath(r.json, "experimental.clash_api"));
    CHECK_JSON(r.json, "experimental.cache_file", "{\"enabled\":true}");
    CHECK_JSON(r.json, "route.rules.0", "{\"domain\":[\"panel.example.com\"],\"outbound\":\"direct\"}");
    sb_test_response_free(&r);
    CHECK_EQ_INT(peer_count(&t), 0);

    /* The first agent poll provisions the device identity. */
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(peer_count(&t), 1);
    CHECK_EQ_INT(jlen(r.json, "endpoints"), 3);
    CHECK_STR(jstr(r.json, "endpoints.2.tag"), "sb-easy-network group");
    CHECK_STR(jstr(r.json, "endpoints.2.type"), "wireguard");
    CHECK_JSON(r.json, "endpoints.2.address", "[\"10.59.32.2/32\"]");
    CHECK_STR(jstr(r.json, "endpoints.2.peers.0.address"), "vpn.example.com");
    CHECK_EQ_INT(jint(r.json, "endpoints.2.peers.0.port"), 51820);
    CHECK_JSON(r.json, "endpoints.2.peers.0.allowed_ips", "[\"10.59.32.0/24\"]");
    CHECK_EQ_INT(jint(r.json, "endpoints.2.mtu"), 1420);
    CHECK_JSON(r.json, "route.rules.0", "{\"domain\":[\"panel.example.com\"],\"outbound\":\"direct\"}");
    CHECK_JSON(r.json, "route.rules.1", "{\"ip_cidr\":[\"10.59.32.0/24\"],\"outbound\":\"sb-easy-network group\"}");
    CHECK(!jpath(r.json, "experimental.clash_api"));
    char *agent_compact = r.json ? sbj_dump(r.json, -1) : NULL;
    sb_test_response_free(&r);
    sb_host host;
    sb_host_init(&host);
    CHECK(find_host(&t, phone, &host) == 1);
    CHECK_STR(host.wg_address, "10.59.32.2/32");
    CHECK(host.wg_public_key != NULL);
    CHECK(host.clash_api == NULL); /* provisioning for embedded devices sets no Clash default */
    sb_host_free(&host);

    /* With an identity, the admin preview shows the same config. */
    r = call(&t, "GET", config_path, NULL);
    CHECK_STR(r.body, agent_compact);
    sb_test_response_free(&r);
    free(agent_compact);

    /* Node tags also count as taken. */
    REQUIRE(execute_sql(&t, "INSERT INTO proxy_nodes (id, tag, node_type, server, server_port, fingerprint, "
                            "protocol_config) VALUES ('g', 'sb-easy-network group', 'shadowsocks', 'g.example', 8388, "
                            "'fg', '{\"method\":\"aes-128-gcm\",\"password\":\"x\"}')") == 0);
    char *profile_path = sb_asprintf("/api/hosts/profiles/%s", profile);
    r = call(&t, "PUT", profile_path,
             "{\"name\":\"Embedded managed\",\"template\":{\"endpoints\":{\"not\":\"an array\"},"
             "\"route\":{\"rules\":[],\"final\":\"Proxy\"}}}");
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_EQ_INT(jlen(r.json, "endpoints"), 1); /* a non-array "endpoints" is replaced */
    CHECK_STR(jstr(r.json, "endpoints.0.tag"), "sb-easy-network");
    CHECK_STR(r.profile_name, "Embedded managed");
    sb_test_response_free(&r);
    r = call(&t, "PUT", profile_path,
             "{\"name\":\"Embedded managed\",\"template\":{\"endpoints\":[{\"tag\":\"sb-easy-network\"}],"
             "\"route\":{\"rules\":[],\"final\":\"Proxy\"}}}");
    sb_test_response_free(&r);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "endpoints.1.tag"), "sb-easy-network group group");
    sb_test_response_free(&r);
    /* value("tag", "") on a template endpoint: non-string tags are errors. */
    r = call(&t, "PUT", profile_path,
             "{\"name\":\"Embedded managed\",\"template\":{\"endpoints\":[{\"tag\":5}],\"route\":{\"rules\":[]}}}");
    sb_test_response_free(&r);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number");
    sb_test_response_free(&r);
    r = call(&t, "GET", config_path, NULL);
    CHECK_ERROR(r, 400, "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number");
    sb_test_response_free(&r);
    free(profile_path);

    /* Capability type errors surface as JSON errors on both config routes. */
    char *host_path = sb_asprintf("/api/hosts/%s", phone);
    static const struct {
        const char *capabilities, *error;
    } bad[] = {
        {"{\"embedded_wireguard\":\"yes\"}",
         "Invalid JSON request: [json.exception.type_error.302] type must be boolean, but is string"},
        {"{\"platform\":5}", "Invalid JSON request: [json.exception.type_error.302] type must be string, but is number"},
        {"{\"platform\":null}", "Invalid JSON request: [json.exception.type_error.302] type must be string, but is null"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        body = sb_asprintf("{\"capabilities\":%s,\"profile_id\":\"default\"}", bad[i].capabilities);
        r = call(&t, "PUT", host_path, body);
        free(body);
        CHECK_EQ_INT(r.status, 200);
        sb_test_response_free(&r);
        r = call_as(&t, token, "GET", "/api/agent/config", NULL);
        CHECK_ERROR(r, 400, bad[i].error);
        sb_test_response_free(&r);
        r = call(&t, "GET", config_path, NULL);
        CHECK_ERROR(r, 400, bad[i].error);
        sb_test_response_free(&r);
    }
    /* embedded_wireguard short-circuits the platform check (a full-mode
     * profile, because the managed renderer reads "platform" itself). */
    r = call(&t, "POST", "/api/hosts/profiles",
             "{\"name\":\"Full plain\",\"mode\":\"full\",\"template\":{\"route\":{\"rules\":[]}}}");
    char *full_plain = sb_strdup(jstr(r.json, "id"));
    sb_test_response_free(&r);
    REQUIRE(full_plain);
    body = sb_asprintf("{\"capabilities\":{\"embedded_wireguard\":true,\"platform\":5},\"profile_id\":\"%s\"}",
                       full_plain);
    r = call(&t, "PUT", host_path, body);
    free(body);
    CHECK_EQ_INT(r.status, 200);
    sb_test_response_free(&r);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK_STR(jstr(r.json, "endpoints.0.tag"), "sb-easy-network");
    CHECK_STR(r.profile_id, full_plain);
    CHECK_STR(r.profile_name, "Full plain");
    CHECK(!jpath(r.json, "experimental.clash_api"));
    sb_test_response_free(&r);
    free(full_plain);
    /* A disabled peer yields no endpoint (but still the embedded rules). */
    REQUIRE(execute_sql(&t, "UPDATE wireguard_peers SET enabled = 0") == 0);
    r = call_as(&t, token, "GET", "/api/agent/config", NULL);
    CHECK_EQ_INT(r.status, 200);
    CHECK(!jpath(r.json, "endpoints.0"));
    CHECK_JSON(r.json, "route.rules.0", "{\"domain\":[\"panel.example.com\"],\"outbound\":\"direct\"}");
    sb_test_response_free(&r);
    free(host_path);
    free(config_path);
    free(token);
    free(phone);
    free(profile);
    sb_test_server_stop(&t);
}
