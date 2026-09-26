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
