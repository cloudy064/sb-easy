/* Agent-side Clash API access (port of cpp/src/agent_clash.cpp). */
#include "sb/agent_clash.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "sb/clash_client.h"

/* ---- small helpers ---------------------------------------------------- */

static bool c_space(unsigned char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }
static bool c_cntrl(unsigned char c) { return c < 32 || c == 127; }
static bool c_alnum(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static void lower_in_place(char *s) {
    for (; s && *s; ++s)
        if (*s >= 'A' && *s <= 'Z') *s = (char)(*s - 'A' + 'a');
}

static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; *s; ++s) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

static int64_t max64(int64_t a, int64_t b) { return a > b ? a : b; }

static int64_t realtime_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* C++ trim(): std::isspace in the "C" locale. */
static char *trim_dup(const char *s) {
    const char *begin = s ? s : "";
    while (*begin && c_space((unsigned char)*begin)) ++begin;
    size_t len = strlen(begin);
    while (len > 0 && c_space((unsigned char)begin[len - 1])) --len;
    return sb_strndup(begin, len);
}

/* std::from_chars<unsigned int> over the whole text, then 1..65535. */
static bool parse_port_text(const char *s, size_t len, uint16_t *out) {
    if (len == 0) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        value = value * 10u + (uint64_t)(s[i] - '0');
        if (value > 65535u) return false; /* out of range either way */
    }
    if (value == 0) return false;
    *out = (uint16_t)value;
    return true;
}

/* C++ replace_all(). */
static char *replace_all(char *value, const char *from, const char *to) {
    size_t from_len = strlen(from), to_len = strlen(to);
    sb_buf out = {0};
    const char *p = value;
    const char *hit;
    while ((hit = strstr(p, from)) != NULL) {
        sb_buf_append(&out, p, (size_t)(hit - p));
        sb_buf_append(&out, to, to_len);
        p = hit + from_len;
    }
    sb_buf_puts(&out, p);
    free(value);
    return sb_buf_detach(&out);
}

/* C++ encode_component(): RFC 3986 unreserved kept, everything else %XX. */
static char *encode_component(const char *value) {
    static const char hexadecimal[] = "0123456789ABCDEF";
    sb_buf out = {0};
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (c_alnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            sb_buf_putc(&out, (char)*p);
        } else {
            sb_buf_putc(&out, '%');
            sb_buf_putc(&out, hexadecimal[*p >> 4u]);
            sb_buf_putc(&out, hexadecimal[*p & 0x0fu]);
        }
    }
    return sb_buf_detach(&out);
}

/* nlohmann object.value(key, "<fallback>"): the fallback when absent, a
 * type_error.302 when present but not a string. Returns a borrowed string. */
static int value_string(const sbj *object, const char *key, const char *fallback,
                        const char **out, sb_err *err) {
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = fallback;
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_BAD_JSON,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = found->v.str.ptr;
    return 0;
}

/* nlohmann get<std::int64_t>() of an integer (unsigned values wrap). */
static int64_t as_int64(const sbj *value) {
    return value->type == SBJ_UINT ? (int64_t)value->v.u : value->v.i;
}

/* nlohmann get<unsigned int>() of an integer (static_cast semantics). */
static uint32_t as_uint32(const sbj *value) {
    return value->type == SBJ_UINT ? (uint32_t)value->v.u : (uint32_t)(uint64_t)value->v.i;
}

/* nlohmann dump() rejects strings ending in a truncated UTF-8 sequence
 * (type_error.316). The inputs were valid UTF-8 before byte truncation, so
 * an incomplete trailing sequence is the only possible defect. */
static int check_utf8_complete(const char *s, sb_err *err) {
    size_t len = strlen(s);
    if (len == 0) return 0;
    size_t i = len, continuation = 0;
    while (i > 0 && continuation < 4 && ((unsigned char)s[i - 1] & 0xC0u) == 0x80u) {
        --i;
        ++continuation;
    }
    if (i == 0) return 0;
    unsigned char lead = (unsigned char)s[i - 1];
    size_t need = lead < 0x80u ? 1 : (lead & 0xE0u) == 0xC0u ? 2 : (lead & 0xF0u) == 0xE0u ? 3
                                  : (lead & 0xF8u) == 0xF0u ? 4 : 1;
    if (continuation + 1 < need)
        return sb_fail(err, SB_ERR_BAD_JSON,
                       "[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0x%02X",
                       (unsigned)(unsigned char)s[len - 1]);
    return 0;
}

/* ---- installed config ------------------------------------------------- */

/* C++ read_config(): an unreadable file vs. anything that is not an object. */
static sbj *read_config(const char *path, sb_err *err) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        sb_fail(err, SB_ERR_GENERIC, "cannot read sing-box config: %s", path);
        return NULL;
    }
    sb_buf buffer = {0};
    sb_buf_append(&buffer, "", 0);
    char chunk[65536];
    for (;;) {
        ssize_t count = read(fd, chunk, sizeof chunk);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            /* libstdc++ basic_filebuf::underflow (e.g. the path is a directory). */
            int saved = errno;
            close(fd);
            sb_buf_free(&buffer);
            sb_fail(err, SB_ERR_GENERIC, "basic_filebuf::underflow error reading the file: %s",
                    strerror(saved));
            return NULL;
        }
        if (count == 0) break;
        sb_buf_append(&buffer, chunk, (size_t)count);
    }
    close(fd);
    size_t len = buffer.len;
    char *text = sb_buf_detach(&buffer);
    const char *start = text;
    if (len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) { /* nlohmann skips a BOM */
        start += 3;
        len -= 3;
    }
    sbj *config = len ? sbj_parse(start, len, NULL, 0) : NULL;
    free(text);
    if (!sbj_is_object(config)) {
        sbj_free(config);
        sb_fail(err, SB_ERR_GENERIC, "sing-box config is not a JSON object: %s", path);
        return NULL;
    }
    return config;
}

typedef struct {
    char *base_url;
    char *secret;
} owned_target;

static void owned_target_free(owned_target *t) {
    free(t->base_url);
    free(t->secret);
    t->base_url = t->secret = NULL;
}

static sb_clash_target borrow_target(const owned_target *t) {
    sb_clash_target target = {t->base_url, t->secret};
    return target;
}

/* C++ read_target(): 1 with *out filled, 0 for std::nullopt (only when
 * use_default_controller is false), -1 on error. */
static int read_target(const char *path, bool use_default_controller, owned_target *out,
                       sb_err *err) {
    memset(out, 0, sizeof *out);
    sbj *config = read_config(path, err);
    if (!config) return -1;
    const sbj *clash_api = sbj_get(sbj_get(config, "experimental"), "clash_api");
    const sbj *controller = sbj_get(clash_api, "external_controller");
    char *address;
    if (sbj_is_string(controller)) {
        address = sb_strdup(controller->v.str.ptr);
    } else if (use_default_controller) {
        address = sb_strdup("127.0.0.1:9090");
    } else {
        sbj_free(config);
        return 0;
    }
    if (address[0] == '\0') {
        if (!use_default_controller) {
            free(address);
            sbj_free(config);
            return 0;
        }
        sb_str_set(&address, "127.0.0.1:9090");
    }
    address = replace_all(address, "0.0.0.0", "127.0.0.1");
    address = replace_all(address, "[::]", "127.0.0.1");
    if (!sb_starts_with(address, "http://") && !sb_starts_with(address, "https://")) {
        char *prefixed = sb_asprintf("http://%s", address);
        free(address);
        address = prefixed;
    }
    size_t len = strlen(address);
    while (len > 0 && address[len - 1] == '/') address[--len] = '\0';

    const sbj *secret = sbj_get(clash_api, "secret");
    out->base_url = address;
    out->secret = sb_strdup(sbj_is_string(secret) ? secret->v.str.ptr : "");
    sbj_free(config);
    return 1;
}

static bool successful(const sb_clash_response *response) {
    return response->status >= 200 && response->status < 300;
}

/* C++ response_error(). malloc'd. */
static char *response_error(const sb_clash_response *response) {
    static const char *const fields[] = {"message", "error"};
    for (size_t i = 0; i < 2; ++i) {
        const sbj *found = sbj_get(response->body, fields[i]);
        if (sbj_is_string(found) && found->v.str.len > 0) return sb_strdup(found->v.str.ptr);
    }
    return sb_asprintf("HTTP %d", response->status);
}

/* C++ integer_or_zero(). */
static int64_t integer_or_zero(const sbj *body, const char *field) {
    const sbj *found = sbj_get(body, field);
    if (!sbj_is_integer(found)) return 0;
    return as_int64(found);
}

/* ---- service state ---------------------------------------------------- */

typedef struct {
    char *key; /* identity.dump() */
    uint64_t hash;
    sbj *identity;
    int64_t connection_count, uplink_total, downlink_total, first_seen, last_seen;
    uint64_t sequence; /* insertion order, used for deterministic ties */
} domain_stat;

typedef struct {
    char *id;
    uint64_t hash;
    char *route_key;
    int64_t uplink_total, downlink_total;
    bool seen;
} observed_connection;

struct sb_agent_clash {
    char *config_path;
    sb_clash_client *client; /* 8 s timeout, 8 MiB (stateless, thread-safe) */

    pthread_mutex_t mutex; /* guards the telemetry state below */
    bool has_last_sample;
    int64_t last_upload_total, last_download_total, last_sample_ns;
    observed_connection *observed;
    size_t observed_len, observed_cap;
    domain_stat *stats;
    size_t stats_len, stats_cap;
    uint64_t next_sequence;
};

sb_agent_clash *sb_agent_clash_new(const char *config_path) {
    sb_agent_clash *clash = sb_xcalloc(1, sizeof *clash);
    clash->config_path = sb_strdup(config_path ? config_path : "");
    sb_clash_client_options options = {.timeout_ms = 8000,
                                       .maximum_body_bytes = 8u * 1024u * 1024u};
    clash->client = sb_clash_client_new(&options, NULL);
    pthread_mutex_init(&clash->mutex, NULL);
    return clash;
}

static void clear_observed(sb_agent_clash *clash) {
    for (size_t i = 0; i < clash->observed_len; ++i) {
        free(clash->observed[i].id);
        free(clash->observed[i].route_key);
    }
    clash->observed_len = 0;
}

void sb_agent_clash_free(sb_agent_clash *clash) {
    if (!clash) return;
    clear_observed(clash);
    free(clash->observed);
    for (size_t i = 0; i < clash->stats_len; ++i) {
        free(clash->stats[i].key);
        sbj_free(clash->stats[i].identity);
    }
    free(clash->stats);
    sb_clash_client_free(clash->client);
    pthread_mutex_destroy(&clash->mutex);
    free(clash->config_path);
    free(clash);
}

/* ---- test_proxies ----------------------------------------------------- */

static bool skipped_type(const char *type) {
    static const char *const skipped[] = {"Selector", "URLTest", "Fallback", "LoadBalance",
                                          "Direct",   "Reject",  "Compatible", "Pass",
                                          "Dns",      "Block",   "Loopback"};
    for (size_t i = 0; i < sizeof skipped / sizeof skipped[0]; ++i)
        if (strcmp(type, skipped[i]) == 0) return true;
    return false;
}

static int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int sb_agent_clash_test_proxies(sb_agent_clash *clash, const sb_strvec *tags,
                                sb_latency_reporter reporter, void *user, size_t *tested,
                                sb_err *err) {
    if (!reporter) return sb_fail(err, SB_ERR_VALIDATION, "proxy latency reporter is required");
    owned_target owned;
    if (read_target(clash->config_path, true, &owned, err) < 0) return -1;
    sb_clash_target target = borrow_target(&owned);
    sb_clash_response response = {0};
    sb_strvec names = {0};
    char *delay_query = NULL;
    int rc = -1;
    size_t count = 0;
    if (sb_clash_get(clash->client, &target, "/proxies", &response, err) != 0) goto out;
    if (!successful(&response)) {
        sb_fail(err, SB_ERR_GENERIC, "Clash proxy list returned HTTP %d", response.status);
        goto out;
    }
    const sbj *found = sbj_get(response.body, "proxies");
    if (!sbj_is_object(found)) {
        rc = 0;
        goto out;
    }
    const char *name;
    const sbj *proxy;
    SBJ_OBJ_FOREACH(found, i, name, proxy) {
        const char *type = "";
        if (sbj_is_object(proxy) && value_string(proxy, "type", "", &type, err) != 0) goto out;
        bool is_group = sbj_is_object(proxy) && sbj_has(proxy, "all");
        if (!is_group && !skipped_type(type) && (!tags || sb_strvec_contains(tags, name)))
            sb_strvec_push(&names, name);
    }
    if (names.len > 1) qsort(names.items, names.len, sizeof *names.items, compare_strings);

    {
        char *probe = encode_component("https://www.gstatic.com/generate_204");
        delay_query = sb_asprintf("/delay?url=%s&timeout=5000", probe);
        free(probe);
    }
    for (size_t i = 0; i < names.len; ++i) {
        sbj *latency = sbj_null();
        char *encoded = encode_component(names.items[i]);
        char *path = sb_asprintf("/proxies/%s%s", encoded, delay_query);
        sb_clash_response delay = {0};
        sb_err ignored = {0};
        /* An unreachable proxy is a valid null measurement; continue
         * reporting the remaining nodes. */
        if (sb_clash_get(clash->client, &target, path, &delay, &ignored) == 0) {
            if (successful(&delay)) {
                const sbj *value = sbj_get(delay.body, "delay");
                if (sbj_is_number(value)) {
                    sbj_free(latency);
                    latency = sbj_clone(value);
                }
            }
            sb_clash_response_free(&delay);
        }
        free(path);
        free(encoded);
        sbj *result = sbj_object();
        sbj_set(result, names.items[i], latency);
        int reported = reporter(result, user, err);
        sbj_free(result);
        if (reported != 0) goto out;
        ++count;
    }
    rc = 0;
out:
    if (rc == 0 && tested) *tested = count;
    free(delay_query);
    sb_strvec_free(&names);
    sb_clash_response_free(&response);
    owned_target_free(&owned);
    return rc;
}

/* ---- telemetry / domain route stats ----------------------------------- */

static domain_stat *find_stat(sb_agent_clash *clash, const char *key, uint64_t hash) {
    for (size_t i = 0; i < clash->stats_len; ++i)
        if (clash->stats[i].hash == hash && strcmp(clash->stats[i].key, key) == 0)
            return &clash->stats[i];
    return NULL;
}

static void erase_stat(sb_agent_clash *clash, size_t index) {
    free(clash->stats[index].key);
    sbj_free(clash->stats[index].identity);
    memmove(&clash->stats[index], &clash->stats[index + 1],
            (clash->stats_len - index - 1) * sizeof *clash->stats);
    --clash->stats_len;
}

static void add_domain_route(sb_agent_clash *clash, const sbj *identity, const char *route_key,
                             uint64_t hash, int64_t connections, int64_t uplink,
                             int64_t downlink, int64_t now) {
    domain_stat *stat = find_stat(clash, route_key, hash);
    if (!stat && clash->stats_len >= 1000u) {
        size_t oldest = 0;
        for (size_t i = 1; i < clash->stats_len; ++i)
            if (clash->stats[i].last_seen < clash->stats[oldest].last_seen) oldest = i;
        erase_stat(clash, oldest);
    }
    if (!stat) {
        if (clash->stats_len == clash->stats_cap) {
            clash->stats_cap = clash->stats_cap ? clash->stats_cap * 2 : 16;
            clash->stats = sb_xrealloc(clash->stats, clash->stats_cap * sizeof *clash->stats);
        }
        stat = &clash->stats[clash->stats_len++];
        memset(stat, 0, sizeof *stat);
        stat->key = sb_strdup(route_key);
        stat->hash = hash;
        stat->identity = sbj_clone(identity);
        stat->first_seen = now;
        stat->last_seen = now;
        stat->sequence = clash->next_sequence++;
    }
    stat->connection_count += max64(connections, 0);
    stat->uplink_total += max64(uplink, 0);
    stat->downlink_total += max64(downlink, 0);
    stat->last_seen = max64(stat->last_seen, now);
}

static void subtract_domain_route(sb_agent_clash *clash, const observed_connection *observed) {
    uint64_t hash = fnv1a(observed->route_key);
    domain_stat *stat = find_stat(clash, observed->route_key, hash);
    if (!stat) return;
    stat->connection_count = max64(stat->connection_count - 1, 0);
    stat->uplink_total = max64(stat->uplink_total - observed->uplink_total, 0);
    stat->downlink_total = max64(stat->downlink_total - observed->downlink_total, 0);
    if (stat->connection_count == 0 && stat->uplink_total == 0 && stat->downlink_total == 0)
        erase_stat(clash, (size_t)(stat - clash->stats));
}

static const char *string_field(const sbj *value, const char *field) {
    const sbj *found = sbj_get(value, field);
    return sbj_is_string(found) ? found->v.str.ptr : "";
}

/* C++ domain_route_identity(); NULL only when nlohmann's dump() would throw. */
static sbj *domain_route_identity(const sbj *connection, sb_err *err) {
    const sbj *metadata = sbj_get(connection, "metadata");
    if (!sbj_is_object(metadata)) metadata = NULL;
    char *domain = sb_strdup(string_field(metadata, "host"));
    if (domain[0] == '\0') sb_str_set(&domain, string_field(metadata, "destinationIP"));
    if (domain[0] == '\0') sb_str_set(&domain, "unknown");
    size_t len = strlen(domain);
    while (len > 0 && domain[len - 1] == '.') domain[--len] = '\0';
    lower_in_place(domain);
    if (len > 512u) domain[512] = '\0';

    sbj *chain = sbj_array();
    const sbj *chains = sbj_get(connection, "chains");
    const sbj *tag;
    SBJ_ARR_FOREACH(chains, i, tag) {
        if (sbj_is_string(tag) && sbj_arr_len(chain) < 16u)
            sbj_arr_push(chain, sbj_strn(tag->v.str.ptr, tag->v.str.len < 256u ? tag->v.str.len : 256u));
    }
    size_t chain_len = sbj_arr_len(chain);
    const char *outbound = chain_len ? sbj_arr_at(chain, chain_len - 1)->v.str.ptr : "";
    char *route_text = sb_strdup(outbound);
    lower_in_place(route_text);
    const char *outbound_type = strstr(route_text, "direct") ? "direct"
                                : route_text[0] == '\0'      ? ""
                                                             : "proxy";
    const char *rule_value = string_field(connection, "rule");
    const char *payload = string_field(connection, "rulePayload");
    char *rule = payload[0] ? sb_asprintf("%s%s%s", rule_value, rule_value[0] ? ": " : "", payload)
                            : sb_strdup(rule_value);
    if (strlen(rule) > 512u) rule[512] = '\0';

    sbj *identity = sbj_object();
    sbj_set_str(identity, "domain", domain);
    sbj_set_str(identity, "outbound", outbound);
    sbj_set_str(identity, "outbound_type", outbound_type);
    sbj_set_str(identity, "rule", rule);
    sbj_set(identity, "chain", chain);

    /* dump() order: "chain" items, "domain", "outbound", "outbound_type", "rule". */
    int rc = 0;
    SBJ_ARR_FOREACH(chain, j, tag) {
        if (rc == 0) rc = check_utf8_complete(tag->v.str.ptr, err);
    }
    if (rc == 0) rc = check_utf8_complete(domain, err);
    if (rc == 0) rc = check_utf8_complete(rule, err);
    free(domain);
    free(route_text);
    free(rule);
    if (rc != 0) {
        sbj_free(identity);
        return NULL;
    }
    return identity;
}

static int64_t nonnegative_connection_integer(const sbj *connection, const char *field) {
    const sbj *value = sbj_get(connection, field);
    if (!sbj_is_integer(value)) return 0;
    return max64(as_int64(value), 0);
}

static observed_connection *find_observed(sb_agent_clash *clash, const char *id, uint64_t hash) {
    for (size_t i = 0; i < clash->observed_len; ++i)
        if (clash->observed[i].hash == hash && strcmp(clash->observed[i].id, id) == 0)
            return &clash->observed[i];
    return NULL;
}

static int compare_stats(const void *a, const void *b) {
    const domain_stat *left = *(const domain_stat *const *)a;
    const domain_stat *right = *(const domain_stat *const *)b;
    if (left->connection_count != right->connection_count)
        return left->connection_count > right->connection_count ? -1 : 1;
    int64_t left_total = left->uplink_total + left->downlink_total;
    int64_t right_total = right->uplink_total + right->downlink_total;
    if (left_total != right_total) return left_total > right_total ? -1 : 1;
    return left->sequence < right->sequence ? -1 : (left->sequence > right->sequence ? 1 : 0);
}

/* C++ update_domain_route_stats(). Caller holds clash->mutex. */
static sbj *update_domain_route_stats(sb_agent_clash *clash, const sbj *connections,
                                      sb_err *err) {
    if (!sbj_is_array(connections)) {
        clear_observed(clash);
        return sbj_array();
    }
    int64_t now = realtime_ms();
    for (size_t i = 0; i < clash->observed_len; ++i) clash->observed[i].seen = false;
    const sbj *connection;
    SBJ_ARR_FOREACH(connections, i, connection) {
        if (!sbj_is_object(connection)) continue;
        const sbj *id_value = sbj_get(connection, "id");
        if (!sbj_is_string(id_value) || id_value->v.str.len == 0) continue;
        const char *id = id_value->v.str.ptr;
        uint64_t id_hash = fnv1a(id);
        observed_connection *observed = find_observed(clash, id, id_hash);
        if (observed) observed->seen = true;
        sbj *identity = domain_route_identity(connection, err);
        if (!identity) return NULL;
        char *route_key = sbj_dump(identity, -1);
        uint64_t key_hash = fnv1a(route_key);
        int64_t uplink = nonnegative_connection_integer(connection, "upload");
        int64_t downlink = nonnegative_connection_integer(connection, "download");
        if (!observed) {
            add_domain_route(clash, identity, route_key, key_hash, 1, uplink, downlink, now);
            if (clash->observed_len == clash->observed_cap) {
                clash->observed_cap = clash->observed_cap ? clash->observed_cap * 2 : 16;
                clash->observed = sb_xrealloc(clash->observed,
                                              clash->observed_cap * sizeof *clash->observed);
            }
            observed_connection *added = &clash->observed[clash->observed_len++];
            added->id = sb_strdup(id);
            added->hash = id_hash;
            added->route_key = route_key;
            added->uplink_total = uplink;
            added->downlink_total = downlink;
            added->seen = true;
            sbj_free(identity);
            continue;
        }
        if (strcmp(observed->route_key, route_key) != 0) {
            subtract_domain_route(clash, observed);
            add_domain_route(clash, identity, route_key, key_hash, 1, uplink, downlink, now);
            free(observed->route_key);
            observed->route_key = route_key;
            observed->uplink_total = uplink;
            observed->downlink_total = downlink;
            sbj_free(identity);
            continue;
        }
        add_domain_route(clash, identity, route_key, key_hash, 0,
                         max64(uplink - observed->uplink_total, 0),
                         max64(downlink - observed->downlink_total, 0), now);
        observed->uplink_total = max64(observed->uplink_total, uplink);
        observed->downlink_total = max64(observed->downlink_total, downlink);
        free(route_key);
        sbj_free(identity);
    }
    size_t kept = 0;
    for (size_t i = 0; i < clash->observed_len; ++i) {
        if (clash->observed[i].seen) {
            clash->observed[kept++] = clash->observed[i];
        } else {
            free(clash->observed[i].id);
            free(clash->observed[i].route_key);
        }
    }
    clash->observed_len = kept;

    domain_stat **ordered = sb_xcalloc(clash->stats_len ? clash->stats_len : 1, sizeof *ordered);
    for (size_t i = 0; i < clash->stats_len; ++i) ordered[i] = &clash->stats[i];
    if (clash->stats_len > 1) qsort(ordered, clash->stats_len, sizeof *ordered, compare_stats);
    sbj *result = sbj_array();
    for (size_t i = 0; i < clash->stats_len; ++i) {
        const domain_stat *stat = ordered[i];
        sbj *value = sbj_clone(stat->identity);
        sbj_set_int(value, "connection_count", stat->connection_count);
        sbj_set_int(value, "uplink_total", stat->uplink_total);
        sbj_set_int(value, "downlink_total", stat->downlink_total);
        sbj_set_int(value, "first_seen", stat->first_seen);
        sbj_set_int(value, "last_seen", stat->last_seen);
        sbj_arr_push(result, value);
    }
    free(ordered);
    return result;
}

int sb_agent_clash_sample_telemetry(sb_agent_clash *clash, sbj **out, sb_err *err) {
    *out = NULL;
    owned_target owned;
    int found_target = read_target(clash->config_path, false, &owned, err);
    if (found_target < 0) return -1;
    if (found_target == 0) return 0;
    sb_clash_target target = borrow_target(&owned);
    sb_clash_response response = {0};
    int rc = sb_clash_get(clash->client, &target, "/connections", &response, err);
    owned_target_free(&owned);
    if (rc != 0) return -1;
    if (!successful(&response)) {
        sb_fail(err, SB_ERR_GENERIC, "Clash connections returned HTTP %d", response.status);
        sb_clash_response_free(&response);
        return -1;
    }

    int64_t upload_total = integer_or_zero(response.body, "uploadTotal");
    int64_t download_total = integer_or_zero(response.body, "downloadTotal");
    int64_t now = monotonic_ns();
    int64_t upload_rate = 0, download_rate = 0;

    pthread_mutex_lock(&clash->mutex);
    if (clash->has_last_sample) {
        double elapsed = (double)(now - clash->last_sample_ns) / 1e9;
        if (elapsed < 0.001) elapsed = 0.001;
        int64_t upload_delta = max64(upload_total - clash->last_upload_total, 0);
        int64_t download_delta = max64(download_total - clash->last_download_total, 0);
        upload_rate = (int64_t)((double)upload_delta / elapsed);
        download_rate = (int64_t)((double)download_delta / elapsed);
    }
    clash->has_last_sample = true;
    clash->last_upload_total = upload_total;
    clash->last_download_total = download_total;
    clash->last_sample_ns = now;

    const sbj *found = sbj_get(response.body, "connections");
    sbj *connections = found ? sbj_clone(found) : sbj_array();
    size_t connection_count = sbj_is_array(connections) ? sbj_arr_len(connections) : 0u;
    sbj *domain_stats = update_domain_route_stats(clash, connections, err);
    pthread_mutex_unlock(&clash->mutex);
    sb_clash_response_free(&response);
    if (!domain_stats) {
        sbj_free(connections);
        return -1;
    }
    sbj *telemetry = sbj_object();
    sbj_set_int(telemetry, "up", upload_rate);
    sbj_set_int(telemetry, "down", download_rate);
    sbj_set_int(telemetry, "up_total", upload_total);
    sbj_set_int(telemetry, "down_total", download_total);
    sbj_set_int(telemetry, "conn_count", (int64_t)connection_count);
    sbj_set(telemetry, "connections", connections);
    sbj_set(telemetry, "domain_stats", domain_stats);
    sbj_set(telemetry, "logs", sbj_array());
    *out = telemetry;
    return 0;
}

/* ---- proxies / select_proxy ------------------------------------------- */

sbj *sb_agent_clash_proxies(sb_agent_clash *clash, sb_err *err) {
    owned_target owned;
    if (read_target(clash->config_path, true, &owned, err) < 0) return NULL;
    sb_clash_target target = borrow_target(&owned);
    sb_clash_response response = {0};
    int rc = sb_clash_get(clash->client, &target, "/proxies", &response, err);
    owned_target_free(&owned);
    if (rc != 0) return NULL;
    sbj *result = NULL;
    if (!successful(&response)) {
        char *message = response_error(&response);
        sb_fail(err, SB_ERR_GENERIC, "读取本地代理组失败：%s", message);
        free(message);
    } else if (!sbj_is_object(response.body) || !sbj_is_object(sbj_get(response.body, "proxies"))) {
        sb_fail(err, SB_ERR_GENERIC, "本地 Clash API 返回了无效的代理组数据");
    } else {
        result = response.body;
        response.body = NULL;
    }
    sb_clash_response_free(&response);
    return result;
}

sbj *sb_agent_clash_select_proxy(sb_agent_clash *clash, const char *group, const char *proxy,
                                 sb_err *err) {
    if (sb_str_empty(group) || sb_str_empty(proxy)) {
        sb_fail(err, SB_ERR_VALIDATION, "策略组和节点名称不能为空");
        return NULL;
    }
    owned_target owned;
    if (read_target(clash->config_path, true, &owned, err) < 0) return NULL;
    sb_clash_target target = borrow_target(&owned);
    char *encoded = encode_component(group);
    char *path = sb_asprintf("/proxies/%s", encoded);
    sbj *body = sbj_object();
    sbj_set_str(body, "name", proxy);
    sb_clash_response response = {0};
    int rc = sb_clash_put(clash->client, &target, path, body, &response, err);
    sbj_free(body);
    free(path);
    free(encoded);
    owned_target_free(&owned);
    if (rc != 0) return NULL;
    sbj *result = NULL;
    if (!successful(&response)) {
        char *message = response_error(&response);
        sb_fail(err, SB_ERR_GENERIC, "切换节点失败：%s", message);
        free(message);
    } else {
        result = sbj_object();
        sbj_set_bool(result, "success", true);
        sbj_set_str(result, "group", group);
        sbj_set_str(result, "name", proxy);
    }
    sb_clash_response_free(&response);
    return result;
}

/* ---- test_route ------------------------------------------------------- */

typedef struct {
    char *url;
    char *host;
    uint16_t port;
} url_target;

static void url_target_free(url_target *t) {
    free(t->url);
    free(t->host);
    memset(t, 0, sizeof *t);
}

/* C++ parse_url(). */
static int parse_url(const char *input, url_target *out, sb_err *err) {
    memset(out, 0, sizeof *out);
    char *value = trim_dup(input);
    if (value[0] == '\0') {
        free(value);
        return sb_fail(err, SB_ERR_VALIDATION, "请输入要测试的 URL");
    }
    if (!strstr(value, "://")) {
        char *prefixed = sb_asprintf("https://%s", value);
        free(value);
        value = prefixed;
    }
    size_t scheme_end = (size_t)(strstr(value, "://") - value);
    char *scheme = sb_strndup(value, scheme_end);
    lower_in_place(scheme);
    bool https = strcmp(scheme, "https") == 0;
    bool supported = https || strcmp(scheme, "http") == 0;
    free(scheme);
    if (!supported) {
        free(value);
        return sb_fail(err, SB_ERR_VALIDATION, "只支持 http:// 或 https:// URL");
    }
    size_t authority_begin = scheme_end + 3u;
    size_t authority_len = strcspn(value + authority_begin, "/?#");
    char *authority = sb_strndup(value + authority_begin, authority_len);
    bool invalid = authority[0] == '\0' || strchr(authority, '@') != NULL;
    for (const unsigned char *p = (const unsigned char *)authority; !invalid && *p; ++p)
        if (c_cntrl(*p) || c_space(*p)) invalid = true;
    int rc = -1;
    char *host = NULL;
    uint16_t port = https ? 443u : 80u;
    if (invalid) {
        sb_fail(err, SB_ERR_VALIDATION, "URL 主机名无效");
        goto out;
    }
    if (authority[0] == '[') {
        char *bracket = strchr(authority, ']');
        if (!bracket) {
            sb_fail(err, SB_ERR_VALIDATION, "URL IPv6 主机名无效");
            goto out;
        }
        size_t index = (size_t)(bracket - authority);
        host = sb_strndup(authority + 1, index - 1u);
        if (index + 1u < authority_len) {
            if (authority[index + 1u] != ':') {
                sb_fail(err, SB_ERR_VALIDATION, "URL 主机名无效");
                goto out;
            }
            if (!parse_port_text(authority + index + 2u, authority_len - index - 2u, &port)) {
                sb_fail(err, SB_ERR_VALIDATION, "URL 端口无效");
                goto out;
            }
        }
    } else {
        char *first = strchr(authority, ':');
        char *last = strrchr(authority, ':');
        if (last && first == last) {
            host = sb_strndup(authority, (size_t)(last - authority));
            if (!parse_port_text(last + 1, strlen(last + 1), &port)) {
                sb_fail(err, SB_ERR_VALIDATION, "URL 端口无效");
                goto out;
            }
        } else {
            host = sb_strdup(authority);
        }
    }
    if (host[0] == '\0') {
        sb_fail(err, SB_ERR_VALIDATION, "URL 主机名无效");
        goto out;
    }
    out->url = value;
    value = NULL;
    out->host = host;
    host = NULL;
    out->port = port;
    rc = 0;
out:
    free(host);
    free(authority);
    free(value);
    return rc;
}

typedef struct {
    char *host;
    uint16_t port;
} local_proxy;

/* C++ read_local_proxy(). */
static int read_local_proxy(const sbj *config, local_proxy *out, sb_err *err) {
    const sbj *inbounds = sbj_get(config, "inbounds");
    if (!sbj_is_array(inbounds))
        return sb_fail(err, SB_ERR_GENERIC, "当前配置没有可用于测试的 HTTP/mixed 入站");
    const sbj *inbound;
    SBJ_ARR_FOREACH(inbounds, i, inbound) {
        if (!sbj_is_object(inbound)) continue;
        const char *type = NULL;
        if (value_string(inbound, "type", "", &type, err) != 0) return -1;
        if (strcmp(type, "mixed") != 0 && strcmp(type, "http") != 0) continue;
        const sbj *port = sbj_get(inbound, "listen_port");
        if (!sbj_is_integer(port)) continue;
        uint32_t number = as_uint32(port);
        if (number == 0u || number > 65535u) continue;
        const char *listen = NULL;
        if (value_string(inbound, "listen", "127.0.0.1", &listen, err) != 0) return -1;
        if (listen[0] == '\0' || strcmp(listen, "0.0.0.0") == 0) listen = "127.0.0.1";
        else if (strcmp(listen, "::") == 0 || strcmp(listen, "[::]") == 0) listen = "::1";
        out->host = sb_strdup(listen);
        out->port = (uint16_t)number;
        return 0;
    }
    return sb_fail(err, SB_ERR_GENERIC, "当前配置需要 mixed 或 http 入站才能执行真实路由测试");
}

/* C++ connect_local_proxy(): returns a connected descriptor or -1. */
static int connect_local_proxy(const local_proxy *proxy, sb_err *err) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *addresses = NULL;
    char service[8];
    snprintf(service, sizeof service, "%u", (unsigned)proxy->port);
    if (getaddrinfo(proxy->host, service, &hints, &addresses) != 0)
        return sb_fail(err, SB_ERR_GENERIC, "无法解析本地代理入口");
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        int descriptor = socket(address->ai_family, address->ai_socktype | SOCK_CLOEXEC,
                                address->ai_protocol);
        if (descriptor < 0) continue;
        struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
        (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        if (connect(descriptor, address->ai_addr, address->ai_addrlen) == 0) {
            freeaddrinfo(addresses);
            return descriptor;
        }
        close(descriptor);
    }
    freeaddrinfo(addresses);
    return sb_fail(err, SB_ERR_GENERIC, "无法连接当前配置的本地代理入口");
}

static int source_port(int descriptor, uint16_t *port, sb_err *err) {
    struct sockaddr_storage address;
    memset(&address, 0, sizeof address);
    socklen_t length = sizeof address;
    if (getsockname(descriptor, (struct sockaddr *)&address, &length) != 0)
        return sb_fail(err, SB_ERR_GENERIC, "无法读取测试连接源端口");
    if (address.ss_family == AF_INET) {
        *port = ntohs(((const struct sockaddr_in *)&address)->sin_port);
        return 0;
    }
    if (address.ss_family == AF_INET6) {
        *port = ntohs(((const struct sockaddr_in6 *)&address)->sin6_port);
        return 0;
    }
    return sb_fail(err, SB_ERR_GENERIC, "测试连接使用了不支持的地址类型");
}

static int send_all(int descriptor, const char *value, sb_err *err) {
    size_t length = strlen(value), sent = 0;
    while (sent < length) {
        ssize_t count = send(descriptor, value + sent, length - sent, MSG_NOSIGNAL);
        if (count <= 0) return sb_fail(err, SB_ERR_GENERIC, "无法向本地代理发送测试请求");
        sent += (size_t)count;
    }
    return 0;
}

/* C++ metadata_matches_port(). nlohmann parses non-negative integers as
 * number_unsigned, which is what is_number_unsigned() accepts. */
static bool metadata_matches_port(const sbj *metadata, uint16_t port) {
    const sbj *found = sbj_get(metadata, "sourcePort");
    if (!found) return false;
    if (found->type == SBJ_UINT || (found->type == SBJ_INT && found->v.i >= 0))
        return as_uint32(found) == port;
    if (sbj_is_string(found)) {
        uint16_t parsed = 0;
        return parse_port_text(found->v.str.ptr, found->v.str.len, &parsed) && parsed == port;
    }
    return false;
}

static const sbj *find_connection(const sbj *response, uint16_t port) {
    const sbj *connections = sbj_get(response, "connections");
    if (!sbj_is_array(connections)) return NULL;
    const sbj *connection;
    SBJ_ARR_FOREACH(connections, i, connection) {
        const sbj *metadata = sbj_get(connection, "metadata");
        if (sbj_is_object(connection) && sbj_is_object(metadata) &&
            metadata_matches_port(metadata, port))
            return connection;
    }
    return NULL;
}

/* C++ route_result(). */
static sbj *route_result(const url_target *target, const sbj *connection, sb_err *err) {
    const sbj *found_chains = sbj_get(connection, "chains");
    sbj *chains = sbj_is_array(found_chains) ? sbj_clone(found_chains) : sbj_array();
    const char *outbound = "";
    if (sbj_arr_len(chains) > 0 && sbj_is_string(sbj_arr_at(chains, 0)))
        outbound = sbj_arr_at(chains, 0)->v.str.ptr;
    char *normalized = sb_strdup(outbound);
    lower_in_place(normalized);
    const char *kind = "proxy";
    if (strcmp(normalized, "direct") == 0) kind = "direct";
    else if (strcmp(normalized, "block") == 0 || strcmp(normalized, "reject") == 0) kind = "block";
    else if (outbound[0] == '\0') kind = "unknown";
    free(normalized);
    const char *rule = NULL, *rule_payload = NULL;
    if (value_string(connection, "rule", "", &rule, err) != 0 ||
        value_string(connection, "rulePayload", "", &rule_payload, err) != 0) {
        sbj_free(chains);
        return NULL;
    }
    sbj *result = sbj_object();
    sbj_set_bool(result, "success", true);
    sbj_set_str(result, "url", target->url);
    sbj_set_str(result, "host", target->host);
    sbj_set_int(result, "port", target->port);
    sbj_set_str(result, "kind", kind);
    sbj_set_str(result, "outbound", outbound);
    sbj_set_str(result, "rule", rule);
    sbj_set_str(result, "rule_payload", rule_payload);
    sbj_set(result, "chains", chains);
    return result;
}

sbj *sb_agent_clash_test_route(sb_agent_clash *clash, const char *url, sb_err *err) {
    url_target destination;
    if (parse_url(url, &destination, err) != 0) return NULL;
    sbj *result = NULL;
    sbj *config = NULL;
    local_proxy proxy = {0};
    owned_target owned = {0};
    sb_clash_client *client = NULL;
    char *request = NULL;
    int descriptor = -1;

    config = read_config(clash->config_path, err);
    if (!config) goto out;
    if (read_local_proxy(config, &proxy, err) != 0) goto out;
    if (read_target(clash->config_path, true, &owned, err) < 0) goto out;
    sb_clash_client_options options = {.timeout_ms = 2000,
                                       .maximum_body_bytes = 8u * 1024u * 1024u};
    client = sb_clash_client_new(&options, err);
    if (!client) goto out;
    descriptor = connect_local_proxy(&proxy, err);
    if (descriptor < 0) goto out;
    uint16_t port = 0;
    if (source_port(descriptor, &port, err) != 0) goto out;
    {
        char *authority = strchr(destination.host, ':')
                              ? sb_asprintf("[%s]:%u", destination.host, (unsigned)destination.port)
                              : sb_asprintf("%s:%u", destination.host, (unsigned)destination.port);
        request = sb_asprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n"
                              "User-Agent: sb-easy-route-test/1.0\r\n"
                              "Proxy-Connection: keep-alive\r\n\r\n",
                              authority, authority);
        free(authority);
    }
    if (send_all(descriptor, request, err) != 0) goto out;

    sb_clash_target target = borrow_target(&owned);
    for (int attempt = 0; attempt < 50; ++attempt) {
        sb_clash_response response = {0};
        if (sb_clash_get(client, &target, "/connections", &response, err) != 0) goto out;
        if (!successful(&response)) {
            sb_fail(err, SB_ERR_GENERIC, "Clash connections returned HTTP %d", response.status);
            sb_clash_response_free(&response);
            goto out;
        }
        const sbj *connection = find_connection(response.body, port);
        if (connection) {
            result = route_result(&destination, connection, err);
            sb_clash_response_free(&response);
            goto out;
        }
        sb_clash_response_free(&response);
        sb_sleep_ms(50);
    }
    sb_fail(err, SB_ERR_GENERIC, "未能在 Clash API 中找到测试连接；目标可能不可达或被规则拒绝");
out:
    if (descriptor >= 0) close(descriptor);
    free(request);
    sb_clash_client_free(client);
    owned_target_free(&owned);
    free(proxy.host);
    sbj_free(config);
    url_target_free(&destination);
    return result;
}
