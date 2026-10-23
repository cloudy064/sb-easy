#include "desktop.h"
#include "libsb_easy_singbox.h"
#include "sb/http_client.h"
#include <curl/curl.h>
#include <fcntl.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
void sbl_runtime_cancel_start(void) {
    SBEasySingBoxCancelStart();
}
/* The upstream TUN owns this rule-priority range on start and stop. Refuse a
 * preexisting owner before it can clean that range or reuse our route table. */
static bool tun_network_available(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return false;
    struct timeval timeout = {.tv_sec = 2};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    bool ok = true;
    for (unsigned query = 0; query < 2 && ok; ++query) {
        struct {
            struct nlmsghdr header;
            struct rtgenmsg message;
        } request = {.header = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)),
                                .nlmsg_type = query ? RTM_GETROUTE : RTM_GETRULE,
                                .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                                .nlmsg_seq = query + 1},
                     .message = {.rtgen_family = AF_UNSPEC}};
        struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
        if (sendto(fd, &request, request.header.nlmsg_len, 0,
                   (struct sockaddr*)&kernel, sizeof kernel) < 0) {
            ok = false;
            break;
        }
        bool done = false;
        for (unsigned page = 0; page < 256 && !done && ok; ++page) {
            unsigned char buffer[32768];
            ssize_t count = recv(fd, buffer, sizeof buffer, MSG_TRUNC);
            if (count <= 0 || (size_t)count > sizeof buffer) {
                ok = false;
                break;
            }
            int remaining = (int)count;
            for (struct nlmsghdr* header = (struct nlmsghdr*)buffer;
                 NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
                if (header->nlmsg_seq != query + 1)
                    continue;
                if (header->nlmsg_type == NLMSG_ERROR ||
                    header->nlmsg_flags & NLM_F_DUMP_INTR) {
                    ok = false;
                    break;
                }
                if (header->nlmsg_type == NLMSG_DONE) {
                    done = true;
                    break;
                }
                unsigned table = 0, priority = 0;
                struct rtattr* attribute = NULL;
                int length = 0;
                if (!query && header->nlmsg_type == RTM_NEWRULE &&
                    NLMSG_PAYLOAD(header, 0) >= sizeof(struct fib_rule_hdr)) {
                    struct fib_rule_hdr* rule = NLMSG_DATA(header);
                    table = rule->table;
                    length = (int)NLMSG_PAYLOAD(header, sizeof *rule);
                    attribute = (struct rtattr*)((char*)rule + NLMSG_ALIGN(sizeof *rule));
                } else if (query && header->nlmsg_type == RTM_NEWROUTE &&
                           NLMSG_PAYLOAD(header, 0) >= sizeof(struct rtmsg)) {
                    struct rtmsg* route = NLMSG_DATA(header);
                    table = route->rtm_table;
                    length = (int)RTM_PAYLOAD(header);
                    attribute = RTM_RTA(route);
                }
                for (; attribute && RTA_OK(attribute, length);
                     attribute = RTA_NEXT(attribute, length)) {
                    unsigned value;
                    if (RTA_PAYLOAD(attribute) != sizeof value)
                        continue;
                    memcpy(&value, RTA_DATA(attribute), sizeof value);
                    if (attribute->rta_type == (query ? RTA_TABLE : FRA_TABLE))
                        table = value;
                    if (!query && attribute->rta_type == FRA_PRIORITY)
                        priority = value;
                }
                if (table == 42041 || (!query && priority >= 12040 && priority <= 12050)) {
                    ok = false;
                    break;
                }
            }
        }
        if (!done)
            ok = false;
    }
    close(fd);
    return ok;
}
static int free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t n = sizeof addr;
    int port = 0;
    if (!bind(fd, (struct sockaddr*)&addr, sizeof addr) &&
        !getsockname(fd, (struct sockaddr*)&addr, &n))
        port = ntohs(addr.sin_port);
    close(fd);
    return port;
}
int sbl_runtime_init(sbl_runtime* r, const char* directory, sb_err* err) {
    memset(r, 0, sizeof *r);
    if (sbl_private_dir(directory, geteuid(), err))
        return -1;
    r->directory = sb_strdup(directory);
    r->path = sb_asprintf("%s/runtime.json", directory);
    /* A previous crash may leave credentials behind, but only in this 0700
     * session directory. Never follow a preexisting file or cache symlink. */
    unlink(r->path);
    sb_singbox_supervisor_options opts;
    sb_singbox_supervisor_options_init(&opts);
    opts.config_path = r->path;
    r->core = sb_singbox_supervisor_new(&opts, err);
    r->clash = sb_agent_clash_new(r->path);
    if (!r->core) {
        sbl_runtime_clear(r);
        return -1;
    }
    return 0;
}
int sbl_runtime_validate(sbl_runtime* r, const sbj* profile, sb_err* err) {
    char* secret = sbl_secret();
    char* cache = sb_asprintf("%s/validation-cache.db", r->directory);
    char* configuration =
        sbl_build(profile, false, getuid(), 23001, 23002, secret, cache, err);
    free(secret);
    free(cache);
    if (!configuration)
        return -1;
    char* path = sb_asprintf("%s/check-XXXXXX", r->directory);
    int fd = g_mkstemp_full(path, O_WRONLY | O_CLOEXEC, 0600);
    size_t total = strlen(configuration), done = 0;
    while (fd >= 0 && done < total) {
        ssize_t n = write(fd, configuration + done, total - done);
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    bool ok = fd >= 0 && done == total;
    if (fd >= 0 && close(fd))
        ok = false;
    char* failure = ok ? SBEasySingBoxCheck(path) : NULL;
    unlink(path);
    free(path);
    OPENSSL_cleanse(configuration, total);
    free(configuration);
    if (failure) {
        SBEasySingBoxFree(failure);
        ok = false;
    }
    return ok ? 0
              : sb_fail(err, SB_ERR_VALIDATION,
                        "The embedded core rejected this configuration; the last saved "
                        "profile was preserved");
}
int sbl_runtime_start(sbl_runtime* r, const sbj* profile, bool tun, uid_t uid,
                      sb_err* err) {
    if (!r->core)
        return sb_fail(err, SB_ERR_GENERIC, "Runtime is unavailable");
    const char* id = sbj_get_str(profile, "id", "");
    if (!*id || strlen(id) > 64 ||
        strspn(id, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(id))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid profile ID");
    bool running = sb_singbox_supervisor_running(r->core);
    if (tun && !running && if_nametoindex("sbeasy0"))
        return sb_fail(
            err, SB_ERR_CONFLICT,
            "The sbeasy0 interface already exists; stop its owner before connecting");
    if (tun && !running && !tun_network_available())
        return sb_fail(err, SB_ERR_CONFLICT,
                       "Cannot reserve the desktop route table and rule priorities; "
                       "another network configuration may already use them");
    if (!running) {
        r->proxy_port = free_port();
        r->clash_port = free_port();
        for (unsigned i = 0; i < 4 && r->proxy_port == r->clash_port; ++i)
            r->clash_port = free_port();
        free(r->secret);
        r->secret = sbl_secret();
    }
    char* cache = sb_asprintf("%s/cache-%s.db", r->directory, id);
    struct stat st;
    if (lstat(cache, &st) == 0 && (!S_ISREG(st.st_mode) || st.st_uid != geteuid())) {
        free(cache);
        return sb_fail(err, SB_ERR_IO, "Unsafe runtime cache file");
    }
    char* configuration = sbl_build(profile, tun, uid, r->proxy_port, r->clash_port,
                                    r->secret, cache, err);
    free(cache);
    if (!configuration)
        return -1;
    sb_err private_error = {0};
    if (sb_singbox_supervisor_apply_config(r->core, configuration,
                                           strlen(configuration), &private_error)) {
        OPENSSL_cleanse(configuration, strlen(configuration));
        free(configuration);
        return sb_fail(err, SB_ERR_GENERIC,
                       "The embedded core rejected this configuration or could not "
                       "start. The previous runtime was restored when available.");
    }
    if (r->configuration) {
        OPENSSL_cleanse(r->configuration, strlen(r->configuration));
        free(r->configuration);
    }
    r->configuration = configuration;
    sb_str_set(&r->profile_id, id);
    r->tun = tun;
    return 0;
}
void sbl_runtime_stop(sbl_runtime* r) {
    if (r->core)
        sb_singbox_supervisor_stop(r->core);
    if (r->path)
        unlink(r->path);
    if (r->configuration) {
        OPENSSL_cleanse(r->configuration, strlen(r->configuration));
        free(r->configuration);
        r->configuration = NULL;
    }
    if (r->secret) {
        OPENSSL_cleanse(r->secret, strlen(r->secret));
        free(r->secret);
        r->secret = NULL;
    }
    free(r->profile_id);
    r->profile_id = NULL;
}
void sbl_runtime_clear(sbl_runtime* r) {
    sbl_runtime_stop(r);
    sb_singbox_supervisor_free(r->core);
    sb_agent_clash_free(r->clash);
    free(r->directory);
    free(r->path);
    memset(r, 0, sizeof *r);
}
sbj* sbl_runtime_status(sbl_runtime* r, sb_err* err) {
    sbj* out = sbj_object();
    bool running = r->core && sb_singbox_supervisor_running(r->core);
    sbj_set_bool(out, "running", running);
    sbj_set_bool(out, "tun", r->tun);
    sbj_set_str(out, "profile_id", r->profile_id ? r->profile_id : "");
    if (!running)
        return out;
    sbj_set_int(out, "proxy_port", r->proxy_port);
    sbj* groups = sb_agent_clash_proxies(r->clash, NULL);
    if (groups)
        sbj_set(out, "groups", groups);
    sbj* telemetry = NULL;
    if (!sb_agent_clash_sample_telemetry(r->clash, &telemetry, NULL) && telemetry)
        sbj_set(out, "telemetry", telemetry);
    (void)err;
    return out;
}
sbj* sbl_runtime_select(sbl_runtime* r, const char* group, const char* name,
                        sb_err* err) {
    if (!r->core || !sb_singbox_supervisor_running(r->core)) {
        sb_fail(err, SB_ERR_CONFLICT, "Connect before selecting a live node");
        return NULL;
    }
    sb_err private_error = {0};
    sbj* out = sb_agent_clash_select_proxy(r->clash, group, name, &private_error);
    if (!out)
        sb_fail(err, SB_ERR_UPSTREAM, "The core could not select that node");
    return out;
}
static int latency(const sbj* result, void* user, sb_err* err) {
    sbj* out = user;
    for (size_t i = 0; i < sbj_obj_len(result); ++i)
        sbj_set(out, sbj_obj_key(result, i), sbj_clone(sbj_obj_val(result, i)));
    (void)err;
    return 0;
}
sbj* sbl_runtime_delay(sbl_runtime* r, const char* tag, sb_err* err) {
    if (!r->core || !sb_singbox_supervisor_running(r->core)) {
        sb_fail(err, SB_ERR_CONFLICT, "Connect before testing latency");
        return NULL;
    }
    sbj *tags = sbj_array(), *out = sbj_object();
    sbj_arr_push(tags, sbj_str(tag));
    size_t tested = 0;
    sb_err private_error = {0};
    int rc = sb_agent_clash_test_proxies(r->clash, tags, latency, out, &tested,
                                         &private_error);
    sbj_free(tags);
    if (rc) {
        sbj_free(out);
        sb_fail(err, SB_ERR_UPSTREAM, "Latency test failed or timed out");
        return NULL;
    }
    return out;
}
static size_t discard_body(char* ptr, size_t size, size_t count, void* data) {
    size_t* received = data;
    if (count && size > (8u * 1024u * 1024u) / count)
        return 0;
    size_t bytes = size * count;
    if (*received > 8u * 1024u * 1024u - bytes)
        return 0;
    *received += bytes;
    (void)ptr;
    return bytes;
}
static sbj* connections(sbl_runtime* r) {
    char *url = sb_asprintf("http://127.0.0.1:%d/connections", r->clash_port),
         *auth = sb_asprintf("Authorization: Bearer %s", r->secret);
    const char* headers[] = {auth, NULL};
    sb_http_request req = {.url = url,
                           .headers = headers,
                           .timeout_ms = 500,
                           .max_body_bytes = 4u * 1024u * 1024u};
    sb_http_response resp = {0};
    sbj* out = NULL;
    if (!sb_http_perform(&req, &resp, NULL) && resp.status == 200)
        out = sbl_parse(resp.body, 4u * 1024u * 1024u, NULL);
    sb_http_response_free(&resp);
    free(auth);
    free(url);
    return out;
}
static long source_port(const sbj* metadata) {
    const sbj* v = sbj_get(metadata, "sourcePort");
    if (sbj_is_string(v)) {
        char* end = NULL;
        long port = strtol(sbj_as_str(v, ""), &end, 10);
        return end && !*end ? port : -1;
    }
    return (long)sbj_as_int(v, -1);
}
sbj* sbl_runtime_probe(sbl_runtime* r, const char* url, sb_err* err) {
    if (!r->core || !sb_singbox_supervisor_running(r->core)) {
        sb_fail(err, SB_ERR_CONFLICT, "Connect before running diagnostics");
        return NULL;
    }
    if (!sbl_url(url, true, err))
        return NULL;
    sbj *before = connections(r), *observed = NULL;
    sb_strvec baseline = {0};
    const sbj* rows = sbj_get(before, "connections");
    for (size_t i = 0; i < sbj_arr_len(rows); ++i)
        sb_strvec_push(&baseline, sbj_get_str(sbj_arr_at(rows, i), "id", ""));
    sbj_free(before);
    CURL* easy = curl_easy_init();
    CURLM* multi = curl_multi_init();
    if (!easy || !multi) {
        if (easy)
            curl_easy_cleanup(easy);
        if (multi)
            curl_multi_cleanup(multi);
        sb_strvec_free(&baseline);
        sb_fail(err, SB_ERR_GENERIC, "Cannot create diagnostic request");
        return NULL;
    }
    char *proxy = sb_asprintf("http://127.0.0.1:%d", r->proxy_port),
         *credential = sb_asprintf("sbeasy:%s", r->secret);
    size_t received = 0;
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_PROXY, proxy);
    curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
    curl_easy_setopt(easy, CURLOPT_PROXYUSERPWD, credential);
    curl_easy_setopt(easy, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 15000L);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, discard_body);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, &received);
    curl_easy_setopt(easy, CURLOPT_USERAGENT, "sb-easy-linux-diagnostics/" SBL_VERSION);
    curl_multi_add_handle(multi, easy);
    int active = 1;
    long local_port = 0;
    int64_t start = sb_monotonic_ms(), last_sample = 0;
    while (active && sb_monotonic_ms() - start < 16000) {
        if (curl_multi_perform(multi, &active) != CURLM_OK)
            break;
        curl_easy_getinfo(easy, CURLINFO_LOCAL_PORT, &local_port);
        if (active && local_port && !observed &&
            sb_monotonic_ms() - last_sample >= 50) {
            last_sample = sb_monotonic_ms();
            sbj* current = connections(r);
            const sbj* items = sbj_get(current, "connections");
            for (size_t i = 0; i < sbj_arr_len(items); ++i) {
                const sbj *row = sbj_arr_at(items, i),
                          *metadata = sbj_get(row, "metadata");
                const char* source_ip = sbj_get_str(metadata, "sourceIP", "");
                if (source_port(metadata) == local_port &&
                    (!strcmp(source_ip, "127.0.0.1") ||
                     !strcmp(source_ip, "::ffff:127.0.0.1")) &&
                    !sb_strvec_contains(&baseline, sbj_get_str(row, "id", ""))) {
                    observed = sbj_clone(row);
                    break;
                }
            }
            sbj_free(current);
        }
        if (active)
            curl_multi_poll(multi, NULL, 0, 50, NULL);
    }
    CURLcode result = CURLE_OPERATION_TIMEDOUT;
    int queue = 0;
    CURLMsg* message;
    while ((message = curl_multi_info_read(multi, &queue)))
        if (message->msg == CURLMSG_DONE)
            result = message->data.result;
    long status = 0;
    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
    sbj* out = sbj_object();
    sbj_set_bool(out, "success", result == CURLE_OK && status >= 200 && status < 300);
    sbj_set_int(out, "http_status", status);
    sbj_set_int(out, "elapsed_ms", sb_monotonic_ms() - start);
    sbj_set_int(out, "received_bytes", (int64_t)received);
    sbj_set_bool(out, "route_observed", observed != NULL);
    sbj_set_str(out, "transport",
                result == CURLE_OK ? "complete" : "failed-or-timed-out");
    if (observed) {
        const char* fields[] = {"id", "chains", "rule", "rulePayload"};
        for (size_t i = 0; i < G_N_ELEMENTS(fields); ++i)
            if (sbj_get(observed, fields[i]))
                sbj_set(out, fields[i], sbj_clone(sbj_get(observed, fields[i])));
    }
    curl_multi_remove_handle(multi, easy);
    curl_multi_cleanup(multi);
    curl_easy_cleanup(easy);
    OPENSSL_cleanse(credential, strlen(credential));
    free(credential);
    free(proxy);
    sbj_free(observed);
    sb_strvec_free(&baseline);
    return out;
}
