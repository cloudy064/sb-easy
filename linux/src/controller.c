#include "controller.h"
#include "SBEasyCore.h"
#include "sb/http_client.h"
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
struct sbl_controller {
    GThreadPool* workers;
    GMutex lock;
    GCancellable* cancel;
    GDBusConnection* bus;
    sbl_vault vault;
    sbl_runtime runtime;
    sbj* state;
    char *data_dir, *runtime_dir;
    unsigned char test_key[32];
    bool test_key_set, session_test, opened, busy, closing, remote, system_proxy;
    unsigned queued;
    sbl_event_callback callback;
    void* user;
};
typedef struct {
    sbl_controller* c;
    sbl_action action;
    char *a, *b, *d;
    int number;
} job;
typedef struct {
    sbl_controller* c;
    sbl_event* event;
} delivery;
static sbj* selected(sbl_controller* c, sbj* state) {
    (void)c;
    return sbl_profile(state, sbj_get_str(state, "selected_id", ""));
}
static void wipe(char* text) {
    if (text) {
        OPENSSL_cleanse(text, strlen(text));
        free(text);
    }
}
void sbl_event_free(sbl_event* event) {
    if (!event)
        return;
    free(event->message);
    sbj_free(event->view);
    sbj_free(event->result);
    free(event);
}
static bool cancelled(sbl_controller* c) {
    return c->cancel && g_cancellable_is_cancelled(c->cancel);
}
static sbj* bus_call(sbl_controller* c, const char* method, GVariant* parameters,
                     sb_err* err) {
    if (!c->bus) {
        GDBusConnection* bus = g_bus_get_sync(
            c->session_test ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM, c->cancel, NULL);
        g_mutex_lock(&c->lock);
        c->bus = bus;
        g_mutex_unlock(&c->lock);
    }
    if (!c->bus) {
        sb_fail(err, SB_ERR_IO,
                "Cannot contact the system bus. Install and enable the sb-easy tunnel "
                "service.");
        return NULL;
    }
    GError* error = NULL;
    GVariant* reply = g_dbus_connection_call_sync(
        c->bus, "io.sbeasy.Desktop.Tunnel", SBL_BUS_PATH, SBL_BUS_IFACE, method,
        parameters, NULL, G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,
        !strcmp(method, "Start") ? 120000 : 20000,
        !strcmp(method, "Stop") ? NULL : c->cancel, &error);
    if (!reply) {
        char* remote_error = error ? g_dbus_error_get_remote_error(error) : NULL;
        bool absent =
            remote_error &&
            (!strcmp(remote_error, "org.freedesktop.DBus.Error.ServiceUnknown") ||
             !strcmp(remote_error, "org.freedesktop.DBus.Error.NameHasNoOwner"));
        bool owner_lost =
            remote_error && !strcmp(remote_error, "io.sbeasy.Desktop.Error") && error &&
            strstr(error->message, "This connection does not own the tunnel");
        if ((!strcmp(method, "Status") || !strcmp(method, "Stop")) &&
            (absent || owner_lost))
            c->remote = false;
        g_free(remote_error);
        const char* message = "Tunnel service request failed. Check that the service "
                              "is installed and approve the administrator prompt.";
        if (error && g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            message = "Tunnel operation cancelled";
        sb_fail(err, SB_ERR_UPSTREAM, "%s", message);
        g_clear_error(&error);
        return NULL;
    }
    sbj* result;
    if (!strcmp(method, "Stop"))
        result = sbj_object();
    else {
        const char* raw;
        g_variant_get(reply, "(&s)", &raw);
        result = sbl_parse(raw, SBL_MAX_STATE, err);
    }
    g_variant_unref(reply);
    return result;
}
static sbj* runtime_status(sbl_controller* c) {
    if (c->remote)
        return bus_call(c, "Status", g_variant_new("()"), NULL);
    return sbl_runtime_status(&c->runtime, NULL);
}
static bool connected(sbl_controller* c) {
    return c->remote ||
           (c->runtime.core && sb_singbox_supervisor_running(c->runtime.core));
}
static int disconnect(sbl_controller* c, sb_err* err) {
    int proxy_rc = sbl_proxy_restore(c->data_dir, err);
    c->system_proxy = false;
    if (c->remote) {
        sbj* result = bus_call(c, "Stop", g_variant_new("()"), err);
        if (!result && c->remote)
            return -1;
        sbj_free(result);
        c->remote = false;
    }
    sbl_runtime_stop(&c->runtime);
    return proxy_rc;
}
static sbj* tunnel_profile(const sbj* profile) {
    sbj* copy = sbj_object();
    const char* fields[] = {"id", "mode", "source", "settings"};
    for (size_t i = 0; i < G_N_ELEMENTS(fields); ++i)
        if (sbj_get(profile, fields[i]))
            sbj_set(copy, fields[i], sbj_clone(sbj_get(profile, fields[i])));
    char* host = sbl_url_host(sbj_get_str(profile, "server", ""));
    if (host) {
        char* url = strchr(host, ':') ? sb_asprintf("https://[%s]", host)
                                      : sb_asprintf("https://%s", host);
        sbj_set_str(copy, "server", url);
        free(url);
        free(host);
    }
    sbj* subs = sbj_array();
    const sbj* input = sbj_get(profile, "subscriptions");
    for (size_t i = 0; i < sbj_arr_len(input); ++i) {
        const sbj* item = sbj_arr_at(input, i);
        sbj* sub = sbj_object();
        sbj_set_str(sub, "id", sbj_get_str(item, "id", ""));
        sbj_set(sub, "nodes", sbj_clone(sbj_get(item, "nodes")));
        sbj_arr_push(subs, sub);
    }
    sbj_set(copy, "subscriptions", subs);
    return copy;
}
static int start_profile(sbl_controller* c, const sbj* profile, bool tun, sb_err* err) {
    if (tun) {
        sbj* safe = tunnel_profile(profile);
        char* raw = sbj_dump(safe, -1);
        sbj_free(safe);
        sbj* result = bus_call(c, "Start", g_variant_new("(s)", raw), err);
        wipe(raw);
        if (!result)
            return -1;
        c->remote = sbj_get_bool(result, "running", false);
        sbj_free(result);
        return c->remote ? 0
                         : sb_fail(err, SB_ERR_GENERIC, "Tunnel service did not start");
    }
    return sbl_runtime_start(&c->runtime, profile, false, getuid(), err);
}
static void remember_good(sbj* profile) {
    sbj* good = sbj_clone(profile);
    sbj_del(good, "last_good");
    sbj_del(good, "pending_refresh");
    sbj_del(profile, "pending_refresh");
    sbj_set(profile, "last_good", good);
}
static void replace_selected(sbj* state, sbj* profile) {
    sbj* profiles = sbj_get(state, "profiles");
    const char* id = sbj_get_str(state, "selected_id", "");
    for (size_t i = 0; i < sbj_arr_len(profiles); ++i) {
        if (sbj_string_is(sbj_get(sbj_arr_at(profiles, i), "id"), id)) {
            sbj_free(sbj_arr_take(profiles, i));
            sbj_arr_insert(profiles, i, profile);
            return;
        }
    }
    sbj_free(profile);
}
static int commit(sbl_controller* c, sbj* next, bool update_runtime, sb_err* err) {
    bool live = connected(c);
    sbj *before = selected(c, c->state), *after = selected(c, next);
    if (update_runtime && live && start_profile(c, after, c->remote, err)) {
        sbj_free(next);
        return -1;
    }
    if (update_runtime && live)
        remember_good(after);
    if (sbl_vault_save(&c->vault, next, err)) {
        if (update_runtime && live && before)
            start_profile(c, before, c->remote, NULL);
        sbj_free(next);
        return -1;
    }
    sbj_free(c->state);
    c->state = next;
    return 0;
}
static sbj* public_profile(const sbj* profile) {
    sbj* out = sbj_object();
    const char* fields[] = {"id",       "name", "mode", "settings", "refresh_minutes",
                            "synced_at"};
    for (size_t i = 0; i < G_N_ELEMENTS(fields); ++i)
        if (sbj_get(profile, fields[i]))
            sbj_set(out, fields[i], sbj_clone(sbj_get(profile, fields[i])));
    char* host = sbl_url_host(sbj_get_str(profile, "server", ""));
    sbj_set_str(out, "server_host", host ? host : "");
    free(host);
    sbj_set_bool(out, "source_ready", *sbj_get_str(profile, "source", "") != 0);
    sbj *subs = sbj_array(), *nodes = sbj_array();
    const sbj* input = sbj_get(profile, "subscriptions");
    sbj* direct = sbj_object();
    sbj_set_str(direct, "tag", SBL_DIRECT);
    sbj_set_str(direct, "name", "直接连接");
    sbj_set_str(direct, "type", "direct");
    sbj_arr_push(nodes, direct);
    for (size_t i = 0; i < sbj_arr_len(input); ++i) {
        const sbj* item = sbj_arr_at(input, i);
        sbj* sub = sbj_object();
        const char* subfields[] = {"id",     "name",     "updated_at",
                                   "report", "metadata", "last_error"};
        for (size_t j = 0; j < G_N_ELEMENTS(subfields); ++j)
            if (sbj_get(item, subfields[j]))
                sbj_set(sub, subfields[j], sbj_clone(sbj_get(item, subfields[j])));
        sbj_set_bool(sub, "remote", *sbj_get_str(item, "url", "") != 0);
        sbj_set_int(sub, "node_count", (int64_t)sbj_arr_len(sbj_get(item, "nodes")));
        sbj_arr_push(subs, sub);
        const sbj* node_list = sbj_get(item, "nodes");
        for (size_t j = 0; j < sbj_arr_len(node_list); ++j) {
            const sbj* node = sbj_arr_at(node_list, j);
            sbj* entry = sbj_object();
            char* tag = sb_asprintf("local-%s/%s", sbj_get_str(item, "id", ""),
                                    sbj_get_str(node, "tag", ""));
            sbj_set_str(entry, "tag", tag);
            free(tag);
            sbj_set_str(entry, "name", sbj_get_str(node, "tag", ""));
            sbj_set_str(entry, "type", sbj_get_str(node, "type", ""));
            sbj_arr_push(nodes, entry);
        }
    }
    const char* source = sbj_get_str(profile, "source", "");
    sbj* base = *source ? sbl_parse(source, 1024u * 1024u, NULL) : NULL;
    const sbj* outbounds = sbj_get(base, "outbounds");
    for (size_t i = 0; i < sbj_arr_len(outbounds); ++i) {
        const sbj* node = sbj_arr_at(outbounds, i);
        const char* type = sbj_get_str(node, "type", "");
        if (!strcmp(type, "selector") || !strcmp(type, "urltest"))
            continue;
        sbj* entry = sbj_object();
        sbj_set_str(entry, "tag", sbj_get_str(node, "tag", ""));
        sbj_set_str(entry, "name", sbj_get_str(node, "tag", ""));
        sbj_set_str(entry, "type", type);
        sbj_arr_push(nodes, entry);
    }
    sbj_free(base);
    sbj_set(out, "subscriptions", subs);
    sbj_set(out, "nodes", nodes);
    return out;
}
static sbj* view(sbl_controller* c) {
    sbj* out = sbj_object();
    sbj_set_bool(out, "opened", c->opened);
    if (!c->opened)
        return out;
    sbj* profiles = sbj_array();
    const sbj* input = sbj_get(c->state, "profiles");
    for (size_t i = 0; i < sbj_arr_len(input); ++i)
        sbj_arr_push(profiles, public_profile(sbj_arr_at(input, i)));
    sbj_set(out, "profiles", profiles);
    sbj_set_str(out, "selected_id", sbj_get_str(c->state, "selected_id", ""));
    sbj_set_bool(out, "system_proxy", sbj_get_bool(c->state, "system_proxy", false));
    sbj_set_bool(out, "system_proxy_active", c->system_proxy);
    sbj_set_bool(out, "system_proxy_available", sbl_proxy_available());
    sbj* status = runtime_status(c);
    if (status)
        sbj_set(out, "runtime", status);
    else {
        sbj_set(out, "runtime", sbj_object());
        sbj_set_bool(out, "runtime_unavailable", true);
    }
    return out;
}
static sbj* find_subscription(sbj* profile, const char* id, size_t* index) {
    sbj* subs = sbj_get(profile, "subscriptions");
    for (size_t i = 0; i < sbj_arr_len(subs); ++i)
        if (sbj_string_is(sbj_get(sbj_arr_at(subs, i), "id"), id)) {
            if (index)
                *index = i;
            return sbj_arr_at(subs, i);
        }
    return NULL;
}
static int add_url(sbj* profile, const char* name, const char* url, sb_err* err) {
    if (!sbl_url(url, true, err))
        return -1;
    sb_http_request req = {.url = url,
                           .timeout_ms = 15000,
                           .max_body_bytes = 512u * 1024u,
                           .user_agent = "sb-easy-linux/" SBL_VERSION};
    sb_http_response response = {0};
    if (sb_http_perform(&req, &response, NULL) || response.status != 200 ||
        memchr(response.body, 0, response.body_len)) {
        sb_http_response_free(&response);
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "Cannot download this subscription. Check its HTTPS address and "
                       "try again.");
    }
    int rc = sbl_import(profile, name, url, response.body, err);
    if (!rc) {
        sbj *subs = sbj_get(profile, "subscriptions"),
            *sub = sbj_arr_at(subs, sbj_arr_len(subs) - 1);
        if (response.etag && strlen(response.etag) <= 2048 &&
            !strpbrk(response.etag, "\r\n"))
            sbj_set_str(sub, "etag", response.etag);
        char *header = sb_http_response_header(&response, "subscription-userinfo"),
             *metadata = sba_subscription_metadata(header, (long long)time(NULL));
        sbj* parsed = sbl_parse(metadata, 4096, NULL);
        if (parsed)
            sbj_set(sub, "metadata", parsed);
        free(header);
        free(metadata);
    }
    sb_http_response_free(&response);
    return rc;
}
static int refresh(sbl_controller* c, sbj* profile, const char* only, bool automatic,
                   bool* changed, sb_err* err) {
    *changed = false;
    const sbj* subs = sbj_get(profile, "subscriptions");
    int failures = 0, successes = 0;
    time_t now = time(NULL);
    int64_t minutes = sbj_get_int(profile, "refresh_minutes", 360);
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        sbj* sub = sbj_arr_at(subs, i);
        const char* id = sbj_get_str(sub, "id", "");
        if ((only && *only && strcmp(only, id)) || !*sbj_get_str(sub, "url", ""))
            continue;
        if (automatic &&
            (!minutes || now - sbj_get_int(sub, "updated_at", 0) < minutes * 60))
            continue;
        if (cancelled(c))
            return sb_fail(err, SB_ERR_CONFLICT, "Refresh cancelled");
        char* old_nodes = sbj_dump(sbj_get(sub, "nodes"), -1);
        sb_err item_error = {0};
        if (sbl_refresh_subscription(profile, id, &item_error)) {
            ++failures;
            sbj_set_str(sub, "last_error", item_error.msg);
        } else {
            ++successes;
            char* new_nodes = sbj_dump(sbj_get(sub, "nodes"), -1);
            if (strcmp(old_nodes, new_nodes))
                *changed = true;
            free(new_nodes);
        }
        free(old_nodes);
    }
    if (failures && !successes)
        return sb_fail(err, SB_ERR_UPSTREAM,
                       "%d subscription refreshes failed; last valid nodes were kept",
                       failures);
    return 0;
}
static sb_agent_client* managed_client(sbj* profile) {
    if (!profile || !sbj_string_is(sbj_get(profile, "mode"), "managed"))
        return NULL;
    sb_agent_client_options options = {.server = sbj_get_str(profile, "server", ""),
                                       .token = sbj_get_str(profile, "token", ""),
                                       .timeout_ms = 15000};
    sb_agent_client* client = sb_agent_client_new(&options, NULL);
    /* A desktop consumes subscriptions; it does not serve shared proxy ingress. */
    sb_agent_client_proxy_capability(client, false);
    return client;
}
static void managed_commands(sbl_controller* c) {
    sbj* profile = selected(c, c->state);
    sb_agent_client* client = managed_client(profile);
    if (!client)
        return;
    bool running = connected(c);
    sb_agent_client_report_status(client, SBL_VERSION, &running,
                                  sbj_get_str(profile, "etag", ""), NULL);
    sbj* status = running ? runtime_status(c) : NULL;
    const sbj* telemetry = sbj_get(status, "telemetry");
    if (telemetry)
        sb_agent_client_report_telemetry(client, telemetry, NULL);
    sbj_free(status);
    sb_agent_command_vec commands = {0};
    if (!cancelled(c) && !sb_agent_client_pending_commands(client, &commands, NULL)) {
        for (size_t i = 0; i < commands.len && i < 32 && !cancelled(c); ++i) {
            const char* command = commands.items[i].command;
            bool success = false;
            const char* message = "Unsupported native desktop command";
            if (!strcmp(command, "reload") || !strcmp(command, "restart")) {
                success = running && start_profile(c, profile, c->remote, NULL) == 0;
                message = success ? "Native desktop runtime reloaded"
                                  : "Desktop is disconnected or reload failed";
            } else if (!strcmp(command, "test-proxies") ||
                       sb_starts_with(command, "test-proxies ")) {
                const char* payload = command + strlen("test-proxies");
                while (*payload == ' ')
                    ++payload;
                sbj* tags = *payload ? sbl_parse(payload, 65536, NULL) : NULL;
                if (!*payload && running) {
                    tags = sbj_array();
                    sbj* live = runtime_status(c);
                    const sbj* proxies = sbj_get(sbj_get(live, "groups"), "proxies");
                    for (size_t k = 0;
                         k < sbj_obj_len(proxies) && sbj_arr_len(tags) < 512; ++k) {
                        const sbj* node = sbj_obj_val(proxies, k);
                        const char* type = sbj_get_str(node, "type", "");
                        if (!sbj_is_array(sbj_get(node, "all")) &&
                            strcmp(type, "Direct") && strcmp(type, "Reject") &&
                            strcmp(type, "Pass"))
                            sbj_arr_push(tags, sbj_str(sbj_obj_key(proxies, k)));
                    }
                    sbj_free(live);
                }
                sbj* results = sbj_object();
                if (running && sbj_is_array(tags) && sbj_arr_len(tags) <= 512) {
                    success = true;
                    for (size_t j = 0; j < sbj_arr_len(tags) && !cancelled(c); ++j) {
                        const char* tag = sbj_as_str(sbj_arr_at(tags, j), "");
                        sbj* delay =
                            c->remote
                                ? bus_call(c, "Delay", g_variant_new("(s)", tag), NULL)
                                : sbl_runtime_delay(&c->runtime, tag, NULL);
                        if (delay) {
                            for (size_t k = 0; k < sbj_obj_len(delay); ++k)
                                sbj_set(results, sbj_obj_key(delay, k),
                                        sbj_clone(sbj_obj_val(delay, k)));
                            sbj_free(delay);
                        } else
                            success = false;
                    }
                    if (cancelled(c))
                        success = false;
                    size_t updated = 0;
                    sb_agent_client_report_proxy_latencies(client, results, &updated,
                                                           NULL);
                }
                sbj_free(tags);
                sbj_free(results);
                message = success ? "Proxy latency tests completed"
                                  : "Latency command requires a connected runtime and "
                                    "an explicit node array";
            }
            sb_agent_client_acknowledge_command(client, commands.items[i].id, success,
                                                message, NULL);
        }
    }
    sb_agent_command_vec_free(&commands);
    sb_agent_client_free(client);
}
static int execute(job* j, sbj** result, sb_err* err) {
    sbl_controller* c = j->c;
    if (j->action == SBL_OPEN) {
        if (c->opened)
            return 0;
        if (sbl_vault_open_cancellable(&c->vault, c->data_dir,
                                       c->test_key_set ? c->test_key : NULL, c->cancel,
                                       err))
            return -1;
        c->state = sbl_vault_load(&c->vault, err);
        if (!c->state) {
            sbl_vault_close(&c->vault);
            return -1;
        }
        if (sbl_runtime_init(&c->runtime, c->runtime_dir, err)) {
            sbj_free(c->state);
            c->state = NULL;
            sbl_vault_close(&c->vault);
            return -1;
        }
        if (!sbj_arr_len(sbj_get(c->state, "profiles"))) {
            sbj* profile = sbl_new_profile("独立连接");
            sbj_set_str(c->state, "selected_id", sbj_get_str(profile, "id", ""));
            sbj_arr_push(sbj_get(c->state, "profiles"), profile);
            if (sbl_vault_save(&c->vault, c->state, err)) {
                sbj_free(c->state);
                c->state = NULL;
                sbl_runtime_clear(&c->runtime);
                sbl_vault_close(&c->vault);
                return -1;
            }
        }
        c->opened = true;
        return sbl_proxy_restore(c->data_dir, err);
    }
    if (j->action == SBL_SHUTDOWN) {
        if (c->opened) {
            disconnect(c, NULL);
            sbl_runtime_clear(&c->runtime);
            sbl_vault_close(&c->vault);
            sbj_free(c->state);
            c->state = NULL;
            c->opened = false;
        }
        g_mutex_lock(&c->lock);
        g_clear_object(&c->bus);
        g_mutex_unlock(&c->lock);
        return 0;
    }
    if (!c->opened)
        return sb_fail(err, SB_ERR_CONFLICT,
                       "Unlock the desktop keyring before using this profile");
    if (j->action == SBL_STATUS)
        return 0;
    if (j->action == SBL_DISCONNECT)
        return disconnect(c, err);
    sbj* current = selected(c, c->state);
    if (j->action == SBL_CONNECT) {
        if (connected(c) && disconnect(c, err))
            return -1;
        bool fallback = false;
        sbj* next = sbj_clone(c->state);
        if (start_profile(c, current, j->number != 0, err)) {
            const sbj* good = sbj_get(current, "last_good");
            if (cancelled(c) || !sbj_get_bool(current, "pending_refresh", false) ||
                !sbj_is_object(good) || start_profile(c, good, j->number != 0, NULL)) {
                sbj_free(next);
                return -1;
            }
            replace_selected(next, sbj_clone(good));
            fallback = true;
            memset(err, 0, sizeof *err);
        }
        if (cancelled(c)) {
            disconnect(c, NULL);
            sbj_free(next);
            return sb_fail(err, SB_ERR_CONFLICT, "Connection cancelled");
        }
        if (!c->remote && sbj_get_bool(c->state, "system_proxy", false)) {
            if (sbl_proxy_apply(c->data_dir, c->runtime.proxy_port, c->runtime.secret,
                                err)) {
                sbl_runtime_stop(&c->runtime);
                sbj_free(next);
                return -1;
            }
            c->system_proxy = true;
        }
        remember_good(selected(c, next));
        if (commit(c, next, false, err)) {
            disconnect(c, NULL);
            return -1;
        }
        if (fallback) {
            *result = sbj_object();
            sbj_set_bool(*result, "fallback", true);
        }
        return 0;
    }
    if (j->action == SBL_DELAY || j->action == SBL_PROBE) {
        *result = c->remote ? bus_call(c, j->action == SBL_DELAY ? "Delay" : "Probe",
                                       g_variant_new("(s)", j->a), err)
                            : (j->action == SBL_DELAY
                                   ? sbl_runtime_delay(&c->runtime, j->a, err)
                                   : sbl_runtime_probe(&c->runtime, j->a, err));
        return *result ? 0 : -1;
    }
    if (j->action == SBL_COPY_PROXY) {
        if (!connected(c) || c->remote)
            return sb_fail(
                err, SB_ERR_CONFLICT,
                "Connect in local proxy mode to copy its authenticated address");
        *result = sbj_object();
        char* uri = sb_asprintf("http://sbeasy:%s@127.0.0.1:%d", c->runtime.secret,
                                c->runtime.proxy_port);
        sbj_set_str(*result, "clipboard", uri);
        wipe(uri);
        return 0;
    }
    sbj *next = sbj_clone(c->state), *profile = selected(c, next);
    int rc = 0;
    bool update_runtime = false;
    switch (j->action) {
    case SBL_NEW_PROFILE: {
        if (sbj_arr_len(sbj_get(next, "profiles")) >= 32) {
            rc = sb_fail(err, SB_ERR_VALIDATION, "Profile limit reached");
            break;
        }
        if (connected(c) && disconnect(c, err)) {
            rc = -1;
            break;
        }
        sbj* created = sbl_new_profile(j->a);
        sbj_arr_push(sbj_get(next, "profiles"), created);
        sbj_set_str(next, "selected_id", sbj_get_str(created, "id", ""));
        break;
    }
    case SBL_SELECT_PROFILE:
        if (!sbl_profile(next, j->a)) {
            rc = sb_fail(err, SB_ERR_NOT_FOUND, "Profile no longer exists");
            break;
        }
        if (connected(c) && disconnect(c, err)) {
            rc = -1;
            break;
        }
        sbj_set_str(next, "selected_id", j->a);
        break;
    case SBL_RENAME_PROFILE:
        sbj_set_str(profile, "name", j->a);
        break;
    case SBL_DELETE_PROFILE: {
        if (connected(c) && disconnect(c, err)) {
            rc = -1;
            break;
        }
        sbj* profiles = sbj_get(next, "profiles");
        for (size_t i = 0; i < sbj_arr_len(profiles); ++i)
            if (sbj_arr_at(profiles, i) == profile) {
                sbj_free(sbj_arr_take(profiles, i));
                break;
            }
        if (!sbj_arr_len(profiles))
            sbj_arr_push(profiles, sbl_new_profile("独立连接"));
        sbj_set_str(next, "selected_id",
                    sbj_get_str(sbj_arr_at(profiles, 0), "id", ""));
        break;
    }
    case SBL_ENROLL:
        if (connected(c)) {
            rc = sb_fail(err, SB_ERR_CONFLICT,
                         "Disconnect before enrolling a managed identity");
            break;
        }
        rc = sbl_enroll(profile, j->a, j->b, err);
        if (!rc) {
            sbj_del(profile, "source");
            sbj_del(profile, "etag");
            sbj_del(profile, "last_good");
            sbj_del(profile, "pending_refresh");
            sbj_del(sbj_get(profile, "settings"), "selector_choices");
            sbj_del(sbj_get(profile, "settings"), "selected_tag");
        }
        break;
    case SBL_DETACH:
        if (connected(c) && disconnect(c, err)) {
            rc = -1;
            break;
        }
        sbj_set_str(profile, "mode", "independent");
        sbj_del(profile, "server");
        sbj_del(profile, "token");
        sbj_del(profile, "source");
        sbj_del(profile, "etag");
        sbj_del(profile, "host_id");
        sbj_del(profile, "last_good");
        sbj_del(profile, "pending_refresh");
        sbj_set(profile, "settings", sbj_object());
        break;
    case SBL_IMPORT:
        rc = sbl_import(profile, j->a, "", j->b, err);
        update_runtime = true;
        break;
    case SBL_ADD_URL:
        rc = add_url(profile, j->a, j->b, err);
        update_runtime = true;
        break;
    case SBL_EDIT_SUBSCRIPTION: {
        sbj* sub = find_subscription(profile, j->a, NULL);
        if (!sub || !*j->b || strlen(j->b) > 128 ||
            (*j->d && !sbl_url(j->d, true, err))) {
            rc = sb_fail(err, SB_ERR_VALIDATION, "Invalid subscription settings");
            break;
        }
        sbj_set_str(sub, "name", j->b);
        if (j->number) {
            sbj_set_str(sub, "url", "");
            sbj_del(sub, "etag");
        } else if (*j->d) {
            sbj_set_str(sub, "url", j->d);
            sbj_del(sub, "etag");
        }
        break;
    }
    case SBL_REMOVE_SUBSCRIPTION: {
        size_t index = 0;
        sbj* sub = find_subscription(profile, j->a, &index);
        if (!sub) {
            rc = sb_fail(err, SB_ERR_NOT_FOUND, "Subscription no longer exists");
            break;
        }
        sbj_free(sbj_arr_take(sbj_get(profile, "subscriptions"), index));
        sbj_del(profile, "last_good");
        update_runtime = true;
        break;
    }
    case SBL_REFRESH:
        rc = refresh(c, profile, j->a, false, &update_runtime, err);
        break;
    case SBL_SYNC: {
        bool changed = false, nodes_changed = false;
        rc = sbl_sync_profile(profile, &changed, err);
        if (!rc)
            rc = refresh(c, profile, "", j->number != 0, &nodes_changed, err);
        update_runtime = changed || nodes_changed;
        break;
    }
    case SBL_SETTINGS: {
        sbj* settings = sbl_parse(j->a, 256u * 1024u, err);
        if (!sbj_is_object(settings)) {
            sbj_free(settings);
            rc = -1;
            break;
        }
        sbj_set(profile, "settings", settings);
        update_runtime = true;
        break;
    }
    case SBL_SELECT_NODE: {
        if (!*j->a || !*j->b || strlen(j->a) > 512 || strlen(j->b) > 512) {
            rc = sb_fail(err, SB_ERR_VALIDATION, "Invalid node selection");
            break;
        }
        sbj_set_str(sbj_get_or_object(sbj_get(profile, "settings"), "selector_choices"),
                    j->a, j->b);
        update_runtime = true;
        break;
    }
    case SBL_PROXY_SETTING:
        sbj_set_bool(next, "system_proxy", j->number != 0);
        if (connected(c) && !c->remote) {
            rc = j->number ? sbl_proxy_apply(c->data_dir, c->runtime.proxy_port,
                                             c->runtime.secret, err)
                           : sbl_proxy_restore(c->data_dir, err);
            if (!rc)
                c->system_proxy = j->number != 0;
        }
        break;
    case SBL_REFRESH_INTERVAL:
        sbj_set_int(profile, "refresh_minutes", j->number);
        break;
    default:
        rc = sb_fail(err, SB_ERR_VALIDATION, "Unsupported desktop action");
        break;
    }
    if (!rc && cancelled(c))
        rc = sb_fail(err, SB_ERR_CONFLICT, "Operation cancelled");
    if (!rc && update_runtime) {
        bool empty_independent =
            sbj_string_is(sbj_get(profile, "mode"), "independent") &&
            !sbj_arr_len(sbj_get(profile, "subscriptions"));
        if (!connected(c) && empty_independent &&
            j->action == SBL_REMOVE_SUBSCRIPTION) {
            sbj_set(profile, "settings", sbj_object());
            update_runtime = false;
        } else if (!connected(c))
            rc = sbl_runtime_validate(&c->runtime, profile, err);
        if (!rc && (j->action == SBL_SYNC || j->action == SBL_REFRESH) &&
            sbj_get(profile, "last_good"))
            sbj_set_bool(profile, "pending_refresh", true);
        else if (j->action != SBL_SYNC && j->action != SBL_REFRESH)
            sbj_del(profile, "pending_refresh");
    }
    if (rc) {
        sbj_free(next);
        return -1;
    }
    rc = commit(c, next, update_runtime, err);
    if (rc && j->action == SBL_PROXY_SETTING && connected(c) && !c->remote) {
        bool enabled = sbj_get_bool(c->state, "system_proxy", false);
        if (enabled)
            sbl_proxy_apply(c->data_dir, c->runtime.proxy_port, c->runtime.secret,
                            NULL);
        else
            sbl_proxy_restore(c->data_dir, NULL);
        c->system_proxy = enabled;
    }
    if (!rc && j->action == SBL_SYNC)
        managed_commands(c);
    return rc;
}
static gboolean deliver(void* data) {
    delivery* d = data;
    sbl_controller* c = d->c;
    g_mutex_lock(&c->lock);
    if (c->queued)
        --c->queued;
    c->busy = c->queued != 0;
    d->event->pending = c->busy;
    g_mutex_unlock(&c->lock);
    c->callback(d->event, c->user);
    free(d);
    return G_SOURCE_REMOVE;
}
static void worker(void* data, void* user) {
    job* j = data;
    sbl_controller* c = j->c;
    sb_err err = {0};
    g_mutex_lock(&c->lock);
    g_clear_object(&c->cancel);
    c->cancel = g_cancellable_new();
    g_mutex_unlock(&c->lock);
    sbl_event* event = sb_xcalloc(1, sizeof *event);
    event->action = j->action;
    event->success = execute(j, &event->result, &err) == 0;
    event->message =
        sb_strdup(event->success ? "" : (err.msg[0] ? err.msg : "Operation failed"));
    event->view = view(c);
    delivery* d = sb_xcalloc(1, sizeof *d);
    d->c = c;
    d->event = event;
    g_main_context_invoke(NULL, deliver, d);
    wipe(j->a);
    wipe(j->b);
    wipe(j->d);
    free(j);
    (void)user;
}
sbl_controller* sbl_controller_new(const char* data_dir, const char* runtime_dir,
                                   const unsigned char* test_key, bool session_test,
                                   sbl_event_callback callback, void* user) {
    sbl_controller* c = sb_xcalloc(1, sizeof *c);
    c->vault.dirfd = c->vault.lockfd = -1;
    c->data_dir = sb_strdup(data_dir);
    c->runtime_dir = sb_strdup(runtime_dir);
    c->callback = callback;
    c->user = user;
    c->session_test = session_test;
    g_mutex_init(&c->lock);
    if (test_key) {
        memcpy(c->test_key, test_key, 32);
        c->test_key_set = true;
    }
    c->workers = g_thread_pool_new(worker, NULL, 1, TRUE, NULL);
    return c;
}
bool sbl_controller_submit(sbl_controller* c, sbl_action action, const char* a,
                           const char* b, const char* d, int number) {
    g_mutex_lock(&c->lock);
    bool stop = action == SBL_DISCONNECT || action == SBL_SHUTDOWN;
    if ((c->busy && !stop) || c->closing ||
        (action == SBL_DISCONNECT && c->queued >= 2)) {
        g_mutex_unlock(&c->lock);
        return false;
    }
    if (action == SBL_SHUTDOWN)
        c->closing = true;
    ++c->queued;
    c->busy = true;
    g_mutex_unlock(&c->lock);
    job* j = sb_xcalloc(1, sizeof *j);
    j->c = c;
    j->action = action;
    j->a = sb_strdup(a ? a : "");
    j->b = sb_strdup(b ? b : "");
    j->d = sb_strdup(d ? d : "");
    j->number = number;
    g_thread_pool_push(c->workers, j, NULL);
    return true;
}
void sbl_controller_cancel(sbl_controller* c) {
    g_mutex_lock(&c->lock);
    if (c->cancel)
        g_cancellable_cancel(c->cancel);
    GDBusConnection* bus = c->bus ? g_object_ref(c->bus) : NULL;
    g_mutex_unlock(&c->lock);
    sbl_runtime_cancel_start();
    if (bus) {
        g_dbus_connection_call(bus, "io.sbeasy.Desktop.Tunnel", SBL_BUS_PATH,
                               SBL_BUS_IFACE, "Stop", g_variant_new("()"), NULL,
                               G_DBUS_CALL_FLAGS_NONE, 10000, NULL, NULL, NULL);
        g_object_unref(bus);
    }
}
void sbl_controller_free(sbl_controller* c) {
    if (!c)
        return;
    g_thread_pool_free(c->workers, FALSE, TRUE);
    g_clear_object(&c->cancel);
    g_clear_object(&c->bus);
    g_mutex_clear(&c->lock);
    wipe(c->data_dir);
    wipe(c->runtime_dir);
    OPENSSL_cleanse(c->test_key, sizeof c->test_key);
    free(c);
}
