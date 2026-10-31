/* Backup export and restore for the repository facade: whole-database JSON
 * snapshot of proxy nodes, WireGuard peers, subscriptions and app settings. */
#include "sb/store.h"

#include <stdlib.h>
#include <string.h>

#include "store_internal.h"

sbj *sb_store_export_backup(sb_store *s, sb_err *err) {
    sb_proxy_record_vec nodes = {0};
    sb_wireguard_peer_vec peers = {0};
    sb_subscription_vec subs = {0};
    sbj *result = NULL, *settings = NULL;
    if (sb_store_list_proxy_nodes(s, &nodes, err) != 0 ||
        sb_store_list_wireguard_peers(s, &peers, err) != 0 ||
        sb_store_list_subscriptions(s, &subs, err) != 0 || !(settings = sb_store_app_settings(s, err)))
        goto done;
    result = sbj_object();
    sbj *a = sbj_array();
    for (size_t i = 0; i < nodes.len; ++i) sbj_arr_push(a, sb_proxy_record_to_json(&nodes.items[i]));
    sbj_set(result, "proxy_nodes", a);
    a = sbj_array();
    for (size_t i = 0; i < peers.len; ++i) sbj_arr_push(a, sb_wireguard_peer_to_json(&peers.items[i]));
    sbj_set(result, "wireguard_peers", a);
    a = sbj_array();
    for (size_t i = 0; i < subs.len; ++i) sbj_arr_push(a, sb_subscription_to_json(&subs.items[i]));
    sbj_set(result, "subscriptions", a);
    sbj_set(result, "app_settings", settings);
    settings = NULL;
done:
    sbj_free(settings);
    sb_proxy_record_vec_free(&nodes);
    sb_wireguard_peer_vec_free(&peers);
    sb_subscription_vec_free(&subs);
    return result;
}

static int restore_subscription(sqlite3 *h, const sbj *value, size_t *count, sb_err *err) {
    const char *id, *url, *name, *created_at;
    bool enabled = false;
    int64_t refresh;
    if (jv_str(value, "id", "", &id, err) || jv_str(value, "url", "", &url, err)) return -1;
    if (!*id || !sbj_has(value, "url") || !sbj_get(value, "url")->v.str.len) return 0;
    if (jv_str(value, "name", "", &name, err) || jv_bool(value, "enabled", true, &enabled, err) ||
        jv_int(value, "refresh_interval", 3600, &refresh, err) ||
        jv_str(value, "created_at", "", &created_at, err))
        return -1;
    SBQ_AUTO q = sbq_stmt_open(h,
                               "INSERT OR REPLACE INTO subscriptions "
                               "(id, name, url, enabled, refresh_interval, last_fetched_at, "
                               "last_fetch_result, created_at, updated_at, usage, last_attempt_at, "
                               "last_error, next_refresh_at, failure_count) "
                               "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, "
                               "COALESCE(NULLIF(?8, ''), datetime('now')), datetime('now'), ?9, ?10, ?11, ?12, ?13)",
                               err);
    if (q.rc != 0) return -1;
    sbq_bind_text(q.st, 1, id);
    sbq_stmt_bind_text_n(&q, 2, name,
                         sbj_has(value, "name") ? sbj_get(value, "name")->v.str.len : 0, err);
    sbq_stmt_bind_text_n(&q, 3, url,
                         sbj_has(value, "url") ? sbj_get(value, "url")->v.str.len : 0, err);
    if (q.rc != 0) return -1;
    sbq_bind_bool(q.st, 4, enabled);
    sbq_bind_int(q.st, 5, refresh);
    sbq_bind_text(q.st, 6, jv_opt_str(value, "last_fetched_at"));
    sbq_bind_text(q.st, 7, jv_opt_str(value, "last_fetch_result"));
    sbq_bind_text(q.st, 8, created_at);
    const sbj *usage = sbj_get(value, "usage");
    sbj *empty = sbj_object();
    int usage_rc = bind_dump(q.st, 9, sbj_is_object(usage) ? usage : empty, err);
    sbj_free(empty);
    if (usage_rc != 0) return -1;
    sbq_bind_text(q.st, 10, jv_opt_str(value, "last_attempt_at"));
    sbq_bind_text(q.st, 11, jv_opt_str(value, "last_error"));
    int64_t next_refresh = 0, failure_count = 0;
    if (jv_int(value, "next_refresh_at", 0, &next_refresh, err) ||
        jv_int(value, "failure_count", 0, &failure_count, err))
        return -1;
    sbq_bind_int(q.st, 12, next_refresh < 0 ? 0 : next_refresh);
    sbq_bind_int(q.st, 13, failure_count < 0 ? 0 : (failure_count > 20 ? 20 : failure_count));
    if (sbq_step_done(q.st, err) != 0) return -1;
    ++*count;
    return 0;
}

static int restore_node(sqlite3 *h, const sbj *value, size_t *count, sb_err *err) {
    const char *id, *tag, *node_type, *server, *fingerprint, *created_at;
    bool enabled = false;
    int64_t port;
    if (jv_str(value, "id", "", &id, err) || jv_str(value, "tag", "", &tag, err)) return -1;
    if (!*id || !sbj_has(value, "tag") || !sbj_get(value, "tag")->v.str.len) return 0;
    const sbj *protocol = sbj_get(value, "protocol_config");
    char *protocol_text = !protocol                 ? sb_strdup("{}")
                          : sbj_is_string(protocol) ? sb_strdup(protocol->v.str.ptr)
                                                    : dump_checked(protocol, err);
    if (!protocol_text) return -1;
    int rc = -1;
    if (jv_str(value, "node_type", "", &node_type, err) ||
        jv_bool(value, "enabled", true, &enabled, err) ||
        jv_str(value, "server", "", &server, err) || jv_int(value, "server_port", 0, &port, err) ||
        jv_str(value, "fingerprint", "", &fingerprint, err) ||
        jv_str(value, "created_at", "", &created_at, err))
        goto done;
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "INSERT OR REPLACE INTO proxy_nodes "
                                   "(id, tag, node_type, enabled, server, server_port, "
                                   "protocol_config, subscription_id, fingerprint, latency, "
                                   "last_latency_test, created_at, updated_at, source_tag) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
                                   "COALESCE(NULLIF(?12, ''), datetime('now')), datetime('now'), ?13)",
                                   err);
        if (q.rc != 0) goto done;
        sbq_bind_text(q.st, 1, id);
        sbq_stmt_bind_text_n(&q, 2, tag,
                             sbj_has(value, "tag") ? sbj_get(value, "tag")->v.str.len : 0, err);
        sbq_stmt_bind_text_n(&q, 3, node_type,
                             sbj_has(value, "node_type") ? sbj_get(value, "node_type")->v.str.len : 0, err);
        sbq_bind_bool(q.st, 4, enabled);
        sbq_stmt_bind_text_n(&q, 5, server,
                             sbj_has(value, "server") ? sbj_get(value, "server")->v.str.len : 0, err);
        sbq_bind_int(q.st, 6, port);
        sbq_bind_text(q.st, 7, protocol_text);
        sbq_bind_text(q.st, 8, jv_opt_str(value, "subscription_id"));
        sbq_bind_text(q.st, 9, fingerprint);
        const sbj *latency = sbj_get(value, "latency");
        double latency_value = sbj_as_double(latency, 0.0);
        sbq_bind_opt_double(q.st, 10, sbj_is_number(latency) ? &latency_value : NULL);
        sbq_bind_text(q.st, 11, jv_opt_str(value, "last_latency_test"));
        sbq_bind_text(q.st, 12, created_at);
        const sbj *source_tag = sbj_get(value, "source_tag");
        if (sbj_is_string(source_tag))
            sbq_stmt_bind_text_n(&q, 13, source_tag->v.str.ptr, source_tag->v.str.len, err);
        else if (jv_opt_str(value, "subscription_id"))
            sbq_stmt_bind_text_n(&q, 13, tag, sbj_get(value, "tag")->v.str.len, err);
        else
            sbq_bind_text(q.st, 13, NULL);
        if (q.rc == 0) rc = sbq_step_done(q.st, err);
    }
    if (rc == 0) ++*count;
done:
    free(protocol_text);
    return rc;
}

int restore_peer(sqlite3 *h, const sbj *value, size_t *count, sb_err *err) {
    const char *id = NULL, *address = NULL, *name = NULL, *private_key = NULL;
    const char *public_key = NULL, *dns = NULL, *allowed_ips = NULL, *created_at = NULL;
    bool enabled = false;
    int64_t keepalive, quota;
    if (jv_str(value, "id", "", &id, err) || jv_str(value, "address", "", &address, err)) return -1;
    if (!*id || !*address) return 0;
    if (jv_str(value, "name", "", &name, err) || jv_str(value, "private_key", "", &private_key, err) ||
        jv_str(value, "public_key", "", &public_key, err) ||
        jv_str(value, "dns", "10.59.32.1", &dns, err) ||
        jv_bool(value, "enabled", true, &enabled, err) ||
        jv_int(value, "persistent_keepalive", 25, &keepalive, err) ||
        jv_str(value, "allowed_ips", "0.0.0.0/0, ::/0", &allowed_ips, err) ||
        jv_int(value, "quota_bytes", 0, &quota, err) ||
        jv_str(value, "created_at", "", &created_at, err))
        return -1;
    SBQ_AUTO q = sbq_stmt_open(h,
                               "INSERT OR REPLACE INTO wireguard_peers "
                               "(id, name, private_key, public_key, preshared_key, address, dns, "
                               "enabled, persistent_keepalive, allowed_ips, expire_at, "
                               "quota_bytes, created_at, updated_at, notes, host_id) "
                               "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                               "COALESCE(NULLIF(?13, ''), datetime('now')), datetime('now'), "
                               "?14, ?15)",
                               err);
    if (q.rc != 0) return -1;
    sbq_bind_text(q.st, 1, id);
    sbq_stmt_bind_text_n(&q, 2, name,
                         sbj_has(value, "name") ? sbj_get(value, "name")->v.str.len : 0, err);
    sbq_bind_text(q.st, 3, private_key);
    sbq_bind_text(q.st, 4, public_key);
    sbq_bind_text(q.st, 5, jv_opt_str(value, "preshared_key"));
    sbq_bind_text(q.st, 6, address);
    sbq_bind_text(q.st, 7, dns);
    sbq_bind_bool(q.st, 8, enabled);
    sbq_bind_int(q.st, 9, keepalive);
    sbq_bind_text(q.st, 10, allowed_ips);
    sbq_bind_text(q.st, 11, jv_opt_str(value, "expire_at"));
    sbq_bind_int(q.st, 12, quota);
    sbq_bind_text(q.st, 13, created_at);
    const sbj *notes = sbj_get(value, "notes");
    sbq_stmt_bind_text_n(&q, 14, jv_opt_str(value, "notes"),
                         sbj_is_string(notes) ? notes->v.str.len : 0, err);
    sbq_bind_text(q.st, 15, jv_opt_str(value, "host_id"));
    if (q.rc != 0 || sbq_step_done(q.st, err) != 0) return -1;
    ++*count;
    return 0;
}

sbj *sb_store_restore_backup(sb_store *s, const sbj *backup, sb_err *err) {
    if (!sbj_is_object(backup)) {
        sb_fail(err, SB_ERR_VALIDATION, "backup must be a JSON object");
        return NULL;
    }
    const sbj *settings = sbj_get(backup, "app_settings");
    const sbj *subscriptions = sbj_get(backup, "subscriptions");
    const sbj *nodes = sbj_get(backup, "proxy_nodes");
    const sbj *peers = sbj_get(backup, "wireguard_peers");
    if (settings && !sbj_is_object(settings)) {
        sb_fail(err, SB_ERR_VALIDATION, "backup app_settings must be an object");
        return NULL;
    }
    if ((subscriptions && !sbj_is_array(subscriptions)) || (nodes && !sbj_is_array(nodes)) ||
        (peers && !sbj_is_array(peers))) {
        sb_fail(err, SB_ERR_VALIDATION, "backup row sections must be arrays");
        return NULL;
    }

    size_t settings_count = 0, subscription_count = 0, node_count = 0, peer_count = 0;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0 && settings) {
        const char *key;
        sbj *value;
        SBJ_OBJ_FOREACH(settings, i, key, value) {
            sqlite3_stmt *st = sbq_prepare(h, settings_upsert_sql, err);
            if (!st) {
                rc = -1;
                break;
            }
            sbq_bind_text(st, 1, key);
            int bound = bind_dump(st, 2, value, err);
            if ((rc = exec_bound(st, bound, err)) != 0) break;
            ++settings_count;
        }
    }
    sbj *item;
    if (rc == 0 && subscriptions) {
        SBJ_ARR_FOREACH(subscriptions, i, item) {
            if (!sbj_is_object(item)) continue;
            if ((rc = restore_subscription(h, item, &subscription_count, err)) != 0) break;
        }
    }
    if (rc == 0 && nodes) {
        SBJ_ARR_FOREACH(nodes, i, item) {
            if (!sbj_is_object(item)) continue;
            if ((rc = restore_node(h, item, &node_count, err)) != 0) break;
        }
    }
    if (rc == 0 && peers) {
        SBJ_ARR_FOREACH(peers, i, item) {
            if (!sbj_is_object(item)) continue;
            if ((rc = restore_peer(h, item, &peer_count, err)) != 0) break;
        }
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    if (rc != 0) return NULL;
    sbj *result = sbj_object();
    sbj_set(result, "app_settings", sbj_uint(settings_count));
    sbj_set(result, "subscriptions", sbj_uint(subscription_count));
    sbj_set(result, "proxy_nodes", sbj_uint(node_count));
    sbj_set(result, "wireguard_peers", sbj_uint(peer_count));
    return result;
}
