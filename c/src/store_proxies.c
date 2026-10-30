/* Proxy node storage and latency updates. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

/* ======================================================================
 * host commands, latency
 * ====================================================================== */


int sb_store_update_proxy_latencies(sb_store *s, const sbj *results, size_t *updated, sb_err *err) {
    if (!sbj_is_object(results)) return sb_fail(err, SB_ERR_VALIDATION, "results must be a JSON object");
    LOCK(s);
    sqlite3 *h = H(s);
    size_t count = 0;
    int rc = sbq_begin(h, err);
    const char *tag;
    sbj *value;
    SBJ_OBJ_FOREACH(results, i, tag, value) {
        if (rc != 0) break;
        double latency = 0.0;
        bool has = false;
        if (!sbj_is_null(value)) {
            if (!sbj_is_number(value)) {
                rc = sb_fail(err, SB_ERR_VALIDATION, "proxy latency values must be numbers or null");
                break;
            }
            latency = sbj_as_double(value, 0.0);
            has = true;
        }
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE proxy_nodes SET latency = ?1, "
                                       "last_latency_test = datetime('now') WHERE tag = ?2",
                                       err);
        if (!st) {
            rc = -1;
            break;
        }
        sbq_bind_opt_double(st, 1, has ? &latency : NULL);
        int bound = sbq_bind_text_n(st, 2, tag, results->v.obj.key_lens[i], err);
        rc = exec_bound(st, bound, err);
        if (rc == 0) count += (size_t)sqlite3_changes(h);
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    if (rc == 0 && updated) *updated = count;
    return rc;
}

int sb_store_update_proxy_latency(sb_store *s, const char *id, const double *latency, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE proxy_nodes SET latency = ?1, "
                                   "last_latency_test = datetime('now') WHERE id = ?2",
                                   err);
    if (st) {
        sbq_bind_opt_double(st, 1, latency);
        sbq_bind_text(st, 2, S(id));
        rc = exec_stmt(st, err);
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Node not found");
    }
    UNLOCK(s);
    return rc;
}

/* ======================================================================
 * proxies
 * ====================================================================== */

static int find_proxy_locked(sqlite3 *h, const char *id, sb_proxy_record *out, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(h, PROXY_SELECT "FROM proxy_nodes WHERE id = ?1", err);
    if (q.rc != 0) return -1;
    const char *pid = S(id);
    sbq_stmt_bind_text_n(&q, 1, pid, strlen(pid), err);
    int r = sbq_stmt_step_row(&q, err);
    if (r == 1 && read_proxy_record(q.st, out, err) != 0) r = -1;
    return r;
}

static int reload_proxy(sqlite3 *h, const char *id, sb_proxy_record *out, sb_err *err) {
    int r = find_proxy_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "proxy node could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_proxy_nodes(sb_store *s, sb_proxy_record_vec *out, sb_err *err) {
    sb_proxy_record_vec rows = {0};
    LOCK(s);
    int r;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), PROXY_SELECT "FROM proxy_nodes ORDER BY node_type, tag", err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1) {
            sb_proxy_record rec;
            sb_proxy_record_init(&rec);
            if (read_proxy_record(q.st, &rec, err) != 0) {
                sb_proxy_record_free(&rec);
                r = -1;
                break;
            }
            sb_proxy_record *slot = sb_proxy_record_vec_push(&rows);
            sb_proxy_record_free(slot);
            *slot = rec;
        }
    }
    UNLOCK(s);
    FINISH_LIST(sb_proxy_record_vec_free, out, rows, r);
}

int sb_store_find_proxy_node(sb_store *s, const char *id, sb_proxy_record *out, sb_err *err) {
    LOCK(s);
    int r = find_proxy_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_proxy_node(sb_store *s, const sb_proxy_record *node, sb_proxy_record *out,
                               sb_err *err) {
    if (validate_proxy(node, err) != 0)
        return -1;
    char *fingerprint = fingerprint_of(node, err);
    if (!fingerprint) return -1;
    if (node->subscription_id) {
        char *scoped = sb_asprintf("%s:%s", node->subscription_id, fingerprint);
        free(fingerprint);
        fingerprint = sb_sha256_hex(scoped, strlen(scoped));
        free(scoped);
    }
    char *id = sb_str_empty(node->id) ? sb_uuid_v4() : sb_strdup(node->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(h, "SELECT 1 FROM proxy_nodes WHERE tag = ?1 OR fingerprint = ?2 LIMIT 1",
                                   err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, node->tag, node->tag_len, err);
        sbq_stmt_bind_text_n(&q, 2, fingerprint, strlen(fingerprint), err);
        r = sbq_stmt_step_row(&q, err);
    }
    if (r < 0) goto done;
    if (r == 1) {
        sb_fail(err, SB_ERR_VALIDATION, "A proxy with the same tag or fingerprint already exists");
        goto done;
    }
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "INSERT INTO proxy_nodes "
                                   "(id, tag, node_type, enabled, server, server_port, protocol_config, "
                                   "subscription_id, fingerprint, latency, last_latency_test, "
                                   "created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
                                   "datetime('now'), datetime('now'))",
                                   err);
        if (q.rc != 0) goto done;
        sbq_bind_text(q.st, 1, id);
        sbq_stmt_bind_text_n(&q, 2, node->tag, node->tag_len, err);
        sbq_stmt_bind_text_n(&q, 3, node->node_type, node->node_type_len, err);
        sbq_bind_bool(q.st, 4, node->enabled);
        sbq_stmt_bind_text_n(&q, 5, node->server, node->server_len, err);
        sbq_bind_int(q.st, 6, node->server_port);
        int bound = bind_dump(q.st, 7, node->protocol_config, err);
        sbq_bind_text(q.st, 8, node->subscription_id);
        sbq_bind_text(q.st, 9, fingerprint);
        sbq_bind_opt_double(q.st, 10, node->has_latency ? &node->latency : NULL);
        sbq_bind_text(q.st, 11, node->last_latency_test);
        if (q.rc != 0 || bound != 0 || sbq_step_done(q.st, err) != 0) goto done;
    }
    rc = reload_proxy(h, id, out, err);
done:
    UNLOCK(s);
    free(id);
    free(fingerprint);
    return rc;
}

int sb_store_update_proxy_node(sb_store *s, const sb_proxy_record *node, sb_proxy_record *out,
                               sb_err *err) {
    if (validate_proxy(node, err) != 0)
        return -1;
    if (sb_str_empty(node->id)) return sb_fail(err, SB_ERR_VALIDATION, "Proxy id is required");
    char *fingerprint = fingerprint_of(node, err);
    if (!fingerprint) return -1;
    if (node->subscription_id) {
        char *scoped = sb_asprintf("%s:%s", node->subscription_id, fingerprint);
        free(fingerprint);
        fingerprint = sb_sha256_hex(scoped, strlen(scoped));
        free(scoped);
    }
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "SELECT 1 FROM proxy_nodes WHERE id != ?1 "
                                   "AND (tag = ?2 OR fingerprint = ?3) LIMIT 1",
                                   err);
        if (q.rc != 0) goto done;
        sbq_bind_text(q.st, 1, node->id);
        sbq_stmt_bind_text_n(&q, 2, node->tag, node->tag_len, err);
        sbq_stmt_bind_text_n(&q, 3, fingerprint, strlen(fingerprint), err);
        r = sbq_stmt_step_row(&q, err);
    }
    if (r < 0) goto done;
    if (r == 1) {
        sb_fail(err, SB_ERR_VALIDATION, "A proxy with the same tag or fingerprint already exists");
        goto done;
    }
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "UPDATE proxy_nodes SET tag = ?1, node_type = ?2, enabled = ?3, "
                                   "server = ?4, server_port = ?5, protocol_config = ?6, "
                                   "subscription_id = ?7, fingerprint = ?8, updated_at = datetime('now') "
                                   "WHERE id = ?9",
                                   err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, node->tag, node->tag_len, err);
        sbq_stmt_bind_text_n(&q, 2, node->node_type, node->node_type_len, err);
        sbq_bind_bool(q.st, 3, node->enabled);
        sbq_stmt_bind_text_n(&q, 4, node->server, node->server_len, err);
        sbq_bind_int(q.st, 5, node->server_port);
        int bound = bind_dump(q.st, 6, node->protocol_config, err);
        sbq_bind_text(q.st, 7, node->subscription_id);
        sbq_bind_text(q.st, 8, fingerprint);
        sbq_bind_text(q.st, 9, node->id);
        if (q.rc != 0 || bound != 0 || sbq_step_done(q.st, err) != 0) goto done;
    }
    if (sqlite3_changes(h) == 0) {
        sb_fail(err, SB_ERR_NOT_FOUND, "Node not found");
        goto done;
    }
    rc = reload_proxy(h, node->id, out, err);
done:
    UNLOCK(s);
    free(fingerprint);
    return rc;
}

int sb_store_delete_proxy_node(sb_store *s, const char *id, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM host_outbounds WHERE node_id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM proxy_nodes WHERE id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Node not found");
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

/* Renderer outbound tags must remain unique even when two subscriptions use
 * the same display name. The provider name stays in source_tag for rotation. */
static char *import_display_tag(sqlite3 *h, const sb_parsed_node *node, const char *existing_id,
                                size_t *length, sb_err *err) {
    char *tag = sb_strndup(node->tag, node->tag_len);
    *length = node->tag_len;
    for (size_t suffix = 1; ; ++suffix) {
        int found;
        {
            SBQ_AUTO q = sbq_stmt_open(h,
                "SELECT 1 FROM proxy_nodes WHERE tag = ?1 AND (?2 IS NULL OR id != ?2) LIMIT 1", err);
            if (q.rc != 0) { free(tag); return NULL; }
            sbq_stmt_bind_text_n(&q, 1, tag, *length, err);
            if (q.rc == 0) sbq_bind_text(q.st, 2, existing_id);
            found = sbq_stmt_step_row(&q, err);
        }
        if (found == 0) return tag;
        if (found < 0) { free(tag); return NULL; }
        sb_buf renamed = {0};
        sb_buf_append(&renamed, node->tag, node->tag_len);
        sb_buf_printf(&renamed, " [%zu]", suffix + 1);
        free(tag);
        *length = renamed.len;
        tag = sb_buf_detach(&renamed);
    }
}

/* One node of upsert_proxy_nodes; errors are collected by the caller. */
int upsert_one(sqlite3 *h, const sb_parsed_node *node, const char *subscription_id,
                      sb_proxy_upsert_result *result, sb_err *err) {
    sb_proxy_record view = {0};
    view.tag = node->tag; view.tag_len = node->tag_len;
    view.node_type = node->node_type; view.node_type_len = node->node_type_len;
    view.server = node->server; view.server_len = node->server_len;
    view.server_port = node->server_port; view.protocol_config = node->protocol_config;
    if (validate_proxy(&view, err) != 0)
        return -1;
    char *fingerprint = fingerprint_of(&view, err);
    if (!fingerprint) return -1;
    char *legacy_fingerprint = sb_strdup(fingerprint);
    if (subscription_id) {
        char *scoped = sb_asprintf("%s:%s", subscription_id, fingerprint);
        free(fingerprint);
        fingerprint = sb_sha256_hex(scoped, strlen(scoped));
        free(scoped);
    }
    char *existing_id = NULL;
    char *display_tag = NULL;
    size_t display_tag_len = 0;
    int rc = -1;
    /* Two-level match: fingerprint first, then the same tag with a different
     * fingerprint (a provider rotating its server address). */
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "SELECT id FROM proxy_nodes WHERE (fingerprint = ?1 OR fingerprint = ?4) "
                                   "AND subscription_id IS ?3 "
                                   "UNION ALL "
                                   "SELECT id FROM proxy_nodes WHERE (tag = ?2 OR source_tag = ?2) "
                                   "AND fingerprint != ?1 AND subscription_id IS ?3 LIMIT 1",
                                   err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, fingerprint, strlen(fingerprint), err);
        sbq_stmt_bind_text_n(&q, 2, node->tag, node->tag_len, err);
        if (q.rc == 0) {
            sbq_bind_text(q.st, 3, subscription_id);
            sbq_bind_text(q.st, 4, legacy_fingerprint);
        }
        r = sbq_stmt_step_row(&q, err);
        if (r == 1) existing_id = sbq_text(q.st, 0);
    }
    if (r < 0) goto done;
    display_tag = import_display_tag(h, node, existing_id, &display_tag_len, err);
    if (!display_tag) goto done;

    if (existing_id) {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "UPDATE proxy_nodes SET tag = CASE WHEN ?7 IS NOT NULL "
                                   "AND source_tag IS NOT NULL AND tag != source_tag THEN tag ELSE ?9 END, "
                                   "source_tag = CASE WHEN ?7 IS NOT NULL THEN ?1 ELSE NULL END, node_type = ?2, "
                                   "server = ?3, server_port = ?4, protocol_config = ?5, "
                                   "fingerprint = ?6, subscription_id = ?7, "
                                   "updated_at = datetime('now') WHERE id = ?8",
                                   err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, node->tag, node->tag_len, err);
        sbq_stmt_bind_text_n(&q, 2, node->node_type, node->node_type_len, err);
        sbq_stmt_bind_text_n(&q, 3, node->server, node->server_len, err);
        sbq_bind_int(q.st, 4, node->server_port);
        int bound = bind_dump(q.st, 5, node->protocol_config, err);
        sbq_bind_text(q.st, 6, fingerprint);
        sbq_bind_text(q.st, 7, subscription_id);
        sbq_bind_text(q.st, 8, existing_id);
        sbq_stmt_bind_text_n(&q, 9, display_tag, display_tag_len, err);
        if (q.rc != 0 || bound != 0 || sbq_step_done(q.st, err) != 0) goto done;
        ++result->updated;
    } else {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "INSERT INTO proxy_nodes "
                                   "(id, tag, node_type, enabled, server, server_port, "
                                   "protocol_config, subscription_id, fingerprint, source_tag, "
                                   "created_at, updated_at) "
                                   "VALUES (?1, ?9, ?3, 1, ?4, ?5, ?6, ?7, ?8, CASE WHEN ?7 IS NOT NULL THEN ?2 END, "
                                   "datetime('now'), datetime('now'))",
                                   err);
        if (q.rc != 0) goto done;
        char *id = sb_uuid_v4();
        sbq_bind_text(q.st, 1, id);
        free(id);
        sbq_stmt_bind_text_n(&q, 2, node->tag, node->tag_len, err);
        sbq_stmt_bind_text_n(&q, 3, node->node_type, node->node_type_len, err);
        sbq_stmt_bind_text_n(&q, 4, node->server, node->server_len, err);
        sbq_bind_int(q.st, 5, node->server_port);
        int bound = bind_dump(q.st, 6, node->protocol_config, err);
        sbq_bind_text(q.st, 7, subscription_id);
        sbq_bind_text(q.st, 8, fingerprint);
        sbq_stmt_bind_text_n(&q, 9, display_tag, display_tag_len, err);
        if (q.rc != 0 || bound != 0 || sbq_step_done(q.st, err) != 0) goto done;
        ++result->added;
    }
    rc = 0;
done:
    free(fingerprint);
    free(legacy_fingerprint);
    free(existing_id);
    free(display_tag);
    return rc;
}

int sb_store_upsert_proxy_nodes(sb_store *s, const sb_parsed_node *nodes, size_t count,
                                const char *subscription_id, sb_proxy_upsert_result *out,
                                sb_err *err) {
    sb_proxy_upsert_result result;
    sb_proxy_upsert_result_init(&result);
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = 0;
    if (subscription_id) {
        int r = -1;
        {
            SBQ_AUTO q = sbq_stmt_open(h, "SELECT 1 FROM subscriptions WHERE id = ?1", err);
            if (q.rc == 0) {
                sbq_stmt_bind_text_n(&q, 1, subscription_id, strlen(subscription_id), err);
                r = sbq_stmt_step_row(&q, err);
            }
        }
        if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Subscription not found");
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) rc = sbq_begin(h, err);
    if (rc == 0) {
        for (size_t i = 0; i < count; ++i) {
            sb_err node_err = {0};
            if (upsert_one(h, &nodes[i], subscription_id, &result, &node_err) != 0)
                sb_strvec_push_take(&result.errors,
                                    sb_asprintf("Failed to import %s: %s", S(nodes[i].tag), node_err.msg));
        }
        rc = sbq_commit(h, err);
        if (rc != 0) sbq_rollback(h);
    }
    UNLOCK(s);
    if (rc != 0) {
        sb_proxy_upsert_result_free(&result);
        return -1;
    }
    sb_proxy_upsert_result_free(out);
    *out = result;
    return 0;
}
