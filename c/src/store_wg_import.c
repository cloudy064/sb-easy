/* wg-easy migration: preview, guarded apply and rollback. Moved verbatim from store.c. */
#include "store_internal.h"

#include <stdlib.h>

/* ---- wg-easy migration: preview, guarded apply and rollback ------------ */
sbj *sb_store_list_wg_imports(sb_store *s, sb_err *err) {
    sbj *rows = sbj_array();
    LOCK(s);
    int r;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s),
            "SELECT id, created_at, status, inserted_ids FROM wireguard_imports ORDER BY created_at DESC, rowid DESC LIMIT 20", err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1) {
            sbj *row = sbj_object();
            sbj_set(row, "id", sbj_str_take(sbq_text(q.st, 0)));
            sbj_set(row, "created_at", sbj_str_take(sbq_text(q.st, 1)));
            sbj_set(row, "status", sbj_str_take(sbq_text(q.st, 2)));
            sbj *ids = sbj_parse((const char *)sqlite3_column_text(q.st, 3), (size_t)sqlite3_column_bytes(q.st, 3), NULL, 0);
            sbj_set(row, "added", sbj_uint(sbj_arr_len(ids))); sbj_free(ids);
            sbj_arr_push(rows, row);
        }
    }
    UNLOCK(s);
    if (r < 0) { sbj_free(rows); return NULL; }
    return rows;
}

static sbj *wg_snapshot_locked(sqlite3 *h, sb_err *err) {
    sbj *snapshot = sbj_object(), *settings = sbj_object(), *peers = sbj_array();
    sbj_set(snapshot, "app_settings", settings);
    sbj_set(snapshot, "wireguard_peers", peers);
    int r = 0;
    {
        SBQ_AUTO q = sbq_stmt_open(h,
            "SELECT key, value FROM app_settings WHERE key IN ('wg_server_key', 'wireguard_interface') ORDER BY key", err);
        if (q.rc != 0) goto fail;
        while ((r = sbq_step_row(q.st, err)) == 1) {
            sbj *value = parse_object_col(q.st, 1, "WireGuard settings", err);
            if (!value) goto fail;
            sbj_set(settings, (const char *)sqlite3_column_text(q.st, 0), value);
        }
    }
    if (r < 0) goto fail;
    {
        SBQ_AUTO q = sbq_stmt_open(h, WIREGUARD_PEER_SELECT " ORDER BY id", err);
        if (q.rc != 0) goto fail;
        while ((r = sbq_step_row(q.st, err)) == 1) {
            sb_wireguard_peer peer; sb_wireguard_peer_init(&peer);
            read_wireguard_peer(q.st, &peer);
            sbj_arr_push(peers, sb_wireguard_peer_to_json(&peer));
            sb_wireguard_peer_free(&peer);
        }
    }
    if (r < 0) goto fail;
    return snapshot;
fail:
    sbj_free(snapshot); return NULL;
}

static int wg_settings_locked(sqlite3 *h, const sbj *settings, sb_err *err) {
    const char *keys[] = {"wg_server_key", "wireguard_interface"};
    for (size_t i = 0; i < 2; ++i) {
        const sbj *value = sbj_get(settings, keys[i]);
        sqlite3_stmt *st = sbq_prepare(h, value ? settings_upsert_sql :
            "DELETE FROM app_settings WHERE key = ?1", err);
        if (!st) return -1;
        sbq_bind_text(st, 1, keys[i]);
        int bound = value ? bind_dump(st, 2, value, err) : 0;
        if (exec_bound(st, bound, err) != 0) return -1;
    }
    return 0;
}

static int wg_import_audit(sqlite3 *h, const char *actor, size_t actor_len,
                            const char *action, const char *id, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(h, "INSERT INTO audit_log(actor, action, target) VALUES(?1, ?2, ?3)", err);
    if (!st) return -1;
    int bound = sbq_bind_text_n(st, 1, S(actor), actor ? actor_len : 0, err);
    sbq_bind_text(st, 2, action); sbq_bind_text(st, 3, id);
    return exec_bound(st, bound, err);
}

static bool wg_import_same_ip(const char *left, const char *right) {
    size_t left_len = strcspn(left, "/"), right_len = strcspn(right, "/");
    return left_len == right_len && memcmp(left, right, left_len) == 0;
}

int sb_store_wg_import(sb_store *s, const sbj *batch, bool apply, const char *preview_digest,
                       const char *actor, size_t actor_len, sbj **out, sb_err *err) {
    const sbj *incoming = sbj_get(batch, "wireguard_peers");
    const sbj *incoming_settings = sbj_get(batch, "app_settings");
    if (!sbj_is_array(incoming) || !sbj_is_object(incoming_settings))
        return sb_fail(err, SB_ERR_VALIDATION, "Validated WireGuard migration batch is required");
    sbj *before = NULL, *after = NULL, *report = sbj_object(), *additions = sbj_array();
    sbj *ids = sbj_array(), *settings = NULL;
    char *digest = NULL, *migration_id = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc != 0) goto done;
    before = wg_snapshot_locked(h, err);
    if (!before) { rc = -1; goto done; }
    sbj *material = sbj_object(); sbj_set(material, "before", sbj_clone(before));
    sbj_set(material, "incoming", sbj_clone(batch));
    char *serialized = dump_checked(material, err); sbj_free(material);
    if (!serialized) { rc = -1; goto done; }
    digest = sb_sha256_hex(serialized, strlen(serialized)); free(serialized);
    const sbj *existing = sbj_get(before, "wireguard_peers");
    const sbj *old_settings = sbj_get(before, "app_settings");
    const sbj *new_keys = sbj_get(incoming_settings, "wg_server_key");
    const sbj *new_interface = sbj_get(incoming_settings, "wireguard_interface");
    sbj *conflicts = sbj_array(), *rows = sbj_array();
    sbj_set(report, "conflicts", conflicts); sbj_set(report, "clients", rows);
    if (sbj_arr_len(existing)) {
        if (strcmp(sbj_get_str(sbj_get(old_settings, "wg_server_key"), "public_key", ""),
                   sbj_get_str(new_keys, "public_key", "")) != 0)
            sbj_arr_push(conflicts, sbj_str("Existing WireGuard peers use a different or unknown server identity"));
        if (strcmp(sbj_get_str(sbj_get(old_settings, "wireguard_interface"), "address", ""),
                   sbj_get_str(new_interface, "address", "")) != 0)
            sbj_arr_push(conflicts, sbj_str("Existing WireGuard peers use a different server subnet"));
    }
    size_t skipped = 0;
    const sbj *peer;
    SBJ_ARR_FOREACH(incoming, index, peer) {
        const char *id = sbj_get_str(peer, "id", ""), *pub = sbj_get_str(peer, "public_key", "");
        const char *address = sbj_get_str(peer, "address", "");
        bool same = false, collision = false;
        const sbj *old;
        SBJ_ARR_FOREACH(existing, previous, old) {
            bool same_key = strcmp(pub, sbj_get_str(old, "public_key", "")) == 0;
            bool same_address = wg_import_same_ip(address, sbj_get_str(old, "address", ""));
            bool same_id = strcmp(id, sbj_get_str(old, "id", "")) == 0;
            if (same_key && same_address) same = true;
            else if (same_key || same_address || same_id) collision = true;
        }
        sbj *row = sbj_object(); sbj_set_str(row, "id", id);
        sbj_set_str(row, "name", sbj_get_str(peer, "name", "")); sbj_set_str(row, "address", address);
        sbj_set_bool(row, "enabled", sbj_get_bool(peer, "enabled", false));
        sbj_set_bool(row, "has_private_key", *sbj_get_str(peer, "private_key", "") != '\0');
        sbj_set_str(row, "action", collision ? "conflict" : same ? "already_present" : "add");
        sbj_arr_push(rows, row);
        if (collision) sbj_arr_push(conflicts, sbj_str_take(sb_asprintf("Client %zu conflicts with an existing identifier, address or public key", index + 1)));
        else if (same) ++skipped;
        else { sbj_arr_push(additions, sbj_clone(peer)); sbj_arr_push(ids, sbj_str(id)); }
    }
    sbj_set_str(report, "format", "wg-easy-v14"); sbj_set_str(report, "status", apply ? "imported" : "preview");
    sbj_set_str(report, "preview_digest", digest); sbj_set_bool(report, "can_import", sbj_arr_len(conflicts) == 0);
    sbj_set(report, "added", sbj_uint(sbj_arr_len(additions))); sbj_set(report, "skipped", sbj_uint(skipped));
    sbj_set_str(report, "server_address", sbj_get_str(new_interface, "address", ""));
    sbj_set_str(report, "server_public_key", sbj_get_str(new_keys, "public_key", ""));
    if (!apply) { sbq_rollback(h); goto success; }
    if (sbj_arr_len(conflicts)) { rc = sb_fail(err, SB_ERR_CONFLICT, "Migration has conflicts; no changes applied"); goto done; }
    if (!preview_digest || strcmp(preview_digest, digest) != 0) {
        rc = sb_fail(err, SB_ERR_CONFLICT, "Migration input or WireGuard state changed; preview again before importing"); goto done;
    }
    settings = sbj_clone(old_settings);
    sbj_set(settings, "wg_server_key", sbj_clone(new_keys));
    sbj *merged_interface = sbj_get(old_settings, "wireguard_interface") ?
        sbj_clone(sbj_get(old_settings, "wireguard_interface")) : sbj_object();
    sbj_set_str(merged_interface, "address", sbj_get_str(new_interface, "address", ""));
    sbj_set(settings, "wireguard_interface", merged_interface);
    rc = wg_settings_locked(h, settings, err);
    size_t inserted = 0;
    SBJ_ARR_FOREACH(additions, index, peer) {
        if (rc == 0) rc = restore_peer(h, peer, &inserted, err);
    }
    if (rc != 0) goto done;
    after = wg_snapshot_locked(h, err);
    if (!after) { rc = -1; goto done; }
    migration_id = sb_uuid_v4();
    sqlite3_stmt *st = sbq_prepare(h,
        "INSERT INTO wireguard_imports(id, before_snapshot, after_snapshot, inserted_ids) VALUES(?1, ?2, ?3, ?4)", err);
    if (!st) { rc = -1; goto done; }
    sbq_bind_text(st, 1, migration_id);
    int bound = bind_dump(st, 2, before, err);
    if (bound == 0) bound = bind_dump(st, 3, after, err);
    if (bound == 0) bound = bind_dump(st, 4, ids, err);
    rc = exec_bound(st, bound, err);
    if (rc == 0) rc = wg_import_audit(h, actor, actor_len, "wireguard.import", migration_id, err);
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) goto done;
    sbj_set_str(report, "migration_id", migration_id);
    sbj_set_bool(report, "restart_required", true);
success:
    *out = report; report = NULL;
done:
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    sbj_free(before); sbj_free(after); sbj_free(report); sbj_free(additions); sbj_free(ids); sbj_free(settings);
    free(digest); free(migration_id);
    return rc;
}

int sb_store_wg_import_rollback(sb_store *s, const char *id, const char *actor,
                                size_t actor_len, sbj **out, sb_err *err) {
    sbj *before = NULL, *after = NULL, *ids = NULL, *current = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc != 0) goto done;
    {
        SBQ_AUTO q = sbq_stmt_open(h,
            "SELECT before_snapshot, after_snapshot, inserted_ids, status FROM wireguard_imports WHERE id = ?1", err);
        if (q.rc != 0) { rc = -1; goto done; }
        sbq_bind_text(q.st, 1, S(id));
        int found = sbq_step_row(q.st, err);
        if (found != 1) {
            rc = found < 0 ? -1 : sb_fail(err, SB_ERR_NOT_FOUND, "Migration record not found"); goto done;
        }
        if (strcmp((const char *)sqlite3_column_text(q.st, 3), "applied") != 0) {
            rc = sb_fail(err, SB_ERR_CONFLICT, "Migration was already rolled back"); goto done;
        }
        before = parse_object_col(q.st, 0, "migration before snapshot", err);
        after = parse_object_col(q.st, 1, "migration after snapshot", err);
        ids = sbj_parse((const char *)sqlite3_column_text(q.st, 2), (size_t)sqlite3_column_bytes(q.st, 2), NULL, 0);
    }
    if (!before || !after || !sbj_is_array(ids)) { rc = sb_fail(err, SB_ERR_GENERIC, "Invalid migration rollback record"); goto done; }
    current = wg_snapshot_locked(h, err);
    if (!current) { rc = -1; goto done; }
    if (!sbj_equal(current, after)) {
        rc = sb_fail(err, SB_ERR_CONFLICT, "WireGuard state changed after import; automatic rollback would overwrite those changes"); goto done;
    }
    const sbj *peer_id;
    SBJ_ARR_FOREACH(ids, index, peer_id) {
        const char *queries[] = {"DELETE FROM one_time_links WHERE peer_id = ?1", "DELETE FROM wireguard_peers WHERE id = ?1"};
        for (size_t i = 0; i < 2 && rc == 0; ++i) {
            SBQ_AUTO q = sbq_stmt_open(h, queries[i], err);
            if (q.rc != 0) { rc = -1; break; }
            sbq_bind_text(q.st, 1, sbj_as_str(peer_id, "")); rc = sbq_step_done(q.st, err);
        }
    }
    if (rc == 0) rc = wg_settings_locked(h, sbj_get(before, "app_settings"), err);
    if (rc == 0) {
        SBQ_AUTO q = sbq_stmt_open(h, "UPDATE wireguard_imports SET status = 'rolled_back' WHERE id = ?1", err);
        if (q.rc != 0) rc = -1;
        else { sbq_bind_text(q.st, 1, id); rc = sbq_step_done(q.st, err); }
    }
    if (rc == 0) rc = wg_import_audit(h, actor, actor_len, "wireguard.import.rollback", id, err);
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc == 0) {
        *out = sbj_object(); sbj_set_str(*out, "status", "rolled_back");
        sbj_set_str(*out, "migration_id", id); sbj_set_bool(*out, "restart_required", true);
    }
done:
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    sbj_free(before); sbj_free(after); sbj_free(ids); sbj_free(current);
    return rc;
}
