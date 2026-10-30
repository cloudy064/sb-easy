/* WireGuard peers and one-time links. Moved verbatim from store.c. */
#include "store_internal.h"

#include <errno.h>
#include <stdlib.h>

/* ======================================================================
 * WireGuard, one-time links, backup
 * ====================================================================== */

static int find_peer_locked(sqlite3 *h, const char *id, sb_wireguard_peer *out, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(h, WIREGUARD_PEER_SELECT " WHERE id = ?1", err);
    if (q.rc != 0) return -1;
    sbq_bind_text(q.st, 1, S(id));
    int r = sbq_stmt_step_row(&q, err);
    if (r == 1) read_wireguard_peer(q.st, out);
    return r;
}

int sb_store_list_wireguard_peers(sb_store *s, sb_wireguard_peer_vec *out, sb_err *err) {
    sb_wireguard_peer_vec rows = {0};
    LOCK(s);
    int r = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(H(s), WIREGUARD_PEER_SELECT " ORDER BY address", err);
        r = q.rc;
        while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1)
            read_wireguard_peer(q.st, sb_wireguard_peer_vec_push(&rows));
    }
    UNLOCK(s);
    FINISH_LIST(sb_wireguard_peer_vec_free, out, rows, r);
}

int sb_store_find_wireguard_peer(sb_store *s, const char *id, sb_wireguard_peer *out, sb_err *err) {
    LOCK(s);
    int r = find_peer_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

static int reload_peer(sqlite3 *h, const char *id, sb_wireguard_peer *out, sb_err *err) {
    int r = find_peer_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "WireGuard peer could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_create_wireguard_peer(sb_store *s, const sb_wireguard_peer *peer,
                                   sb_wireguard_peer *out, sb_err *err) {
    if ((!peer->name || peer->name_len == 0) || sb_str_empty(peer->private_key) ||
        sb_str_empty(peer->public_key) || sb_str_empty(peer->address))
        return sb_fail(err, SB_ERR_VALIDATION, "WireGuard name, keys, and address are required");
    if (peer->persistent_keepalive < 0 || peer->persistent_keepalive > 65535 || peer->quota_bytes < 0)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard keepalive or quota");
    char *id = sb_str_empty(peer->id) ? sb_uuid_v4() : sb_strdup(peer->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    {
        SBQ_AUTO q = sbq_stmt_open(h, "SELECT 1 FROM wireguard_peers WHERE address = ?1", err);
        if (q.rc != 0) goto done;
        sbq_bind_text(q.st, 1, peer->address);
        int r = sbq_stmt_step_row(&q, err);
        if (r < 0) goto done;
        if (r == 1) {
            sb_fail(err, SB_ERR_CONFLICT, "WireGuard address already exists");
            goto done;
        }
    }
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "INSERT INTO wireguard_peers "
                                   "(id, name, private_key, public_key, preshared_key, address, dns, "
                                   "enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes, "
                                   "created_at, updated_at, notes, host_id) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                                   "datetime('now'), datetime('now'), ?13, ?14)",
                                   err);
        if (q.rc != 0) goto done;
        sbq_bind_text(q.st, 1, id);
        sbq_stmt_bind_text_n(&q, 2, peer->name, peer->name_len, err);
        sbq_bind_text(q.st, 3, peer->private_key);
        sbq_bind_text(q.st, 4, peer->public_key);
        sbq_bind_text(q.st, 5, peer->preshared_key);
        sbq_bind_text(q.st, 6, peer->address);
        sbq_bind_text(q.st, 7, S(peer->dns));
        sbq_bind_bool(q.st, 8, peer->enabled);
        sbq_bind_int(q.st, 9, peer->persistent_keepalive);
        sbq_bind_text(q.st, 10, S(peer->allowed_ips));
        sbq_bind_text(q.st, 11, peer->expire_at);
        sbq_bind_int(q.st, 12, peer->quota_bytes);
        sbq_stmt_bind_text_n(&q, 13, peer->notes, peer->notes_len, err);
        sbq_bind_text(q.st, 14, peer->host_id);
        if (q.rc != 0 || sbq_step_done(q.st, err) != 0) goto done;
    }
    rc = reload_peer(h, id, out, err);
done:
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_update_wireguard_peer(sb_store *s, const sb_wireguard_peer *peer,
                                   sb_wireguard_peer *out, sb_err *err) {
    if (sb_str_empty(peer->id) || (!peer->name || peer->name_len == 0) || peer->persistent_keepalive < 0 ||
        peer->persistent_keepalive > 65535 || peer->quota_bytes < 0)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard peer");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    {
        SBQ_AUTO q = sbq_stmt_open(h,
                                   "UPDATE wireguard_peers SET name = ?1, enabled = ?2, dns = ?3, "
                                   "persistent_keepalive = ?4, allowed_ips = ?5, expire_at = ?6, "
                                   "quota_bytes = ?7, updated_at = datetime('now'), notes = ?8, "
                                   "host_id = ?9 WHERE id = ?10",
                                   err);
        if (q.rc != 0) goto done;
        sbq_stmt_bind_text_n(&q, 1, peer->name, peer->name_len, err);
        sbq_bind_bool(q.st, 2, peer->enabled);
        sbq_bind_text(q.st, 3, S(peer->dns));
        sbq_bind_int(q.st, 4, peer->persistent_keepalive);
        sbq_bind_text(q.st, 5, S(peer->allowed_ips));
        sbq_bind_text(q.st, 6, peer->expire_at);
        sbq_bind_int(q.st, 7, peer->quota_bytes);
        sbq_stmt_bind_text_n(&q, 8, peer->notes, peer->notes_len, err);
        sbq_bind_text(q.st, 9, peer->host_id);
        sbq_bind_text(q.st, 10, peer->id);
        if (q.rc != 0 || sbq_step_done(q.st, err) != 0) goto done;
        if (sqlite3_changes(h) == 0) {
            sb_fail(err, SB_ERR_NOT_FOUND, "Peer not found");
            goto done;
        }
    }
    rc = reload_peer(h, peer->id, out, err);
done:
    UNLOCK(s);
    return rc;
}

int sb_store_delete_wireguard_peer(sb_store *s, const char *id, sb_err *err) {
    const char *binds[] = {S(id)};
    return exec_changes(s, "DELETE FROM wireguard_peers WHERE id = ?1", "Peer not found", err, 1,
                        binds);
}

int sb_store_set_wireguard_peer_enabled(sb_store *s, const char *id, bool enabled, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE wireguard_peers SET enabled = ?1, updated_at = datetime('now') "
                                   "WHERE id = ?2",
                                   err);
    if (st) {
        sbq_bind_bool(st, 1, enabled);
        sbq_bind_text(st, 2, S(id));
        rc = exec_stmt(st, err);
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Peer not found");
    }
    UNLOCK(s);
    return rc;
}

char *sb_store_next_wireguard_address(sb_store *s, const char *server_address, sb_err *err) {
    const char *addr = S(server_address);
    size_t host_len = strcspn(addr, "/");
    char *host = sb_strndup(addr, host_len);
    char *dot = strrchr(host, '.');
    char *base = dot ? sb_strndup(host, (size_t)(dot - host)) : sb_strdup("10.59.32");
    free(host);
    bool taken[255] = {false};
    LOCK(s);
    int r = -1;
    {
    SBQ_AUTO q = sbq_stmt_open(H(s), "SELECT address FROM wireguard_peers", err);
    r = q.rc;
    while (q.rc == 0 && (r = sbq_step_row(q.st, err)) == 1) {
        char *address = sbq_text(q.st, 0);
        address[strcspn(address, "/")] = '\0';
        char *address_dot = strrchr(address, '.');
        if (address_dot) {
            *address_dot = '\0';
            if (strcmp(address, base) == 0) {
                const char *digits = address_dot + 1;
                char *end = NULL;
                errno = 0;
                unsigned long octet = strtoul(digits, &end, 10);
                if (end != digits && errno == 0 && octet < 255) taken[octet] = true;
            }
        }
        free(address);
    }
    }
    UNLOCK(s);
    if (r < 0) {
        free(base);
        return NULL;
    }
    for (size_t octet = 2; octet <= 254; ++octet) {
        if (!taken[octet]) {
            char *result = sb_asprintf("%s.%zu/24", base, octet);
            free(base);
            return result;
        }
    }
    free(base);
    sb_fail(err, SB_ERR_CONFLICT, "No available IPs in subnet");
    return NULL;
}

int sb_store_create_one_time_link(sb_store *s, const char *token, const char *peer_id,
                                  const char *expires_at, sb_err *err) {
    sb_wireguard_peer peer;
    sb_wireguard_peer_init(&peer);
    int found = sb_store_find_wireguard_peer(s, peer_id, &peer, err);
    sb_wireguard_peer_free(&peer);
    if (found < 0) return -1;
    if (found == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Peer not found");
    const char *binds[] = {S(token), S(peer_id), S(expires_at)};
    return exec_changes(s,
                        "INSERT INTO one_time_links "
                        "(id, peer_id, expires_at, used, created_at) "
                        "VALUES (?1, ?2, ?3, 0, datetime('now'))",
                        NULL, err, 3, binds);
}
