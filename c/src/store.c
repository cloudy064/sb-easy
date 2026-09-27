/* Repository facade over the sb-easy schema. Port of cpp/src/store.cpp: same
 * queries (verbatim), validation rules, error messages and JSON shapes. */
#include "sb/store.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb/auth.h"
#include "sqlite_internal.h"

struct sb_store {
    sb_database *db;
};

#define S(x) ((x) ? (x) : "")
#define LOCK(s) sb_database_lock((s)->db)
#define UNLOCK(s) sb_database_unlock((s)->db)
#define H(s) sb_database_handle((s)->db)

/* ======================================================================
 * struct helpers
 * ====================================================================== */

#define DEFINE_VEC(type)                                                               \
    type *type##_vec_push(type##_vec *v) {                                             \
        if (v->len == v->cap) {                                                        \
            v->cap = v->cap ? v->cap * 2 : 8;                                          \
            v->items = sb_xrealloc(v->items, v->cap * sizeof *v->items);               \
        }                                                                              \
        type *slot = &v->items[v->len++];                                              \
        type##_init(slot);                                                             \
        return slot;                                                                   \
    }                                                                                  \
    void type##_vec_free(type##_vec *v) {                                              \
        for (size_t i = 0; i < v->len; ++i) type##_free(&v->items[i]);                 \
        free(v->items);                                                                \
        memset(v, 0, sizeof *v);                                                       \
    }

static sbj *opt_str(const char *value) { return value ? sbj_str(value) : sbj_null(); }

/* ---- user ---- */
void sb_user_account_init(sb_user_account *u) {
    u->id = sb_strdup("");
    u->username = sb_strdup("");
    u->username_len = 0;
    u->password_hash = sb_strdup("");
    u->role = sb_strdup("");
    u->created_at = sb_strdup("");
}
void sb_user_account_free(sb_user_account *u) {
    free(u->id);
    free(u->username);
    free(u->password_hash);
    free(u->role);
    free(u->created_at);
    memset(u, 0, sizeof *u);
}
sbj *sb_user_account_to_json(const sb_user_account *u) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(u->id));
    sbj_set(v, "username", sbj_strn(S(u->username), u->username_len));
    sbj_set_str(v, "role", S(u->role));
    sbj_set_str(v, "created_at", S(u->created_at));
    return v;
}
DEFINE_VEC(sb_user_account)

/* ---- audit ---- */
void sb_audit_entry_init(sb_audit_entry *e) {
    e->id = 0;
    e->timestamp = sb_strdup("");
    e->actor = sb_strdup("");
    e->actor_len = 0;
    e->action = sb_strdup("");
    e->target = NULL;
}
void sb_audit_entry_free(sb_audit_entry *e) {
    free(e->timestamp);
    free(e->actor);
    free(e->action);
    free(e->target);
    memset(e, 0, sizeof *e);
}
sbj *sb_audit_entry_to_json(const sb_audit_entry *e) {
    sbj *v = sbj_object();
    sbj_set_int(v, "id", e->id);
    sbj_set_str(v, "ts", S(e->timestamp));
    sbj_set(v, "actor", sbj_strn(S(e->actor), e->actor_len));
    sbj_set_str(v, "action", S(e->action));
    sbj_set(v, "target", opt_str(e->target));
    return v;
}
DEFINE_VEC(sb_audit_entry)

/* ---- wireguard ---- */
void sb_wireguard_peer_init(sb_wireguard_peer *p) {
    memset(p, 0, sizeof *p);
    p->id = sb_strdup("");
    p->name = sb_strdup("");
    p->private_key = sb_strdup("");
    p->public_key = sb_strdup("");
    p->address = sb_strdup("");
    p->dns = sb_strdup("10.59.32.1");
    p->enabled = true;
    p->persistent_keepalive = 25;
    p->allowed_ips = sb_strdup("0.0.0.0/0, ::/0");
    p->created_at = sb_strdup("");
    p->updated_at = sb_strdup("");
}
void sb_wireguard_peer_free(sb_wireguard_peer *p) {
    free(p->id);
    free(p->name);
    free(p->private_key);
    free(p->public_key);
    free(p->preshared_key);
    free(p->address);
    free(p->dns);
    free(p->allowed_ips);
    free(p->expire_at);
    free(p->created_at);
    free(p->updated_at);
    free(p->notes);
    free(p->host_id);
    memset(p, 0, sizeof *p);
}
sbj *sb_wireguard_peer_to_json(const sb_wireguard_peer *p) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(p->id));
    sbj_set_str(v, "name", S(p->name));
    sbj_set_str(v, "private_key", S(p->private_key));
    sbj_set_str(v, "public_key", S(p->public_key));
    sbj_set(v, "preshared_key", opt_str(p->preshared_key));
    sbj_set_str(v, "address", S(p->address));
    sbj_set_str(v, "dns", S(p->dns));
    sbj_set_bool(v, "enabled", p->enabled);
    sbj_set_int(v, "persistent_keepalive", p->persistent_keepalive);
    sbj_set_str(v, "allowed_ips", S(p->allowed_ips));
    sbj_set(v, "expire_at", opt_str(p->expire_at));
    sbj_set_int(v, "quota_bytes", p->quota_bytes);
    sbj_set_str(v, "created_at", S(p->created_at));
    sbj_set_str(v, "updated_at", S(p->updated_at));
    sbj_set(v, "notes", opt_str(p->notes));
    sbj_set(v, "host_id", opt_str(p->host_id));
    return v;
}
DEFINE_VEC(sb_wireguard_peer)

/* ---- profile ---- */
void sb_config_profile_init(sb_config_profile *p) {
    memset(p, 0, sizeof *p);
    p->id = sb_strdup("");
    p->name = sb_strdup("");
    p->profile = sbj_object();
    p->mode = SB_PROFILE_MANAGED;
    p->rule_script = sb_strdup("");
    p->created_at = sb_strdup("");
    p->updated_at = sb_strdup("");
}
void sb_config_profile_free(sb_config_profile *p) {
    free(p->id);
    free(p->name);
    sbj_free(p->profile);
    free(p->rule_script);
    free(p->created_at);
    free(p->updated_at);
    memset(p, 0, sizeof *p);
}
void sb_config_profile_copy(sb_config_profile *dst, const sb_config_profile *src) {
    sb_config_profile_free(dst);
    dst->id = sb_strdup(S(src->id));
    dst->name = sb_strdup(S(src->name));
    dst->profile = src->profile ? sbj_clone(src->profile) : sbj_object();
    dst->mode = src->mode;
    dst->rule_script = sb_strdup(S(src->rule_script));
    dst->rule_script_enabled = src->rule_script_enabled;
    dst->created_at = sb_strdup(S(src->created_at));
    dst->updated_at = sb_strdup(S(src->updated_at));
}
sbj *sb_config_profile_to_json(const sb_config_profile *p) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(p->id));
    sbj_set_str(v, "name", S(p->name));
    sbj_set(v, "template", sbj_str_take(sbj_dump(p->profile, -1)));
    sbj_set_str(v, "mode", sb_profile_mode_name(p->mode));
    sbj_set_str(v, "rule_script", S(p->rule_script));
    sbj_set_bool(v, "rule_script_enabled", p->rule_script_enabled);
    sbj_set_str(v, "created_at", S(p->created_at));
    sbj_set_str(v, "updated_at", S(p->updated_at));
    return v;
}
DEFINE_VEC(sb_config_profile)

/* ---- host ---- */
void sb_host_init(sb_host *h) {
    memset(h, 0, sizeof *h);
    h->id = sb_strdup("");
    h->name = sb_strdup("");
    h->agent_token = sb_strdup("");
    h->capabilities = sbj_object();
    h->clash_secret = sb_strdup("");
    h->enabled = true;
    h->created_at = sb_strdup("");
    h->updated_at = sb_strdup("");
}
void sb_host_free(sb_host *h) {
    free(h->id);
    free(h->name);
    free(h->agent_token);
    sbj_free(h->capabilities);
    free(h->profile_id);
    free(h->wg_address);
    free(h->wg_public_key);
    free(h->wg_endpoint);
    free(h->clash_api);
    free(h->clash_secret);
    free(h->last_seen);
    free(h->singbox_state);
    free(h->created_at);
    free(h->updated_at);
    memset(h, 0, sizeof *h);
}
void sb_host_copy(sb_host *dst, const sb_host *src) {
    sb_host_free(dst);
    dst->id = sb_strdup(S(src->id));
    dst->name = sb_strdup(S(src->name));
    dst->agent_token = sb_strdup(S(src->agent_token));
    dst->capabilities = src->capabilities ? sbj_clone(src->capabilities) : sbj_object();
    dst->profile_id = sb_strdup(src->profile_id);
    dst->wg_address = sb_strdup(src->wg_address);
    dst->wg_public_key = sb_strdup(src->wg_public_key);
    dst->wg_endpoint = sb_strdup(src->wg_endpoint);
    dst->clash_api = sb_strdup(src->clash_api);
    dst->clash_secret = sb_strdup(S(src->clash_secret));
    dst->last_seen = sb_strdup(src->last_seen);
    dst->singbox_state = sb_strdup(src->singbox_state);
    dst->enabled = src->enabled;
    dst->created_at = sb_strdup(S(src->created_at));
    dst->updated_at = sb_strdup(S(src->updated_at));
    dst->assigned_outbounds = src->assigned_outbounds;
}
sbj *sb_host_to_json(const sb_host *h) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(h->id));
    sbj_set_str(v, "name", S(h->name));
    sbj_set(v, "capabilities", h->capabilities ? sbj_clone(h->capabilities) : sbj_null());
    sbj_set(v, "profile_id", opt_str(h->profile_id));
    sbj_set(v, "wg_address", opt_str(h->wg_address));
    sbj_set(v, "wg_public_key", opt_str(h->wg_public_key));
    sbj_set(v, "wg_endpoint", opt_str(h->wg_endpoint));
    sbj_set(v, "clash_api", opt_str(h->clash_api));
    sbj_set(v, "last_seen", opt_str(h->last_seen));
    sbj_set(v, "singbox_state", opt_str(h->singbox_state));
    sbj_set_bool(v, "enabled", h->enabled);
    sbj_set_str(v, "created_at", S(h->created_at));
    sbj_set_str(v, "updated_at", S(h->updated_at));
    sbj_set(v, "assigned_outbounds", sbj_uint(h->assigned_outbounds));
    sbj_set_bool(v, "has_token", !sb_str_empty(h->agent_token));
    return v;
}
DEFINE_VEC(sb_host)

/* ---- host command ---- */
void sb_host_command_init(sb_host_command *c) {
    memset(c, 0, sizeof *c);
    c->id = sb_strdup("");
    c->host_id = sb_strdup("");
    c->command = sb_strdup("");
    c->status = sb_strdup("");
    c->created_at = sb_strdup("");
}
void sb_host_command_free(sb_host_command *c) {
    free(c->id);
    free(c->host_id);
    free(c->command);
    free(c->status);
    free(c->result);
    free(c->created_at);
    free(c->acked_at);
    memset(c, 0, sizeof *c);
}
sbj *sb_host_command_to_json(const sb_host_command *c) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(c->id));
    sbj_set_str(v, "host_id", S(c->host_id));
    sbj_set_str(v, "command", S(c->command));
    sbj_set_str(v, "status", S(c->status));
    sbj_set(v, "result", opt_str(c->result));
    sbj_set_str(v, "created_at", S(c->created_at));
    sbj_set(v, "acked_at", opt_str(c->acked_at));
    return v;
}
DEFINE_VEC(sb_host_command)

/* ---- enrollment ---- */
void sb_agent_enrollment_init(sb_agent_enrollment *e) {
    e->id = sb_strdup("");
    e->host_id = sb_strdup("");
    e->code = sb_strdup("");
    e->expires_at = sb_strdup("");
}
void sb_agent_enrollment_free(sb_agent_enrollment *e) {
    free(e->id);
    free(e->host_id);
    free(e->code);
    free(e->expires_at);
    memset(e, 0, sizeof *e);
}
sbj *sb_agent_enrollment_to_json(const sb_agent_enrollment *e) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(e->id));
    sbj_set_str(v, "host_id", S(e->host_id));
    sbj_set_str(v, "code", S(e->code));
    sbj_set_str(v, "expires_at", S(e->expires_at));
    return v;
}
void sb_agent_enrollment_result_init(sb_agent_enrollment_result *r) {
    r->host_id = sb_strdup("");
    r->host_name = sb_strdup("");
    r->agent_token = sb_strdup("");
    r->profile_id = sb_strdup("");
    r->profile_name = sb_strdup("");
}
void sb_agent_enrollment_result_free(sb_agent_enrollment_result *r) {
    free(r->host_id);
    free(r->host_name);
    free(r->agent_token);
    free(r->profile_id);
    free(r->profile_name);
    memset(r, 0, sizeof *r);
}
sbj *sb_agent_enrollment_result_to_json(const sb_agent_enrollment_result *r) {
    sbj *v = sbj_object();
    sbj_set_str(v, "host_id", S(r->host_id));
    sbj_set_str(v, "host_name", S(r->host_name));
    sbj_set_str(v, "agent_token", S(r->agent_token));
    sbj_set_str(v, "profile_id", S(r->profile_id));
    sbj_set_str(v, "profile_name", S(r->profile_name));
    return v;
}

/* ---- proxy record ---- */
void sb_proxy_record_init(sb_proxy_record *r) {
    memset(r, 0, sizeof *r);
    r->id = sb_strdup("");
    r->tag = sb_strdup("");
    r->node_type = sb_strdup("");
    r->enabled = true;
    r->server = sb_strdup("");
    r->protocol_config = sbj_object();
    r->fingerprint = sb_strdup("");
    r->created_at = sb_strdup("");
    r->updated_at = sb_strdup("");
}
void sb_proxy_record_free(sb_proxy_record *r) {
    free(r->id);
    free(r->tag);
    free(r->node_type);
    free(r->server);
    sbj_free(r->protocol_config);
    free(r->subscription_id);
    free(r->fingerprint);
    free(r->last_latency_test);
    free(r->created_at);
    free(r->updated_at);
    memset(r, 0, sizeof *r);
}
void sb_proxy_record_copy(sb_proxy_record *dst, const sb_proxy_record *src) {
    sb_proxy_record_free(dst);
    dst->id = sb_strdup(S(src->id));
    dst->tag = sb_strdup(S(src->tag));
    dst->node_type = sb_strdup(S(src->node_type));
    dst->enabled = src->enabled;
    dst->server = sb_strdup(S(src->server));
    dst->server_port = src->server_port;
    dst->protocol_config = src->protocol_config ? sbj_clone(src->protocol_config) : sbj_object();
    dst->subscription_id = sb_strdup(src->subscription_id);
    dst->fingerprint = sb_strdup(S(src->fingerprint));
    dst->has_latency = src->has_latency;
    dst->latency = src->latency;
    dst->last_latency_test = sb_strdup(src->last_latency_test);
    dst->created_at = sb_strdup(S(src->created_at));
    dst->updated_at = sb_strdup(S(src->updated_at));
}
sbj *sb_proxy_record_to_json(const sb_proxy_record *r) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(r->id));
    sbj_set_str(v, "tag", S(r->tag));
    sbj_set_str(v, "node_type", S(r->node_type));
    sbj_set_bool(v, "enabled", r->enabled);
    sbj_set_str(v, "server", S(r->server));
    sbj_set(v, "server_port", sbj_uint(r->server_port));
    sbj_set(v, "protocol_config", sbj_str_take(sbj_dump(r->protocol_config, -1)));
    sbj_set(v, "subscription_id", opt_str(r->subscription_id));
    sbj_set_str(v, "fingerprint", S(r->fingerprint));
    sbj_set(v, "latency", r->has_latency ? sbj_float(r->latency) : sbj_null());
    sbj_set(v, "last_latency_test", opt_str(r->last_latency_test));
    sbj_set_str(v, "created_at", S(r->created_at));
    sbj_set_str(v, "updated_at", S(r->updated_at));
    return v;
}
DEFINE_VEC(sb_proxy_record)

/* ---- subscription ---- */
void sb_subscription_init(sb_subscription *s) {
    memset(s, 0, sizeof *s);
    s->id = sb_strdup("");
    s->name = sb_strdup("");
    s->url = sb_strdup("");
    s->enabled = true;
    s->refresh_interval = 3600;
    s->created_at = sb_strdup("");
    s->updated_at = sb_strdup("");
}
void sb_subscription_free(sb_subscription *s) {
    free(s->id);
    free(s->name);
    free(s->url);
    free(s->last_fetched_at);
    free(s->last_fetch_result);
    free(s->created_at);
    free(s->updated_at);
    memset(s, 0, sizeof *s);
}
void sb_subscription_copy(sb_subscription *dst, const sb_subscription *src) {
    sb_subscription_free(dst);
    dst->id = sb_strdup(S(src->id));
    dst->name = sb_strdup(S(src->name));
    dst->url = sb_strdup(S(src->url));
    dst->enabled = src->enabled;
    dst->refresh_interval = src->refresh_interval;
    dst->last_fetched_at = sb_strdup(src->last_fetched_at);
    dst->last_fetch_result = sb_strdup(src->last_fetch_result);
    dst->created_at = sb_strdup(S(src->created_at));
    dst->updated_at = sb_strdup(S(src->updated_at));
}
sbj *sb_subscription_to_json(const sb_subscription *s) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(s->id));
    sbj_set_str(v, "name", S(s->name));
    sbj_set_str(v, "url", S(s->url));
    sbj_set_bool(v, "enabled", s->enabled);
    sbj_set_int(v, "refresh_interval", s->refresh_interval);
    sbj_set(v, "last_fetched_at", opt_str(s->last_fetched_at));
    sbj_set(v, "last_fetch_result", opt_str(s->last_fetch_result));
    sbj_set_str(v, "created_at", S(s->created_at));
    sbj_set_str(v, "updated_at", S(s->updated_at));
    return v;
}
DEFINE_VEC(sb_subscription)

static sbj *strvec_to_json(const sb_strvec *v) {
    sbj *a = sbj_array();
    for (size_t i = 0; i < v->len; ++i) sbj_arr_push(a, sbj_str(v->items[i]));
    return a;
}

void sb_proxy_upsert_result_init(sb_proxy_upsert_result *r) { memset(r, 0, sizeof *r); }
void sb_proxy_upsert_result_free(sb_proxy_upsert_result *r) {
    sb_strvec_free(&r->errors);
    memset(r, 0, sizeof *r);
}
sbj *sb_proxy_upsert_result_to_json(const sb_proxy_upsert_result *r) {
    sbj *v = sbj_object();
    sbj_set(v, "added", sbj_uint(r->added));
    sbj_set(v, "updated", sbj_uint(r->updated));
    sbj_set(v, "errors", strvec_to_json(&r->errors));
    return v;
}
void sb_subscription_fetch_result_init(sb_subscription_fetch_result *r) { memset(r, 0, sizeof *r); }
void sb_subscription_fetch_result_free(sb_subscription_fetch_result *r) {
    sb_strvec_free(&r->errors);
    memset(r, 0, sizeof *r);
}
sbj *sb_subscription_fetch_result_to_json(const sb_subscription_fetch_result *r) {
    sbj *v = sbj_object();
    sbj_set(v, "added", sbj_uint(r->added));
    sbj_set(v, "updated", sbj_uint(r->updated));
    sbj_set(v, "skipped", sbj_uint(r->skipped));
    sbj_set(v, "found", sbj_uint(r->found));
    sbj_set(v, "errors", strvec_to_json(&r->errors));
    return v;
}

/* ======================================================================
 * row readers / helpers
 * ====================================================================== */

static sb_profile_mode parse_profile_mode(const char *value) {
    return sb_streq(value, "full") ? SB_PROFILE_FULL : SB_PROFILE_MANAGED;
}

/* parse_object(): the text must be a JSON object. */
static sbj *parse_object(const char *text, const char *description, sb_err *err) {
    sbj *parsed = sbj_parse(text, strlen(text), NULL, 0);
    if (!sbj_is_object(parsed)) {
        sbj_free(parsed);
        sb_fail(err, SB_ERR_GENERIC, "%s must contain a JSON object", description);
        return NULL;
    }
    return parsed;
}

static sbj *parse_object_or_empty(const char *text) {
    sbj *parsed = sbj_parse(text, strlen(text), NULL, 0);
    if (!sbj_is_object(parsed)) {
        sbj_free(parsed);
        return sbj_object();
    }
    return parsed;
}

static sbj *parse_object_col(sqlite3_stmt *st, int col, const char *description, sb_err *err) {
    char *text = sbq_text(st, col);
    sbj *v = parse_object(text, description, err);
    free(text);
    return v;
}

static void read_user(sqlite3_stmt *st, sb_user_account *u) {
    sb_user_account_free(u);
    u->id = sbq_text(st, 0);
    u->username = sbq_text(st, 1);
    u->username_len = (size_t)sqlite3_column_bytes(st, 1);
    u->password_hash = sbq_text(st, 2);
    u->role = sbq_text(st, 3);
    u->created_at = sbq_text(st, 4);
}

static int read_profile(sqlite3_stmt *st, sb_config_profile *p, sb_err *err) {
    sbj *profile = parse_object_col(st, 2, "profile template", err);
    if (!profile) return -1;
    sb_config_profile_free(p);
    p->id = sbq_text(st, 0);
    p->name = sbq_text(st, 1);
    p->profile = profile;
    char *mode = sbq_text(st, 3);
    p->mode = parse_profile_mode(mode);
    free(mode);
    p->rule_script = sbq_text(st, 4);
    p->rule_script_enabled = sbq_int(st, 5) != 0;
    p->created_at = sbq_text(st, 6);
    p->updated_at = sbq_text(st, 7);
    return 0;
}

static void read_host(sqlite3_stmt *st, sb_host *h) {
    sb_host_free(h);
    h->id = sbq_text(st, 0);
    h->name = sbq_text(st, 1);
    h->agent_token = sbq_text(st, 2);
    char *caps = sbq_text(st, 3);
    h->capabilities = parse_object_or_empty(caps);
    free(caps);
    h->profile_id = sbq_opt_text(st, 4);
    h->wg_address = sbq_opt_text(st, 5);
    h->wg_public_key = sbq_opt_text(st, 6);
    h->wg_endpoint = sbq_opt_text(st, 7);
    h->clash_api = sbq_opt_text(st, 8);
    h->clash_secret = sbq_text(st, 9);
    h->last_seen = sbq_opt_text(st, 10);
    h->singbox_state = sbq_opt_text(st, 11);
    h->enabled = sbq_int(st, 12) != 0;
    h->created_at = sbq_text(st, 13);
    h->updated_at = sbq_text(st, 14);
    h->assigned_outbounds = (size_t)sbq_int(st, 15);
}

static void read_host_command(sqlite3_stmt *st, sb_host_command *c) {
    sb_host_command_free(c);
    c->id = sbq_text(st, 0);
    c->host_id = sbq_text(st, 1);
    c->command = sbq_text(st, 2);
    c->status = sbq_text(st, 3);
    c->result = sbq_opt_text(st, 4);
    c->created_at = sbq_text(st, 5);
    c->acked_at = sbq_opt_text(st, 6);
}

static void read_wireguard_peer(sqlite3_stmt *st, sb_wireguard_peer *p) {
    sb_wireguard_peer_free(p);
    p->id = sbq_text(st, 0);
    p->name = sbq_text(st, 1);
    p->private_key = sbq_text(st, 2);
    p->public_key = sbq_text(st, 3);
    p->preshared_key = sbq_opt_text(st, 4);
    p->address = sbq_text(st, 5);
    p->dns = sbq_text(st, 6);
    p->enabled = sbq_int(st, 7) != 0;
    p->persistent_keepalive = (int32_t)sbq_int(st, 8);
    p->allowed_ips = sbq_text(st, 9);
    p->expire_at = sbq_opt_text(st, 10);
    p->quota_bytes = sbq_int(st, 11);
    p->created_at = sbq_text(st, 12);
    p->updated_at = sbq_text(st, 13);
    p->notes = sbq_opt_text(st, 14);
    p->host_id = sbq_opt_text(st, 15);
}

static int read_proxy_record(sqlite3_stmt *st, sb_proxy_record *r, sb_err *err) {
    int64_t raw_port = sbq_int(st, 5);
    if (raw_port <= 0 || raw_port > 65535) {
        char *id = sbq_text(st, 0);
        sb_fail(err, SB_ERR_GENERIC, "proxy server_port is out of range for node %s", id);
        free(id);
        return -1;
    }
    sbj *config = parse_object_col(st, 6, "proxy protocol_config", err);
    if (!config) return -1;
    sb_proxy_record_free(r);
    r->id = sbq_text(st, 0);
    r->tag = sbq_text(st, 1);
    r->node_type = sbq_text(st, 2);
    r->enabled = sbq_int(st, 3) != 0;
    r->server = sbq_text(st, 4);
    r->server_port = (uint16_t)raw_port;
    r->protocol_config = config;
    r->subscription_id = sbq_opt_text(st, 7);
    r->fingerprint = sbq_text(st, 8);
    r->has_latency = sqlite3_column_type(st, 9) != SQLITE_NULL;
    r->latency = r->has_latency ? sqlite3_column_double(st, 9) : 0.0;
    r->last_latency_test = sbq_opt_text(st, 10);
    r->created_at = sbq_text(st, 11);
    r->updated_at = sbq_text(st, 12);
    return 0;
}

static void read_subscription(sqlite3_stmt *st, sb_subscription *s) {
    sb_subscription_free(s);
    s->id = sbq_text(st, 0);
    s->name = sbq_text(st, 1);
    s->url = sbq_text(st, 2);
    s->enabled = sbq_int(st, 3) != 0;
    s->refresh_interval = sbq_int(st, 4);
    s->last_fetched_at = sbq_opt_text(st, 5);
    s->last_fetch_result = sbq_opt_text(st, 6);
    s->created_at = sbq_text(st, 7);
    s->updated_at = sbq_text(st, 8);
}

static bool supported_proxy_type(const char *type) {
    static const char *const supported[] = {"shadowsocks", "vmess",     "vless", "trojan",
                                            "hysteria2",   "tuic",      "http"};
    for (size_t i = 0; i < sizeof supported / sizeof *supported; ++i)
        if (sb_streq(type, supported[i])) return true;
    return false;
}

static int validate_proxy(const char *tag, const char *node_type, const char *server,
                          uint16_t port, const sbj *config, sb_err *err) {
    if (sb_str_empty(tag) || sb_str_empty(server) || port == 0U || !sbj_is_object(config))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Proxy tag, server, port, and object protocol_config are required");
    if (!supported_proxy_type(S(node_type)))
        return sb_fail(err, SB_ERR_VALIDATION, "Unsupported proxy type: %s", S(node_type));
    return 0;
}

static char *new_agent_token(void) {
    char *first = sb_uuid_v4(), *second = sb_uuid_v4();
    sb_buf b = {0};
    for (const char *p = first; *p; ++p)
        if (*p != '-') sb_buf_putc(&b, *p);
    for (const char *p = second; *p; ++p)
        if (*p != '-') sb_buf_putc(&b, *p);
    free(first);
    free(second);
    return sb_buf_detach(&b);
}

#define HOST_SELECT                                                                    \
    "\nSELECT h.id, h.name, h.agent_token, h.capabilities, h.profile_id,\n"            \
    "       h.wg_address, h.wg_public_key, h.wg_endpoint, h.clash_api,\n"              \
    "       h.clash_secret, h.last_seen, h.singbox_state, h.enabled,\n"                \
    "       h.created_at, h.updated_at,\n"                                             \
    "       (SELECT COUNT(*) FROM host_outbounds o WHERE o.host_id = h.id)\n"          \
    "FROM hosts h\n"

#define WIREGUARD_PEER_SELECT                                                          \
    "\nSELECT id, name, private_key, public_key, preshared_key, address, dns,\n"       \
    "       enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes,\n"     \
    "       created_at, updated_at, notes, host_id\n"                                  \
    "FROM wireguard_peers\n"

#define PROFILE_SELECT                                                                 \
    "SELECT id, name, template, mode, rule_script, "                                   \
    "rule_script_enabled, created_at, updated_at "

#define PROXY_SELECT                                                                   \
    "SELECT id, tag, node_type, enabled, server, server_port, "                        \
    "protocol_config, subscription_id, fingerprint, latency, "                         \
    "last_latency_test, created_at, updated_at "

#define SUBSCRIPTION_SELECT                                                            \
    "SELECT id, name, url, enabled, refresh_interval, last_fetched_at, "               \
    "last_fetch_result, created_at, updated_at "

#define COMMAND_SELECT "SELECT id, host_id, command, status, result, created_at, acked_at "

static char *controller_address(const char *address) {
    if (sb_str_empty(address)) return sb_strdup("0.0.0.0:9090");
    const char *v = address;
    if (sb_starts_with(v, "https://"))
        v += 8;
    else if (sb_starts_with(v, "http://"))
        v += 7;
    size_t n = strlen(v);
    while (n > 0 && v[n - 1] == '/') --n;
    return sb_strndup(v, n);
}

static int read_nodes(sqlite3 *db, const char *sql, const char *host_id, sb_proxy_node_vec *out,
                      sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, sql, err);
    if (!st) return -1;
    if (host_id) sbq_bind_text(st, 1, host_id);
    int r;
    while ((r = sbq_step_row(st, err)) == 1) {
        int64_t server_port = sbq_int(st, 5);
        if (server_port < 0 || server_port > 65535) {
            char *id = sbq_text(st, 0);
            sb_fail(err, SB_ERR_GENERIC, "proxy server_port is out of range for node %s", id);
            free(id);
            r = -1;
            break;
        }
        sbj *config = parse_object_col(st, 6, "proxy protocol_config", err);
        if (!config) {
            r = -1;
            break;
        }
        sb_proxy_node *n = sb_proxy_node_vec_push(out);
        free(n->id);
        n->id = sbq_text(st, 0);
        free(n->tag);
        n->tag = sbq_text(st, 1);
        free(n->type);
        n->type = sbq_text(st, 2);
        n->enabled = sbq_int(st, 3) != 0;
        free(n->server);
        n->server = sbq_text(st, 4);
        n->server_port = (uint16_t)server_port;
        sbj_free(n->protocol_config);
        n->protocol_config = config;
    }
    sqlite3_finalize(st);
    return r < 0 ? -1 : 0;
}

/* Runs a prepared statement that expects no row and finalises it. */
static int exec_stmt(sqlite3_stmt *st, sb_err *err) {
    int r = sbq_step_done(st, err);
    sqlite3_finalize(st);
    return r;
}

/* SELECT 1 FROM hosts WHERE id = ?1 -> 1 exists, 0 missing, -1 error */
static int host_exists(sqlite3 *db, const char *host_id, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, "SELECT 1 FROM hosts WHERE id = ?1", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, S(host_id));
    int r = sbq_step_row(st, err);
    sqlite3_finalize(st);
    return r;
}

/* ---- nlohmann emulation ------------------------------------------------
 * The C++ store reads backup/report members with json::value() and writes JSON
 * columns with json::dump(); both throw json::exception, which the HTTP layer
 * answers with 400 "Invalid JSON request: <what>". These helpers reproduce the
 * same conditions and what() texts, reported as SB_ERR_BAD_JSON. */
static int type_error(sb_err *err, const char *want, const sbj *got) {
    return sb_fail(err, SB_ERR_BAD_JSON, "[json.exception.type_error.302] type must be %s, but is %s",
                   want, sbj_type_name(got));
}
/* value(key, default) for strings; *out is borrowed. */
static int jv_str(const sbj *obj, const char *key, const char *def, const char **out, sb_err *err) {
    const sbj *v = sbj_get(obj, key);
    if (!v) {
        *out = def;
        return 0;
    }
    if (!sbj_is_string(v)) return type_error(err, "string", v);
    *out = v->v.str.ptr;
    return 0;
}
static int jv_bool(const sbj *obj, const char *key, bool def, bool *out, sb_err *err) {
    const sbj *v = sbj_get(obj, key);
    if (!v) {
        *out = def;
        return 0;
    }
    if (!sbj_is_bool(v)) return type_error(err, "boolean", v);
    *out = v->v.b;
    return 0;
}
/* static_cast<std::int64_t>(double) as compiled for x86-64 (cvttsd2si): NaN and
 * out-of-range values become INT64_MIN instead of being undefined. */
static int64_t float_to_int64(double f) {
    if (!(f >= -9223372036854775808.0 && f < 9223372036854775808.0)) return INT64_MIN;
    return (int64_t)f;
}
/* value<std::int64_t>(key, default): nlohmann's get<std::int64_t> converts any
 * number but rejects everything else, booleans included. */
static int jv_int(const sbj *obj, const char *key, int64_t def, int64_t *out, sb_err *err) {
    const sbj *v = sbj_get(obj, key);
    if (!v) {
        *out = def;
        return 0;
    }
    switch (v->type) {
    case SBJ_INT: *out = v->v.i; return 0;
    case SBJ_UINT: *out = (int64_t)v->v.u; return 0;
    case SBJ_FLOAT: *out = float_to_int64(v->v.f); return 0;
    default: return type_error(err, "number", v);
    }
}
/* contains(key) && is_string() ? value : nullopt  (borrowed) */
static const char *jv_opt_str(const sbj *obj, const char *key) {
    const sbj *v = sbj_get(obj, key);
    return sbj_is_string(v) ? v->v.str.ptr : NULL;
}

/* json::dump(); NULL (err set) where nlohmann would throw. */
static char *dump_checked(const sbj *value, sb_err *err) {
    if (sbj_validate_utf8(value, err) != 0) return NULL;
    return sbj_dump(value, -1);
}

static const char *const settings_upsert_sql =
    "INSERT INTO app_settings (key, value, updated_at) "
    "VALUES (?1, ?2, datetime('now')) "
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
    "updated_at = datetime('now')";

/* Binds json::dump() of value; -1 (err set) where nlohmann would throw. */
static int bind_dump(sqlite3_stmt *st, int i, const sbj *value, sb_err *err) {
    char *text = dump_checked(value, err);
    if (!text) return -1;
    sbq_bind_text(st, i, text);
    free(text);
    return 0;
}

/* exec_stmt() unless an earlier bind failed (bound != 0): then only finalise. */
static int exec_bound(sqlite3_stmt *st, int bound, sb_err *err) {
    if (bound != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    return exec_stmt(st, err);
}

/* ParsedProxyNode::fingerprint(): its key material is read with json::value(),
 * which throws for present-but-non-string members (sb_parsed_node_fingerprint
 * silently uses ""). Returns the malloc'd fingerprint or NULL (err set). */
static char *fingerprint_of(const char *node_type, const char *tag, const char *server,
                            uint16_t port, const sbj *config, sb_err *err) {
    const char *t = S(node_type), *first = NULL, *second = NULL, *ignored;
    if (sb_streq(t, "shadowsocks") || sb_streq(t, "trojan") || sb_streq(t, "hysteria2")) {
        first = "password";
    } else if (sb_streq(t, "vmess") || sb_streq(t, "vless")) {
        first = "uuid";
    } else if (sb_streq(t, "tuic")) {
        first = "uuid";
        second = "password";
    } else if (sb_streq(t, "http")) {
        first = "username";
        second = "password";
    }
    if ((first && jv_str(config, first, "", &ignored, err) != 0) ||
        (second && jv_str(config, second, "", &ignored, err) != 0))
        return NULL;
    sb_parsed_node n;
    n.node_type = (char *)t;
    n.tag = (char *)S(tag);
    n.server = (char *)S(server);
    n.server_port = port;
    n.protocol_config = (sbj *)config;
    return sb_parsed_node_fingerprint(&n);
}

/* ---- list results ----------------------------------------------------
 * Rows are collected in a local vector and appended to *out only on success,
 * so a failed call leaves *out untouched. */
#define VEC_APPEND_MOVE(dst, src)                                                      \
    do {                                                                               \
        if ((dst)->len + (src)->len > (dst)->cap) {                                    \
            (dst)->cap = (dst)->len + (src)->len;                                      \
            (dst)->items = sb_xrealloc((dst)->items, (dst)->cap * sizeof *(dst)->items); \
        }                                                                              \
        if ((src)->len)                                                                \
            memcpy((dst)->items + (dst)->len, (src)->items, (src)->len * sizeof *(src)->items); \
        (dst)->len += (src)->len;                                                      \
        free((src)->items);                                                            \
        memset((src), 0, sizeof *(src));                                               \
    } while (0)

#define FINISH_LIST(free_fn, out, rows, r)                                             \
    do {                                                                               \
        if ((r) < 0) {                                                                 \
            free_fn(&(rows));                                                          \
            return -1;                                                                 \
        }                                                                              \
        VEC_APPEND_MOVE((out), &(rows));                                               \
        return 0;                                                                      \
    } while (0)

/* ======================================================================
 * store: lifecycle, users, audit, settings
 * ====================================================================== */

sb_store *sb_store_open(const char *db_path, const char *migrations_dir, sb_err *err) {
    sb_database *db = sb_database_open(db_path, err);
    if (!db) return NULL;
    if (sb_database_migrate(db, migrations_dir, err) != 0) {
        sb_database_free(db);
        return NULL;
    }
    sb_store *s = sb_xcalloc(1, sizeof *s);
    s->db = db;
    return s;
}

void sb_store_free(sb_store *s) {
    if (!s) return;
    sb_database_free(s->db);
    free(s);
}

sb_database *sb_store_database(sb_store *s) { return s->db; }

static int find_user_locked(sqlite3 *h, const char *username, size_t username_len, sb_user_account *out, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(h,
                                   "SELECT id, username, password_hash, role, created_at "
                                   "FROM users WHERE username = ?1 LIMIT 1",
                                   err);
    if (!st) return -1;
    int r = sbq_bind_text_n(st, 1, S(username), username_len, err);
    if (r == 0) r = sbq_step_row(st, err);
    if (r == 1) read_user(st, out);
    sqlite3_finalize(st);
    return r;
}

int sb_store_ensure_default_admin(sb_store *s, const char *password, sb_err *err) {
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), "SELECT COUNT(*) FROM users", err);
    int r = st ? sbq_step_row(st, err) : -1;
    int64_t count = r == 1 ? sbq_int(st, 0) : 0;
    sqlite3_finalize(st);
    UNLOCK(s);
    if (r < 0) return -1;
    if (r == 1 && count != 0) return 0;
    char *hash = sb_hash_password(password, err);
    if (!hash) return -1;
    sb_user_account created;
    sb_user_account_init(&created);
    int rc = sb_store_create_user(s, "admin", hash, "admin", &created, err);
    sb_user_account_free(&created);
    free(hash);
    return rc;
}

int sb_store_list_users(sb_store *s, sb_user_account_vec *out, sb_err *err) {
    sb_user_account_vec rows = {0};
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s),
                                   "SELECT id, username, password_hash, role, created_at "
                                   "FROM users ORDER BY created_at",
                                   err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1) read_user(st, sb_user_account_vec_push(&rows));
    sqlite3_finalize(st);
    UNLOCK(s);
    FINISH_LIST(sb_user_account_vec_free, out, rows, r);
}

int sb_store_find_user_by_username(sb_store *s, const char *username, sb_user_account *out,
                                   sb_err *err) {
    return sb_store_find_user_by_username_n(s, username, strlen(S(username)), out, err);
}

int sb_store_find_user_by_username_n(sb_store *s, const char *username, size_t username_len,
                                    sb_user_account *out, sb_err *err) {
    LOCK(s);
    int r = find_user_locked(H(s), username, username ? username_len : 0, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_user(sb_store *s, const char *username, const char *password_hash,
                         const char *role, sb_user_account *out, sb_err *err) {
    return sb_store_create_user_n(s, username, strlen(S(username)), password_hash, role, out, err);
}

int sb_store_create_user_n(sb_store *s, const char *username, size_t username_len,
                           const char *password_hash, const char *role,
                           sb_user_account *out, sb_err *err) {
    if (!username || username_len == 0 || sb_str_empty(password_hash) ||
        (!sb_streq(role, "admin") && !sb_streq(role, "viewer")))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid user");
    char *id = sb_uuid_v4();
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h, "SELECT 1 FROM users WHERE username = ?1", err);
    if (!st) goto done;
    int r = sbq_bind_text_n(st, 1, username, username_len, err);
    if (r == 0) r = sbq_step_row(st, err);
    sqlite3_finalize(st);
    if (r < 0) goto done;
    if (r == 1) {
        sb_fail(err, SB_ERR_CONFLICT, "Username already exists");
        goto done;
    }
    st = sbq_prepare(h,
                     "INSERT INTO users (id, username, password_hash, role) "
                     "VALUES (?1, ?2, ?3, ?4)",
                     err);
    if (!st) goto done;
    sbq_bind_text(st, 1, id);
    if (sbq_bind_text_n(st, 2, username, username_len, err) != 0) {
        sqlite3_finalize(st);
        goto done;
    }
    sbq_bind_text(st, 3, password_hash);
    sbq_bind_text(st, 4, role);
    if (exec_stmt(st, err) != 0) goto done;
    r = find_user_locked(h, username, username_len, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "created user could not be reloaded");
    rc = r == 1 ? 0 : -1;
done:
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_delete_user(sb_store *s, const char *actor_id, const char *user_id, sb_err *err) {
    if (sb_streq(S(actor_id), S(user_id)))
        return sb_fail(err, SB_ERR_VALIDATION, "You cannot delete your own account");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h, "SELECT role FROM users WHERE id = ?1", err);
    if (!st) goto done;
    sbq_bind_text(st, 1, S(user_id));
    int r = sbq_step_row(st, err);
    bool is_admin = r == 1 && sb_streq((const char *)sqlite3_column_text(st, 0), "admin");
    sqlite3_finalize(st);
    if (r < 0) goto done;
    if (r == 0) {
        rc = 0;
        goto done;
    }
    if (is_admin) {
        st = sbq_prepare(h, "SELECT COUNT(*) FROM users WHERE role = 'admin'", err);
        if (!st) goto done;
        r = sbq_step_row(st, err);
        int64_t count = r == 1 ? sbq_int(st, 0) : 0;
        sqlite3_finalize(st);
        if (r < 0) goto done;
        if (r == 1 && count <= 1) {
            sb_fail(err, SB_ERR_VALIDATION, "Cannot delete the last admin");
            goto done;
        }
    }
    st = sbq_prepare(h, "DELETE FROM users WHERE id = ?1", err);
    if (!st) goto done;
    sbq_bind_text(st, 1, S(user_id));
    rc = exec_stmt(st, err);
done:
    UNLOCK(s);
    return rc;
}

/* Executes a single-statement UPDATE/DELETE with text binds; fails with
 * SB_ERR_NOT_FOUND + not_found message when no row changed (unless NULL). */
static int exec_changes(sb_store *s, const char *sql, const char *not_found, sb_err *err,
                        int nbinds, const char *const *binds) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    sqlite3_stmt *st = sbq_prepare(h, sql, err);
    if (st) {
        for (int i = 0; i < nbinds; ++i) sbq_bind_text(st, i + 1, binds[i]);
        rc = exec_stmt(st, err);
        if (rc == 0 && not_found && sqlite3_changes(h) == 0)
            rc = sb_fail(err, SB_ERR_NOT_FOUND, "%s", not_found);
    }
    UNLOCK(s);
    return rc;
}

int sb_store_reset_user_password(sb_store *s, const char *user_id, const char *password_hash,
                                 sb_err *err) {
    const char *binds[] = {S(password_hash), S(user_id)};
    return exec_changes(s, "UPDATE users SET password_hash = ?1 WHERE id = ?2", "User not found",
                        err, 2, binds);
}

int sb_store_record_audit(sb_store *s, const char *actor, const char *action, const char *target,
                          sb_err *err) {
    return sb_store_record_audit_n(s, actor, strlen(S(actor)), action, target, err);
}

int sb_store_record_audit_n(sb_store *s, const char *actor, size_t actor_len,
                            const char *action, const char *target, sb_err *err) {
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s),
        "INSERT INTO audit_log (actor, action, target) VALUES (?1, ?2, ?3)", err);
    int rc = -1;
    if (st) {
        int bound = sbq_bind_text_n(st, 1, S(actor), actor ? actor_len : 0, err);
        sbq_bind_text(st, 2, S(action));
        sbq_bind_text(st, 3, target);
        rc = exec_bound(st, bound, err);
    }
    UNLOCK(s);
    return rc;
}

int sb_store_list_audit(sb_store *s, size_t limit, sb_audit_entry_vec *out, sb_err *err) {
    sb_audit_entry_vec rows = {0};
    size_t bounded = limit < 1 ? 1 : limit > 1000 ? 1000 : limit;
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s),
                                   "SELECT id, ts, actor, action, target FROM audit_log "
                                   "ORDER BY id DESC LIMIT ?1",
                                   err);
    int r = st ? 0 : -1;
    if (st) sbq_bind_int(st, 1, (int64_t)bounded);
    while (st && (r = sbq_step_row(st, err)) == 1) {
        sb_audit_entry *e = sb_audit_entry_vec_push(&rows);
        sb_audit_entry_free(e);
        e->id = sbq_int(st, 0);
        e->timestamp = sbq_text(st, 1);
        e->actor = sbq_text(st, 2);
        e->actor_len = (size_t)sqlite3_column_bytes(st, 2);
        e->action = sbq_text(st, 3);
        e->target = sbq_opt_text(st, 4);
    }
    sqlite3_finalize(st);
    UNLOCK(s);
    FINISH_LIST(sb_audit_entry_vec_free, out, rows, r);
}

sbj *sb_store_app_settings(sb_store *s, sb_err *err) {
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), "SELECT key, value FROM app_settings", err);
    sbj *settings = st ? sbj_object() : NULL;
    int r = 0;
    while (st && (r = sbq_step_row(st, err)) == 1) {
        const char *text = (const char *)sqlite3_column_text(st, 1);
        sbj *value = text ? sbj_parse(text, (size_t)sqlite3_column_bytes(st, 1), NULL, 0) : NULL;
        const char *key = (const char *)sqlite3_column_text(st, 0);
        if (value) sbj_set(settings, key ? key : "", value);
    }
    sqlite3_finalize(st);
    UNLOCK(s);
    if (r < 0) {
        sbj_free(settings);
        return NULL;
    }
    return settings;
}

int sb_store_update_app_settings(sb_store *s, const sbj *sections, sb_err *err) {
    if (!sbj_is_object(sections)) return sb_fail(err, SB_ERR_VALIDATION, "settings must be a JSON object");
    static const char *const allowed[] = {"wireguard_interface", "singbox_connection", "general"};
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    for (size_t i = 0; rc == 0 && i < 3; ++i) {
        const sbj *found = sbj_get(sections, allowed[i]);
        if (!found) continue;
        sqlite3_stmt *st = sbq_prepare(h, settings_upsert_sql, err);
        if (!st) {
            rc = -1;
            break;
        }
        sbq_bind_text(st, 1, allowed[i]);
        int bound = bind_dump(st, 2, found, err);
        rc = exec_bound(st, bound, err);
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

int sb_store_app_setting(sb_store *s, const char *key, sbj **out, sb_err *err) {
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), "SELECT value FROM app_settings WHERE key = ?1", err);
    int r = -1;
    if (st) {
        sbq_bind_text(st, 1, S(key));
        r = sbq_step_row(st, err);
        if (r == 1) {
            const char *text = (const char *)sqlite3_column_text(st, 0);
            sbj *value = text ? sbj_parse(text, (size_t)sqlite3_column_bytes(st, 0), NULL, 0) : NULL;
            if (value)
                *out = value;
            else
                r = 0;
        }
    }
    sqlite3_finalize(st);
    UNLOCK(s);
    return r;
}

int sb_store_set_app_setting(sb_store *s, const char *key, const sbj *value, sb_err *err) {
    if (sb_str_empty(key)) return sb_fail(err, SB_ERR_VALIDATION, "setting key is required");
    char *text = dump_checked(value, err);
    if (!text) return -1;
    const char *binds[] = {key, text};
    int rc = exec_changes(s, settings_upsert_sql, NULL, err, 2, binds);
    free(text);
    return rc;
}

/* ======================================================================
 * WireGuard, one-time links, backup
 * ====================================================================== */

static int find_peer_locked(sqlite3 *h, const char *id, sb_wireguard_peer *out, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(h, WIREGUARD_PEER_SELECT " WHERE id = ?1", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, S(id));
    int r = sbq_step_row(st, err);
    if (r == 1) read_wireguard_peer(st, out);
    sqlite3_finalize(st);
    return r;
}

int sb_store_list_wireguard_peers(sb_store *s, sb_wireguard_peer_vec *out, sb_err *err) {
    sb_wireguard_peer_vec rows = {0};
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), WIREGUARD_PEER_SELECT " ORDER BY address", err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1)
        read_wireguard_peer(st, sb_wireguard_peer_vec_push(&rows));
    sqlite3_finalize(st);
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
    if (sb_str_empty(peer->name) || sb_str_empty(peer->private_key) ||
        sb_str_empty(peer->public_key) || sb_str_empty(peer->address))
        return sb_fail(err, SB_ERR_VALIDATION, "WireGuard name, keys, and address are required");
    if (peer->persistent_keepalive < 0 || peer->persistent_keepalive > 65535 || peer->quota_bytes < 0)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard keepalive or quota");
    char *id = sb_str_empty(peer->id) ? sb_uuid_v4() : sb_strdup(peer->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h, "SELECT 1 FROM wireguard_peers WHERE address = ?1", err);
    if (!st) goto done;
    sbq_bind_text(st, 1, peer->address);
    int r = sbq_step_row(st, err);
    sqlite3_finalize(st);
    if (r < 0) goto done;
    if (r == 1) {
        sb_fail(err, SB_ERR_CONFLICT, "WireGuard address already exists");
        goto done;
    }
    st = sbq_prepare(h,
                     "INSERT INTO wireguard_peers "
                     "(id, name, private_key, public_key, preshared_key, address, dns, "
                     "enabled, persistent_keepalive, allowed_ips, expire_at, quota_bytes, "
                     "created_at, updated_at, notes, host_id) "
                     "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                     "datetime('now'), datetime('now'), ?13, ?14)",
                     err);
    if (!st) goto done;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, peer->name);
    sbq_bind_text(st, 3, peer->private_key);
    sbq_bind_text(st, 4, peer->public_key);
    sbq_bind_text(st, 5, peer->preshared_key);
    sbq_bind_text(st, 6, peer->address);
    sbq_bind_text(st, 7, S(peer->dns));
    sbq_bind_bool(st, 8, peer->enabled);
    sbq_bind_int(st, 9, peer->persistent_keepalive);
    sbq_bind_text(st, 10, S(peer->allowed_ips));
    sbq_bind_text(st, 11, peer->expire_at);
    sbq_bind_int(st, 12, peer->quota_bytes);
    sbq_bind_text(st, 13, peer->notes);
    sbq_bind_text(st, 14, peer->host_id);
    if (exec_stmt(st, err) != 0) goto done;
    rc = reload_peer(h, id, out, err);
done:
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_update_wireguard_peer(sb_store *s, const sb_wireguard_peer *peer,
                                   sb_wireguard_peer *out, sb_err *err) {
    if (sb_str_empty(peer->id) || sb_str_empty(peer->name) || peer->persistent_keepalive < 0 ||
        peer->persistent_keepalive > 65535 || peer->quota_bytes < 0)
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid WireGuard peer");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE wireguard_peers SET name = ?1, enabled = ?2, dns = ?3, "
                                   "persistent_keepalive = ?4, allowed_ips = ?5, expire_at = ?6, "
                                   "quota_bytes = ?7, updated_at = datetime('now'), notes = ?8, "
                                   "host_id = ?9 WHERE id = ?10",
                                   err);
    if (!st) goto done;
    sbq_bind_text(st, 1, peer->name);
    sbq_bind_bool(st, 2, peer->enabled);
    sbq_bind_text(st, 3, S(peer->dns));
    sbq_bind_int(st, 4, peer->persistent_keepalive);
    sbq_bind_text(st, 5, S(peer->allowed_ips));
    sbq_bind_text(st, 6, peer->expire_at);
    sbq_bind_int(st, 7, peer->quota_bytes);
    sbq_bind_text(st, 8, peer->notes);
    sbq_bind_text(st, 9, peer->host_id);
    sbq_bind_text(st, 10, peer->id);
    if (exec_stmt(st, err) != 0) goto done;
    if (sqlite3_changes(h) == 0) {
        sb_fail(err, SB_ERR_NOT_FOUND, "Peer not found");
        goto done;
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
    sqlite3_stmt *st = sbq_prepare(H(s), "SELECT address FROM wireguard_peers", err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1) {
        char *address = sbq_text(st, 0);
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
    sqlite3_finalize(st);
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
    if (!*id || !*url) return 0;
    if (jv_str(value, "name", "", &name, err) || jv_bool(value, "enabled", true, &enabled, err) ||
        jv_int(value, "refresh_interval", 3600, &refresh, err) ||
        jv_str(value, "created_at", "", &created_at, err))
        return -1;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT OR REPLACE INTO subscriptions "
                                   "(id, name, url, enabled, refresh_interval, last_fetched_at, "
                                   "last_fetch_result, created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, "
                                   "COALESCE(NULLIF(?8, ''), datetime('now')), datetime('now'))",
                                   err);
    if (!st) return -1;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, name);
    sbq_bind_text(st, 3, url);
    sbq_bind_bool(st, 4, enabled);
    sbq_bind_int(st, 5, refresh);
    sbq_bind_text(st, 6, jv_opt_str(value, "last_fetched_at"));
    sbq_bind_text(st, 7, jv_opt_str(value, "last_fetch_result"));
    sbq_bind_text(st, 8, created_at);
    if (exec_stmt(st, err) != 0) return -1;
    ++*count;
    return 0;
}

static int restore_node(sqlite3 *h, const sbj *value, size_t *count, sb_err *err) {
    const char *id, *tag, *node_type, *server, *fingerprint, *created_at;
    bool enabled = false;
    int64_t port;
    if (jv_str(value, "id", "", &id, err) || jv_str(value, "tag", "", &tag, err)) return -1;
    if (!*id || !*tag) return 0;
    const sbj *protocol = sbj_get(value, "protocol_config");
    char *protocol_text = !protocol                 ? sb_strdup("{}")
                          : sbj_is_string(protocol) ? sb_strdup(protocol->v.str.ptr)
                                                    : dump_checked(protocol, err);
    if (!protocol_text) return -1;
    int rc = -1;
    sqlite3_stmt *st = NULL;
    if (jv_str(value, "node_type", "", &node_type, err) ||
        jv_bool(value, "enabled", true, &enabled, err) ||
        jv_str(value, "server", "", &server, err) || jv_int(value, "server_port", 0, &port, err) ||
        jv_str(value, "fingerprint", "", &fingerprint, err) ||
        jv_str(value, "created_at", "", &created_at, err))
        goto done;
    st = sbq_prepare(h,
                     "INSERT OR REPLACE INTO proxy_nodes "
                     "(id, tag, node_type, enabled, server, server_port, "
                     "protocol_config, subscription_id, fingerprint, latency, "
                     "last_latency_test, created_at, updated_at) "
                     "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
                     "COALESCE(NULLIF(?12, ''), datetime('now')), datetime('now'))",
                     err);
    if (!st) goto done;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, tag);
    sbq_bind_text(st, 3, node_type);
    sbq_bind_bool(st, 4, enabled);
    sbq_bind_text(st, 5, server);
    sbq_bind_int(st, 6, port);
    sbq_bind_text(st, 7, protocol_text);
    sbq_bind_text(st, 8, jv_opt_str(value, "subscription_id"));
    sbq_bind_text(st, 9, fingerprint);
    const sbj *latency = sbj_get(value, "latency");
    double latency_value = sbj_as_double(latency, 0.0);
    sbq_bind_opt_double(st, 10, sbj_is_number(latency) ? &latency_value : NULL);
    sbq_bind_text(st, 11, jv_opt_str(value, "last_latency_test"));
    sbq_bind_text(st, 12, created_at);
    rc = exec_stmt(st, err);
    if (rc == 0) ++*count;
done:
    free(protocol_text);
    return rc;
}

static int restore_peer(sqlite3 *h, const sbj *value, size_t *count, sb_err *err) {
    const char *id, *address, *name, *private_key, *public_key, *dns, *allowed_ips, *created_at;
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
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT OR REPLACE INTO wireguard_peers "
                                   "(id, name, private_key, public_key, preshared_key, address, dns, "
                                   "enabled, persistent_keepalive, allowed_ips, expire_at, "
                                   "quota_bytes, created_at, updated_at, notes, host_id) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                                   "COALESCE(NULLIF(?13, ''), datetime('now')), datetime('now'), "
                                   "?14, ?15)",
                                   err);
    if (!st) return -1;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, name);
    sbq_bind_text(st, 3, private_key);
    sbq_bind_text(st, 4, public_key);
    sbq_bind_text(st, 5, jv_opt_str(value, "preshared_key"));
    sbq_bind_text(st, 6, address);
    sbq_bind_text(st, 7, dns);
    sbq_bind_bool(st, 8, enabled);
    sbq_bind_int(st, 9, keepalive);
    sbq_bind_text(st, 10, allowed_ips);
    sbq_bind_text(st, 11, jv_opt_str(value, "expire_at"));
    sbq_bind_int(st, 12, quota);
    sbq_bind_text(st, 13, created_at);
    sbq_bind_text(st, 14, jv_opt_str(value, "notes"));
    sbq_bind_text(st, 15, jv_opt_str(value, "host_id"));
    if (exec_stmt(st, err) != 0) return -1;
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

/* ======================================================================
 * profiles
 * ====================================================================== */

static int find_profile_locked(sqlite3 *h, const char *id, sb_config_profile *out, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(h, PROFILE_SELECT "FROM config_profiles WHERE id = ?1", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, S(id));
    int r = sbq_step_row(st, err);
    if (r == 1 && read_profile(st, out, err) != 0) r = -1;
    sqlite3_finalize(st);
    return r;
}

static int reload_profile(sqlite3 *h, const char *id, sb_config_profile *out, sb_err *err) {
    int r = find_profile_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "profile could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_profiles(sb_store *s, sb_config_profile_vec *out, sb_err *err) {
    sb_config_profile_vec rows = {0};
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), PROFILE_SELECT "FROM config_profiles ORDER BY name", err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1) {
        sb_config_profile p;
        sb_config_profile_init(&p);
        if (read_profile(st, &p, err) != 0) {
            sb_config_profile_free(&p);
            r = -1;
            break;
        }
        sb_config_profile *slot = sb_config_profile_vec_push(&rows);
        sb_config_profile_free(slot);
        *slot = p;
    }
    sqlite3_finalize(st);
    UNLOCK(s);
    FINISH_LIST(sb_config_profile_vec_free, out, rows, r);
}

int sb_store_find_profile(sb_store *s, const char *id, sb_config_profile *out, sb_err *err) {
    LOCK(s);
    int r = find_profile_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_profile(sb_store *s, const sb_config_profile *profile, sb_config_profile *out,
                            sb_err *err) {
    if (sb_str_empty(profile->name) || !sbj_is_object(profile->profile))
        return sb_fail(err, SB_ERR_VALIDATION, "Profile name and object template are required");
    char *id = sb_str_empty(profile->id) ? sb_uuid_v4() : sb_strdup(profile->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO config_profiles "
                                   "(id, name, template, mode, rule_script, "
                                   "rule_script_enabled, created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, "
                                   "datetime('now'), datetime('now'))",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, id);
        sbq_bind_text(st, 2, profile->name);
        int bound = bind_dump(st, 3, profile->profile, err);
        sbq_bind_text(st, 4, sb_profile_mode_name(profile->mode));
        sbq_bind_text(st, 5, S(profile->rule_script));
        sbq_bind_bool(st, 6, profile->rule_script_enabled);
        if (exec_bound(st, bound, err) == 0) rc = reload_profile(h, id, out, err);
    }
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_update_profile(sb_store *s, const sb_config_profile *profile, sb_config_profile *out,
                            sb_err *err) {
    if (sb_str_empty(profile->id) || sb_str_empty(profile->name) || !sbj_is_object(profile->profile))
        return sb_fail(err, SB_ERR_VALIDATION, "Profile id, name, and object template are required");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE config_profiles SET name = ?1, template = ?2, "
                                   "mode = ?3, rule_script = ?4, rule_script_enabled = ?5, "
                                   "updated_at = datetime('now') WHERE id = ?6",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, profile->name);
        int bound = bind_dump(st, 2, profile->profile, err);
        sbq_bind_text(st, 3, sb_profile_mode_name(profile->mode));
        sbq_bind_text(st, 4, S(profile->rule_script));
        sbq_bind_bool(st, 5, profile->rule_script_enabled);
        sbq_bind_text(st, 6, profile->id);
        if (exec_bound(st, bound, err) == 0) {
            if (sqlite3_changes(h) == 0)
                sb_fail(err, SB_ERR_NOT_FOUND, "Profile not found");
            else
                rc = reload_profile(h, profile->id, out, err);
        }
    }
    UNLOCK(s);
    return rc;
}

int sb_store_delete_profile(sb_store *s, const char *id, sb_err *err) {
    if (sb_streq(id, "default")) return sb_fail(err, SB_ERR_VALIDATION, "Cannot delete the default profile");
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE hosts SET profile_id = 'default', updated_at = datetime('now') "
                                       "WHERE profile_id = ?1",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM config_profiles WHERE id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Profile not found");
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

/* ======================================================================
 * hosts
 * ====================================================================== */

static int find_host_locked(sqlite3 *h, const char *id, sb_host *out, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(h, HOST_SELECT " WHERE h.id = ?1", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, S(id));
    int r = sbq_step_row(st, err);
    if (r == 1) read_host(st, out);
    sqlite3_finalize(st);
    return r;
}

static int reload_host(sqlite3 *h, const char *id, sb_host *out, sb_err *err) {
    int r = find_host_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "host could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_hosts(sb_store *s, sb_host_vec *out, sb_err *err) {
    sb_host_vec rows = {0};
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), HOST_SELECT " ORDER BY h.created_at", err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1) read_host(st, sb_host_vec_push(&rows));
    sqlite3_finalize(st);
    UNLOCK(s);
    FINISH_LIST(sb_host_vec_free, out, rows, r);
}

int sb_store_find_host(sb_store *s, const char *id, sb_host *out, sb_err *err) {
    LOCK(s);
    int r = find_host_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_host(sb_store *s, const sb_host *host, sb_host *out, sb_err *err) {
    if (sb_str_empty(host->name) || !sbj_is_object(host->capabilities))
        return sb_fail(err, SB_ERR_VALIDATION, "Host name and object capabilities are required");
    char *id = sb_str_empty(host->id) ? sb_uuid_v4() : sb_strdup(host->id);
    char *token = sb_str_empty(host->agent_token) ? new_agent_token() : sb_strdup(host->agent_token);
    const char *profile_id = host->profile_id ? host->profile_id : "default";
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO hosts "
                                   "(id, name, agent_token, capabilities, profile_id, wg_address, "
                                   "wg_public_key, wg_endpoint, clash_api, clash_secret, last_seen, "
                                   "singbox_state, enabled, created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, "
                                   "?13, datetime('now'), datetime('now'))",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, id);
        sbq_bind_text(st, 2, host->name);
        sbq_bind_text(st, 3, token);
        int bound = bind_dump(st, 4, host->capabilities, err);
        sbq_bind_text(st, 5, profile_id);
        sbq_bind_text(st, 6, host->wg_address);
        sbq_bind_text(st, 7, host->wg_public_key);
        sbq_bind_text(st, 8, host->wg_endpoint);
        sbq_bind_text(st, 9, host->clash_api);
        sbq_bind_text(st, 10, S(host->clash_secret));
        sbq_bind_text(st, 11, host->last_seen);
        sbq_bind_text(st, 12, host->singbox_state);
        sbq_bind_bool(st, 13, host->enabled);
        if (exec_bound(st, bound, err) == 0) rc = reload_host(h, id, out, err);
    }
    UNLOCK(s);
    free(id);
    free(token);
    return rc;
}

int sb_store_update_host(sb_store *s, const sb_host *host, sb_host *out, sb_err *err) {
    if (sb_str_empty(host->id) || sb_str_empty(host->name) || !sbj_is_object(host->capabilities))
        return sb_fail(err, SB_ERR_VALIDATION, "Host id, name, and object capabilities are required");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE hosts SET name = ?1, capabilities = ?2, profile_id = ?3, "
                                   "wg_address = ?4, wg_public_key = ?5, wg_endpoint = ?6, "
                                   "clash_api = ?7, clash_secret = ?8, enabled = ?9, "
                                   "updated_at = datetime('now') WHERE id = ?10",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, host->name);
        int bound = bind_dump(st, 2, host->capabilities, err);
        sbq_bind_text(st, 3, host->profile_id);
        sbq_bind_text(st, 4, host->wg_address);
        sbq_bind_text(st, 5, host->wg_public_key);
        sbq_bind_text(st, 6, host->wg_endpoint);
        sbq_bind_text(st, 7, host->clash_api);
        sbq_bind_text(st, 8, S(host->clash_secret));
        sbq_bind_bool(st, 9, host->enabled);
        sbq_bind_text(st, 10, host->id);
        if (exec_bound(st, bound, err) == 0) {
            if (sqlite3_changes(h) == 0)
                sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
            else
                rc = reload_host(h, host->id, out, err);
        }
    }
    UNLOCK(s);
    return rc;
}

int sb_store_delete_host(sb_store *s, const char *id, sb_err *err) {
    if (sb_streq(id, "self")) return sb_fail(err, SB_ERR_VALIDATION, "Cannot delete the built-in self host");
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM host_outbounds WHERE host_id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM hosts WHERE id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(id)), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) == 0) rc = sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    return rc;
}

char *sb_store_save_diagnostic_report(sb_store *s, const char *host_id, const sbj *report,
                                      sb_err *err) {
    if (!sbj_is_object(report)) {
        sb_fail(err, SB_ERR_VALIDATION, "Diagnostic report must be a JSON object");
        return NULL;
    }
    const char *reason, *app_version, *core_version;
    if (jv_str(report, "reason", "manual", &reason, err) ||
        jv_str(report, "app_version", "", &app_version, err) ||
        jv_str(report, "core_version", "", &core_version, err))
        return NULL;
    char *id = sb_uuid_v4();
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        int r = host_exists(h, host_id, err);
        if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "INSERT INTO diagnostic_reports "
                                       "(id, host_id, reason, app_version, core_version, payload, created_at) "
                                       "VALUES (?1, ?2, ?3, ?4, ?5, ?6, "
                                       "strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                                       err);
        if (st) {
            sbq_bind_text(st, 1, id);
            sbq_bind_text(st, 2, S(host_id));
            sbq_bind_text(st, 3, reason);
            sbq_bind_text(st, 4, app_version);
            sbq_bind_text(st, 5, core_version);
            int bound = bind_dump(st, 6, report, err);
            rc = exec_bound(st, bound, err);
        } else {
            rc = -1;
        }
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "DELETE FROM diagnostic_reports WHERE host_id = ?1 AND id NOT IN "
                                       "(SELECT id FROM diagnostic_reports WHERE host_id = ?1 "
                                       "ORDER BY created_at DESC, rowid DESC LIMIT 20)",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, S(host_id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    if (rc != 0) {
        free(id);
        return NULL;
    }
    return id;
}

sbj *sb_store_list_diagnostic_reports(sb_store *s, const char *host_id, size_t limit, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    sbj *reports = NULL;
    int r = host_exists(h, host_id, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "SELECT id, reason, app_version, core_version, payload, created_at "
                                   "FROM diagnostic_reports WHERE host_id = ?1 "
                                   "ORDER BY created_at DESC, rowid DESC LIMIT ?2",
                                   err);
    if (!st) goto done;
    sbq_bind_text(st, 1, S(host_id));
    sbq_bind_int(st, 2, (int64_t)(limit < 20U ? limit : 20U));
    reports = sbj_array();
    while ((r = sbq_step_row(st, err)) == 1) {
        char *payload = sbq_text(st, 4);
        sbj *report = sbj_parse(payload, strlen(payload), NULL, 0);
        free(payload);
        if (!sbj_is_object(report)) {
            sbj_free(report);
            report = sbj_object();
            sbj_set(report, "logs", sbj_array());
        }
        sbj_set(report, "report_id", sbj_str_take(sbq_text(st, 0)));
        sbj_set(report, "reason", sbj_str_take(sbq_text(st, 1)));
        sbj_set(report, "app_version", sbj_str_take(sbq_text(st, 2)));
        sbj_set(report, "core_version", sbj_str_take(sbq_text(st, 3)));
        sbj_set(report, "created_at", sbj_str_take(sbq_text(st, 5)));
        sbj_arr_push(reports, report);
    }
    sqlite3_finalize(st);
    if (r < 0) {
        sbj_free(reports);
        reports = NULL;
    }
done:
    UNLOCK(s);
    return reports;
}

int sb_store_host_outbounds(sb_store *s, const char *host_id, sb_strvec *out, sb_err *err) {
    sb_strvec rows = {0};
    LOCK(s);
    sqlite3 *h = H(s);
    int r = host_exists(h, host_id, err);
    if (r == 0) r = sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r == 1) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "SELECT node_id FROM host_outbounds WHERE host_id = ?1 "
                                       "ORDER BY node_id",
                                       err);
        r = st ? 0 : -1;
        if (st) sbq_bind_text(st, 1, S(host_id));
        while (st && (r = sbq_step_row(st, err)) == 1) sb_strvec_push_take(&rows, sbq_text(st, 0));
        sqlite3_finalize(st);
    }
    UNLOCK(s);
    FINISH_LIST(sb_strvec_free, out, rows, r);
}

int sb_store_set_host_outbounds(sb_store *s, const char *host_id, const sb_strvec *node_ids,
                                sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    int r = host_exists(h, host_id, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;
    rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "DELETE FROM host_outbounds WHERE host_id = ?1", err);
        rc = st ? (sbq_bind_text(st, 1, S(host_id)), exec_stmt(st, err)) : -1;
    }
    for (size_t i = 0; rc == 0 && node_ids && i < node_ids->len; ++i) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "INSERT OR IGNORE INTO host_outbounds (host_id, node_id) "
                                       "VALUES (?1, ?2)",
                                       err);
        if (!st) {
            rc = -1;
            break;
        }
        sbq_bind_text(st, 1, S(host_id));
        sbq_bind_text(st, 2, node_ids->items[i]);
        rc = exec_stmt(st, err);
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
done:
    UNLOCK(s);
    return rc;
}

char *sb_store_rotate_agent_token(sb_store *s, const char *host_id, sb_err *err) {
    char *token = new_agent_token();
    const char *binds[] = {token, S(host_id)};
    if (exec_changes(s,
                     "UPDATE hosts SET agent_token = ?1, updated_at = datetime('now') "
                     "WHERE id = ?2",
                     "Host not found", err, 2, binds) != 0) {
        free(token);
        return NULL;
    }
    return token;
}

int sb_store_create_agent_enrollment(sb_store *s, const char *host_id, sb_agent_enrollment *out,
                                     sb_err *err) {
    sb_host host;
    sb_host_init(&host);
    int found = sb_store_find_host(s, host_id, &host, err);
    bool usable = found == 1 && !sb_streq(host.id, "self") && host.enabled;
    sb_host_free(&host);
    if (found < 0) return -1;
    if (found == 0) return sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (!usable) return sb_fail(err, SB_ERR_VALIDATION, "Enrollment requires an enabled remote host");

    char *id = sb_uuid_v4();
    char *code = new_agent_token();
    char *code_hash = sb_sha256_hex(code, strlen(code));
    char *expires_at = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE agent_enrollments SET expires_at = datetime('now') "
                                       "WHERE host_id = ?1 AND redeemed_at IS NULL",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, S(host_id)), exec_stmt(st, err)) : -1;
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "INSERT INTO agent_enrollments "
                                       "(id, host_id, code_hash, expires_at) "
                                       "VALUES (?1, ?2, ?3, datetime('now', '+10 minutes'))",
                                       err);
        if (st) {
            sbq_bind_text(st, 1, id);
            sbq_bind_text(st, 2, S(host_id));
            sbq_bind_text(st, 3, code_hash);
            rc = exec_stmt(st, err);
        } else {
            rc = -1;
        }
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h, "SELECT expires_at FROM agent_enrollments WHERE id = ?1", err);
        int r = -1;
        if (st) {
            sbq_bind_text(st, 1, id);
            r = sbq_step_row(st, err);
            if (r == 1) expires_at = sbq_text(st, 0);
            if (r == 0) sb_fail(err, SB_ERR_GENERIC, "Created enrollment could not be read");
        }
        sqlite3_finalize(st);
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    free(code_hash);
    if (rc != 0) {
        free(id);
        free(code);
        free(expires_at);
        return -1;
    }
    sb_agent_enrollment_free(out);
    out->id = id;
    out->host_id = sb_strdup(S(host_id));
    out->code = code;
    out->expires_at = expires_at;
    return 0;
}

int sb_store_redeem_agent_enrollment(sb_store *s, const char *code, const sbj *device,
                                     sb_agent_enrollment_result *out, sb_err *err) {
    if (strlen(S(code)) < 32U || !sbj_is_object(device))
        return sb_fail(err, SB_ERR_VALIDATION, "A valid enrollment code and device are required");
    char *code_hash = sb_sha256_hex(code, strlen(code));
    sb_agent_enrollment_result result;
    sb_agent_enrollment_result_init(&result);
    char *enrollment_id = NULL;
    sbj *capabilities = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = sbq_begin(h, err);
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "SELECT e.id, h.id, h.name, h.agent_token, "
                                       "COALESCE(h.profile_id, 'default'), p.name, h.capabilities "
                                       "FROM agent_enrollments e "
                                       "JOIN hosts h ON h.id = e.host_id "
                                       "JOIN config_profiles p ON p.id = COALESCE(h.profile_id, 'default') "
                                       "WHERE e.code_hash = ?1 AND e.redeemed_at IS NULL "
                                       "AND e.expires_at > datetime('now') AND h.enabled = 1",
                                       err);
        int r = -1;
        if (st) {
            sbq_bind_text(st, 1, code_hash);
            r = sbq_step_row(st, err);
            if (r == 0) sb_fail(err, SB_ERR_VALIDATION, "Enrollment code is invalid or expired");
            if (r == 1) {
                sb_agent_enrollment_result_free(&result);
                enrollment_id = sbq_text(st, 0);
                result.host_id = sbq_text(st, 1);
                result.host_name = sbq_text(st, 2);
                result.agent_token = sbq_text(st, 3);
                result.profile_id = sbq_text(st, 4);
                result.profile_name = sbq_text(st, 5);
                char *caps = sbq_text(st, 6);
                capabilities = parse_object_or_empty(caps);
                free(caps);
            }
        }
        sqlite3_finalize(st);
        rc = r == 1 ? 0 : -1;
    }
    if (rc == 0) {
        /* Enrollment is shared by every managed device. The enrolling runtime may
         * describe its platform and build, but the server must never infer a
         * device kind from the transport used to redeem the code. */
        static const char *const keys[] = {"platform", "app_version", "agent_version",
                                           "core_version", "install_id", "model",
                                           "hostname", "architecture", "os"};
        for (size_t i = 0; i < sizeof keys / sizeof *keys; ++i) {
            const sbj *found = sbj_get(device, keys[i]);
            if (sbj_is_string(found) && found->v.str.len > 0)
                sbj_set(capabilities, keys[i], sbj_clone(found));
        }
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE agent_enrollments SET redeemed_at = datetime('now') "
                                       "WHERE id = ?1 AND redeemed_at IS NULL",
                                       err);
        rc = st ? (sbq_bind_text(st, 1, enrollment_id), exec_stmt(st, err)) : -1;
        if (rc == 0 && sqlite3_changes(h) != 1)
            rc = sb_fail(err, SB_ERR_CONFLICT, "Enrollment code was already redeemed");
    }
    if (rc == 0) {
        sqlite3_stmt *st = sbq_prepare(h,
                                       "UPDATE hosts SET capabilities = ?1, last_seen = datetime('now'), "
                                       "updated_at = datetime('now') WHERE id = ?2",
                                       err);
        if (st) {
            int bound = bind_dump(st, 1, capabilities, err);
            sbq_bind_text(st, 2, result.host_id);
            rc = exec_bound(st, bound, err);
        } else {
            rc = -1;
        }
    }
    if (rc == 0) rc = sbq_commit(h, err);
    if (rc != 0) sbq_rollback(h);
    UNLOCK(s);
    free(code_hash);
    free(enrollment_id);
    sbj_free(capabilities);
    if (rc != 0) {
        sb_agent_enrollment_result_free(&result);
        return -1;
    }
    sb_agent_enrollment_result_free(out);
    *out = result;
    return 0;
}

int sb_store_find_enabled_host_by_token(sb_store *s, const char *token, sb_host *out, sb_err *err) {
    if (sb_str_empty(token)) return 0;
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s),
                                   HOST_SELECT " WHERE h.agent_token = ?1 "
                                               "AND h.agent_token != '' AND h.enabled = 1",
                                   err);
    int r = -1;
    if (st) {
        sbq_bind_text(st, 1, token);
        r = sbq_step_row(st, err);
        if (r == 1) read_host(st, out);
    }
    sqlite3_finalize(st);
    UNLOCK(s);
    return r;
}

int sb_store_touch_host(sb_store *s, const char *host_id, sb_err *err) {
    const char *binds[] = {S(host_id)};
    return exec_changes(s, "UPDATE hosts SET last_seen = datetime('now') WHERE id = ?1",
                        "Host not found", err, 1, binds);
}

int sb_store_update_agent_status(sb_store *s, const char *host_id, const sbj *state, sb_err *err) {
    if (!sbj_is_object(state)) return sb_fail(err, SB_ERR_VALIDATION, "Agent state must be a JSON object");
    char *text = dump_checked(state, err);
    if (!text) return -1;
    const char *binds[] = {text, S(host_id)};
    int rc = exec_changes(s,
                          "UPDATE hosts SET last_seen = datetime('now'), singbox_state = ?1 "
                          "WHERE id = ?2",
                          "Host not found", err, 2, binds);
    free(text);
    return rc;
}

/* ======================================================================
 * host commands, latency
 * ====================================================================== */

int sb_store_enqueue_host_command(sb_store *s, const char *host_id, const char *command,
                                  sb_host_command *out, sb_err *err) {
    if (sb_str_empty(command)) return sb_fail(err, SB_ERR_VALIDATION, "Command is required");
    char *id = sb_uuid_v4();
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    int r = host_exists(h, host_id, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO host_commands "
                                   "(id, host_id, command, status, created_at) "
                                   "VALUES (?1, ?2, ?3, 'pending', datetime('now'))",
                                   err);
    if (!st) goto done;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, S(host_id));
    sbq_bind_text(st, 3, command);
    if (exec_stmt(st, err) != 0) goto done;
    st = sbq_prepare(h, COMMAND_SELECT "FROM host_commands WHERE id = ?1", err);
    if (!st) goto done;
    sbq_bind_text(st, 1, id);
    r = sbq_step_row(st, err);
    if (r == 1) read_host_command(st, out);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "created host command could not be reloaded");
    sqlite3_finalize(st);
    rc = r == 1 ? 0 : -1;
done:
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_list_host_commands(sb_store *s, const char *host_id, bool pending_only,
                                sb_host_command_vec *out, sb_err *err) {
    sb_host_command_vec rows = {0};
    LOCK(s);
    sqlite3 *h = H(s);
    int r = host_exists(h, host_id, err);
    if (r == 0) r = sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r == 1) {
        const char *sql = pending_only
                              ? COMMAND_SELECT "FROM host_commands WHERE host_id = ?1 AND status = 'pending' "
                                               "ORDER BY created_at"
                              : COMMAND_SELECT "FROM host_commands WHERE host_id = ?1 "
                                               "ORDER BY created_at DESC LIMIT 20";
        sqlite3_stmt *st = sbq_prepare(h, sql, err);
        r = st ? 0 : -1;
        if (st) sbq_bind_text(st, 1, S(host_id));
        while (st && (r = sbq_step_row(st, err)) == 1) read_host_command(st, sb_host_command_vec_push(&rows));
        sqlite3_finalize(st);
    }
    UNLOCK(s);
    FINISH_LIST(sb_host_command_vec_free, out, rows, r);
}

int sb_store_acknowledge_host_command(sb_store *s, const char *host_id, const char *command_id,
                                      const char *status, const char *result, sb_err *err) {
    LOCK(s);
    sqlite3 *h = H(s);
    int rc = -1;
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE host_commands SET status = ?1, result = ?2, "
                                   "acked_at = datetime('now') WHERE id = ?3 AND host_id = ?4",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, S(status));
        sbq_bind_text(st, 2, result);
        sbq_bind_text(st, 3, S(command_id));
        sbq_bind_text(st, 4, S(host_id));
        if (exec_stmt(st, err) == 0) rc = sqlite3_changes(h) != 0 ? 1 : 0;
    }
    UNLOCK(s);
    return rc;
}

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
        sbq_bind_text(st, 2, tag);
        rc = exec_stmt(st, err);
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
    sqlite3_stmt *st = sbq_prepare(h, PROXY_SELECT "FROM proxy_nodes WHERE id = ?1", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, S(id));
    int r = sbq_step_row(st, err);
    if (r == 1 && read_proxy_record(st, out, err) != 0) r = -1;
    sqlite3_finalize(st);
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
    sqlite3_stmt *st = sbq_prepare(H(s), PROXY_SELECT "FROM proxy_nodes ORDER BY node_type, tag", err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1) {
        sb_proxy_record rec;
        sb_proxy_record_init(&rec);
        if (read_proxy_record(st, &rec, err) != 0) {
            sb_proxy_record_free(&rec);
            r = -1;
            break;
        }
        sb_proxy_record *slot = sb_proxy_record_vec_push(&rows);
        sb_proxy_record_free(slot);
        *slot = rec;
    }
    sqlite3_finalize(st);
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
    if (validate_proxy(node->tag, node->node_type, node->server, node->server_port,
                       node->protocol_config, err) != 0)
        return -1;
    char *fingerprint = fingerprint_of(node->node_type, node->tag, node->server, node->server_port,
                                       node->protocol_config, err);
    if (!fingerprint) return -1;
    char *id = sb_str_empty(node->id) ? sb_uuid_v4() : sb_strdup(node->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h, "SELECT 1 FROM proxy_nodes WHERE tag = ?1 OR fingerprint = ?2 LIMIT 1",
                                   err);
    if (!st) goto done;
    sbq_bind_text(st, 1, node->tag);
    sbq_bind_text(st, 2, fingerprint);
    int r = sbq_step_row(st, err);
    sqlite3_finalize(st);
    if (r < 0) goto done;
    if (r == 1) {
        sb_fail(err, SB_ERR_VALIDATION, "A proxy with the same tag or fingerprint already exists");
        goto done;
    }
    st = sbq_prepare(h,
                     "INSERT INTO proxy_nodes "
                     "(id, tag, node_type, enabled, server, server_port, protocol_config, "
                     "subscription_id, fingerprint, latency, last_latency_test, "
                     "created_at, updated_at) "
                     "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
                     "datetime('now'), datetime('now'))",
                     err);
    if (!st) goto done;
    sbq_bind_text(st, 1, id);
    sbq_bind_text(st, 2, node->tag);
    sbq_bind_text(st, 3, node->node_type);
    sbq_bind_bool(st, 4, node->enabled);
    sbq_bind_text(st, 5, node->server);
    sbq_bind_int(st, 6, node->server_port);
    int bound = bind_dump(st, 7, node->protocol_config, err);
    sbq_bind_text(st, 8, node->subscription_id);
    sbq_bind_text(st, 9, fingerprint);
    sbq_bind_opt_double(st, 10, node->has_latency ? &node->latency : NULL);
    sbq_bind_text(st, 11, node->last_latency_test);
    if (exec_bound(st, bound, err) != 0) goto done;
    rc = reload_proxy(h, id, out, err);
done:
    UNLOCK(s);
    free(id);
    free(fingerprint);
    return rc;
}

int sb_store_update_proxy_node(sb_store *s, const sb_proxy_record *node, sb_proxy_record *out,
                               sb_err *err) {
    if (validate_proxy(node->tag, node->node_type, node->server, node->server_port,
                       node->protocol_config, err) != 0)
        return -1;
    if (sb_str_empty(node->id)) return sb_fail(err, SB_ERR_VALIDATION, "Proxy id is required");
    char *fingerprint = fingerprint_of(node->node_type, node->tag, node->server, node->server_port,
                                       node->protocol_config, err);
    if (!fingerprint) return -1;
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "SELECT 1 FROM proxy_nodes WHERE id != ?1 "
                                   "AND (tag = ?2 OR fingerprint = ?3) LIMIT 1",
                                   err);
    if (!st) goto done;
    sbq_bind_text(st, 1, node->id);
    sbq_bind_text(st, 2, node->tag);
    sbq_bind_text(st, 3, fingerprint);
    int r = sbq_step_row(st, err);
    sqlite3_finalize(st);
    if (r < 0) goto done;
    if (r == 1) {
        sb_fail(err, SB_ERR_VALIDATION, "A proxy with the same tag or fingerprint already exists");
        goto done;
    }
    st = sbq_prepare(h,
                     "UPDATE proxy_nodes SET tag = ?1, node_type = ?2, enabled = ?3, "
                     "server = ?4, server_port = ?5, protocol_config = ?6, "
                     "subscription_id = ?7, fingerprint = ?8, updated_at = datetime('now') "
                     "WHERE id = ?9",
                     err);
    if (!st) goto done;
    sbq_bind_text(st, 1, node->tag);
    sbq_bind_text(st, 2, node->node_type);
    sbq_bind_bool(st, 3, node->enabled);
    sbq_bind_text(st, 4, node->server);
    sbq_bind_int(st, 5, node->server_port);
    int bound = bind_dump(st, 6, node->protocol_config, err);
    sbq_bind_text(st, 7, node->subscription_id);
    sbq_bind_text(st, 8, fingerprint);
    sbq_bind_text(st, 9, node->id);
    if (exec_bound(st, bound, err) != 0) goto done;
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

/* One node of upsert_proxy_nodes; errors are collected by the caller. */
static int upsert_one(sqlite3 *h, const sb_parsed_node *node, const char *subscription_id,
                      sb_proxy_upsert_result *result, sb_err *err) {
    if (validate_proxy(node->tag, node->node_type, node->server, node->server_port,
                       node->protocol_config, err) != 0)
        return -1;
    char *fingerprint = fingerprint_of(node->node_type, node->tag, node->server, node->server_port,
                                       node->protocol_config, err);
    if (!fingerprint) return -1;
    char *existing_id = NULL;
    int rc = -1;
    /* Two-level match: fingerprint first, then the same tag with a different
     * fingerprint (a provider rotating its server address). */
    sqlite3_stmt *st = sbq_prepare(h,
                                   "SELECT id FROM proxy_nodes WHERE fingerprint = ?1 "
                                   "UNION ALL "
                                   "SELECT id FROM proxy_nodes WHERE tag = ?2 "
                                   "AND fingerprint != ?1 LIMIT 1",
                                   err);
    if (!st) goto done;
    sbq_bind_text(st, 1, fingerprint);
    sbq_bind_text(st, 2, S(node->tag));
    int r = sbq_step_row(st, err);
    if (r == 1) existing_id = sbq_text(st, 0);
    sqlite3_finalize(st);
    if (r < 0) goto done;

    if (existing_id) {
        st = sbq_prepare(h,
                         "UPDATE proxy_nodes SET tag = ?1, node_type = ?2, "
                         "server = ?3, server_port = ?4, protocol_config = ?5, "
                         "fingerprint = ?6, subscription_id = ?7, "
                         "updated_at = datetime('now') WHERE id = ?8",
                         err);
        if (!st) goto done;
        sbq_bind_text(st, 1, S(node->tag));
        sbq_bind_text(st, 2, S(node->node_type));
        sbq_bind_text(st, 3, S(node->server));
        sbq_bind_int(st, 4, node->server_port);
        int bound = bind_dump(st, 5, node->protocol_config, err);
        sbq_bind_text(st, 6, fingerprint);
        sbq_bind_text(st, 7, subscription_id);
        sbq_bind_text(st, 8, existing_id);
        if (exec_bound(st, bound, err) != 0) goto done;
        ++result->updated;
    } else {
        st = sbq_prepare(h,
                         "INSERT INTO proxy_nodes "
                         "(id, tag, node_type, enabled, server, server_port, "
                         "protocol_config, subscription_id, fingerprint, "
                         "created_at, updated_at) "
                         "VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, "
                         "datetime('now'), datetime('now'))",
                         err);
        if (!st) goto done;
        char *id = sb_uuid_v4();
        sbq_bind_text(st, 1, id);
        free(id);
        sbq_bind_text(st, 2, S(node->tag));
        sbq_bind_text(st, 3, S(node->node_type));
        sbq_bind_text(st, 4, S(node->server));
        sbq_bind_int(st, 5, node->server_port);
        int bound = bind_dump(st, 6, node->protocol_config, err);
        sbq_bind_text(st, 7, subscription_id);
        sbq_bind_text(st, 8, fingerprint);
        if (exec_bound(st, bound, err) != 0) goto done;
        ++result->added;
    }
    rc = 0;
done:
    free(fingerprint);
    free(existing_id);
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
        sqlite3_stmt *st = sbq_prepare(h, "SELECT 1 FROM subscriptions WHERE id = ?1", err);
        int r = -1;
        if (st) {
            sbq_bind_text(st, 1, subscription_id);
            r = sbq_step_row(st, err);
        }
        sqlite3_finalize(st);
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

/* ======================================================================
 * subscriptions
 * ====================================================================== */

static int find_subscription_locked(sqlite3 *h, const char *id, sb_subscription *out, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(h, SUBSCRIPTION_SELECT "FROM subscriptions WHERE id = ?1", err);
    if (!st) return -1;
    sbq_bind_text(st, 1, S(id));
    int r = sbq_step_row(st, err);
    if (r == 1) read_subscription(st, out);
    sqlite3_finalize(st);
    return r;
}

static int reload_subscription(sqlite3 *h, const char *id, sb_subscription *out, sb_err *err) {
    int r = find_subscription_locked(h, id, out, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "subscription could not be reloaded");
    return r == 1 ? 0 : -1;
}

int sb_store_list_subscriptions(sb_store *s, sb_subscription_vec *out, sb_err *err) {
    sb_subscription_vec rows = {0};
    LOCK(s);
    sqlite3_stmt *st = sbq_prepare(H(s), SUBSCRIPTION_SELECT "FROM subscriptions ORDER BY name", err);
    int r = st ? 0 : -1;
    while (st && (r = sbq_step_row(st, err)) == 1) read_subscription(st, sb_subscription_vec_push(&rows));
    sqlite3_finalize(st);
    UNLOCK(s);
    FINISH_LIST(sb_subscription_vec_free, out, rows, r);
}

int sb_store_find_subscription(sb_store *s, const char *id, sb_subscription *out, sb_err *err) {
    LOCK(s);
    int r = find_subscription_locked(H(s), id, out, err);
    UNLOCK(s);
    return r;
}

int sb_store_create_subscription(sb_store *s, const sb_subscription *sub, sb_subscription *out,
                                 sb_err *err) {
    if (sb_str_empty(sub->name) || sb_str_empty(sub->url) || sub->refresh_interval <= 0)
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Subscription name, URL, and positive refresh interval are required");
    char *id = sb_str_empty(sub->id) ? sb_uuid_v4() : sb_strdup(sub->id);
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "INSERT INTO subscriptions "
                                   "(id, name, url, enabled, refresh_interval, last_fetched_at, "
                                   "last_fetch_result, created_at, updated_at) "
                                   "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, "
                                   "datetime('now'), datetime('now'))",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, id);
        sbq_bind_text(st, 2, sub->name);
        sbq_bind_text(st, 3, sub->url);
        sbq_bind_bool(st, 4, sub->enabled);
        sbq_bind_int(st, 5, sub->refresh_interval);
        sbq_bind_text(st, 6, sub->last_fetched_at);
        sbq_bind_text(st, 7, sub->last_fetch_result);
        if (exec_stmt(st, err) == 0) rc = reload_subscription(h, id, out, err);
    }
    UNLOCK(s);
    free(id);
    return rc;
}

int sb_store_update_subscription(sb_store *s, const sb_subscription *sub, sb_subscription *out,
                                 sb_err *err) {
    if (sb_str_empty(sub->id) || sb_str_empty(sub->name) || sb_str_empty(sub->url) ||
        sub->refresh_interval <= 0)
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Subscription id, name, URL, and positive refresh interval are required");
    int rc = -1;
    LOCK(s);
    sqlite3 *h = H(s);
    sqlite3_stmt *st = sbq_prepare(h,
                                   "UPDATE subscriptions SET name = ?1, url = ?2, enabled = ?3, "
                                   "refresh_interval = ?4, updated_at = datetime('now') WHERE id = ?5",
                                   err);
    if (st) {
        sbq_bind_text(st, 1, sub->name);
        sbq_bind_text(st, 2, sub->url);
        sbq_bind_bool(st, 3, sub->enabled);
        sbq_bind_int(st, 4, sub->refresh_interval);
        sbq_bind_text(st, 5, sub->id);
        if (exec_stmt(st, err) == 0) {
            if (sqlite3_changes(h) == 0)
                sb_fail(err, SB_ERR_NOT_FOUND, "Subscription not found");
            else
                rc = reload_subscription(h, sub->id, out, err);
        }
    }
    UNLOCK(s);
    return rc;
}

int sb_store_delete_subscription(sb_store *s, const char *id, sb_err *err) {
    const char *binds[] = {S(id)};
    return exec_changes(s, "DELETE FROM subscriptions WHERE id = ?1", "Subscription not found", err, 1,
                        binds);
}

int sb_store_record_subscription_fetch(sb_store *s, const char *id,
                                       const sb_subscription_fetch_result *result, sb_err *err) {
    sbj *metadata = sbj_object();
    sbj_set(metadata, "added", sbj_uint(result->added));
    sbj_set(metadata, "updated", sbj_uint(result->updated));
    sbj_set(metadata, "skipped", sbj_uint(result->skipped));
    sbj_set(metadata, "total", sbj_uint(result->found));
    sbj_set(metadata, "errors", strvec_to_json(&result->errors));
    char *text = dump_checked(metadata, err);
    sbj_free(metadata);
    if (!text) return -1;
    const char *binds[] = {text, S(id)};
    int rc = exec_changes(s,
                          "UPDATE subscriptions SET last_fetched_at = datetime('now'), "
                          "last_fetch_result = ?1 WHERE id = ?2",
                          "Subscription not found", err, 2, binds);
    free(text);
    return rc;
}

/* ======================================================================
 * render request
 * ====================================================================== */

int sb_store_render_request_for_host(sb_store *s, const char *host_id, sb_render_request *out,
                                     sb_err *err) {
    int rc = -1;
    sb_config_profile profile;
    sb_config_profile_init(&profile);
    sb_proxy_node_vec nodes = {0};
    char *profile_id = NULL;
    sbj *capabilities = NULL;
    sqlite3_stmt *host = NULL;
    LOCK(s);
    sqlite3 *h = H(s);
    host = sbq_prepare(h,
                       "SELECT id, name, capabilities, profile_id, clash_api, "
                       "clash_secret FROM hosts WHERE id = ?1",
                       err);
    if (!host) goto done;
    sbq_bind_text(host, 1, S(host_id));
    int r = sbq_step_row(host, err);
    if (r == 0) sb_fail(err, SB_ERR_NOT_FOUND, "Host not found");
    if (r != 1) goto done;

    profile_id = sbq_opt_text(host, 3);
    if (!profile_id) profile_id = sb_strdup("default");
    r = find_profile_locked(h, profile_id, &profile, err);
    if (r == 0) sb_fail(err, SB_ERR_GENERIC, "host profile not found: %s", profile_id);
    if (r != 1) goto done;

    if (profile.mode == SB_PROFILE_MANAGED) {
        if (read_nodes(h,
                       "SELECT p.id, p.tag, p.node_type, p.enabled, p.server, "
                       "p.server_port, p.protocol_config FROM proxy_nodes p "
                       "JOIN host_outbounds h ON h.node_id = p.id "
                       "WHERE h.host_id = ?1 AND p.enabled = 1 "
                       "ORDER BY p.node_type, p.tag",
                       S(host_id), &nodes, err) != 0)
            goto done;
        if (nodes.len == 0 &&
            read_nodes(h,
                       "SELECT id, tag, node_type, enabled, server, server_port, "
                       "protocol_config FROM proxy_nodes WHERE enabled = 1 "
                       "ORDER BY node_type, tag",
                       NULL, &nodes, err) != 0)
            goto done;
    }

    capabilities = parse_object_col(host, 2, "host capabilities", err);
    if (!capabilities) goto done;

    sb_render_request_free(out);
    sb_render_request_init(out);
    out->mode = profile.mode;
    sbj_free(out->profile);
    out->profile = profile.profile;
    profile.profile = NULL;
    out->nodes = nodes;
    memset(&nodes, 0, sizeof nodes);
    sbj_set(out->host_context, "id", sbj_str_take(sbq_text(host, 0)));
    sbj_set(out->host_context, "name", sbj_str_take(sbq_text(host, 1)));
    sbj_set(out->host_context, "capabilities", capabilities);
    capabilities = NULL;
    free(out->clash_controller);
    char *clash_api = sbq_opt_text(host, 4);
    out->clash_controller = controller_address(clash_api);
    free(clash_api);
    free(out->clash_secret);
    out->clash_secret = sbq_text(host, 5);
    if (profile.rule_script_enabled && !sb_str_empty(profile.rule_script))
        out->rule_script = sb_strdup(profile.rule_script);

    const sbj *endpoints = sbj_get(out->profile, "endpoints");
    const sbj *endpoint;
    SBJ_ARR_FOREACH(endpoints, i, endpoint) {
        const sbj *tag = sbj_get(endpoint, "tag");
        if (sbj_is_string(tag)) sb_strvec_push(&out->external_route_tags, tag->v.str.ptr);
    }
    rc = 0;
done:
    sqlite3_finalize(host);
    UNLOCK(s);
    free(profile_id);
    sbj_free(capabilities);
    sb_proxy_node_vec_free(&nodes);
    sb_config_profile_free(&profile);
    return rc;
}
