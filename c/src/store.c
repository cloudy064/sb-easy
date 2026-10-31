/* Repository facade over the sb-easy schema. Port of cpp/src/store.cpp: same
 * queries (verbatim), validation rules, error messages and JSON shapes. */
#include "sb/store.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sb/auth.h"
#include "store_internal.h"



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
    sbj_set(v, "name", sbj_strn(S(p->name), p->name_len));
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
    sbj_set(v, "notes", p->notes ? sbj_strn(p->notes, p->notes_len) : sbj_null());
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
    dst->name = sb_strndup(S(src->name), src->name_len);
    dst->name_len = src->name_len;
    dst->profile = src->profile ? sbj_clone(src->profile) : sbj_object();
    dst->mode = src->mode;
    dst->rule_script = sb_strndup(S(src->rule_script), src->rule_script_len);
    dst->rule_script_len = src->rule_script_len;
    dst->rule_script_enabled = src->rule_script_enabled;
    dst->created_at = sb_strdup(S(src->created_at));
    dst->updated_at = sb_strdup(S(src->updated_at));
}
sbj *sb_config_profile_to_json(const sb_config_profile *p) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(p->id));
    sbj_set(v, "name", sbj_strn(S(p->name), p->name_len));
    sbj_set(v, "template", sbj_str_take(sbj_dump(p->profile, -1)));
    sbj_set_str(v, "mode", sb_profile_mode_name(p->mode));
    sbj_set(v, "rule_script", sbj_strn(S(p->rule_script), p->rule_script_len));
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
    dst->name = sb_strndup(S(src->name), src->name_len);
    dst->name_len = src->name_len;
    dst->agent_token = sb_strdup(S(src->agent_token));
    dst->capabilities = src->capabilities ? sbj_clone(src->capabilities) : sbj_object();
    dst->profile_id = sb_strndup(src->profile_id, src->profile_id_len);
    dst->profile_id_len = src->profile_id_len;
    dst->wg_address = sb_strndup(src->wg_address, src->wg_address_len);
    dst->wg_address_len = src->wg_address_len;
    dst->wg_public_key = sb_strndup(src->wg_public_key, src->wg_public_key_len);
    dst->wg_public_key_len = src->wg_public_key_len;
    dst->wg_endpoint = sb_strndup(src->wg_endpoint, src->wg_endpoint_len);
    dst->wg_endpoint_len = src->wg_endpoint_len;
    dst->clash_api = sb_strndup(src->clash_api, src->clash_api_len);
    dst->clash_api_len = src->clash_api_len;
    dst->clash_secret = sb_strndup(S(src->clash_secret), src->clash_secret_len);
    dst->clash_secret_len = src->clash_secret_len;
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
    sbj_set(v, "name", sbj_strn(S(h->name), h->name_len));
    sbj_set(v, "capabilities", h->capabilities ? sbj_clone(h->capabilities) : sbj_null());
    sbj_set(v, "profile_id", h->profile_id ? sbj_strn(h->profile_id, h->profile_id_len) : sbj_null());
    sbj_set(v, "wg_address", h->wg_address ? sbj_strn(h->wg_address, h->wg_address_len) : sbj_null());
    sbj_set(v, "wg_public_key", h->wg_public_key ? sbj_strn(h->wg_public_key, h->wg_public_key_len) : sbj_null());
    sbj_set(v, "wg_endpoint", h->wg_endpoint ? sbj_strn(h->wg_endpoint, h->wg_endpoint_len) : sbj_null());
    sbj_set(v, "clash_api", h->clash_api ? sbj_strn(h->clash_api, h->clash_api_len) : sbj_null());
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
    sbj_set(v, "result", c->result ? sbj_strn(c->result, c->result_len) : sbj_null());
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
    r->host_name_len = 0;
    r->agent_token = sb_strdup("");
    r->profile_id = sb_strdup("");
    r->profile_name = sb_strdup("");
    r->profile_name_len = 0;
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
    sbj_set(v, "host_name", sbj_strn(S(r->host_name), r->host_name_len));
    sbj_set_str(v, "agent_token", S(r->agent_token));
    sbj_set_str(v, "profile_id", S(r->profile_id));
    sbj_set(v, "profile_name", sbj_strn(S(r->profile_name), r->profile_name_len));
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
    free(r->source_tag);
    free(r->fingerprint);
    free(r->last_latency_test);
    free(r->created_at);
    free(r->updated_at);
    memset(r, 0, sizeof *r);
}
void sb_proxy_record_copy(sb_proxy_record *dst, const sb_proxy_record *src) {
    sb_proxy_record_free(dst);
    dst->id = sb_strdup(S(src->id));
    dst->tag = sb_strndup(S(src->tag), src->tag_len);
    dst->tag_len = src->tag_len;
    dst->node_type = sb_strndup(S(src->node_type), src->node_type_len);
    dst->node_type_len = src->node_type_len;
    dst->enabled = src->enabled;
    dst->server = sb_strndup(S(src->server), src->server_len);
    dst->server_len = src->server_len;
    dst->server_port = src->server_port;
    dst->protocol_config = src->protocol_config ? sbj_clone(src->protocol_config) : sbj_object();
    dst->subscription_id = sb_strdup(src->subscription_id);
    dst->source_tag = src->source_tag ? sb_strndup(src->source_tag, src->source_tag_len) : NULL;
    dst->source_tag_len = src->source_tag_len;
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
    sbj_set(v, "tag", sbj_strn(S(r->tag), r->tag_len));
    sbj_set(v, "node_type", sbj_strn(S(r->node_type), r->node_type_len));
    sbj_set_bool(v, "enabled", r->enabled);
    sbj_set(v, "server", sbj_strn(S(r->server), r->server_len));
    sbj_set(v, "server_port", sbj_uint(r->server_port));
    sbj_set(v, "protocol_config", sbj_str_take(sbj_dump(r->protocol_config, -1)));
    sbj_set(v, "subscription_id", opt_str(r->subscription_id));
    sbj_set(v, "source_tag", r->source_tag ? sbj_strn(r->source_tag, r->source_tag_len) : sbj_null());
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
    s->usage = sbj_object();
    s->created_at = sb_strdup("");
    s->updated_at = sb_strdup("");
}
void sb_subscription_free(sb_subscription *s) {
    free(s->id);
    free(s->name);
    free(s->url);
    free(s->last_fetched_at);
    free(s->last_fetch_result);
    sbj_free(s->usage);
    free(s->last_attempt_at);
    free(s->last_error);
    free(s->created_at);
    free(s->updated_at);
    memset(s, 0, sizeof *s);
}
void sb_subscription_copy(sb_subscription *dst, const sb_subscription *src) {
    sb_subscription_free(dst);
    dst->id = sb_strdup(S(src->id));
    dst->name = sb_strndup(S(src->name), src->name_len);
    dst->name_len = src->name_len;
    dst->url = sb_strndup(S(src->url), src->url_len);
    dst->url_len = src->url_len;
    dst->enabled = src->enabled;
    dst->refresh_interval = src->refresh_interval;
    dst->last_fetched_at = sb_strdup(src->last_fetched_at);
    dst->last_fetch_result = sb_strdup(src->last_fetch_result);
    dst->usage = src->usage ? sbj_clone(src->usage) : sbj_object();
    dst->last_attempt_at = sb_strdup(src->last_attempt_at);
    dst->last_error = sb_strdup(src->last_error);
    dst->next_refresh_at = src->next_refresh_at;
    dst->failure_count = src->failure_count;
    dst->created_at = sb_strdup(S(src->created_at));
    dst->updated_at = sb_strdup(S(src->updated_at));
}
sbj *sb_subscription_to_json(const sb_subscription *s) {
    sbj *v = sbj_object();
    sbj_set_str(v, "id", S(s->id));
    sbj_set(v, "name", sbj_strn(S(s->name), s->name_len));
    sbj_set(v, "url", sbj_strn(S(s->url), s->url_len));
    sbj_set_bool(v, "enabled", s->enabled);
    sbj_set_int(v, "refresh_interval", s->refresh_interval);
    sbj_set(v, "last_fetched_at", opt_str(s->last_fetched_at));
    sbj_set(v, "last_fetch_result", opt_str(s->last_fetch_result));
    sbj_set(v, "usage", s->usage ? sbj_clone(s->usage) : sbj_object());
    sbj_set(v, "last_attempt_at", opt_str(s->last_attempt_at));
    sbj_set(v, "last_error", opt_str(s->last_error));
    sbj_set_int(v, "next_refresh_at", s->next_refresh_at);
    sbj_set_int(v, "failure_count", s->failure_count);
    sbj_set_str(v, "created_at", S(s->created_at));
    sbj_set_str(v, "updated_at", S(s->updated_at));
    return v;
}
DEFINE_VEC(sb_subscription)

sbj *strvec_to_json(const sb_strvec *v) {
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
    sbj_free(r->usage);
    memset(r, 0, sizeof *r);
}
sbj *sb_subscription_fetch_result_to_json(const sb_subscription_fetch_result *r) {
    sbj *v = sbj_object();
    sbj_set(v, "added", sbj_uint(r->added));
    sbj_set(v, "updated", sbj_uint(r->updated));
    sbj_set(v, "skipped", sbj_uint(r->skipped));
    sbj_set(v, "found", sbj_uint(r->found));
    sbj_set(v, "usage", r->usage ? sbj_clone(r->usage) : sbj_object());
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

sbj *parse_object_or_empty(const char *text) {
    sbj *parsed = sbj_parse(text, strlen(text), NULL, 0);
    if (!sbj_is_object(parsed)) {
        sbj_free(parsed);
        return sbj_object();
    }
    return parsed;
}

sbj *parse_object_col(sqlite3_stmt *st, int col, const char *description, sb_err *err) {
    char *text = sbq_text(st, col);
    sbj *v = parse_object(text, description, err);
    free(text);
    return v;
}

void read_user(sqlite3_stmt *st, sb_user_account *u) {
    sb_user_account_free(u);
    u->id = sbq_text(st, 0);
    u->username = sbq_text(st, 1);
    u->username_len = (size_t)sqlite3_column_bytes(st, 1);
    u->password_hash = sbq_text(st, 2);
    u->role = sbq_text(st, 3);
    u->created_at = sbq_text(st, 4);
}

int read_profile(sqlite3_stmt *st, sb_config_profile *p, sb_err *err) {
    sbj *profile = parse_object_col(st, 2, "profile template", err);
    if (!profile) return -1;
    sb_config_profile_free(p);
    p->id = sbq_text(st, 0);
    p->name = sbq_text(st, 1);
    p->name_len = (size_t)sqlite3_column_bytes(st, 1);
    p->profile = profile;
    char *mode = sbq_text(st, 3);
    p->mode = parse_profile_mode(mode);
    free(mode);
    p->rule_script = sbq_text(st, 4);
    p->rule_script_len = (size_t)sqlite3_column_bytes(st, 4);
    p->rule_script_enabled = sbq_int(st, 5) != 0;
    p->created_at = sbq_text(st, 6);
    p->updated_at = sbq_text(st, 7);
    return 0;
}

void read_host(sqlite3_stmt *st, sb_host *h) {
    sb_host_free(h);
    h->id = sbq_text(st, 0);
    h->name = sbq_text(st, 1);
    h->name_len = (size_t)sqlite3_column_bytes(st, 1);
    h->agent_token = sbq_text(st, 2);
    char *caps = sbq_text(st, 3);
    h->capabilities = parse_object_or_empty(caps);
    free(caps);
    h->profile_id = sbq_opt_text(st, 4);
    h->profile_id_len = (size_t)sqlite3_column_bytes(st, 4);
    h->wg_address = sbq_opt_text(st, 5);
    h->wg_address_len = (size_t)sqlite3_column_bytes(st, 5);
    h->wg_public_key = sbq_opt_text(st, 6);
    h->wg_public_key_len = (size_t)sqlite3_column_bytes(st, 6);
    h->wg_endpoint = sbq_opt_text(st, 7);
    h->wg_endpoint_len = (size_t)sqlite3_column_bytes(st, 7);
    h->clash_api = sbq_opt_text(st, 8);
    h->clash_api_len = (size_t)sqlite3_column_bytes(st, 8);
    h->clash_secret = sbq_text(st, 9);
    h->clash_secret_len = (size_t)sqlite3_column_bytes(st, 9);
    h->last_seen = sbq_opt_text(st, 10);
    h->singbox_state = sbq_opt_text(st, 11);
    h->enabled = sbq_int(st, 12) != 0;
    h->created_at = sbq_text(st, 13);
    h->updated_at = sbq_text(st, 14);
    h->assigned_outbounds = (size_t)sbq_int(st, 15);
}

void read_host_command(sqlite3_stmt *st, sb_host_command *c) {
    sb_host_command_free(c);
    c->id = sbq_text(st, 0);
    c->host_id = sbq_text(st, 1);
    c->command = sbq_text(st, 2);
    c->status = sbq_text(st, 3);
    c->result = sbq_opt_text(st, 4);
    c->result_len = (size_t)sqlite3_column_bytes(st, 4);
    c->created_at = sbq_text(st, 5);
    c->acked_at = sbq_opt_text(st, 6);
}

void read_wireguard_peer(sqlite3_stmt *st, sb_wireguard_peer *p) {
    sb_wireguard_peer_free(p);
    p->id = sbq_text(st, 0);
    p->name = sbq_text(st, 1);
    p->name_len = (size_t)sqlite3_column_bytes(st, 1);
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
    p->notes_len = (size_t)sqlite3_column_bytes(st, 14);
    p->host_id = sbq_opt_text(st, 15);
}

int read_proxy_record(sqlite3_stmt *st, sb_proxy_record *r, sb_err *err) {
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
    r->tag_len = (size_t)sqlite3_column_bytes(st, 1);
    r->node_type = sbq_text(st, 2);
    r->node_type_len = (size_t)sqlite3_column_bytes(st, 2);
    r->enabled = sbq_int(st, 3) != 0;
    r->server = sbq_text(st, 4);
    r->server_len = (size_t)sqlite3_column_bytes(st, 4);
    r->server_port = (uint16_t)raw_port;
    r->protocol_config = config;
    r->subscription_id = sbq_opt_text(st, 7);
    r->fingerprint = sbq_text(st, 8);
    r->has_latency = sqlite3_column_type(st, 9) != SQLITE_NULL;
    r->latency = r->has_latency ? sqlite3_column_double(st, 9) : 0.0;
    r->last_latency_test = sbq_opt_text(st, 10);
    r->created_at = sbq_text(st, 11);
    r->updated_at = sbq_text(st, 12);
    r->source_tag = sbq_opt_text(st, 13);
    r->source_tag_len = (size_t)sqlite3_column_bytes(st, 13);
    return 0;
}

void read_subscription(sqlite3_stmt *st, sb_subscription *s) {
    sb_subscription_free(s);
    s->id = sbq_text(st, 0);
    s->name = sbq_text(st, 1);
    s->name_len = (size_t)sqlite3_column_bytes(st, 1);
    s->url = sbq_text(st, 2);
    s->url_len = (size_t)sqlite3_column_bytes(st, 2);
    s->enabled = sbq_int(st, 3) != 0;
    s->refresh_interval = sbq_int(st, 4);
    s->last_fetched_at = sbq_opt_text(st, 5);
    s->last_fetch_result = sbq_opt_text(st, 6);
    s->created_at = sbq_text(st, 7);
    s->updated_at = sbq_text(st, 8);
    const char *usage = (const char *)sqlite3_column_text(st, 9);
    s->usage = usage ? sbj_parse_cstr(usage) : NULL;
    if (!sbj_is_object(s->usage)) { sbj_free(s->usage); s->usage = sbj_object(); }
    s->last_attempt_at = sbq_opt_text(st, 10);
    s->last_error = sbq_opt_text(st, 11);
    s->next_refresh_at = sbq_int(st, 12);
    s->failure_count = sbq_int(st, 13);
}

static bool supported_proxy_type(const char *type, size_t len) {
    static const char *const supported[] = {"shadowsocks", "vmess",     "vless", "trojan",
                                            "hysteria2",   "tuic",      "http", "socks"};
    for (size_t i = 0; i < sizeof supported / sizeof *supported; ++i)
        if (sb_strn_eq(type, len, supported[i])) return true;
    return false;
}

int validate_proxy(const sb_proxy_record *node, sb_err *err) {
    if (!node->tag || node->tag_len == 0 || !node->server || node->server_len == 0 ||
        node->server_port == 0U || !sbj_is_object(node->protocol_config))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "Proxy tag, server, port, and object protocol_config are required");
    if (!supported_proxy_type(S(node->node_type), node->node_type_len))
        return sb_fail(err, SB_ERR_VALIDATION, "Unsupported proxy type: %s", S(node->node_type));
    return 0;
}

char *new_agent_token(void) {
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



char *controller_address(const char *address, size_t len, size_t *out_len) {
    if (!address || !len) {
        *out_len = strlen("0.0.0.0:9090");
        return sb_strdup("0.0.0.0:9090");
    }
    size_t start = 0;
    if (len >= 8 && memcmp(address, "https://", 8) == 0) start = 8;
    else if (len >= 7 && memcmp(address, "http://", 7) == 0) start = 7;
    while (len > start && address[len - 1] == '/') --len;
    *out_len = len - start;
    return sb_strndup(address + start, *out_len);
}

int read_nodes(sqlite3 *db, const char *sql, const char *host_id, sb_proxy_node_vec *out,
                      sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(db, sql, err);
    if (q.rc != 0) return -1;
    sqlite3_stmt *st = q.st;
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
        n->id_len = (size_t)sqlite3_column_bytes(st, 0);
        free(n->tag);
        n->tag = sbq_text(st, 1);
        n->tag_len = (size_t)sqlite3_column_bytes(st, 1);
        free(n->type);
        n->type = sbq_text(st, 2);
        n->type_len = (size_t)sqlite3_column_bytes(st, 2);
        n->enabled = sbq_int(st, 3) != 0;
        free(n->server);
        n->server = sbq_text(st, 4);
        n->server_len = (size_t)sqlite3_column_bytes(st, 4);
        n->server_port = (uint16_t)server_port;
        sbj_free(n->protocol_config);
        n->protocol_config = config;
    }
    return r < 0 ? -1 : 0;
}

/* Runs a prepared statement that expects no row and finalises it. */
int exec_stmt(sqlite3_stmt *st, sb_err *err) {
    int r = sbq_step_done(st, err);
    sqlite3_finalize(st);
    return r;
}

/* SELECT 1 FROM hosts WHERE id = ?1 -> 1 exists, 0 missing, -1 error */
int host_exists(sqlite3 *db, const char *host_id, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(db, "SELECT 1 FROM hosts WHERE id = ?1", err);
    if (q.rc != 0) return -1;
    const char *id = S(host_id);
    sbq_stmt_bind_text_n(&q, 1, id, strlen(id), err);
    return sbq_stmt_step_row(&q, err);
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
int jv_str(const sbj *obj, const char *key, const char *def, const char **out, sb_err *err) {
    const sbj *v = sbj_get(obj, key);
    if (!v) {
        *out = def;
        return 0;
    }
    if (!sbj_is_string(v)) return type_error(err, "string", v);
    *out = v->v.str.ptr;
    return 0;
}
int jv_bool(const sbj *obj, const char *key, bool def, bool *out, sb_err *err) {
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
int jv_int(const sbj *obj, const char *key, int64_t def, int64_t *out, sb_err *err) {
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
const char *jv_opt_str(const sbj *obj, const char *key) {
    const sbj *v = sbj_get(obj, key);
    return sbj_is_string(v) ? v->v.str.ptr : NULL;
}

/* json::dump(); NULL (err set) where nlohmann would throw. */
char *dump_checked(const sbj *value, sb_err *err) {
    if (sbj_validate_utf8(value, err) != 0) return NULL;
    return sbj_dump(value, -1);
}

const char *const settings_upsert_sql =
    "INSERT INTO app_settings (key, value, updated_at) "
    "VALUES (?1, ?2, datetime('now')) "
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
    "updated_at = datetime('now')";

/* Binds json::dump() of value; -1 (err set) where nlohmann would throw. */
int bind_dump(sqlite3_stmt *st, int i, const sbj *value, sb_err *err) {
    char *text = dump_checked(value, err);
    if (!text) return -1;
    sbq_bind_text(st, i, text);
    free(text);
    return 0;
}

/* exec_stmt() unless an earlier bind failed (bound != 0): then only finalise. */
int exec_bound(sqlite3_stmt *st, int bound, sb_err *err) {
    if (bound != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    return exec_stmt(st, err);
}

/* ParsedProxyNode::fingerprint(): its key material is read with json::value(),
 * which throws for present-but-non-string members (sb_parsed_node_fingerprint
 * silently uses ""). Returns the malloc'd fingerprint or NULL (err set). */
char *fingerprint_of(const sb_proxy_record *node, sb_err *err) {
    const char *node_type = node->node_type, *server = node->server;
    size_t type_len = node->node_type_len, server_len = node->server_len;
    uint16_t port = node->server_port;
    const sbj *config = node->protocol_config;
    const char *t = S(node_type), *first = NULL, *second = NULL, *ignored;
    if (sb_strn_eq(t, type_len, "shadowsocks") || sb_strn_eq(t, type_len, "trojan") || sb_strn_eq(t, type_len, "hysteria2")) {
        first = "password";
    } else if (sb_strn_eq(t, type_len, "vmess") || sb_strn_eq(t, type_len, "vless")) {
        first = "uuid";
    } else if (sb_strn_eq(t, type_len, "tuic")) {
        first = "uuid";
        second = "password";
    } else if (sb_strn_eq(t, type_len, "http") || sb_strn_eq(t, type_len, "socks")) {
        first = "username";
        second = "password";
    }
    if ((first && jv_str(config, first, "", &ignored, err) != 0) ||
        (second && jv_str(config, second, "", &ignored, err) != 0))
        return NULL;
    sb_parsed_node n = {0};
    n.node_type = (char *)t;
    n.node_type_len = type_len;
    n.server_len = server_len;
    n.server = (char *)S(server);
    n.server_port = port;
    n.protocol_config = (sbj *)config;
    return sb_parsed_node_fingerprint(&n);
}

/* ---- list results ----------------------------------------------------
 * Rows are collected in a local vector and appended to *out only on success,
 * so a failed call leaves *out untouched. */

/* ======================================================================
 * store: lifecycle, users, audit, settings
 * ====================================================================== */

int exec_changes(sb_store *s, const char *sql, const char *not_found, sb_err *err,
                        int nbinds, const char *const *binds);

/* Fills agent_token_hash for rows created before migration 019 (SQLite has no
 * SHA-256). Best effort: rows that fail stay on the plaintext lookup fallback. */
static void backfill_agent_token_hashes(sb_store *s) {
    sb_strvec ids = {0}, tokens = {0};
    LOCK(s);
    {
        SBQ_AUTO q = sbq_stmt_open(H(s),
                                   "SELECT id, agent_token FROM hosts "
                                   "WHERE agent_token != '' AND agent_token_hash = ''",
                                   NULL);
        while (q.rc == 0 && sbq_step_row(q.st, NULL) == 1) {
            char *id = sbq_text(q.st, 0);
            char *token = sbq_text(q.st, 1);
            sb_strvec_push(&ids, id);
            sb_strvec_push(&tokens, token);
            free(id);
            free(token);
        }
    }
    UNLOCK(s);
    size_t done = 0;
    for (size_t i = 0; i < ids.len; ++i) {
        char *hash = sb_sha256_hex(tokens.items[i], strlen(tokens.items[i]));
        const char *binds[] = {hash, ids.items[i]};
        if (exec_changes(s, "UPDATE hosts SET agent_token_hash = ?1 WHERE id = ?2",
                         "Host not found", NULL, 2, binds) == 0)
            ++done;
        free(hash);
    }
    if (ids.len) SB_INFO("agent token hash backfill: %zu of %zu hosts", done, ids.len);
    sb_strvec_free(&ids);
    sb_strvec_free(&tokens);
}

sb_store *sb_store_open(const char *db_path, const char *migrations_dir, sb_err *err) {
    sb_database *db = sb_database_open(db_path, err);
    if (!db) return NULL;
    if (sb_database_migrate(db, migrations_dir, err) != 0) {
        sb_database_free(db);
        return NULL;
    }
    sb_store *s = sb_xcalloc(1, sizeof *s);
    s->db = db;
    backfill_agent_token_hashes(s);
    return s;
}

void sb_store_free(sb_store *s) {
    if (!s) return;
    sb_database_free(s->db);
    free(s);
}

sb_database *sb_store_database(sb_store *s) { return s->db; }



