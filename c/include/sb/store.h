/* Repository facade over the sb-easy SQLite schema. Port of
 * cpp/include/sbeasy/store.hpp + cpp/src/store.cpp.
 *
 * It deliberately uses the existing schema and query semantics instead of
 * introducing a new ORM-owned data model. Every call is serialised on the
 * database mutex, so one sb_store may be shared by many threads.
 *
 * Conventions:
 *  - int-returning functions: 0 ok / -1 error (err filled; kinds
 *    SB_ERR_NOT_FOUND / SB_ERR_VALIDATION / SB_ERR_CONFLICT mirror the C++
 *    NotFoundError / ValidationError / ConflictError; SB_ERR_BAD_JSON is
 *    where C++ lets a nlohmann json::exception escape (json::value() type
 *    errors in backups/reports, json::dump() of invalid UTF-8) and carries
 *    the identical what() text; SQLite and other failures are SB_ERR_GENERIC).
 *    Messages are the C++ exception messages verbatim.
 *  - find_* functions (std::optional in C++): 1 found (out filled), 0 not
 *    found (out untouched), -1 error.
 *  - `out` structs must be initialised by the caller (*_init) and are
 *    released with *_free; they are overwritten on success and untouched on
 *    failure.
 *  - list-style functions (std::vector in C++) append the rows to *out on
 *    success (pass a zeroed vector) and leave *out untouched on failure.
 *  - Nullable char* members correspond to std::optional<std::string>.
 */
#ifndef SB_STORE_H
#define SB_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sb/database.h"
#include "sb/json.h"
#include "sb/types.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SB_VEC_TYPE(name, elem)                                                        \
    typedef struct {                                                                   \
        elem *items;                                                                   \
        size_t len, cap;                                                               \
    } name

/* ---- users / audit ---------------------------------------------------- */
typedef struct {
    char *id, *username, *password_hash, *role, *created_at;
    size_t username_len;
} sb_user_account;
void sb_user_account_init(sb_user_account *u);
void sb_user_account_free(sb_user_account *u);
/* Serializes a user without exposing the password hash. */
sbj *sb_user_account_to_json(const sb_user_account *u);
SB_VEC_TYPE(sb_user_account_vec, sb_user_account);
sb_user_account *sb_user_account_vec_push(sb_user_account_vec *v);
void sb_user_account_vec_free(sb_user_account_vec *v);

typedef struct {
    int64_t id;
    char *timestamp, *actor, *action;
    size_t actor_len;
    char *target; /* nullable */
} sb_audit_entry;
void sb_audit_entry_init(sb_audit_entry *e);
void sb_audit_entry_free(sb_audit_entry *e);
sbj *sb_audit_entry_to_json(const sb_audit_entry *e);
SB_VEC_TYPE(sb_audit_entry_vec, sb_audit_entry);
sb_audit_entry *sb_audit_entry_vec_push(sb_audit_entry_vec *v);
void sb_audit_entry_vec_free(sb_audit_entry_vec *v);

/* ---- WireGuard -------------------------------------------------------- */
typedef struct {
    char *id, *name, *private_key, *public_key;
    size_t name_len;
    char *preshared_key; /* nullable */
    char *address;
    char *dns;           /* default "10.59.32.1" */
    bool enabled;        /* default true */
    int32_t persistent_keepalive; /* default 25 */
    char *allowed_ips;   /* default "0.0.0.0/0, ::/0" */
    char *expire_at;     /* nullable */
    int64_t quota_bytes;
    char *created_at, *updated_at;
    char *notes;         /* nullable */
    char *host_id;       /* nullable */
} sb_wireguard_peer;
void sb_wireguard_peer_init(sb_wireguard_peer *p);
void sb_wireguard_peer_free(sb_wireguard_peer *p);
sbj *sb_wireguard_peer_to_json(const sb_wireguard_peer *p);
SB_VEC_TYPE(sb_wireguard_peer_vec, sb_wireguard_peer);
sb_wireguard_peer *sb_wireguard_peer_vec_push(sb_wireguard_peer_vec *v);
void sb_wireguard_peer_vec_free(sb_wireguard_peer_vec *v);

/* ---- profiles --------------------------------------------------------- */
typedef struct {
    char *id, *name;
    sbj *profile; /* object */
    sb_profile_mode mode;
    char *rule_script;
    size_t name_len, rule_script_len; /* exact byte lengths; update with the strings */
    bool rule_script_enabled;
    char *created_at, *updated_at;
} sb_config_profile;
void sb_config_profile_init(sb_config_profile *p);
void sb_config_profile_free(sb_config_profile *p);
void sb_config_profile_copy(sb_config_profile *dst, const sb_config_profile *src);
sbj *sb_config_profile_to_json(const sb_config_profile *p);
SB_VEC_TYPE(sb_config_profile_vec, sb_config_profile);
sb_config_profile *sb_config_profile_vec_push(sb_config_profile_vec *v);
void sb_config_profile_vec_free(sb_config_profile_vec *v);

/* ---- hosts ------------------------------------------------------------ */
typedef struct {
    char *id, *name, *agent_token;
    size_t name_len;
    sbj *capabilities; /* object */
    char *profile_id, *wg_address, *wg_public_key, *wg_endpoint, *clash_api; /* nullable */
    char *clash_secret;
    char *last_seen, *singbox_state; /* nullable */
    bool enabled; /* default true */
    char *created_at, *updated_at;
    size_t assigned_outbounds;
} sb_host;
void sb_host_init(sb_host *h);
void sb_host_free(sb_host *h);
void sb_host_copy(sb_host *dst, const sb_host *src);
/* Public host representation. Agent and Clash secrets are deliberately omitted. */
sbj *sb_host_to_json(const sb_host *h);
SB_VEC_TYPE(sb_host_vec, sb_host);
sb_host *sb_host_vec_push(sb_host_vec *v);
void sb_host_vec_free(sb_host_vec *v);

typedef struct {
    char *id, *host_id, *command, *status;
    char *result; /* nullable */
    char *created_at;
    char *acked_at; /* nullable */
} sb_host_command;
void sb_host_command_init(sb_host_command *c);
void sb_host_command_free(sb_host_command *c);
sbj *sb_host_command_to_json(const sb_host_command *c);
SB_VEC_TYPE(sb_host_command_vec, sb_host_command);
sb_host_command *sb_host_command_vec_push(sb_host_command_vec *v);
void sb_host_command_vec_free(sb_host_command_vec *v);

typedef struct {
    char *id, *host_id, *code, *expires_at;
} sb_agent_enrollment;
void sb_agent_enrollment_init(sb_agent_enrollment *e);
void sb_agent_enrollment_free(sb_agent_enrollment *e);
/* C-only helper (no C++ to_json): plain field dump, not the HTTP response shape. */
sbj *sb_agent_enrollment_to_json(const sb_agent_enrollment *e);

typedef struct {
    char *host_id, *host_name, *agent_token, *profile_id, *profile_name;
    size_t host_name_len, profile_name_len;
} sb_agent_enrollment_result;
void sb_agent_enrollment_result_init(sb_agent_enrollment_result *r);
void sb_agent_enrollment_result_free(sb_agent_enrollment_result *r);
/* C-only helper (no C++ to_json): plain field dump, not the HTTP response shape. */
sbj *sb_agent_enrollment_result_to_json(const sb_agent_enrollment_result *r);

/* ---- proxies / subscriptions ----------------------------------------- */
typedef struct {
    char *id, *tag, *node_type;
    size_t tag_len, node_type_len, server_len;
    bool enabled; /* default true */
    char *server;
    uint16_t server_port;
    sbj *protocol_config; /* object */
    char *subscription_id; /* nullable */
    char *fingerprint;
    bool has_latency; /* std::optional<double> latency */
    double latency;
    char *last_latency_test; /* nullable */
    char *created_at, *updated_at;
} sb_proxy_record;
void sb_proxy_record_init(sb_proxy_record *r);
void sb_proxy_record_free(sb_proxy_record *r);
void sb_proxy_record_copy(sb_proxy_record *dst, const sb_proxy_record *src);
sbj *sb_proxy_record_to_json(const sb_proxy_record *r);
SB_VEC_TYPE(sb_proxy_record_vec, sb_proxy_record);
sb_proxy_record *sb_proxy_record_vec_push(sb_proxy_record_vec *v);
void sb_proxy_record_vec_free(sb_proxy_record_vec *v);

typedef struct {
    char *id, *name, *url;
    size_t name_len, url_len;
    bool enabled;             /* default true */
    int64_t refresh_interval; /* default 3600 */
    char *last_fetched_at, *last_fetch_result; /* nullable */
    char *created_at, *updated_at;
} sb_subscription;
void sb_subscription_init(sb_subscription *s);
void sb_subscription_free(sb_subscription *s);
void sb_subscription_copy(sb_subscription *dst, const sb_subscription *src);
sbj *sb_subscription_to_json(const sb_subscription *s);
SB_VEC_TYPE(sb_subscription_vec, sb_subscription);
sb_subscription *sb_subscription_vec_push(sb_subscription_vec *v);
void sb_subscription_vec_free(sb_subscription_vec *v);

typedef struct {
    size_t added, updated;
    sb_strvec errors;
} sb_proxy_upsert_result;
void sb_proxy_upsert_result_init(sb_proxy_upsert_result *r);
void sb_proxy_upsert_result_free(sb_proxy_upsert_result *r);
/* C-only helper (no C++ to_json): {"added","updated","errors"} field dump. */
sbj *sb_proxy_upsert_result_to_json(const sb_proxy_upsert_result *r);

typedef struct {
    size_t added, updated, skipped, found;
    sb_strvec errors;
} sb_subscription_fetch_result;
void sb_subscription_fetch_result_init(sb_subscription_fetch_result *r);
void sb_subscription_fetch_result_free(sb_subscription_fetch_result *r);
sbj *sb_subscription_fetch_result_to_json(const sb_subscription_fetch_result *r);

/* ---- store ------------------------------------------------------------ */
typedef struct sb_store sb_store;

/* Opens the database and applies the migrations. NULL on failure. */
sb_store *sb_store_open(const char *db_path, const char *migrations_dir, sb_err *err);
void sb_store_free(sb_store *store);
/* Borrowed; for migrate/execute (tests, maintenance). */
sb_database *sb_store_database(sb_store *store);

int sb_store_ensure_default_admin(sb_store *s, const char *password, sb_err *err);
int sb_store_list_users(sb_store *s, sb_user_account_vec *out, sb_err *err);
int sb_store_find_user_by_username(sb_store *s, const char *username, sb_user_account *out,
                                   sb_err *err);
int sb_store_create_user(sb_store *s, const char *username, const char *password_hash,
                         const char *role, sb_user_account *out, sb_err *err);
/* Length-aware variants preserve JSON usernames, including embedded NUL. */
int sb_store_find_user_by_username_n(sb_store *s, const char *username, size_t username_len,
                                    sb_user_account *out, sb_err *err);
int sb_store_create_user_n(sb_store *s, const char *username, size_t username_len,
                           const char *password_hash, const char *role,
                           sb_user_account *out, sb_err *err);
int sb_store_record_audit_n(sb_store *s, const char *actor, size_t actor_len,
                            const char *action, const char *target, sb_err *err);
int sb_store_delete_user(sb_store *s, const char *actor_id, const char *user_id, sb_err *err);
int sb_store_reset_user_password(sb_store *s, const char *user_id, const char *password_hash,
                                 sb_err *err);
int sb_store_record_audit(sb_store *s, const char *actor, const char *action,
                          const char *target /* nullable */, sb_err *err);
/* limit is clamped to [1, 1000] (C++ default 200). */
int sb_store_list_audit(sb_store *s, size_t limit, sb_audit_entry_vec *out, sb_err *err);
/* Object of all settings rows whose value parses as JSON. NULL on error. */
sbj *sb_store_app_settings(sb_store *s, sb_err *err);
int sb_store_update_app_settings(sb_store *s, const sbj *sections, sb_err *err);
/* 1 found (*out owned by caller), 0 missing/unparseable, -1 error. */
int sb_store_app_setting(sb_store *s, const char *key, sbj **out, sb_err *err);
int sb_store_set_app_setting(sb_store *s, const char *key, const sbj *value, sb_err *err);

int sb_store_list_wireguard_peers(sb_store *s, sb_wireguard_peer_vec *out, sb_err *err);
int sb_store_find_wireguard_peer(sb_store *s, const char *id, sb_wireguard_peer *out, sb_err *err);
int sb_store_create_wireguard_peer(sb_store *s, const sb_wireguard_peer *peer,
                                   sb_wireguard_peer *out, sb_err *err);
int sb_store_update_wireguard_peer(sb_store *s, const sb_wireguard_peer *peer,
                                   sb_wireguard_peer *out, sb_err *err);
int sb_store_delete_wireguard_peer(sb_store *s, const char *id, sb_err *err);
int sb_store_set_wireguard_peer_enabled(sb_store *s, const char *id, bool enabled, sb_err *err);
/* Returns a malloc'd "a.b.c.N/24" or NULL. */
char *sb_store_next_wireguard_address(sb_store *s, const char *server_address, sb_err *err);
int sb_store_create_one_time_link(sb_store *s, const char *token, const char *peer_id,
                                  const char *expires_at, sb_err *err);
sbj *sb_store_export_backup(sb_store *s, sb_err *err);
/* Returns the per-section counts object, NULL on error. */
sbj *sb_store_restore_backup(sb_store *s, const sbj *backup, sb_err *err);

int sb_store_list_profiles(sb_store *s, sb_config_profile_vec *out, sb_err *err);
int sb_store_find_profile(sb_store *s, const char *id, sb_config_profile *out, sb_err *err);
int sb_store_create_profile(sb_store *s, const sb_config_profile *profile,
                            sb_config_profile *out, sb_err *err);
int sb_store_update_profile(sb_store *s, const sb_config_profile *profile,
                            sb_config_profile *out, sb_err *err);
int sb_store_delete_profile(sb_store *s, const char *id, sb_err *err);

int sb_store_list_hosts(sb_store *s, sb_host_vec *out, sb_err *err);
int sb_store_find_host(sb_store *s, const char *id, sb_host *out, sb_err *err);
int sb_store_create_host(sb_store *s, const sb_host *host, sb_host *out, sb_err *err);
int sb_store_update_host(sb_store *s, const sb_host *host, sb_host *out, sb_err *err);
int sb_store_delete_host(sb_store *s, const char *id, sb_err *err);
/* Returns the new report id (malloc'd) or NULL. */
char *sb_store_save_diagnostic_report(sb_store *s, const char *host_id, const sbj *report,
                                      sb_err *err);
/* Returns a JSON array of reports (C++: std::vector<json>), newest first;
 * limit is capped at 20 (C++ default 20). NULL on error. */
sbj *sb_store_list_diagnostic_reports(sb_store *s, const char *host_id, size_t limit,
                                      sb_err *err);

int sb_store_host_outbounds(sb_store *s, const char *host_id, sb_strvec *out, sb_err *err);
int sb_store_set_host_outbounds(sb_store *s, const char *host_id, const sb_strvec *node_ids,
                                sb_err *err);
char *sb_store_rotate_agent_token(sb_store *s, const char *host_id, sb_err *err);
int sb_store_create_agent_enrollment(sb_store *s, const char *host_id, sb_agent_enrollment *out,
                                     sb_err *err);
int sb_store_redeem_agent_enrollment(sb_store *s, const char *code, const sbj *device,
                                     sb_agent_enrollment_result *out, sb_err *err);

int sb_store_find_enabled_host_by_token(sb_store *s, const char *token, sb_host *out,
                                        sb_err *err);
int sb_store_touch_host(sb_store *s, const char *host_id, sb_err *err);
int sb_store_update_agent_status(sb_store *s, const char *host_id, const sbj *state, sb_err *err);

int sb_store_enqueue_host_command(sb_store *s, const char *host_id, const char *command,
                                  sb_host_command *out, sb_err *err);
int sb_store_list_host_commands(sb_store *s, const char *host_id, bool pending_only,
                                sb_host_command_vec *out, sb_err *err);
/* 1 acknowledged, 0 no matching command for that host, -1 error. */
int sb_store_acknowledge_host_command(sb_store *s, const char *host_id, const char *command_id,
                                      const char *status, const char *result /* nullable */,
                                      sb_err *err);

int sb_store_update_proxy_latencies(sb_store *s, const sbj *results, size_t *updated,
                                    sb_err *err);
/* latency NULL == std::nullopt */
int sb_store_update_proxy_latency(sb_store *s, const char *id, const double *latency,
                                  sb_err *err);

int sb_store_list_proxy_nodes(sb_store *s, sb_proxy_record_vec *out, sb_err *err);
int sb_store_find_proxy_node(sb_store *s, const char *id, sb_proxy_record *out, sb_err *err);
int sb_store_create_proxy_node(sb_store *s, const sb_proxy_record *node, sb_proxy_record *out,
                               sb_err *err);
int sb_store_update_proxy_node(sb_store *s, const sb_proxy_record *node, sb_proxy_record *out,
                               sb_err *err);
int sb_store_delete_proxy_node(sb_store *s, const char *id, sb_err *err);
/* subscription_id nullable. Per-node failures land in out->errors. */
int sb_store_upsert_proxy_nodes(sb_store *s, const sb_parsed_node *nodes, size_t count,
                                const char *subscription_id, sb_proxy_upsert_result *out,
                                sb_err *err);

int sb_store_list_subscriptions(sb_store *s, sb_subscription_vec *out, sb_err *err);
int sb_store_find_subscription(sb_store *s, const char *id, sb_subscription *out, sb_err *err);
int sb_store_create_subscription(sb_store *s, const sb_subscription *sub, sb_subscription *out,
                                 sb_err *err);
int sb_store_update_subscription(sb_store *s, const sb_subscription *sub, sb_subscription *out,
                                 sb_err *err);
int sb_store_delete_subscription(sb_store *s, const char *id, sb_err *err);
int sb_store_record_subscription_fetch(sb_store *s, const char *id,
                                       const sb_subscription_fetch_result *result, sb_err *err);

/* Fills *out (initialised by the caller with sb_render_request_init). */
int sb_store_render_request_for_host(sb_store *s, const char *host_id, sb_render_request *out,
                                     sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
