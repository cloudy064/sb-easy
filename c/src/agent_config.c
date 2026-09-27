#include "sb/agent_config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "sb/atomic_file.h"

void sb_agent_config_options_init(sb_agent_config_options *o) {
    o->local_proxy_egress = true;
    o->outbound_server_overrides = sbj_object();
    o->outbound_overrides = sbj_object();
    o->default_proxy_outbound = NULL;
    o->local_route_rules = sbj_array();
}

void sb_agent_config_options_free(sb_agent_config_options *o) {
    if (!o) return;
    sbj_free(o->outbound_server_overrides);
    sbj_free(o->outbound_overrides);
    free(o->default_proxy_outbound);
    sbj_free(o->local_route_rules);
    memset(o, 0, sizeof *o);
}

void sb_agent_config_options_copy(sb_agent_config_options *dst,
                                  const sb_agent_config_options *src) {
    dst->local_proxy_egress = src->local_proxy_egress;
    dst->outbound_server_overrides = src->outbound_server_overrides
                                         ? sbj_clone(src->outbound_server_overrides)
                                         : sbj_object();
    dst->outbound_overrides =
        src->outbound_overrides ? sbj_clone(src->outbound_overrides) : sbj_object();
    dst->default_proxy_outbound = sb_strdup(src->default_proxy_outbound);
    dst->local_route_rules =
        src->local_route_rules ? sbj_clone(src->local_route_rules) : sbj_array();
}

/* nlohmann empty(): null -> true, containers -> size()==0, scalars -> false. */
static bool json_empty(const sbj *v) {
    if (sbj_is_null(v)) return true;
    if (sbj_is_array(v)) return v->v.arr.len == 0;
    if (sbj_is_object(v)) return v->v.obj.len == 0;
    return false;
}

/* nlohmann object.value(key, std::string{}): the fallback when absent, a
 * type_error when present but not a string. Returns a borrowed string. */
static int value_string(const sbj *object, const char *key, const char **out, sb_err *err) {
    const sbj *found = sbj_get(object, key);
    if (!found) {
        *out = "";
        return 0;
    }
    if (!sbj_is_string(found))
        return sb_fail(err, SB_ERR_GENERIC,
                       "[json.exception.type_error.302] type must be string, but is %s",
                       sbj_type_name(found));
    *out = found->v.str.ptr;
    return 0;
}

static bool json_equals_string(const sbj *v, const char *s) {
    return sbj_is_string(v) && strcmp(v->v.str.ptr, s) == 0;
}

static void rewrite_tag_references(sbj *value, const sbj *renames) {
    if (sbj_is_string(value)) {
        const sbj *found = sbj_get(renames, value->v.str.ptr);
        if (found) {
            free(value->v.str.ptr);
            value->v.str.ptr = sb_strdup(found->v.str.ptr);
            value->v.str.len = found->v.str.len;
        }
        return;
    }
    if (sbj_is_array(value)) {
        for (size_t i = 0; i < value->v.arr.len; ++i)
            rewrite_tag_references(value->v.arr.items[i], renames);
        return;
    }
    if (sbj_is_object(value)) {
        for (size_t i = 0; i < value->v.obj.len; ++i)
            rewrite_tag_references(value->v.obj.vals[i], renames);
    }
}

static bool is_builtin_route(const char *tag) {
    return strcmp(tag, "direct") == 0 || strcmp(tag, "block") == 0 ||
           strcmp(tag, "wg-internal") == 0;
}

static sbj *proxy_dns_server(const char *detour) {
    sbj *server = sbj_object();
    sbj_set_str(server, "type", "https");
    sbj_set_str(server, "tag", "proxy-dns");
    sbj_set_str(server, "server", "1.1.1.1");
    sbj_set_int(server, "server_port", 443);
    sbj_set_str(server, "path", "/dns-query");
    sbj *tls = sbj_object();
    sbj_set_bool(tls, "enabled", true);
    sbj_set_str(tls, "server_name", "cloudflare-dns.com");
    sbj_set(server, "tls", tls);
    sbj_set_str(server, "detour", detour);
    return server;
}

static sbj *proxy_dns_rule(void) {
    sbj *rule = sbj_object();
    sbj *suffixes = sbj_array();
    sbj_arr_push(suffixes, sbj_str("chatgpt.com"));
    sbj_arr_push(suffixes, sbj_str("openai.com"));
    sbj_arr_push(suffixes, sbj_str("oaistatic.com"));
    sbj_arr_push(suffixes, sbj_str("oaiusercontent.com"));
    sbj_set(rule, "domain_suffix", suffixes);
    sbj_set_str(rule, "server", "proxy-dns");
    return rule;
}

/* Handles one outbound of the "outbounds" array; may replace *slot. */
static int transform_outbound(sbj **slot, const sb_agent_config_options *options,
                              const char *original_route_final, sbj *renamed,
                              size_t *changes, sb_err *err) {
    sbj *outbound = *slot;
    if (!sbj_is_object(outbound)) return 0;
    const sbj *tag_value = sbj_get(outbound, "tag");
    if (!sbj_is_string(tag_value)) return 0;
    char *original_tag = sb_strdup(tag_value->v.str.ptr);
    int rc = -1;

    const sbj *replacement = sbj_get(options->outbound_overrides, original_tag);
    if (replacement) {
        if (!sbj_is_object(replacement)) {
            sb_fail(err, SB_ERR_VALIDATION, "outbound override for %s must be a JSON object",
                    original_tag);
            goto out;
        }
        sbj_free(outbound);
        outbound = *slot = sbj_clone(replacement);
        ++*changes;
    }

    const sbj *replacement_tag = sbj_get(outbound, "tag");
    char *effective_tag = sb_strdup(sbj_is_string(replacement_tag)
                                        ? replacement_tag->v.str.ptr
                                        : original_tag);
    if (strcmp(effective_tag, original_tag) != 0 && !sbj_has(renamed, original_tag))
        sbj_set_str(renamed, original_tag, effective_tag);
    sbj_set(outbound, "tag", sbj_str_take(effective_tag));

    if (json_equals_string(sbj_get(outbound, "detour"), "wg-internal")) {
        sbj_del(outbound, "detour");
        ++*changes;
    }
    const sbj *server = sbj_get(options->outbound_server_overrides, original_tag);
    if (server) {
        const sbj *current = sbj_get(outbound, "server");
        if (!current || !sbj_equal(current, server)) {
            sbj_set(outbound, "server", sbj_clone(server));
            ++*changes;
        }
    }

    if (options->default_proxy_outbound && original_route_final &&
        strcmp(original_route_final, original_tag) == 0) {
        const char *type = NULL;
        if (value_string(outbound, "type", &type, err) != 0) goto out;
        if (strcmp(type, "selector") == 0) {
            const char *wanted = options->default_proxy_outbound;
            const sbj *choices = sbj_get(outbound, "outbounds");
            bool allowed = false;
            const sbj *choice;
            SBJ_ARR_FOREACH(choices, i, choice) {
                if (json_equals_string(choice, wanted)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                sb_fail(err, SB_ERR_VALIDATION,
                        "default proxy outbound %s is not in selector %s", wanted,
                        original_tag);
                goto out;
            }
            if (!json_equals_string(sbj_get(outbound, "default"), wanted)) {
                sbj_set_str(outbound, "default", wanted);
                ++*changes;
            }
        }
    }
    rc = 0;
out:
    free(original_tag);
    return rc;
}

char *sb_prepare_agent_config(const char *body, size_t len,
                              const sb_agent_config_options *options, sb_err *err) {
    const sbj *local_rules = options->local_route_rules;
    if (!options->local_proxy_egress && json_empty(local_rules)) return sb_strndup(body, len);
    /* A NULL member is treated as the default empty array. */
    if (local_rules && !sbj_is_array(local_rules)) {
        sb_fail(err, SB_ERR_VALIDATION, "local_route_rules must be a JSON array");
        return NULL;
    }
    const sbj *rule;
    SBJ_ARR_FOREACH(local_rules, i, rule) {
        if (!sbj_is_object(rule)) {
            sb_fail(err, SB_ERR_VALIDATION, "local route rules must be JSON objects");
            return NULL;
        }
    }

    char parse_error[256] = {0};
    sbj *config = sbj_parse(body, len, parse_error, sizeof parse_error);
    if (!config) {
        sb_fail(err, SB_ERR_GENERIC, "%s", parse_error);
        return NULL;
    }

    char *result = NULL;
    char *original_route_final = NULL;
    char *proxy_detour = NULL;
    sbj *renamed = sbj_object();
    size_t changes = 0;
    {
        const sbj *route = sbj_get(config, "route");
        if (sbj_is_object(route)) {
            const sbj *final_value = sbj_get(route, "final");
            if (sbj_is_string(final_value))
                original_route_final = sb_strdup(final_value->v.str.ptr);
        }
    }

    sbj *outbounds = sbj_get(config, "outbounds");
    if (sbj_is_array(outbounds)) {
        for (size_t i = 0; i < outbounds->v.arr.len; ++i) {
            if (transform_outbound(&outbounds->v.arr.items[i], options, original_route_final,
                                   renamed, &changes, err) != 0)
                goto out;
        }
    }

    if (sbj_obj_len(renamed) > 0) {
        rewrite_tag_references(config, renamed);
        ++changes;
    }

    sbj *dns = sbj_get(config, "dns");
    if (sbj_is_object(dns)) {
        sbj *servers = sbj_get(dns, "servers");
        sbj *server;
        SBJ_ARR_FOREACH(servers, i, server) {
            if (!sbj_is_object(server)) continue;
            if (json_equals_string(sbj_get(server, "detour"), "wg-internal")) {
                sbj_del(server, "detour");
                ++changes;
            }
        }
    }

    {
        const sbj *route = sbj_get(config, "route");
        if (sbj_is_object(route)) {
            const sbj *final_value = sbj_get(route, "final");
            if (sbj_is_string(final_value) && !is_builtin_route(final_value->v.str.ptr))
                proxy_detour = sb_strdup(final_value->v.str.ptr);
        }
    }
    if (options->local_proxy_egress && proxy_detour && sbj_is_object(dns)) {
        sbj *servers = sbj_get(dns, "servers");
        if (sbj_is_array(servers)) {
            bool present = false;
            sbj *server;
            SBJ_ARR_FOREACH(servers, i, server) {
                if (!sbj_is_object(server)) continue;
                const char *tag = NULL;
                if (value_string(server, "tag", &tag, err) != 0) goto out;
                if (strcmp(tag, "proxy-dns") == 0) {
                    present = true;
                    break;
                }
            }
            if (!present) {
                sbj_arr_push(servers, proxy_dns_server(proxy_detour));
                ++changes;
            }
        }
        sbj *rules = sbj_get(dns, "rules");
        if (sbj_is_array(rules)) {
            bool present = false;
            sbj *item;
            SBJ_ARR_FOREACH(rules, i, item) {
                if (!sbj_is_object(item)) continue;
                const char *server_tag = NULL;
                if (value_string(item, "server", &server_tag, err) != 0) goto out;
                if (strcmp(server_tag, "proxy-dns") == 0) {
                    present = true;
                    break;
                }
            }
            if (!present) {
                sbj_arr_insert(rules, 0, proxy_dns_rule());
                ++changes;
            }
        }
    }

    if (!json_empty(local_rules)) {
        /* nlohmann config["route"]: null converts to an object, other
         * non-objects throw type_error 305. */
        if (sbj_is_null(config)) {
            sbj_free(config);
            config = sbj_object();
        }
        if (!sbj_is_object(config)) {
            sb_fail(err, SB_ERR_GENERIC,
                    "[json.exception.type_error.305] cannot use operator[] with a string "
                    "argument with %s",
                    sbj_type_name(config));
            goto out;
        }
        sbj *local_route = sbj_get_or_object(config, "route");
        if (!sbj_is_object(local_route)) {
            sb_fail(err, SB_ERR_VALIDATION, "route must be a JSON object");
            goto out;
        }
        sbj *rules = sbj_get_or_array(local_route, "rules");
        if (!sbj_is_array(rules)) {
            sb_fail(err, SB_ERR_VALIDATION, "route rules must be a JSON array");
            goto out;
        }
        for (size_t i = 0; i < local_rules->v.arr.len; ++i)
            sbj_arr_insert(rules, i, sbj_clone(local_rules->v.arr.items[i]));
        ++changes;
    }

    result = changes == 0 ? sb_strndup(body, len) : sbj_dump(config, 2);
out:
    free(original_route_final);
    free(proxy_detour);
    sbj_free(renamed);
    sbj_free(config);
    return result;
}

sbj *sb_agent_config_options_to_json(const sb_agent_config_options *options) {
    sbj *value = sbj_object();
    sbj_set_bool(value, "local_proxy_egress", options->local_proxy_egress);
    sbj_set(value, "default_proxy_outbound", sbj_str(options->default_proxy_outbound));
    sbj_set(value, "outbound_server_overrides",
            options->outbound_server_overrides ? sbj_clone(options->outbound_server_overrides)
                                               : sbj_object());
    sbj_set(value, "outbound_overrides",
            options->outbound_overrides ? sbj_clone(options->outbound_overrides)
                                        : sbj_object());
    return value;
}

static sbj *server_overrides_from_json(const sbj *value, sb_err *err) {
    if (!sbj_is_object(value)) {
        sb_fail(err, SB_ERR_VALIDATION, "outbound_server_overrides must be a JSON object");
        return NULL;
    }
    const char *tag = NULL;
    const sbj *server;
    SBJ_OBJ_FOREACH(value, i, tag, server) {
        if (tag[0] == '\0' || !sbj_is_string(server) || server->v.str.len == 0) {
            sb_fail(err, SB_ERR_VALIDATION,
                    "outbound_server_overrides values must be non-empty strings");
            return NULL;
        }
    }
    return sbj_clone(value);
}

static sbj *outbound_overrides_from_json(const sbj *value, sb_err *err) {
    if (!sbj_is_object(value)) {
        sb_fail(err, SB_ERR_VALIDATION, "outbound_overrides must be a JSON object");
        return NULL;
    }
    const char *tag = NULL;
    const sbj *outbound;
    SBJ_OBJ_FOREACH(value, i, tag, outbound) {
        if (tag[0] == '\0' || !sbj_is_object(outbound)) {
            sb_fail(err, SB_ERR_VALIDATION, "outbound_overrides values must be JSON objects");
            return NULL;
        }
    }
    return sbj_clone(value);
}

int sb_agent_config_options_from_json(const sbj *value,
                                      const sb_agent_config_options *defaults,
                                      sb_agent_config_options *out, sb_err *err) {
    if (!sbj_is_object(value))
        return sb_fail(err, SB_ERR_VALIDATION, "agent settings must be a JSON object");
    sb_agent_config_options options;
    if (defaults) sb_agent_config_options_copy(&options, defaults);
    else sb_agent_config_options_init(&options);

    const sbj *found = sbj_get(value, "local_proxy_egress");
    if (found) {
        if (!sbj_is_bool(found)) {
            sb_fail(err, SB_ERR_VALIDATION, "local_proxy_egress must be a boolean");
            goto fail;
        }
        options.local_proxy_egress = found->v.b;
    }
    found = sbj_get(value, "default_proxy_outbound");
    if (found) {
        if (sbj_is_null(found)) {
            sb_str_set(&options.default_proxy_outbound, NULL);
        } else if (sbj_is_string(found)) {
            sb_str_set(&options.default_proxy_outbound,
                       found->v.str.len == 0 ? NULL : found->v.str.ptr);
        } else {
            sb_fail(err, SB_ERR_VALIDATION, "default_proxy_outbound must be a string or null");
            goto fail;
        }
    }
    found = sbj_get(value, "outbound_server_overrides");
    if (found) {
        sbj *parsed = server_overrides_from_json(found, err);
        if (!parsed) goto fail;
        sbj_free(options.outbound_server_overrides);
        options.outbound_server_overrides = parsed;
    }
    found = sbj_get(value, "outbound_overrides");
    if (found) {
        sbj *parsed = outbound_overrides_from_json(found, err);
        if (!parsed) goto fail;
        sbj_free(options.outbound_overrides);
        options.outbound_overrides = parsed;
    }
    *out = options;
    return 0;
fail:
    sb_agent_config_options_free(&options);
    return -1;
}

int sb_agent_config_options_load(const char *path, const sb_agent_config_options *defaults,
                                 sb_agent_config_options *out, sb_err *err) {
    size_t len = 0;
    char *text = sb_read_file(path, &len);
    if (!text) {
        if (!sb_file_exists(path)) {
            if (defaults) sb_agent_config_options_copy(out, defaults);
            else sb_agent_config_options_init(out);
            return 0;
        }
        return sb_fail(err, SB_ERR_GENERIC, "cannot read agent settings: %s", path);
    }
    char parse_error[256] = {0};
    sbj *value = sbj_parse(text, len, parse_error, sizeof parse_error);
    free(text);
    if (!value)
        return sb_fail(err, SB_ERR_VALIDATION, "invalid agent settings %s: %s", path,
                       parse_error);
    sb_err inner = {0};
    int rc = sb_agent_config_options_from_json(value, defaults, out, &inner);
    sbj_free(value);
    if (rc != 0)
        return sb_fail(err, SB_ERR_VALIDATION, "invalid agent settings %s: %s", path,
                       inner.msg);
    return 0;
}

int sb_agent_config_options_save(const char *path, const sb_agent_config_options *options,
                                 sb_err *err) {
    sbj *value = sb_agent_config_options_to_json(options);
    char *text = sbj_dump(value, 2);
    sbj_free(value);
    sb_buf buf = {0};
    sb_buf_puts(&buf, text);
    sb_buf_putc(&buf, '\n');
    free(text);
    int rc = sb_atomic_replace_file(path, buf.p, buf.len, NULL, NULL, err);
    sb_buf_free(&buf);
    return rc;
}
