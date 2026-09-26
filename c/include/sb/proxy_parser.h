/* Proxy share-link / subscription / sing-box outbound parsing
 * (C++ proxy_parser.hpp). sb_parsed_node and its vector live in sb/types.h. */
#ifndef SB_PROXY_PARSER_H
#define SB_PROXY_PARSER_H

#include <stddef.h>

#include "sb/json.h"
#include "sb/types.h"
#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* C++ ProxyImport. */
typedef struct {
    sb_parsed_node_vec nodes;
    sb_strvec skipped;
} sb_proxy_import;

void sb_proxy_import_init(sb_proxy_import *imp);
void sb_proxy_import_free(sb_proxy_import *imp);

/* Parse one supported proxy URI:
 * ss, vmess, trojan, vless, hysteria2/hy2, or tuic. HTTP is config-only.
 * Returns 1 and fills *out (initialised by the callee) when parsed, 0 when the
 * URI is unsupported or invalid (std::nullopt). */
int sb_parse_proxy_uri(const char *uri, sb_parsed_node *out);

/* Same, but reports the exceptions the C++ version can throw (nlohmann
 * type_error for vmess JSON with mistyped fields, e.g. a string "aid") as
 * SB_ERR_GENERIC with the nlohmann message. Returns 1 parsed, 0 nullopt,
 * -1 error. `uri` may contain NULs (len is exact). */
int sb_parse_proxy_uri_ex(const char *uri, size_t len, sb_parsed_node *out, sb_err *err);

/* Parse a subscription response as Clash YAML, a base64-encoded URI list, or
 * a plain newline-separated URI list. On an exception the C++ version would
 * throw, the partial result is discarded and an empty vector is returned; use
 * the _ex variant to observe the error. */
sb_parsed_node_vec sb_parse_subscription_body(const char *body, size_t len);
/* Returns 0 and fills *out, or -1 (out left empty) with err set. */
int sb_parse_subscription_body_ex(const char *body, size_t len, sb_parsed_node_vec *out,
                                  sb_err *err);

/* Parse proxy outbounds from a complete sing-box config or a bare outbounds
 * array. Selector/urltest and built-in outbounds are ignored. Returns 0, or -1
 * with err set (nlohmann type_error messages for mistyped "type"/"tag"). *out
 * is initialised by the callee and is empty on failure. */
int sb_parse_outbound_config(const sbj *config, sb_proxy_import *out, sb_err *err);

#ifdef __cplusplus
}
#endif

#endif
