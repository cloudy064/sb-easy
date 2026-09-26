/* Config ETag (port of cpp config_etag.hpp). */
#ifndef SB_CONFIG_ETAG_H
#define SB_CONFIG_ETAG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Produces the quoted SHA-256 ETag used by the Rust agent API:
 * SHA256(host_id || pretty_config || seed). NULL arguments count as "".
 * Returns a malloc'd string like "\"<64 hex>\"", or NULL if OpenSSL fails. */
char *sb_config_etag(const char *host_id, const char *pretty_config, const char *seed);

#ifdef __cplusplus
}
#endif

#endif
