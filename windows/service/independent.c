#include "independent.h"
#include "subscriptions.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool sbw_identity_is_independent(const sbj *identity) {
    return sbj_is_object(identity) && sbj_string_is(sbj_get(identity, "mode"), "independent");
}
sbj *sbw_independent_identity(void) {
    sbj *identity = sbj_object();
    sbj_set_str(identity, "mode", "independent");
    sbj_set_str(identity, "server", "");
    sbj_set_str(identity, "host_id", "");
    sbj_set_str(identity, "agent_token", "");
    sbj_set_str(identity, "host_name", "本机独立配置");
    sbj_set_str(identity, "profile_id", "local");
    sbj_set_str(identity, "profile_name", "本机订阅");
    sbj_set(identity, "local_subscriptions", sbj_array());
    return identity;
}
static char *content_hash(const char *content) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    DWORD size = 0, length = 0;
    BYTE *object = NULL;
    char *out = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0 ||
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (BYTE *)&length, sizeof(length), &size, 0) < 0)
        goto done;
    object = sb_xmalloc(length);
    if (BCryptCreateHash(alg, &hash, object, length, NULL, 0, 0) < 0 ||
        BCryptHashData(hash, (BYTE *)content, (ULONG)strlen(content), 0) < 0 ||
        BCryptFinishHash(hash, digest, sizeof(digest), 0) < 0)
        goto done;
    out = sb_xcalloc(71, 1);
    strcpy_s(out, 71, "local-");
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[6 + 2 * i] = hex[digest[i] >> 4];
        out[7 + 2 * i] = hex[digest[i] & 15];
    }
done:
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    free(object);
    SecureZeroMemory(digest, sizeof(digest));
    return out;
}
sbj *sbw_independent_snapshot(const sbj *identity, sbw_error *error) {
    if (!sbw_identity_is_independent(identity)) {
        sbw_fail(error, "INVALID_REQUEST", "This profile is not independent.");
        return NULL;
    }
    sbj *config = sbj_parse_cstr(
        "{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"local-tun\",\"interface_name\":\"sb-easy\",\"address\":["
        "\"172.19.0.1/30\",\"fd71:5be:a5e::1/"
        "126\"],\"auto_route\":true,\"strict_route\":true}],\"outbounds\":[{\"type\":\"direct\",\"tag\":"
        "\"direct\"}],\"dns\":{\"servers\":[{\"type\":\"https\",\"tag\":\"local-remote-dns\",\"server\":\"1."
        "1.1.1\",\"path\":\"/"
        "dns-query\"},{\"type\":\"https\",\"tag\":\"local-bootstrap-dns\",\"server\":\"1.1.1.1\",\"path\":\"/"
        "dns-query\"}],\"rules\":[],\"final\":\"local-remote-dns\",\"strategy\":\"prefer_ipv4\","
        "\"independent_cache\":true},\"route\":{\"auto_detect_interface\":true,\"find_process\":true,"
        "\"rules\":[{\"action\":\"sniff\"},{\"protocol\":\"dns\",\"action\":\"hijack-dns\"},{\"ip_is_"
        "private\":true,\"outbound\":\"direct\"}],\"final\":\"direct\",\"default_domain_resolver\":\"local-"
        "bootstrap-dns\"}}");
    sbj *check = sbj_clone(config);
    if (sbw_subscriptions_merge(check, identity, error)) {
        sbj_free(check);
        sbj_free(config);
        return NULL;
    }
    const sbj *nodes = sbj_get(check, "outbounds");
    const char *first = "direct";
    if (sbj_arr_len(nodes) > 1)
        first = sbj_get_str(sbj_arr_at(nodes, 1), "tag", "direct");
    sbj_set_str(sbj_get(config, "route"), "final", first);
    if (strcmp(first, "direct"))
        sbj_set_str(sbj_arr_at(sbj_get(sbj_get(config, "dns"), "servers"), 0), "detour", first);
    /* The ETag includes imported node bytes, so credential and endpoint changes
     * invalidate a previously checked configuration without leaking them. */
    sbj_set(check, "route", sbj_clone(sbj_get(config, "route")));
    sbj_set(check, "dns", sbj_clone(sbj_get(config, "dns")));
    char *full = sbj_dump(check, -1), *etag = content_hash(full);
    sbw_secret_free(full);
    sbj_free(check);
    if (!etag) {
        sbj_free(config);
        sbw_fail(error, "RUNTIME_RESOURCE_ERROR", "The local configuration digest could not be generated.");
        return NULL;
    }
    sbj *snapshot = sbj_object();
    sbj_set(snapshot, "content", sbj_str_take(sbj_dump(config, -1)));
    sbj_set_str(snapshot, "etag", etag);
    sbj_set_str(snapshot, "rule_source", "local");
    sbj_set_str(snapshot, "profile_id", "local");
    sbj_set_str(snapshot, "profile_name", "本机订阅");
    sbj_set(snapshot, "subscription_sources", sbj_array());
    free(etag);
    sbj_free(config);
    return snapshot;
}
