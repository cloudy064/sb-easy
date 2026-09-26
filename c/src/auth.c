/* Argon2id password hashing and HS256 JWT sessions. Port of cpp/src/auth.cpp. */
#include "sb/auth.h"

#include <stdlib.h>
#include <string.h>

#include <argon2.h>
#include <openssl/crypto.h>

#include "sb/json.h"

#define ARGON_TIME_COST 2U
#define ARGON_MEMORY_COST (19U * 1024U)
#define ARGON_PARALLELISM 1U
#define ARGON_SALT_BYTES 16U
#define ARGON_HASH_BYTES 32U
#define TOKEN_LIFETIME_SECONDS ((int64_t)72 * 60 * 60)

void sb_auth_claims_free(sb_auth_claims *c) {
    if (!c) return;
    free(c->subject);
    free(c->username);
    free(c->role);
    memset(c, 0, sizeof *c);
}

/* Decodes unpadded base64url; rejects anything that does not re-encode to the
 * identical text (the C++ canonical check). */
static unsigned char *b64url_decode(const char *text, size_t len, size_t *out_len) {
    if (len % 4U == 1U) return NULL;
    for (size_t i = 0; i < len; ++i) {
        char c = text[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_'))
            return NULL;
    }
    unsigned char *decoded;
    size_t n = 0;
    if (len == 0) {
        decoded = sb_xcalloc(1, 1);
    } else {
        decoded = sb_base64_decode(text, len, &n);
        if (!decoded) return NULL;
    }
    char *again = sb_base64url_encode(decoded, n);
    bool same = again && strlen(again) == len && memcmp(again, text, len) == 0;
    free(again);
    if (!same) {
        free(decoded);
        return NULL;
    }
    *out_len = n;
    return decoded;
}

static sbj *decode_json_segment(const char *text, size_t len) {
    size_t n = 0;
    unsigned char *raw = b64url_decode(text, len, &n);
    if (!raw) return NULL;
    sbj *value = sbj_parse((const char *)raw, n, NULL, 0);
    free(raw);
    if (!sbj_is_object(value)) {
        sbj_free(value);
        return NULL;
    }
    return value;
}

char *sb_hash_password(const char *password, sb_err *err) {
    unsigned char salt[ARGON_SALT_BYTES];
    if (sb_random_bytes(salt, sizeof salt) != 0) {
        sb_fail(err, SB_ERR_GENERIC, "password salt generation failed");
        return NULL;
    }
    size_t encoded_size = argon2_encodedlen(ARGON_TIME_COST, ARGON_MEMORY_COST,
                                            ARGON_PARALLELISM, sizeof salt,
                                            ARGON_HASH_BYTES, Argon2_id);
    char *encoded = sb_xcalloc(encoded_size + 1, 1);
    const char *pw = password ? password : "";
    int result = argon2id_hash_encoded(ARGON_TIME_COST, ARGON_MEMORY_COST, ARGON_PARALLELISM,
                                       pw, strlen(pw), salt, sizeof salt, ARGON_HASH_BYTES,
                                       encoded, encoded_size);
    if (result != ARGON2_OK) {
        free(encoded);
        sb_fail(err, SB_ERR_GENERIC, "password hashing failed: %s", argon2_error_message(result));
        return NULL;
    }
    return encoded;
}

bool sb_verify_password(const char *password, const char *encoded_hash) {
    if (sb_str_empty(encoded_hash)) return false;
    const char *pw = password ? password : "";
    return argon2id_verify(encoded_hash, pw, strlen(pw)) == ARGON2_OK;
}

char *sb_auth_create_token(const char *secret, const char *user_id, const char *username,
                           const char *role) {
    if (sb_str_empty(secret)) {
        SB_ERROR("JWT secret is not configured");
        return NULL;
    }
    int64_t issued_at = sb_unix_now();
    sbj *h = sbj_object();
    sbj_set_str(h, "alg", "HS256");
    sbj_set_str(h, "typ", "JWT");
    sbj *p = sbj_object();
    sbj_set_str(p, "sub", user_id ? user_id : "");
    sbj_set_str(p, "username", username ? username : "");
    sbj_set_str(p, "role", role ? role : "");
    sbj_set_int(p, "exp", issued_at + TOKEN_LIFETIME_SECONDS);
    sbj_set_int(p, "iat", issued_at);
    char *header = sbj_dump(h, -1), *payload = sbj_dump(p, -1);
    sbj_free(h);
    sbj_free(p);
    char *eh = sb_base64url_encode((const unsigned char *)header, strlen(header));
    char *ep = sb_base64url_encode((const unsigned char *)payload, strlen(payload));
    free(header);
    free(payload);
    char *unsigned_token = sb_asprintf("%s.%s", eh, ep);
    free(eh);
    free(ep);
    unsigned char digest[32];
    sb_hmac_sha256(secret, strlen(secret), unsigned_token, strlen(unsigned_token), digest);
    char *sig = sb_base64url_encode(digest, sizeof digest);
    char *token = sb_asprintf("%s.%s", unsigned_token, sig);
    free(unsigned_token);
    free(sig);
    return token;
}

bool sb_auth_verify_token(const char *secret, const char *token, sb_auth_claims *out) {
    if (sb_str_empty(secret) || !token) return false;
    const char *first = strchr(token, '.');
    const char *second = first ? strchr(first + 1, '.') : NULL;
    if (!first || !second || strchr(second + 1, '.')) return false;

    bool ok = false;
    sbj *header = decode_json_segment(token, (size_t)(first - token));
    sbj *payload = decode_json_segment(first + 1, (size_t)(second - first - 1));
    size_t sig_len = 0;
    unsigned char *supplied = b64url_decode(second + 1, strlen(second + 1), &sig_len);
    if (!header || !payload || !supplied ||
        !sb_streq(sbj_get_str(header, "alg", ""), "HS256") || sig_len != 32U)
        goto done;
    unsigned char expected[32];
    sb_hmac_sha256(secret, strlen(secret), token, (size_t)(second - token), expected);
    if (CRYPTO_memcmp(expected, supplied, 32) != 0) goto done;

    sbj *sub = sbj_get(payload, "sub"), *user = sbj_get(payload, "username"),
        *role = sbj_get(payload, "role"), *exp = sbj_get(payload, "exp"),
        *iat = sbj_get(payload, "iat");
    if (!sbj_is_string(sub) || !sbj_is_string(user) || !sbj_is_string(role) ||
        !sbj_is_integer(exp) || !sbj_is_integer(iat))
        goto done;
    int64_t expires_at = sbj_as_int(exp, 0);
    if (expires_at <= sb_unix_now()) goto done;
    if (out) {
        out->subject = sb_strdup(sub->v.str.ptr);
        out->username = sb_strdup(user->v.str.ptr);
        out->role = sb_strdup(role->v.str.ptr);
        out->expires_at = expires_at;
        out->issued_at = sbj_as_int(iat, 0);
    }
    ok = true;
done:
    sbj_free(header);
    sbj_free(payload);
    free(supplied);
    return ok;
}
