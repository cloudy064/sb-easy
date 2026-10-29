#include "auth_security_internal.h"
#include "sb/http_client.h"

#include <ctype.h>
#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

/* Authorization-code + S256 only. Provider data is untrusted even after TLS:
 * bounded, duplicate-free JSON and locally pinned issuer/algorithm/audience. */
#define OIDC_FLOW_SECONDS 300
#define OIDC_BODY_LIMIT (64u * 1024u)

typedef struct {
    bool present, enabled;
    char *issuer, *client_id, *secret_enc, *redirect_uri, *discovery;
} oidc_config;

static void config_free(oidc_config *c) {
    free(c->issuer);
    free(c->client_id);
    free(c->secret_enc);
    free(c->redirect_uri);
    free(c->discovery);
    memset(c, 0, sizeof *c);
}
static int config_load_locked(sb_auth_security *s, oidc_config *c, sb_err *err) {
    memset(c, 0, sizeof *c);
    SBQ_AUTO q = sbq_stmt_open(
        SB_AUTH_DB(s),
        "SELECT enabled,issuer,client_id,secret_enc,redirect_uri,discovery FROM auth_oidc_config WHERE id=1",
        err);
    if (q.rc != 0)
        return -1;
    sqlite3_stmt *st = q.st;
    int rc = sbq_step_row(st, err);
    if (rc == 1) {
        c->present = true;
        c->enabled = sbq_int(st, 0) != 0;
        c->issuer = sbq_text(st, 1);
        c->client_id = sbq_text(st, 2);
        c->secret_enc = sbq_opt_text(st, 3);
        c->redirect_uri = sbq_text(st, 4);
        c->discovery = sbq_text(st, 5);
    }
    return rc < 0 ? -1 : 0;
}
static bool config_same(const oidc_config *a, const oidc_config *b) {
    return a->present == b->present && a->enabled == b->enabled && sb_streq(a->issuer, b->issuer) &&
           sb_streq(a->client_id, b->client_id) && sb_streq(a->secret_enc, b->secret_enc) &&
           sb_streq(a->redirect_uri, b->redirect_uri) && sb_streq(a->discovery, b->discovery);
}
static bool text_valid(const sbj *v, size_t max, bool empty) {
    if (!sbj_is_string(v) || v->v.str.len > max || (!empty && !v->v.str.len) ||
        strlen(v->v.str.ptr) != v->v.str.len)
        return false;
    for (size_t i = 0; i < v->v.str.len; ++i)
        if ((unsigned char)v->v.str.ptr[i] < 0x20 || (unsigned char)v->v.str.ptr[i] == 0x7f)
            return false;
    return sbj_validate_utf8(v, NULL) == 0;
}
static bool ascii_token(const sbj *v, size_t max) {
    return text_valid(v, max, false) && sb_auth_sec_token(v->v.str.ptr, max);
}
static bool array_has(const sbj *a, const char *value) {
    if (!sbj_is_array(a) || sbj_arr_len(a) > 128)
        return false;
    for (size_t i = 0; i < sbj_arr_len(a); ++i)
        if (sbj_string_is(sbj_arr_at(a, i), value))
            return true;
    return false;
}
static bool url_valid(sb_auth_security *s, const char *url, bool allow_query) {
    if (!sb_auth_sec_token(url, 2048) || strchr(url, '\\') || strchr(url, '#') ||
        (!allow_query && strchr(url, '?')))
        return false;
    CURLU *u = curl_url();
    if (!u)
        return false;
    char *scheme = NULL, *host = NULL, *user = NULL, *password = NULL;
    bool ok = curl_url_set(u, CURLUPART_URL, url, 0) == CURLUE_OK &&
              curl_url_get(u, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
              curl_url_get(u, CURLUPART_HOST, &host, 0) == CURLUE_OK && host && *host;
    if (ok) {
        bool loopback = sb_streq(host, "127.0.0.1") || sb_streq(host, "[::1]");
        ok = sb_streq(scheme, "https") || (s->allow_loopback_oidc && loopback && sb_streq(scheme, "http"));
        if (curl_url_get(u, CURLUPART_USER, &user, 0) == CURLUE_OK ||
            curl_url_get(u, CURLUPART_PASSWORD, &password, 0) == CURLUE_OK)
            ok = false;
    }
    curl_free(scheme);
    curl_free(host);
    curl_free(user);
    curl_free(password);
    curl_url_cleanup(u);
    return ok;
}

/* Preflight raw JSON before the general parser (which permits duplicate keys).
 * The scanner bounds nesting/node counts and compares decoded object keys. */
typedef struct {
    const char *p, *end;
    size_t nodes;
} json_scan;
static void scan_space(json_scan *s) {
    while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\r' || *s->p == '\n'))
        ++s->p;
}
static bool scan_string(json_scan *s) {
    if (s->p == s->end || *s->p++ != '"')
        return false;
    while (s->p < s->end) {
        unsigned char c = (unsigned char)*s->p++;
        if (c == '"')
            return true;
        if (c < 0x20)
            return false;
        if (c == '\\') {
            if (s->p == s->end)
                return false;
            ++s->p;
        }
    }
    return false;
}
static bool scan_value(json_scan *s, unsigned depth) {
    scan_space(s);
    if (depth > 16 || ++s->nodes > 4096 || s->p == s->end)
        return false;
    if (*s->p == '"')
        return scan_string(s);
    if (*s->p == '{' || *s->p == '[') {
        bool object = *s->p++ == '{';
        char close = object ? '}' : ']';
        sb_strvec keys = {0};
        bool ok = false;
        scan_space(s);
        if (s->p < s->end && *s->p == close) {
            ++s->p;
            ok = true;
            goto done;
        }
        for (;;) {
            if (object) {
                scan_space(s);
                const char *start = s->p;
                if (!scan_string(s))
                    goto done;
                sbj *key = sbj_parse(start, (size_t)(s->p - start), NULL, 0);
                if (!text_valid(key, 4096, true) || sb_strvec_contains(&keys, key->v.str.ptr)) {
                    sbj_free(key);
                    goto done;
                }
                sb_strvec_push(&keys, key->v.str.ptr);
                sbj_free(key);
                scan_space(s);
                if (s->p == s->end || *s->p++ != ':')
                    goto done;
            }
            if (!scan_value(s, depth + 1))
                goto done;
            scan_space(s);
            if (s->p == s->end)
                goto done;
            if (*s->p == close) {
                ++s->p;
                ok = true;
                goto done;
            }
            if (*s->p++ != ',')
                goto done;
        }
    done:
        sb_strvec_free(&keys);
        return ok;
    }
    const char *start = s->p;
    while (s->p < s->end && !strchr(" \t\r\n,]}", *s->p))
        ++s->p;
    return s->p > start;
}
static sbj *strict_json(const char *raw, size_t len) {
    if (!raw || !len || len > OIDC_BODY_LIMIT || memchr(raw, 0, len))
        return NULL;
    json_scan scanner = {raw, raw + len, 0};
    if (!scan_value(&scanner, 0))
        return NULL;
    scan_space(&scanner);
    if (scanner.p != scanner.end)
        return NULL;
    sbj *value = sbj_parse(raw, len, NULL, 0);
    if (!sbj_is_object(value) || sbj_validate_utf8(value, NULL)) {
        sbj_free(value);
        return NULL;
    }
    return value;
}
static sbj *fetch_json(const char *url, const char *body, const char *authorization) {
    const char *headers[] = {"Accept: application/json",
                             body ? "Content-Type: application/x-www-form-urlencoded" : NULL, authorization,
                             NULL};
    /* GET has no authorization header; POST always has the content type. */
    sb_http_request request = {.method = body ? "POST" : "GET",
                               .url = url,
                               .headers = headers,
                               .body = body,
                               .body_len = body ? strlen(body) : 0,
                               .timeout_ms = 10000,
                               .max_body_bytes = OIDC_BODY_LIMIT,
                               .max_redirects = 0};
    sb_http_response response = {0};
    int rc = sb_http_perform(&request, &response, NULL);
    sbj *value = rc == 0 && response.status == 200 ? strict_json(response.body, response.body_len) : NULL;
    if (response.body)
        OPENSSL_cleanse(response.body, response.body_len);
    sb_http_response_free(&response);
    return value;
}
static char *secret_purpose(const oidc_config *c) {
    /* Length prefix prevents issuer/client concatenation collisions. */
    char *identity = sb_asprintf("%zu:%s:%s", strlen(c->issuer), c->issuer, c->client_id);
    char *digest = sb_sha256_hex(identity, strlen(identity));
    char *purpose = sb_asprintf("oidc-client:%s", digest);
    free(identity);
    free(digest);
    return purpose;
}
static sbj *discovery_get(sb_auth_security *s, const oidc_config *c, bool has_secret) {
    size_t length = strlen(c->issuer);
    while (length && c->issuer[length - 1] == '/')
        --length;
    char *url = sb_asprintf("%.*s/.well-known/openid-configuration", (int)length, c->issuer);
    sbj *d = fetch_json(url, NULL, NULL);
    free(url);
    if (!d || !sbj_string_is(sbj_get(d, "issuer"), c->issuer) ||
        !array_has(sbj_get(d, "response_types_supported"), "code") ||
        !array_has(sbj_get(d, "id_token_signing_alg_values_supported"), "RS256") ||
        (sbj_has(d, "code_challenge_methods_supported") &&
         !array_has(sbj_get(d, "code_challenge_methods_supported"), "S256")))
        goto bad;
    const char *fields[] = {"authorization_endpoint", "token_endpoint", "jwks_uri"};
    for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i) {
        const sbj *v = sbj_get(d, fields[i]);
        if (!ascii_token(v, 2048) || !url_valid(s, v->v.str.ptr, false))
            goto bad;
    }
    const sbj *methods = sbj_get(d, "token_endpoint_auth_methods_supported");
    const char *method = NULL;
    if (has_secret) {
        if (!methods || array_has(methods, "client_secret_basic"))
            method = "client_secret_basic";
        else if (array_has(methods, "client_secret_post"))
            method = "client_secret_post";
    } else if (array_has(methods, "none"))
        method = "none";
    if (!method)
        goto bad;
    sbj *saved = sbj_object();
    for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i)
        sbj_set(saved, fields[i], sbj_clone(sbj_get(d, fields[i])));
    sbj_set_str(saved, "auth_method", method);
    sbj_free(d);
    return saved;
bad:
    sbj_free(d);
    return NULL;
}

sbj *sb_auth_oidc_config(sb_auth_security *s, sb_err *err) {
    oidc_config c = {0};
    sb_database_lock(s->database);
    int rc = config_load_locked(s, &c, err);
    sb_database_unlock(s->database);
    if (rc)
        return NULL;
    sbj *result = sbj_object();
    sbj_set_bool(result, "enabled", c.enabled);
    if (c.present) {
        sbj_set_str(result, "issuer", c.issuer);
        sbj_set_str(result, "client_id", c.client_id);
        sbj_set_str(result, "redirect_uri", c.redirect_uri);
        sbj_set_bool(result, "has_client_secret", !sb_str_empty(c.secret_enc));
    }
    config_free(&c);
    return result;
}
int sb_auth_oidc_configure(sb_auth_security *s, const sbj *input, sb_err *err) {
    if (!sbj_is_object(input) || !sbj_is_bool(sbj_get(input, "enabled")))
        return sb_fail(err, SB_ERR_VALIDATION, "OIDC enabled must be a boolean");
    const char *allowed[] = {"enabled", "issuer", "client_id", "redirect_uri", "client_secret"};
    for (size_t i = 0; i < sbj_obj_len(input); ++i) {
        const char *key = sbj_obj_key(input, i);
        bool known = false;
        for (size_t j = 0; j < sizeof allowed / sizeof *allowed; ++j)
            known |= sb_streq(key, allowed[j]);
        if (!known || strlen(key) != input->v.obj.key_lens[i])
            return sb_fail(err, SB_ERR_VALIDATION, "Unknown OIDC configuration field");
    }
    if (!sbj_get_bool(input, "enabled", false)) {
        sb_database_lock(s->database);
        sqlite3 *db = SB_AUTH_DB(s);
        int rc = sbq_begin(db, err);
        if (!rc)
            rc = sbq_exec(db, "UPDATE auth_oidc_config SET enabled=0; DELETE FROM auth_oidc_flows", err);
        if (!rc)
            rc = sbq_commit(db, err);
        if (rc)
            sbq_rollback(db);
        sb_database_unlock(s->database);
        return rc;
    }
    if (!ascii_token(sbj_get(input, "issuer"), 2048) ||
        !text_valid(sbj_get(input, "client_id"), 512, false) ||
        !ascii_token(sbj_get(input, "redirect_uri"), 2048) ||
        !url_valid(s, sbj_get_str(input, "issuer", ""), false) ||
        !url_valid(s, sbj_get_str(input, "redirect_uri", ""), false) ||
        (sbj_has(input, "client_secret") && !text_valid(sbj_get(input, "client_secret"), 4096, true)))
        return sb_fail(err, SB_ERR_VALIDATION,
                       "OIDC requires valid HTTPS issuer, redirect URI and client credentials");
    oidc_config old = {0}, c = {.present = true, .enabled = true};
    sb_database_lock(s->database);
    int rc = config_load_locked(s, &old, err);
    sb_database_unlock(s->database);
    if (rc)
        return -1;
    c.issuer = sb_strdup(sbj_get_str(input, "issuer", ""));
    c.client_id = sb_strdup(sbj_get_str(input, "client_id", ""));
    c.redirect_uri = sb_strdup(sbj_get_str(input, "redirect_uri", ""));
    const char *secret = sbj_get_str(input, "client_secret", NULL);
    if (secret && *secret) {
        char *purpose = secret_purpose(&c);
        c.secret_enc = sb_auth_sec_encrypt(s, purpose, secret, err);
        free(purpose);
        if (!c.secret_enc) {
            rc = -1;
            goto done;
        }
    } else if (!secret && sb_streq(old.issuer, c.issuer) && sb_streq(old.client_id, c.client_id)) {
        c.secret_enc = sb_strdup(old.secret_enc);
    }
    sbj *d = discovery_get(s, &c, !sb_str_empty(c.secret_enc));
    if (!d) {
        rc =
            sb_fail(err, SB_ERR_VALIDATION, "OIDC discovery or supported authentication methods are invalid");
        goto done;
    }
    char *revision = sb_auth_sec_random(16, err);
    if (!revision) {
        sbj_free(d);
        rc = -1;
        goto done;
    }
    sbj_set_str(d, "revision", revision);
    free(revision);
    c.discovery = sbj_dump(d, -1);
    sbj_free(d);
    sb_database_lock(s->database);
    oidc_config current = {0};
    rc = config_load_locked(s, &current, err);
    if (!rc && !config_same(&old, &current))
        rc = sb_fail(err, SB_ERR_CONFLICT, "OIDC configuration changed; retry");
    config_free(&current);
    sqlite3 *db = SB_AUTH_DB(s);
    bool transaction = !rc && !sbq_begin(db, err);
    if (!rc && !transaction)
        rc = -1;
    sqlite3_stmt *st = !rc ? sbq_prepare(db,
                                         "INSERT INTO "
                                         "auth_oidc_config(id,enabled,issuer,client_id,secret_enc,redirect_"
                                         "uri,discovery) VALUES(1,1,?,?,?,?,?) "
                                         "ON CONFLICT(id) DO UPDATE SET "
                                         "enabled=1,issuer=excluded.issuer,client_id=excluded.client_id,"
                                         "secret_enc=excluded.secret_enc,redirect_uri=excluded.redirect_uri,"
                                         "discovery=excluded.discovery",
                                         err)
                           : NULL;
    if (!rc && !st)
        rc = -1;
    if (st) {
        sbq_bind_text(st, 1, c.issuer);
        sbq_bind_text(st, 2, c.client_id);
        sbq_bind_text(st, 3, c.secret_enc);
        sbq_bind_text(st, 4, c.redirect_uri);
        sbq_bind_text(st, 5, c.discovery);
        rc = sbq_step_done(st, err);
    }
    sqlite3_finalize(st);
    if (!rc)
        rc = sbq_exec(db, "DELETE FROM auth_oidc_flows", err);
    if (!rc)
        rc = sbq_commit(db, err);
    if (rc && transaction)
        sbq_rollback(db);
    sb_database_unlock(s->database);
done:
    config_free(&old);
    config_free(&c);
    return rc;
}
static void form_add(sb_buf *form, const char *name, const char *value) {
    char *encoded = sb_url_encode(value);
    if (form->len)
        sb_buf_putc(form, '&');
    sb_buf_printf(form, "%s=%s", name, encoded);
    free(encoded);
}
void sb_auth_oidc_start_free(sb_auth_oidc_start *start) {
    if (!start)
        return;
    free(start->authorization_url);
    sb_auth_sec_secret_free(start->browser_binding);
    memset(start, 0, sizeof *start);
}
int sb_auth_oidc_begin(sb_auth_security *s, sb_auth_oidc_start *out, sb_err *err) {
    if (!out)
        return sb_fail(err, SB_ERR_VALIDATION, "Missing OIDC result");
    memset(out, 0, sizeof *out);
    oidc_config c = {0};
    sb_database_lock(s->database);
    int rc = config_load_locked(s, &c, err);
    sb_database_unlock(s->database);
    if (rc)
        return -1;
    if (!c.enabled) {
        config_free(&c);
        return sb_fail(err, SB_ERR_AUTH, "OpenID Connect is disabled");
    }
    sbj *d = strict_json(c.discovery, strlen(c.discovery));
    char *state = sb_auth_sec_random(32, err), *binding = sb_auth_sec_random(32, err);
    char *nonce = sb_auth_sec_random(32, err), *verifier = sb_auth_sec_random(32, err);
    char *state_hash = NULL, *binding_hash = NULL, *encrypted = NULL, *challenge = NULL, *purpose = NULL;
    sb_buf form = {0};
    if (!d || !state || !binding || !nonce || !verifier) {
        rc = -1;
        goto done;
    }
    state_hash = sb_auth_sec_hash(s, "oidc-state", state);
    binding_hash = sb_auth_sec_hash(s, "oidc-browser", binding);
    purpose = sb_asprintf("oidc-verifier:%s", state_hash);
    encrypted = sb_auth_sec_encrypt(s, purpose, verifier, err);
    if (!encrypted) {
        rc = -1;
        goto done;
    }
    unsigned char hash[32];
    sb_sha256(verifier, strlen(verifier), hash);
    challenge = sb_base64url_encode(hash, sizeof hash);
    form_add(&form, "response_type", "code");
    form_add(&form, "client_id", c.client_id);
    form_add(&form, "redirect_uri", c.redirect_uri);
    form_add(&form, "scope", "openid");
    form_add(&form, "state", state);
    form_add(&form, "nonce", nonce);
    form_add(&form, "code_challenge_method", "S256");
    form_add(&form, "code_challenge", challenge);
    sb_database_lock(s->database);
    oidc_config current = {0};
    rc = config_load_locked(s, &current, err);
    if (!rc && !config_same(&c, &current))
        rc = sb_fail(err, SB_ERR_AUTH, "OIDC configuration changed");
    config_free(&current);
    sqlite3_stmt *st =
        !rc ? sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_oidc_flows WHERE expires_at<=?", err) : NULL;
    if (!rc && !st)
        rc = -1;
    if (st) {
        sbq_bind_int(st, 1, sb_unix_now());
        rc = sbq_step_done(st, err);
    }
    sqlite3_finalize(st);
    st = !rc ? sbq_prepare(SB_AUTH_DB(s),
                           "INSERT INTO "
                           "auth_oidc_flows(state_hash,binding_hash,verifier_enc,nonce,issuer,client_id,"
                           "redirect_uri,expires_at) "
                           "SELECT ?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM auth_oidc_flows)<1024",
                           err)
             : NULL;
    if (!rc && !st)
        rc = -1;
    if (st) {
        sbq_bind_text(st, 1, state_hash);
        sbq_bind_text(st, 2, binding_hash);
        sbq_bind_text(st, 3, encrypted);
        sbq_bind_text(st, 4, nonce);
        sbq_bind_text(st, 5, c.issuer);
        sbq_bind_text(st, 6, c.client_id);
        sbq_bind_text(st, 7, c.redirect_uri);
        sbq_bind_int(st, 8, sb_unix_now() + OIDC_FLOW_SECONDS);
        rc = sbq_step_done(st, err);
        if (!rc && sqlite3_changes(SB_AUTH_DB(s)) != 1)
            rc = sb_fail(err, SB_ERR_UNAVAILABLE, "Too many pending OIDC logins");
    }
    sqlite3_finalize(st);
    sb_database_unlock(s->database);
    if (!rc) {
        out->authorization_url = sb_asprintf("%s?%s", sbj_get_str(d, "authorization_endpoint", ""), form.p);
        out->browser_binding = binding;
        binding = NULL;
    }
done:
    config_free(&c);
    sbj_free(d);
    sb_auth_sec_secret_free(state);
    sb_auth_sec_secret_free(binding);
    sb_auth_sec_secret_free(nonce);
    sb_auth_sec_secret_free(verifier);
    free(state_hash);
    free(binding_hash);
    free(encrypted);
    free(challenge);
    free(purpose);
    sb_buf_free(&form);
    return rc;
}

/* Convert an explicitly eligible RSA JWK into a public-only OpenSSL key. */
static EVP_PKEY *jwk_key(const sbj *jwk) {
    if (!sbj_is_object(jwk) || !sbj_string_is(sbj_get(jwk, "kty"), "RSA") ||
        (sbj_has(jwk, "use") && !sbj_string_is(sbj_get(jwk, "use"), "sig")) ||
        (sbj_has(jwk, "alg") && !sbj_string_is(sbj_get(jwk, "alg"), "RS256")))
        return NULL;
    const char *private_fields[] = {"d", "p", "q", "dp", "dq", "qi", "oth"};
    for (size_t i = 0; i < sizeof private_fields / sizeof *private_fields; ++i)
        if (sbj_has(jwk, private_fields[i]))
            return NULL;
    const sbj *ops = sbj_get(jwk, "key_ops");
    if (ops && (!sbj_is_array(ops) || sbj_arr_len(ops) != 1 || !sbj_string_is(sbj_arr_at(ops, 0), "verify")))
        return NULL;
    const sbj *nv = sbj_get(jwk, "n"), *ev = sbj_get(jwk, "e");
    if (!ascii_token(nv, 1400) || !ascii_token(ev, 8))
        return NULL;
    size_t nl = 0, el = 0;
    unsigned char *nr = sb_base64url_decode_strict(nv->v.str.ptr, nv->v.str.len, &nl);
    unsigned char *er = sb_base64url_decode_strict(ev->v.str.ptr, ev->v.str.len, &el);
    BIGNUM *n = NULL, *e = NULL;
    EVP_PKEY *key = NULL;
    if (!nr || !er || nl < 256 || nl > 1024 || el == 0 || el > 4 || nr[0] == 0 || er[0] == 0)
        goto done;
    n = BN_bin2bn(nr, (int)nl, NULL);
    e = BN_bin2bn(er, (int)el, NULL);
    if (!n || !e || BN_num_bits(n) < 2048 || !BN_is_odd(n) || !BN_is_odd(e) || BN_get_word(e) < 3)
        goto done;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    bool ok = builder && context && OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, n) &&
              OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, e) &&
              (params = OSSL_PARAM_BLD_to_param(builder)) && EVP_PKEY_fromdata_init(context) > 0 &&
              EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) > 0;
    if (!ok) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
#else
    RSA *rsa = RSA_new();
    if (rsa && RSA_set0_key(rsa, n, e, NULL) == 1) {
        n = e = NULL;
        key = EVP_PKEY_new();
        if (!key || EVP_PKEY_assign_RSA(key, rsa) != 1) {
            EVP_PKEY_free(key);
            key = NULL;
            RSA_free(rsa);
        }
    } else
        RSA_free(rsa);
#endif
    if (key && sbj_has(jwk, "x5c")) {
        const sbj *chain = sbj_get(jwk, "x5c"), *first = sbj_arr_at(chain, 0);
        size_t length = 0;
        unsigned char *raw = ascii_token(first, 16384)
                                 ? sb_base64_decode_strict(first->v.str.ptr, first->v.str.len, &length)
                                 : NULL;
        const unsigned char *cursor = raw;
        X509 *cert = raw ? d2i_X509(NULL, &cursor, (long)length) : NULL;
        EVP_PKEY *cert_key = cert ? X509_get_pubkey(cert) : NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        bool match = cert_key && cursor == raw + length && EVP_PKEY_eq(key, cert_key) == 1;
#else
        bool match = cert_key && cursor == raw + length && EVP_PKEY_cmp(key, cert_key) == 1;
#endif
        if (!match) {
            EVP_PKEY_free(key);
            key = NULL;
        }
        EVP_PKEY_free(cert_key);
        X509_free(cert);
        free(raw);
    }
done:
    BN_free(n);
    BN_free(e);
    free(nr);
    free(er);
    return key;
}
static bool numeric_date(const sbj *v, int64_t *out) {
    if (!v || v->type != SBJ_INT || v->v.i <= 0 || v->v.i > INT64_C(253402300799))
        return false;
    *out = v->v.i;
    return true;
}
static char *verify_id_token(const oidc_config *c, const sbj *jwks, const sbj *token, const char *nonce,
                             int64_t created) {
    const sbj *id = sbj_get(token, "id_token");
    if (!ascii_token(id, 16384))
        return NULL;
    const char *compact = id->v.str.ptr, *dot = strchr(compact, '.'),
               *last = dot ? strchr(dot + 1, '.') : NULL;
    if (!dot || !last || strchr(last + 1, '.') || dot == compact || last == dot + 1 || !last[1] ||
        dot - compact > 3000 || last - dot > 12000)
        return NULL;
    size_t hl = 0, pl = 0, sl = 0;
    unsigned char *hr = sb_base64url_decode_strict(compact, (size_t)(dot - compact), &hl);
    unsigned char *pr = sb_base64url_decode_strict(dot + 1, (size_t)(last - dot - 1), &pl);
    unsigned char *sig = sb_base64url_decode_strict(last + 1, strlen(last + 1), &sl);
    sbj *h = hr && hl <= 2048 ? strict_json((char *)hr, hl) : NULL;
    sbj *p = pr && pl <= 8192 ? strict_json((char *)pr, pl) : NULL;
    EVP_PKEY *key = NULL;
    char *subject = NULL;
    if (!h || !p || !sig || !sbj_string_is(sbj_get(h, "alg"), "RS256"))
        goto done;
    const char *forbidden[] = {"crit", "b64", "enc", "cty", "jku", "jwk", "x5u"};
    for (size_t i = 0; i < sizeof forbidden / sizeof *forbidden; ++i)
        if (sbj_has(h, forbidden[i]))
            goto done;
    const sbj *typ = sbj_get(h, "typ"), *kid = sbj_get(h, "kid");
    if ((typ && !sbj_string_is(typ, "JWT") && !sbj_string_is(typ, "application/jwt")) ||
        (kid && !ascii_token(kid, 256)))
        goto done;
    const sbj *keys = sbj_get(jwks, "keys");
    if (!sbj_is_array(keys) || sbj_arr_len(keys) > 64)
        goto done;
    unsigned matches = 0;
    for (size_t i = 0; i < sbj_arr_len(keys); ++i) {
        const sbj *j = sbj_arr_at(keys, i), *jkid = sbj_get(j, "kid");
        if (kid && !sbj_equal(kid, jkid))
            continue;
        if (jkid && !ascii_token(jkid, 256))
            continue;
        EVP_PKEY *candidate = jwk_key(j);
        if (candidate) {
            ++matches;
            EVP_PKEY_free(key);
            key = candidate;
        }
    }
    if (matches != 1 || !key || sl != (size_t)EVP_PKEY_size(key))
        goto done;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pk = NULL;
    bool verified = md && EVP_DigestVerifyInit(md, &pk, EVP_sha256(), NULL, key) == 1 &&
                    EVP_PKEY_CTX_set_rsa_padding(pk, RSA_PKCS1_PADDING) > 0 &&
                    EVP_DigestVerifyUpdate(md, compact, (size_t)(last - compact)) == 1 &&
                    EVP_DigestVerifyFinal(md, sig, sl) == 1;
    EVP_MD_CTX_free(md);
    if (!verified)
        goto done;
    if (!sbj_string_is(sbj_get(p, "iss"), c->issuer) || !ascii_token(sbj_get(p, "sub"), 255) ||
        !ascii_token(sbj_get(p, "nonce"), 256) || !sb_consttime_streq(sbj_get_str(p, "nonce", ""), nonce))
        goto done;
    const sbj *aud = sbj_get(p, "aud"), *azp = sbj_get(p, "azp");
    bool audience = sbj_string_is(aud, c->client_id);
    if (sbj_is_array(aud)) {
        if (!sbj_arr_len(aud) || sbj_arr_len(aud) > 16)
            goto done;
        for (size_t i = 0; i < sbj_arr_len(aud); ++i) {
            if (!text_valid(sbj_arr_at(aud, i), 512, false))
                goto done;
            if (sbj_string_is(sbj_arr_at(aud, i), c->client_id))
                audience = true;
        }
        if (sbj_arr_len(aud) > 1 && !sbj_string_is(azp, c->client_id))
            goto done;
    }
    if (!audience || (azp && !sbj_string_is(azp, c->client_id)))
        goto done;
    int64_t exp = 0, iat = 0, optional = 0, now = sb_unix_now();
    if (!numeric_date(sbj_get(p, "exp"), &exp) || !numeric_date(sbj_get(p, "iat"), &iat) || exp <= now ||
        iat > now + 60 || iat > exp || iat < created - 60)
        goto done;
    if (sbj_has(p, "nbf") &&
        (!numeric_date(sbj_get(p, "nbf"), &optional) || optional > now + 60 || optional > exp))
        goto done;
    if (sbj_has(p, "auth_time") && (!numeric_date(sbj_get(p, "auth_time"), &optional) || optional > now + 60))
        goto done;
    if (sbj_has(p, "at_hash")) {
        const sbj *access = sbj_get(token, "access_token"), *claim = sbj_get(p, "at_hash");
        if (!ascii_token(access, 16384) || !ascii_token(claim, 128))
            goto done;
        unsigned char digest[32];
        sb_sha256(access->v.str.ptr, access->v.str.len, digest);
        char *expected = sb_base64url_encode(digest, 16);
        bool match = sb_consttime_streq(expected, claim->v.str.ptr);
        free(expected);
        if (!match)
            goto done;
    }
    subject = sb_strdup(sbj_get_str(p, "sub", ""));
done:
    EVP_PKEY_free(key);
    sbj_free(h);
    sbj_free(p);
    free(hr);
    if (pr) {
        OPENSSL_cleanse(pr, pl);
        free(pr);
    }
    free(sig);
    return subject;
}
static bool opaque_nonce(const char *value) {
    if (!value || strlen(value) != 43)
        return false;
    size_t length = 0;
    unsigned char *raw = sb_base64url_decode_strict(value, 43, &length);
    bool ok = raw && length == 32;
    free(raw);
    return ok;
}
char *sb_auth_oidc_finish(sb_auth_security *s, const char *state, const char *code,
                          const char *browser_binding, sb_err *err) {
    if (!opaque_nonce(state) || !opaque_nonce(browser_binding) || !sb_auth_sec_token(code, 4096)) {
        sb_fail(err, SB_ERR_AUTH, "OIDC authentication failed");
        return NULL;
    }
    oidc_config c = {0};
    char *state_hash = sb_auth_sec_hash(s, "oidc-state", state);
    char *binding_hash = sb_auth_sec_hash(s, "oidc-browser", browser_binding);
    char *verifier_enc = NULL, *nonce = NULL, *verifier = NULL, *secret = NULL, *authorization = NULL;
    char *purpose = NULL, *subject = NULL, *user_id = NULL;
    int64_t expires = 0;
    sbj *d = NULL, *token = NULL, *jwks = NULL;
    sb_buf body = {0};
    sb_database_lock(s->database);
    sqlite3 *db = SB_AUTH_DB(s);
    int rc = sbq_begin(db, NULL);
    sqlite3_stmt *st =
        !rc ? sbq_prepare(db,
                          "SELECT binding_hash,verifier_enc,nonce,issuer,client_id,redirect_uri,expires_at "
                          "FROM auth_oidc_flows WHERE state_hash=?",
                          NULL)
            : NULL;
    bool accepted = false;
    if (st) {
        sbq_bind_text(st, 1, state_hash);
        if (sbq_step_row(st, NULL) == 1 && !config_load_locked(s, &c, NULL)) {
            char *binding_saved = sbq_text(st, 0), *issuer = sbq_text(st, 3);
            char *client = sbq_text(st, 4), *redirect = sbq_text(st, 5);
            expires = sbq_int(st, 6);
            accepted = c.enabled && expires > sb_unix_now() &&
                       sb_consttime_streq(binding_saved, binding_hash) && sb_streq(c.issuer, issuer) &&
                       sb_streq(c.client_id, client) && sb_streq(c.redirect_uri, redirect);
            if (accepted) {
                verifier_enc = sbq_text(st, 1);
                nonce = sbq_text(st, 2);
            }
            free(binding_saved);
            free(issuer);
            free(client);
            free(redirect);
        }
    }
    sqlite3_finalize(st);
    st = !rc ? sbq_prepare(db, "DELETE FROM auth_oidc_flows WHERE state_hash=?", NULL) : NULL;
    if (!st)
        rc = -1;
    if (st) {
        sbq_bind_text(st, 1, state_hash);
        rc = sbq_step_done(st, NULL);
    }
    sqlite3_finalize(st);
    if (!rc)
        rc = sbq_commit(db, NULL);
    if (rc)
        sbq_rollback(db);
    sb_database_unlock(s->database);
    if (rc || !accepted)
        goto done;
    purpose = sb_asprintf("oidc-verifier:%s", state_hash);
    verifier = sb_auth_sec_decrypt(s, purpose, verifier_enc, NULL);
    free(purpose);
    purpose = NULL;
    if (!opaque_nonce(verifier))
        goto done;
    d = strict_json(c.discovery, strlen(c.discovery));
    if (!d)
        goto done;
    if (c.secret_enc) {
        purpose = secret_purpose(&c);
        secret = sb_auth_sec_decrypt(s, purpose, c.secret_enc, NULL);
        free(purpose);
        purpose = NULL;
        if (!secret)
            goto done;
    }
    form_add(&body, "grant_type", "authorization_code");
    form_add(&body, "code", code);
    form_add(&body, "redirect_uri", c.redirect_uri);
    form_add(&body, "code_verifier", verifier);
    const char *method = sbj_get_str(d, "auth_method", "");
    if (sb_streq(method, "client_secret_basic") && secret) {
        char *client_encoded = sb_url_encode(c.client_id), *secret_encoded = sb_url_encode(secret);
        char *plain = sb_asprintf("%s:%s", client_encoded, secret_encoded);
        char *encoded = sb_base64_encode((unsigned char *)plain, strlen(plain));
        authorization = sb_asprintf("Authorization: Basic %s", encoded);
        free(client_encoded);
        sb_auth_sec_secret_free(secret_encoded);
        sb_auth_sec_secret_free(plain);
        sb_auth_sec_secret_free(encoded);
    } else if (sb_streq(method, "client_secret_post") && secret) {
        form_add(&body, "client_id", c.client_id);
        form_add(&body, "client_secret", secret);
    } else if (sb_streq(method, "none") && !secret)
        form_add(&body, "client_id", c.client_id);
    else
        goto done;
    token = fetch_json(sbj_get_str(d, "token_endpoint", ""), body.p, authorization);
    if (!token || sbj_has(token, "error"))
        goto done;
    jwks = fetch_json(sbj_get_str(d, "jwks_uri", ""), NULL, NULL);
    if (!jwks)
        goto done;
    subject = verify_id_token(&c, jwks, token, nonce, expires - OIDC_FLOW_SECONDS);
    if (!subject)
        goto done;
    /* A disable/config change while exchanging the code invalidates the login. */
    sb_database_lock(s->database);
    oidc_config current = {0};
    if (!config_load_locked(s, &current, NULL) && config_same(&c, &current) && expires > sb_unix_now()) {
        st = sbq_prepare(db,
                         "SELECT l.user_id FROM auth_oidc_links l JOIN users u ON u.id=l.user_id WHERE "
                         "issuer=? AND subject=?",
                         NULL);
        if (st) {
            sbq_bind_text(st, 1, c.issuer);
            sbq_bind_text(st, 2, subject);
            if (sbq_step_row(st, NULL) == 1)
                user_id = sbq_text(st, 0);
        }
        sqlite3_finalize(st);
    }
    config_free(&current);
    sb_database_unlock(s->database);
done:
    if (!user_id)
        sb_fail(err, SB_ERR_AUTH, "OIDC authentication failed");
    config_free(&c);
    free(state_hash);
    free(binding_hash);
    free(verifier_enc);
    free(nonce);
    free(purpose);
    free(subject);
    sb_auth_sec_secret_free(verifier);
    sb_auth_sec_secret_free(secret);
    sb_auth_sec_secret_free(authorization);
    if (body.p)
        OPENSSL_cleanse(body.p, body.len);
    sb_buf_free(&body);
    sbj_free(d);
    sbj_free(token);
    sbj_free(jwks);
    return user_id;
}
int sb_auth_oidc_link(sb_auth_security *s, const char *user_id, const char *issuer, const char *subject,
                      bool remove, sb_err *err) {
    if (!sb_auth_sec_token(user_id, 256) || !url_valid(s, issuer, false) || !sb_auth_sec_token(subject, 255))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid OIDC identity link");
    sb_database_lock(s->database);
    int exists = sb_auth_sec_user_exists_locked(s, user_id, err);
    int rc = exists == 1 ? 0 : exists < 0 ? -1 : sb_fail(err, SB_ERR_NOT_FOUND, "User not found");
    if (!rc) {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s),
                                   remove ? "DELETE FROM auth_oidc_links WHERE user_id=? AND issuer=? AND subject=?"
                                          : "INSERT INTO auth_oidc_links(user_id,issuer,subject) VALUES(?,?,?) ON "
                                            "CONFLICT(issuer,subject) DO NOTHING",
                                   err);
        if (q.rc != 0) {
            rc = -1;
        } else {
            sbq_bind_text(q.st, 1, user_id);
            sbq_bind_text(q.st, 2, issuer);
            sbq_bind_text(q.st, 3, subject);
            rc = sbq_step_done(q.st, err);
        }
    }
    if (!rc && !remove) {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT user_id FROM auth_oidc_links WHERE issuer=? AND subject=?",
                                   err);
        if (q.rc != 0)
            rc = -1;
        else {
            sbq_bind_text(q.st, 1, issuer);
            sbq_bind_text(q.st, 2, subject);
            int step = sbq_step_row(q.st, err);
            char *owner = step == 1 ? sbq_text(q.st, 0) : NULL;
            if (step < 0)
                rc = -1;
            else if (!sb_streq(owner, user_id))
                rc = sb_fail(err, SB_ERR_CONFLICT, "OIDC identity is already linked to another user");
            free(owner);
        }
    }
    sb_database_unlock(s->database);
    return rc;
}
sbj *sb_auth_oidc_links(sb_auth_security *s, const char *user_id, sb_err *err) {
    if (!sb_auth_sec_token(user_id, 256)) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid user ID");
        return NULL;
    }
    sb_database_lock(s->database);
    int exists = sb_auth_sec_user_exists_locked(s, user_id, err);
    sbj *result = exists == 1 ? sbj_array() : NULL;
    if (exists == 0)
        sb_fail(err, SB_ERR_NOT_FOUND, "User not found");
    if (result) {
        SBQ_AUTO q = sbq_stmt_open(
            SB_AUTH_DB(s),
            "SELECT issuer,subject FROM auth_oidc_links WHERE user_id=? ORDER BY issuer,subject", err);
        if (q.rc != 0) {
            sbj_free(result);
            result = NULL;
        } else {
            sbq_bind_text(q.st, 1, user_id);
            int step;
            while ((step = sbq_step_row(q.st, err)) == 1) {
                sbj *link = sbj_object();
                char *issuer = sbq_text(q.st, 0), *subject = sbq_text(q.st, 1);
                sbj_set_str(link, "issuer", issuer);
                sbj_set_str(link, "subject", subject);
                sbj_arr_push(result, link);
                free(issuer);
                free(subject);
            }
            if (step < 0) {
                sbj_free(result);
                result = NULL;
            }
        }
    }
    sb_database_unlock(s->database);
    return result;
}
