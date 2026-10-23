#include "sb/auth_security.h"
#include "../src/auth_security_internal.h"
#include "test.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <pthread.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum {
    VALID,
    BAD_NONCE,
    BAD_ISSUER,
    BAD_AUD,
    BAD_AZP,
    MULTI_AUD,
    MULTI_AUD_OK,
    EXPIRED,
    FUTURE_IAT,
    OLD_IAT,
    FUTURE_NBF,
    FLOAT_EXP,
    BAD_SIG,
    ALG_NONE,
    ALG_HS256,
    NO_KID,
    WRONG_KID,
    BAD_AT_HASH,
    DUP_CLAIM,
    ESCAPED_DUP_CLAIM,
    DUP_HEADER,
    CRIT_HEADER,
    JKU_HEADER,
    UNKNOWN_SUB,
    CONFIG_DISABLE,
    DELETED_USER,
    DUP_KEY,
    PRIVATE_KEY,
    EMPTY_KEYS,
    BAD_KEY_USE,
    SMALL_KEY,
    BAD_X5C,
    TOKEN_ERROR,
    CONFIG_REVISION,
    EXPIRED_FLOW_DURING_EXCHANGE
} token_mode;
typedef struct {
    sb_database *db;
    sb_auth_security *auth;
    int listener, port;
    pthread_t thread;
    pthread_mutex_t mutex;
    EVP_PKEY *key;
    char *issuer;
    sbj *jwk;
    char *nonce, *challenge, *state, *token_body, *token_authorization;
    token_mode mode;
    int metadata_mode, auth_method, token_requests, jwks_requests;
    bool pkce_valid;
} fixture;

static char *header(const char *raw, const char *name) {
    size_t n = strlen(name);
    for (const char *p = raw; p && *p;) {
        const char *end = strstr(p, "\r\n");
        if (!end)
            break;
        if ((size_t)(end - p) > n && !strncasecmp(p, name, n) && p[n] == ':') {
            const char *value = p + n + 1;
            while (*value == ' ')
                ++value;
            return sb_strndup(value, (size_t)(end - value));
        }
        p = end + 2;
    }
    return NULL;
}
static char *parameter(const char *query, const char *key) {
    if (!query)
        return NULL;
    sb_strvec parts = sb_split(query, '&');
    char *value = NULL;
    for (size_t i = 0; i < parts.len; ++i) {
        const char *equal = strchr(parts.items[i], '=');
        if (equal && sb_strn_eq(parts.items[i], (size_t)(equal - parts.items[i]), key)) {
            free(value);
            value = sb_url_decode(equal + 1, true);
        }
    }
    sb_strvec_free(&parts);
    return value;
}
static char *sign_token(fixture *f) {
    int64_t now = sb_unix_now();
    sbj *h = sbj_object(), *p = sbj_object();
    sbj_set_str(h, "alg", f->mode == ALG_NONE ? "none" : f->mode == ALG_HS256 ? "HS256" : "RS256");
    sbj_set_str(h, "typ", "JWT");
    if (f->mode != NO_KID)
        sbj_set_str(h, "kid", f->mode == WRONG_KID ? "unknown" : "fixture-key");
    if (f->mode == CRIT_HEADER)
        sbj_set(h, "crit", sbj_array());
    if (f->mode == JKU_HEADER)
        sbj_set_str(h, "jku", "http://127.0.0.1/attacker");
    sbj_set_str(p, "iss", f->mode == BAD_ISSUER ? "https://another.example" : f->issuer);
    sbj_set_str(p, "sub", f->mode == UNKNOWN_SUB ? "unmapped" : "fixture-subject");
    sbj_set_str(p, "aud", f->mode == BAD_AUD ? "wrong-client" : "fixture-client");
    sbj_set_str(p, "email", "admin@example.test");
    sbj_set_str(p, "role", "admin");
    if (f->mode == BAD_AZP)
        sbj_set_str(p, "azp", "wrong-client");
    if (f->mode == MULTI_AUD || f->mode == MULTI_AUD_OK) {
        sbj *aud = sbj_array();
        sbj_arr_push(aud, sbj_str("fixture-client"));
        sbj_arr_push(aud, sbj_str("another-client"));
        sbj_set(p, "aud", aud);
        if (f->mode == MULTI_AUD_OK)
            sbj_set_str(p, "azp", "fixture-client");
    }
    sbj_set_str(p, "nonce", f->mode == BAD_NONCE ? "wrong-nonce" : f->nonce);
    sbj_set_int(p, "exp", f->mode == EXPIRED ? now - 1 : now + 120);
    sbj_set_int(p, "iat", f->mode == FUTURE_IAT ? now + 300 : f->mode == OLD_IAT ? now - 3600 : now);
    if (f->mode == FLOAT_EXP)
        sbj_set_float(p, "exp", (double)now + 100.25);
    if (f->mode == FUTURE_NBF)
        sbj_set_int(p, "nbf", now + 90);
    unsigned char hash[32];
    sb_sha256("fixture-access-token", 20, hash);
    char *at_hash = sb_base64url_encode(hash, 16);
    sbj_set_str(p, "at_hash", f->mode == BAD_AT_HASH ? "wrong" : at_hash);
    free(at_hash);
    char *hs = sbj_dump(h, -1), *ps = sbj_dump(p, -1);
    sbj_free(h);
    sbj_free(p);
    if (f->mode == DUP_CLAIM || f->mode == ESCAPED_DUP_CLAIM) {
        char *dup =
            sb_asprintf("{\"%s\":\"attacker\",%s", f->mode == DUP_CLAIM ? "sub" : "s\\u0075b", ps + 1);
        free(ps);
        ps = dup;
    }
    if (f->mode == DUP_HEADER) {
        char *dup = sb_asprintf("{\"alg\":\"none\",%s", hs + 1);
        free(hs);
        hs = dup;
    }
    char *he = sb_base64url_encode((unsigned char *)hs, strlen(hs)),
         *pe = sb_base64url_encode((unsigned char *)ps, strlen(ps));
    char *signed_text = sb_asprintf("%s.%s", he, pe);
    free(hs);
    free(ps);
    free(he);
    free(pe);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t size = 0;
    if (!md || EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, f->key) != 1 ||
        EVP_DigestSignUpdate(md, signed_text, strlen(signed_text)) != 1 ||
        EVP_DigestSignFinal(md, NULL, &size) != 1)
        abort();
    unsigned char *signature = sb_xmalloc(size);
    if (EVP_DigestSignFinal(md, signature, &size) != 1)
        abort();
    EVP_MD_CTX_free(md);
    if (f->mode == BAD_SIG)
        signature[0] ^= 1;
    char *se = sb_base64url_encode(signature, size), *result = sb_asprintf("%s.%s", signed_text, se);
    free(signature);
    free(se);
    free(signed_text);
    return result;
}
static sbj *response_json(fixture *f, const char *path, const char *body, const char *headers) {
    if (strstr(path, "/.well-known/openid-configuration")) {
        sbj *d = sbj_object();
        sbj_set_str(d, "issuer", f->metadata_mode == 1 ? "https://wrong.example" : f->issuer);
        char *auth = sb_asprintf("%s/authorize", f->issuer), *token = sb_asprintf("%s/token", f->issuer),
             *jwks = sb_asprintf("%s/keys", f->issuer);
        sbj_set_str(d, "authorization_endpoint", auth);
        sbj_set_str(d, "token_endpoint", f->metadata_mode == 2 ? "http://example.test/token" : token);
        sbj_set_str(d, "jwks_uri", jwks);
        free(auth);
        free(token);
        free(jwks);
        sbj *responses = sbj_array();
        sbj_arr_push(responses, sbj_str("code"));
        sbj_set(d, "response_types_supported", responses);
        sbj *algorithms = sbj_array();
        sbj_arr_push(algorithms, sbj_str(f->metadata_mode == 3 ? "HS256" : "RS256"));
        sbj_set(d, "id_token_signing_alg_values_supported", algorithms);
        sbj *methods = sbj_array();
        sbj_arr_push(methods, sbj_str(f->auth_method == 1   ? "client_secret_basic"
                                      : f->auth_method == 2 ? "client_secret_post"
                                                            : "none"));
        sbj_set(d, "token_endpoint_auth_methods_supported", methods);
        sbj *challenges = sbj_array();
        sbj_arr_push(challenges, sbj_str(f->metadata_mode == 4 ? "plain" : "S256"));
        sbj_set(d, "code_challenge_methods_supported", challenges);
        return d;
    }
    if (sb_ends_with(path, "/token")) {
        ++f->token_requests;
        sb_str_set(&f->token_body, body);
        free(f->token_authorization);
        f->token_authorization = header(headers, "Authorization");
        char *verifier = parameter(body, "code_verifier"), *grant = parameter(body, "grant_type");
        unsigned char hash[32];
        sb_sha256(verifier ? verifier : "", verifier ? strlen(verifier) : 0, hash);
        char *challenge = sb_base64url_encode(hash, 32);
        f->pkce_valid = sb_streq(challenge, f->challenge) && sb_streq(grant, "authorization_code") &&
                        verifier && strlen(verifier) == 43;
        free(verifier);
        free(grant);
        free(challenge);
        if (f->mode == CONFIG_DISABLE) {
            sbj *off = sbj_object();
            sbj_set_bool(off, "enabled", false);
            sb_auth_oidc_configure(f->auth, off, NULL);
            sbj_free(off);
        }
        if (f->mode == CONFIG_REVISION)
            sb_database_execute(f->db,
                                "UPDATE auth_oidc_config SET "
                                "discovery=json_set(discovery,'$.revision','changed-during-exchange')",
                                NULL);
        if (f->mode == DELETED_USER)
            sb_database_execute(f->db, "DELETE FROM users WHERE id='local-viewer'", NULL);
        if (f->mode == EXPIRED_FLOW_DURING_EXCHANGE)
            sb_sleep_ms(2100);
        char *jwt = sign_token(f);
        sbj *r = sbj_object();
        sbj_set_str(r, "id_token", jwt);
        free(jwt);
        sbj_set_str(r, "access_token", "fixture-access-token");
        sbj_set_str(r, "token_type", "Bearer");
        if (f->mode == TOKEN_ERROR)
            sbj_set_str(r, "error", "invalid_grant");
        return r;
    }
    if (sb_ends_with(path, "/keys")) {
        ++f->jwks_requests;
        sbj *r = sbj_object(), *keys = sbj_array(), *key = sbj_clone(f->jwk);
        if (f->mode == PRIVATE_KEY)
            sbj_set_str(key, "d", "private-material");
        if (f->mode == BAD_KEY_USE)
            sbj_set_str(key, "use", "enc");
        if (f->mode == SMALL_KEY)
            sbj_set_str(key, "n", "AQID");
        if (f->mode == BAD_X5C) {
            sbj *certs = sbj_array();
            sbj_arr_push(certs, sbj_str("AQID"));
            sbj_set(key, "x5c", certs);
        }
        if (f->mode != EMPTY_KEYS)
            sbj_arr_push(keys, key);
        else
            sbj_free(key);
        if (f->mode == DUP_KEY)
            sbj_arr_push(keys, sbj_clone(f->jwk));
        sbj_set(r, "keys", keys);
        return r;
    }
    return sbj_object();
}
static void *serve(void *arg) {
    fixture *f = arg;
    for (;;) {
        int fd = accept(f->listener, NULL, NULL);
        if (fd < 0)
            break;
        sb_buf req = {0};
        char buffer[4096];
        char *end = NULL;
        while (!(end = req.p ? strstr(req.p, "\r\n\r\n") : NULL) && req.len < 32768) {
            ssize_t n = recv(fd, buffer, sizeof buffer, 0);
            if (n <= 0)
                break;
            sb_buf_append(&req, buffer, (size_t)n);
        }
        if (!end) {
            sb_buf_free(&req);
            close(fd);
            continue;
        }
        size_t header_len = (size_t)(end - req.p) + 4;
        char *head = sb_strndup(req.p, header_len);
        char *content_length = header(head, "Content-Length");
        size_t length = content_length ? (size_t)strtoul(content_length, NULL, 10) : 0;
        free(content_length);
        if (length > 32768) {
            free(head);
            sb_buf_free(&req);
            close(fd);
            continue;
        }
        while (req.len < header_len + length) {
            ssize_t n = recv(fd, buffer, sizeof buffer, 0);
            if (n <= 0)
                break;
            sb_buf_append(&req, buffer, (size_t)n);
        }
        char method[16] = {0}, path[512] = {0};
        sscanf(req.p, "%15s %511s", method, path);
        char *body = sb_strndup(req.p + header_len, req.len - header_len);
        pthread_mutex_lock(&f->mutex);
        sbj *value = response_json(f, path, body, head);
        char *json = sbj_dump(value, -1);
        sbj_free(value);
        int status = f->metadata_mode == 5 && strstr(path, "/.well-known/") ? 302 : 200;
        if (f->metadata_mode == 6 && strstr(path, "/.well-known/")) {
            char *dup = sb_asprintf("{\"issuer\":\"bad\",%s", json + 1);
            free(json);
            json = dup;
        }
        pthread_mutex_unlock(&f->mutex);
        char *response = sb_asprintf("HTTP/1.1 %d Test\r\nContent-Type: application/json\r\nConnection: "
                                     "close\r\nLocation: %s\r\nContent-Length: %zu\r\n\r\n%s",
                                     status, f->issuer, strlen(json), json);
        size_t sent = 0, total = strlen(response);
        while (sent < total) {
            ssize_t n = send(fd, response + sent, total - sent, MSG_NOSIGNAL);
            if (n <= 0)
                break;
            sent += (size_t)n;
        }
        free(response);
        free(json);
        free(body);
        free(head);
        sb_buf_free(&req);
        close(fd);
    }
    return NULL;
}
static char *bn_text(const BIGNUM *n) {
    int size = BN_num_bytes(n);
    unsigned char *raw = sb_xmalloc((size_t)size);
    BN_bn2bin(n, raw);
    char *text = sb_base64url_encode(raw, (size_t)size);
    free(raw);
    return text;
}
static fixture *fixture_new(void) {
    fixture *f = sb_xcalloc(1, sizeof *f);
    pthread_mutex_init(&f->mutex, NULL);
    f->db = sb_database_open(":memory:", NULL);
    if (!f->db || sb_database_migrate(f->db, sb_getenv_or("SB_EASY_MIGRATIONS", "migrations"), NULL) ||
        sb_database_execute(
            f->db,
            "INSERT INTO users(id,username,password_hash,role) "
            "VALUES('local-admin','admin','unused','admin'),('local-viewer','viewer','unused','viewer')",
            NULL))
        abort();
    f->auth = sb_auth_security_new(f->db, "test-oidc-server-secret", true, NULL);
    if (!f->auth)
        abort();
    EVP_PKEY_CTX *keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!keygen || EVP_PKEY_keygen_init(keygen) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048) <= 0 ||
        EVP_PKEY_keygen(keygen, &f->key) <= 0)
        abort();
    EVP_PKEY_CTX_free(keygen);
    BIGNUM *n = NULL, *e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_get_bn_param(f->key, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(f->key, OSSL_PKEY_PARAM_RSA_E, &e);
#else
    const RSA *rsa = EVP_PKEY_get0_RSA(f->key);
    const BIGNUM *nn = NULL, *ee = NULL;
    RSA_get0_key(rsa, &nn, &ee, NULL);
    n = BN_dup(nn);
    e = BN_dup(ee);
#endif
    char *nt = bn_text(n), *et = bn_text(e);
    BN_free(n);
    BN_free(e);
    f->jwk = sbj_object();
    sbj_set_str(f->jwk, "kty", "RSA");
    sbj_set_str(f->jwk, "alg", "RS256");
    sbj_set_str(f->jwk, "use", "sig");
    sbj_set_str(f->jwk, "kid", "fixture-key");
    sbj_set_str(f->jwk, "n", nt);
    sbj_set_str(f->jwk, "e", et);
    free(nt);
    free(et);
    f->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (f->listener < 0 || bind(f->listener, (struct sockaddr *)&addr, sizeof addr) || listen(f->listener, 8))
        abort();
    socklen_t size = sizeof addr;
    getsockname(f->listener, (struct sockaddr *)&addr, &size);
    f->port = ntohs(addr.sin_port);
    f->issuer = sb_asprintf("http://127.0.0.1:%d/tenant", f->port);
    if (pthread_create(&f->thread, NULL, serve, f))
        abort();
    return f;
}
static void fixture_free(fixture *f) {
    shutdown(f->listener, SHUT_RDWR);
    close(f->listener);
    pthread_join(f->thread, NULL);
    pthread_mutex_destroy(&f->mutex);
    sb_auth_security_free(f->auth);
    sb_database_free(f->db);
    EVP_PKEY_free(f->key);
    sbj_free(f->jwk);
    free(f->issuer);
    free(f->nonce);
    free(f->challenge);
    free(f->state);
    free(f->token_body);
    free(f->token_authorization);
    free(f);
}
static sbj *config_input(fixture *f, const char *secret) {
    sbj *c = sbj_object();
    sbj_set_bool(c, "enabled", true);
    sbj_set_str(c, "issuer", f->issuer);
    sbj_set_str(c, "client_id", "fixture-client");
    sbj_set_str(c, "redirect_uri", "https://panel.example/login");
    if (secret)
        sbj_set_str(c, "client_secret", secret);
    return c;
}
static int configure(fixture *f, const char *secret, sb_err *err) {
    sbj *c = config_input(f, secret);
    int rc = sb_auth_oidc_configure(f->auth, c, err);
    sbj_free(c);
    return rc;
}
static int begin(fixture *f, sb_auth_oidc_start *start, sb_err *err) {
    int rc = sb_auth_oidc_begin(f->auth, start, err);
    if (rc)
        return rc;
    const char *q = strchr(start->authorization_url, '?');
    if (!q)
        return -1;
    pthread_mutex_lock(&f->mutex);
    free(f->nonce);
    free(f->challenge);
    free(f->state);
    f->nonce = parameter(q + 1, "nonce");
    f->challenge = parameter(q + 1, "code_challenge");
    f->state = parameter(q + 1, "state");
    pthread_mutex_unlock(&f->mutex);
    return 0;
}
static void mode_set(fixture *f, token_mode mode) {
    pthread_mutex_lock(&f->mutex);
    f->mode = mode;
    pthread_mutex_unlock(&f->mutex);
}
static char *query_text(fixture *f, const char *sql) {
    sb_database_lock(f->db);
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(f->auth), sql, NULL);
    char *text = st && sbq_step_row(st, NULL) == 1 ? sbq_text(st, 0) : NULL;
    sqlite3_finalize(st);
    sb_database_unlock(f->db);
    return text;
}
TEST(oidc_disabled_https_and_discovery_validation) {
    fixture *f = fixture_new();
    sb_err err = {0};
    sb_auth_oidc_start start = {0};
    sbj *public = sb_auth_oidc_config(f->auth, &err);
    CHECK(!sbj_get_bool(public, "enabled", true));
    sbj_free(public);
    CHECK_EQ_INT(sb_auth_oidc_begin(f->auth, &start, &err), -1);
    sb_auth_security *production = sb_auth_security_new(f->db, "test-oidc-server-secret", false, NULL);
    sbj *c = config_input(f, "");
    CHECK_EQ_INT(sb_auth_oidc_configure(production, c, &err), -1);
    sbj_free(c);
    sb_auth_security_free(production);
    for (int i = 1; i <= 6; ++i) {
        pthread_mutex_lock(&f->mutex);
        f->metadata_mode = i;
        pthread_mutex_unlock(&f->mutex);
        CHECK_EQ_INT(configure(f, "", &err), -1);
    }
    pthread_mutex_lock(&f->mutex);
    f->metadata_mode = 0;
    pthread_mutex_unlock(&f->mutex);
    CHECK_EQ_INT(configure(f, "", &err), 0);
    public = sb_auth_oidc_config(f->auth, &err);
    CHECK(sbj_get_bool(public, "enabled", false));
    CHECK(!sbj_has(public, "discovery"));
    sbj_free(public);
    sbj *off = sbj_object();
    sbj_set_bool(off, "enabled", false);
    CHECK_EQ_INT(sb_auth_oidc_configure(f->auth, off, &err), 0);
    sbj_free(off);
    fixture_free(f);
}
TEST(oidc_public_pkce_mapping_and_one_use_state) {
    fixture *f = fixture_new();
    sb_err err = {0};
    REQUIRE(!configure(f, "", &err));
    REQUIRE(!sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", false, &err));
    CHECK_EQ_INT(sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", false, &err), 0);
    CHECK_EQ_INT(sb_auth_oidc_link(f->auth, "local-admin", f->issuer, "fixture-subject", false, &err), -1);
    CHECK_EQ_INT(err.code, SB_ERR_CONFLICT);
    sbj *links = sb_auth_oidc_links(f->auth, "local-viewer", &err);
    CHECK_EQ_INT(sbj_arr_len(links), 1);
    sbj_free(links);
    sb_auth_oidc_start start = {0};
    REQUIRE(!begin(f, &start, &err));
    CHECK_CONTAINS(start.authorization_url, "code_challenge_method=S256");
    CHECK(!strstr(start.authorization_url, start.browser_binding));
    char *stored = query_text(f, "SELECT verifier_enc FROM auth_oidc_flows");
    CHECK(stored && strlen(stored) > 43);
    free(stored);
    char *user = sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err);
    CHECK_STR(user, "local-viewer");
    free(user);
    CHECK(f->pkce_valid);
    CHECK(!f->token_authorization);
    char *client = parameter(f->token_body, "client_id"),
         *redirect = parameter(f->token_body, "redirect_uri");
    CHECK_STR(client, "fixture-client");
    CHECK_STR(redirect, "https://panel.example/login");
    free(client);
    free(redirect);
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    REQUIRE(!begin(f, &start, &err));
    char *wrong = sb_auth_sec_random(32, NULL);
    int requests = f->token_requests;
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", wrong, &err));
    free(wrong);
    CHECK_EQ_INT(f->token_requests, requests);
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    REQUIRE(!begin(f, &start, &err));
    sb_database_execute(f->db, "UPDATE auth_oidc_flows SET expires_at=1", NULL);
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    CHECK_EQ_INT(sb_auth_oidc_link(f->auth, "local-admin", f->issuer, "fixture-subject", true, &err), 0);
    links = sb_auth_oidc_links(f->auth, "local-viewer", &err);
    CHECK_EQ_INT(sbj_arr_len(links), 1);
    sbj_free(links);
    CHECK_EQ_INT(sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", true, &err), 0);
    fixture_free(f);
}
TEST(oidc_rejects_invalid_signed_tokens_and_untrusted_keys) {
    fixture *f = fixture_new();
    sb_err err = {0};
    REQUIRE(!configure(f, "", &err));
    REQUIRE(!sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", false, &err));
    token_mode cases[] = {BAD_NONCE,   BAD_ISSUER, BAD_AUD,     BAD_AZP,    MULTI_AUD,         EXPIRED,
                          FUTURE_IAT,  OLD_IAT,    FUTURE_NBF,  FLOAT_EXP,  BAD_SIG,           ALG_NONE,
                          ALG_HS256,   WRONG_KID,  BAD_AT_HASH, DUP_CLAIM,  ESCAPED_DUP_CLAIM, DUP_HEADER,
                          CRIT_HEADER, JKU_HEADER, UNKNOWN_SUB, DUP_KEY,    PRIVATE_KEY,       EMPTY_KEYS,
                          BAD_KEY_USE, SMALL_KEY,  BAD_X5C,     TOKEN_ERROR};
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
        mode_set(f, cases[i]);
        sb_auth_oidc_start start = {0};
        REQUIRE(!begin(f, &start, &err));
        char *user = sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err);
        if (user)
            SB_FAIL_AT("rejection case %d accepted %s", cases[i], user);
        free(user);
        CHECK_EQ_INT(err.code, SB_ERR_AUTH);
        CHECK_STR(err.msg, "OIDC authentication failed");
        sb_auth_oidc_start_free(&start);
    }
    token_mode valid[] = {VALID, NO_KID, MULTI_AUD_OK};
    for (size_t i = 0; i < sizeof valid / sizeof *valid; ++i) {
        mode_set(f, valid[i]);
        sb_auth_oidc_start start = {0};
        REQUIRE(!begin(f, &start, &err));
        char *user = sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err);
        CHECK_STR(user, "local-viewer");
        free(user);
        sb_auth_oidc_start_free(&start);
    }
    fixture_free(f);
}
TEST(oidc_confidential_credentials_are_encrypted_and_encoded) {
    fixture *f = fixture_new();
    sb_err err = {0};
    REQUIRE(!sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", false, &err));
    for (int method = 1; method <= 2; ++method) {
        pthread_mutex_lock(&f->mutex);
        f->auth_method = method;
        pthread_mutex_unlock(&f->mutex);
        REQUIRE(!configure(f, "secret:+/%& words", &err));
        char *stored = query_text(f, "SELECT secret_enc FROM auth_oidc_config");
        CHECK(stored && !strstr(stored, "secret:"));
        sbj *public = sb_auth_oidc_config(f->auth, &err);
        char *json = sbj_dump(public, -1);
        CHECK(sbj_get_bool(public, "has_client_secret", false));
        CHECK(!strstr(json, "secret:"));
        CHECK(!sbj_has(public, "secret_enc"));
        free(json);
        sbj_free(public);
        REQUIRE(!configure(f, NULL, &err));
        char *retained = query_text(f, "SELECT secret_enc FROM auth_oidc_config");
        CHECK_STR(retained, stored);
        free(retained);
        free(stored);
        sb_auth_oidc_start start = {0};
        REQUIRE(!begin(f, &start, &err));
        char *user = sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err);
        CHECK_STR(user, "local-viewer");
        free(user);
        CHECK(f->pkce_valid);
        if (method == 1) {
            char *encoded = sb_url_encode("secret:+/%& words"),
                 *plain = sb_asprintf("fixture-client:%s", encoded);
            char *base64 = sb_base64_encode((unsigned char *)plain, strlen(plain)),
                 *expected = sb_asprintf("Basic %s", base64);
            CHECK_STR(f->token_authorization, expected);
            CHECK(!strstr(f->token_body, "client_secret"));
            free(encoded);
            free(plain);
            free(base64);
            free(expected);
        } else {
            char *secret = parameter(f->token_body, "client_secret");
            CHECK_STR(secret, "secret:+/%& words");
            free(secret);
            CHECK(!f->token_authorization);
        }
        sb_auth_oidc_start_free(&start);
    }
    fixture_free(f);
}
TEST(oidc_disable_config_changes_and_deleted_users_invalidate_flows) {
    fixture *f = fixture_new();
    sb_err err = {0};
    REQUIRE(!configure(f, "", &err));
    REQUIRE(!sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", false, &err));
    sb_auth_oidc_start start = {0};
    REQUIRE(!begin(f, &start, &err));
    REQUIRE(!configure(f, "", &err));
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    mode_set(f, CONFIG_DISABLE);
    REQUIRE(!begin(f, &start, &err));
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    REQUIRE(!configure(f, "", &err));
    mode_set(f, CONFIG_REVISION);
    REQUIRE(!begin(f, &start, &err));
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    mode_set(f, EXPIRED_FLOW_DURING_EXCHANGE);
    REQUIRE(!begin(f, &start, &err));
    char *expire_sql =
        sb_asprintf("UPDATE auth_oidc_flows SET expires_at=%lld", (long long)sb_unix_now() + 1);
    sb_database_execute(f->db, expire_sql, NULL);
    free(expire_sql);
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    mode_set(f, DELETED_USER);
    REQUIRE(!begin(f, &start, &err));
    CHECK(!sb_auth_oidc_finish(f->auth, f->state, "fixture-code", start.browser_binding, &err));
    sb_auth_oidc_start_free(&start);
    fixture_free(f);
}

typedef struct {
    fixture *f;
    const char *binding;
    char *result;
} finish_task;
static void *finish_thread(void *arg) {
    finish_task *task = arg;
    task->result = sb_auth_oidc_finish(task->f->auth, task->f->state, "fixture-code", task->binding, NULL);
    return NULL;
}
TEST(oidc_concurrent_callbacks_consume_one_state_once) {
    fixture *f = fixture_new();
    sb_err err = {0};
    REQUIRE(!configure(f, "", &err));
    REQUIRE(!sb_auth_oidc_link(f->auth, "local-viewer", f->issuer, "fixture-subject", false, &err));
    sb_auth_oidc_start start = {0};
    REQUIRE(!begin(f, &start, &err));
    finish_task tasks[2] = {{f, start.browser_binding, NULL}, {f, start.browser_binding, NULL}};
    pthread_t threads[2];
    REQUIRE(!pthread_create(&threads[0], NULL, finish_thread, &tasks[0]));
    REQUIRE(!pthread_create(&threads[1], NULL, finish_thread, &tasks[1]));
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    CHECK_EQ_INT((tasks[0].result != NULL) + (tasks[1].result != NULL), 1);
    pthread_mutex_lock(&f->mutex);
    CHECK_EQ_INT(f->token_requests, 1);
    pthread_mutex_unlock(&f->mutex);
    free(tasks[0].result);
    free(tasks[1].result);
    sb_auth_oidc_start_free(&start);
    fixture_free(f);
}
