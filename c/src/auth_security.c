#include "auth_security_internal.h"

#include <limits.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SESSION_SECONDS (72 * 60 * 60)
#define CHALLENGE_SECONDS 300
#define MFA_PENDING_SECONDS 600
#define MFA_LOCK_SECONDS 300

static int clear_challenges_locked(sb_auth_security *s, const char *user_id, sb_err *err);

void sb_auth_sec_secret_free(char *text) {
    if (text) { OPENSSL_cleanse(text, strlen(text)); free(text); }
}

bool sb_auth_sec_token(const char *text, size_t max) {
    if (!text || !*text || strlen(text) > max) return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (*p < 33 || *p > 126) return false;
    return true;
}

char *sb_auth_sec_random(size_t bytes, sb_err *err) {
    if (!bytes || bytes > 256) { sb_fail(err, SB_ERR_VALIDATION, "Invalid random token size"); return NULL; }
    unsigned char raw[256];
    if (sb_random_bytes(raw, bytes)) { sb_fail(err, SB_ERR_GENERIC, "Secure random generation failed"); return NULL; }
    char *result = sb_base64url_encode(raw, bytes);
    OPENSSL_cleanse(raw, sizeof raw);
    return result;
}

char *sb_auth_sec_hash(sb_auth_security *s, const char *purpose, const char *text) {
    if (!s || !purpose || !text) return NULL;
    sb_buf input = {0};
    sb_buf_puts(&input, "sb-easy:auth:v1:");
    sb_buf_puts(&input, purpose);
    sb_buf_putc(&input, '\0');
    sb_buf_puts(&input, text);
    unsigned char digest[32];
    sb_hmac_sha256(s->jwt_secret, strlen(s->jwt_secret), input.p, input.len, digest);
    sb_buf_free(&input);
    char *result = sb_hex_encode(digest, sizeof digest);
    OPENSSL_cleanse(digest, sizeof digest);
    return result;
}

char *sb_auth_sec_encrypt(sb_auth_security *s, const char *purpose, const char *plaintext, sb_err *err) {
    if (!s || !purpose || !plaintext || strlen(plaintext) > 65536 || strlen(purpose) > 1024) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid encrypted secret"); return NULL;
    }
    size_t length = strlen(plaintext);
    unsigned char *raw = sb_xcalloc(length + 29, 1);
    raw[0] = 1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int count = 0, tail = 0;
    bool ok = ctx && !sb_random_bytes(raw + 1, 12) &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, s->encryption_key, raw + 1) == 1 &&
        EVP_EncryptUpdate(ctx, NULL, &count, (const unsigned char *)purpose, (int)strlen(purpose)) == 1 &&
        EVP_EncryptUpdate(ctx, raw + 13, &count, (const unsigned char *)plaintext, (int)length) == 1 &&
        EVP_EncryptFinal_ex(ctx, raw + 13 + count, &tail) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, raw + 13 + length) == 1;
    EVP_CIPHER_CTX_free(ctx);
    char *result = ok ? sb_base64url_encode(raw, length + 29) : NULL;
    OPENSSL_cleanse(raw, length + 29); free(raw);
    if (!ok) sb_fail(err, SB_ERR_GENERIC, "Secret encryption failed");
    return result;
}

char *sb_auth_sec_decrypt(sb_auth_security *s, const char *purpose, const char *envelope, sb_err *err) {
    if (!s || !purpose || !envelope || strlen(envelope) > 90000 || strlen(purpose) > 1024) {
        sb_fail(err, SB_ERR_AUTH, "Encrypted secret is unavailable"); return NULL;
    }
    size_t size = 0;
    unsigned char *raw = sb_base64url_decode_strict(envelope, strlen(envelope), &size);
    if (!raw || size < 29 || raw[0] != 1) {
        free(raw); sb_fail(err, SB_ERR_AUTH, "Encrypted secret is unavailable"); return NULL;
    }
    size_t length = size - 29;
    char *plain = sb_xcalloc(length + 1, 1);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int count = 0, tail = 0;
    bool ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, s->encryption_key, raw + 1) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &count, (const unsigned char *)purpose, (int)strlen(purpose)) == 1 &&
        EVP_DecryptUpdate(ctx, (unsigned char *)plain, &count, raw + 13, (int)length) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, raw + 13 + length) == 1 &&
        EVP_DecryptFinal_ex(ctx, (unsigned char *)plain + count, &tail) == 1 &&
        !memchr(plain, '\0', length);
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(raw, size); free(raw);
    if (!ok) {
        OPENSSL_cleanse(plain, length); free(plain);
        sb_fail(err, SB_ERR_AUTH, "Encrypted secret is unavailable"); return NULL;
    }
    return plain;
}

sb_auth_security *sb_auth_security_new(sb_database *database, const char *jwt_secret,
                                       bool allow_loopback_oidc, sb_err *err) {
    if (!database || sb_str_empty(jwt_secret)) {
        sb_fail(err, SB_ERR_VALIDATION, "Authentication database and JWT secret are required"); return NULL;
    }
    sb_auth_security *s = sb_xcalloc(1, sizeof *s);
    s->database = database; s->jwt_secret = sb_strdup(jwt_secret);
    s->allow_loopback_oidc = allow_loopback_oidc;
    const char *domain = "sb-easy:auth:v1:encryption-key";
    sb_hmac_sha256(jwt_secret, strlen(jwt_secret), domain, strlen(domain), s->encryption_key);
    return s;
}

void sb_auth_security_free(sb_auth_security *s) {
    if (!s) return;
    sb_auth_sec_secret_free(s->jwt_secret);
    OPENSSL_cleanse(s, sizeof *s); free(s);
}

int sb_auth_sec_user_exists_locked(sb_auth_security *s, const char *user_id, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT 1 FROM users WHERE id=?", err);
    if (q.rc != 0) return -1;
    sbq_bind_text(q.st, 1, user_id);
    return sbq_step_row(q.st, err);
}

static int required_user_locked(sb_auth_security *s, const char *user_id, sb_err *err) {
    int exists = sb_auth_sec_user_exists_locked(s, user_id, err);
    if (!exists) return sb_fail(err, SB_ERR_NOT_FOUND, "User not found");
    return exists < 0 ? -1 : 0;
}

static bool label_valid(const char *label) {
    if (!label) return true;
    if (strlen(label) > 128) return false;
    for (const unsigned char *p = (const unsigned char *)label; *p; ++p)
        if (*p < 32 || *p == 127) return false;
    sbj *j = sbj_str(label);
    bool valid = sbj_validate_utf8(j, NULL) == 0; sbj_free(j);
    return valid;
}

static char *issue_locked(sb_auth_security *s, const char *user_id, const char *method,
                           const char *client_label, bool mfa_completed, sb_err *err) {
    if (!sb_auth_sec_token(method, 32) || !label_valid(client_label)) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid session details"); return NULL;
    }
    if (required_user_locked(s, user_id, err)) return NULL;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "SELECT username,role,EXISTS(SELECT 1 FROM auth_mfa WHERE user_id=users.id AND secret_enc IS NOT NULL) FROM users WHERE id=?", err);
    if (!st) return NULL;
    sbq_bind_text(st, 1, user_id);
    int row = sbq_step_row(st, err);
    if (row != 1) {
        sqlite3_finalize(st);
        if (!row) sb_fail(err, SB_ERR_AUTH, "User is unavailable");
        return NULL;
    }
    /* The HTTP layer may have observed disabled MFA before another request
     * enabled it. Recheck under the same mutex as enrollment and session INSERT;
     * a method label such as 'password+mfa' is never proof of completion. */
    if (sbq_int(st, 2) && !mfa_completed) {
        sqlite3_finalize(st); sb_fail(err, SB_ERR_AUTH, "MFA is required; restart login"); return NULL;
    }
    char *id = sb_auth_sec_random(24, err);
    if (!id) { sqlite3_finalize(st); return NULL; }
    int64_t now = sb_unix_now();
    sbj *payload = sbj_object();
    sbj_set_str(payload, "sub", user_id);
    sbj_set(payload, "username", sbj_strn((const char *)sqlite3_column_text(st, 0),
                                            (size_t)sqlite3_column_bytes(st, 0)));
    sbj_set_str(payload, "role", (const char *)sqlite3_column_text(st, 1));
    sbj_set_str(payload, "jti", id);
    sbj_set_int(payload, "iat", now); sbj_set_int(payload, "exp", now + SESSION_SECONDS);
    sqlite3_finalize(st);
    char *json = sbj_dump(payload, -1); sbj_free(payload);
    char *encoded = sb_base64url_encode((const unsigned char *)json, strlen(json)); free(json);
    char *unsigned_token = sb_asprintf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.%s", encoded); free(encoded);
    unsigned char digest[32];
    sb_hmac_sha256(s->jwt_secret, strlen(s->jwt_secret), unsigned_token, strlen(unsigned_token), digest);
    char *signature = sb_base64url_encode(digest, sizeof digest);
    char *token = sb_asprintf("%s.%s", unsigned_token, signature);
    free(unsigned_token); free(signature); OPENSSL_cleanse(digest, sizeof digest);
    char *hash = sb_auth_sec_hash(s, "session", token);
    st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_sessions(id,user_id,token_hash,method,client_label,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)", err);
    int result = -1;
    if (st) {
        sbq_bind_text(st, 1, id); sbq_bind_text(st, 2, user_id); sbq_bind_text(st, 3, hash);
        sbq_bind_text(st, 4, method); sbq_bind_text(st, 5, client_label ? client_label : "");
        sbq_bind_int(st, 6, now); sbq_bind_int(st, 7, now + SESSION_SECONDS); sbq_bind_int(st, 8, now);
        result = sbq_step_done(st, err); sqlite3_finalize(st);
    }
    free(id); free(hash);
    if (result) { sb_auth_sec_secret_free(token); return NULL; }
    /* Keep at most 100 recent sessions per account and bounded stale history. */
    st = sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_sessions WHERE expires_at<? OR (user_id=? AND id NOT IN (SELECT id FROM auth_sessions WHERE user_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100))", err);
    if (st) {
        sbq_bind_int(st, 1, now - 86400); sbq_bind_text(st, 2, user_id); sbq_bind_text(st, 3, user_id);
        result = sbq_step_done(st, err); sqlite3_finalize(st);
    } else result = -1;
    if (result) { sb_auth_sec_secret_free(token); return NULL; }
    return token;
}

char *sb_auth_security_issue(sb_auth_security *s, const char *user_id, const char *method,
                              const char *client_label, sb_err *err) {
    if (!s) return NULL;
    sb_database_lock(s->database);
    char *token = NULL;
    if (!sbq_begin(SB_AUTH_DB(s), err)) {
        token = issue_locked(s, user_id, method, client_label, false, err);
        if (!token || sbq_commit(SB_AUTH_DB(s), err)) {
            sbq_rollback(SB_AUTH_DB(s)); sb_auth_sec_secret_free(token); token = NULL;
        }
    }
    sb_database_unlock(s->database); return token;
}

bool sb_auth_security_verify(sb_auth_security *s, const char *token, sb_auth_claims *out, sb_err *err) {
    sb_auth_claims claims = {0};
    if (!s || !token || strlen(token) > 16384 || !sb_auth_verify_token(s->jwt_secret, token, &claims)) {
        sb_fail(err, SB_ERR_AUTH, "Invalid or expired session"); return false;
    }
    char *hash = sb_auth_sec_hash(s, "session", token);
    sb_database_lock(s->database);
    bool valid = false;
    {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT u.username,u.role FROM auth_sessions a JOIN users u ON u.id=a.user_id WHERE a.token_hash=? AND a.user_id=? AND a.revoked_at IS NULL AND a.expires_at>?", err);
    sqlite3_stmt *st = q.st;
    if (q.rc == 0) {
        sbq_bind_text(st, 1, hash); sbq_bind_text(st, 2, claims.subject); sbq_bind_int(st, 3, sb_unix_now());
        int row = sbq_step_row(st, err);
        if (row == 1) {
            free(claims.username); free(claims.role);
            claims.username_len = (size_t)sqlite3_column_bytes(st, 0);
            claims.username = sbq_text(st, 0); claims.role = sbq_text(st, 1); valid = true;
        } else if (!row) sb_fail(err, SB_ERR_AUTH, "Invalid or expired session");
    }
    }
    if (valid) {
        SBQ_AUTO u = sbq_stmt_open(SB_AUTH_DB(s), "UPDATE auth_sessions SET last_seen_at=? WHERE token_hash=? AND last_seen_at<?", err);
        if (u.rc == 0) {
            int64_t now = sb_unix_now(); sbq_bind_int(u.st, 1, now); sbq_bind_text(u.st, 2, hash); sbq_bind_int(u.st, 3, now - 60);
            valid = !sbq_step_done(u.st, err);
        } else valid = false;
    }
    sb_database_unlock(s->database); free(hash);
    if (valid && out) *out = claims; else sb_auth_claims_free(&claims);
    return valid;
}

sbj *sb_auth_security_sessions(sb_auth_security *s, const char *user_id, const char *current_token, sb_err *err) {
    if (!s) return NULL;
    char *hash = current_token ? sb_auth_sec_hash(s, "session", current_token) : NULL;
    sbj *result = sbj_array(); sb_database_lock(s->database);
    int row = -1;
    {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT id,method,client_label,created_at,expires_at,last_seen_at,revoked_at,token_hash FROM auth_sessions WHERE user_id=? AND expires_at>? ORDER BY created_at DESC,rowid DESC LIMIT 100", err);
    sqlite3_stmt *st = q.st;
    if (q.rc == 0) {
        sbq_bind_text(st, 1, user_id); sbq_bind_int(st, 2, sb_unix_now());
        while ((row = sbq_step_row(st, err)) == 1) {
            sbj *item = sbj_object();
            const char *names[] = {"id", "method", "client_label"};
            for (int i = 0; i < 3; ++i) sbj_set_str(item, names[i], (const char *)sqlite3_column_text(st, i));
            sbj_set_int(item, "created_at", sbq_int(st, 3)); sbj_set_int(item, "expires_at", sbq_int(st, 4));
            sbj_set_int(item, "last_seen_at", sbq_int(st, 5));
            if (sqlite3_column_type(st, 6) == SQLITE_NULL) sbj_set_null(item, "revoked_at");
            else sbj_set_int(item, "revoked_at", sbq_int(st, 6));
            sbj_set_bool(item, "current", sb_streq(hash, (const char *)sqlite3_column_text(st, 7)));
            sbj_arr_push(result, item);
        }
    }
    }
    sb_database_unlock(s->database); free(hash);
    if (row < 0) { sbj_free(result); return NULL; }
    return result;
}

static int revoke_locked(sb_auth_security *s, const char *user_id, const char *session_id,
                           const char *keep_token, sb_err *err) {
    char *keep = keep_token ? sb_auth_sec_hash(s, "session", keep_token) : NULL;
    int result = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "UPDATE auth_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND (? IS NULL OR id=?) AND (? IS NULL OR token_hash<>?)", err);
        if (q.rc == 0) {
            sbq_bind_int(q.st, 1, sb_unix_now()); sbq_bind_text(q.st, 2, user_id);
            sbq_bind_text(q.st, 3, session_id); sbq_bind_text(q.st, 4, session_id);
            sbq_bind_text(q.st, 5, keep); sbq_bind_text(q.st, 6, keep);
            result = sbq_step_done(q.st, err);
        }
    }
    free(keep); return result;
}

int sb_auth_security_revoke(sb_auth_security *s, const char *user_id, const char *session_id,
                             const char *keep_token, sb_err *err) {
    if (!s) return -1;
    sb_database_lock(s->database);
    int result = -1;
    if (!sbq_begin(SB_AUTH_DB(s), err)) {
        result = revoke_locked(s, user_id, session_id, keep_token, err);
        if (!result && !session_id) result = clear_challenges_locked(s, user_id, err);
        if (result || sbq_commit(SB_AUTH_DB(s), err)) {
            sbq_rollback(SB_AUTH_DB(s)); result = -1;
        }
    }
    sb_database_unlock(s->database); return result;
}

int sb_auth_security_logout(sb_auth_security *s, const char *token, sb_err *err) {
    if (!s || !token || strlen(token) > 16384) return sb_fail(err, SB_ERR_AUTH, "Invalid session");
    char *hash = sb_auth_sec_hash(s, "session", token);
    sb_database_lock(s->database);
    int result = -1;
    {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", err);
        if (q.rc == 0) {
            sbq_bind_int(q.st, 1, sb_unix_now()); sbq_bind_text(q.st, 2, hash);
            result = sbq_step_done(q.st, err);
        }
    }
    sb_database_unlock(s->database); free(hash); return result;
}

static int base32_decode(const char *text, unsigned char out[80], size_t *length) {
    if (!text || strlen(text) < 16 || strlen(text) > 128) return -1;
    unsigned accumulator = 0, bits = 0;
    size_t written = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        unsigned value;
        if (*p >= 'A' && *p <= 'Z') value = *p - 'A';
        else if (*p >= '2' && *p <= '7') value = *p - '2' + 26U;
        else return -1;
        accumulator = (accumulator << 5) | value; bits += 5;
        if (bits >= 8) { bits -= 8; out[written++] = (unsigned char)(accumulator >> bits); }
    }
    if (bits && (accumulator & ((1U << bits) - 1U))) return -1;
    *length = written; return 0;
}

int sb_auth_totp_code(const char *base32_secret, int64_t now, unsigned digits, char out[9], sb_err *err) {
    unsigned char secret[80] = {0}, counter[8], mac[EVP_MAX_MD_SIZE];
    size_t length = 0;
    if (!out || now < 0 || (digits != 6 && digits != 8) || base32_decode(base32_secret, secret, &length)) {
        OPENSSL_cleanse(secret, sizeof secret);
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid TOTP input");
    }
    uint64_t step = (uint64_t)now / 30U;
    for (unsigned i = 0; i < 8; ++i) { counter[7 - i] = (unsigned char)(step & 255U); step >>= 8; }
    unsigned mac_length = 0;
    bool ok = HMAC(EVP_sha1(), secret, (int)length, counter, sizeof counter, mac, &mac_length) && mac_length == 20;
    OPENSSL_cleanse(secret, sizeof secret);
    if (!ok) return sb_fail(err, SB_ERR_GENERIC, "TOTP computation failed");
    unsigned offset = mac[19] & 15U;
    uint32_t binary = ((uint32_t)(mac[offset] & 127U) << 24) | ((uint32_t)mac[offset + 1] << 16) |
                      ((uint32_t)mac[offset + 2] << 8) | mac[offset + 3];
    unsigned modulus = digits == 6 ? 1000000U : 100000000U;
    snprintf(out, 9, "%0*u", (int)digits, binary % modulus);
    OPENSSL_cleanse(mac, sizeof mac); return 0;
}

static char *totp_secret_new(sb_err *err) {
    unsigned char raw[20];
    if (sb_random_bytes(raw, sizeof raw)) { sb_fail(err, SB_ERR_GENERIC, "MFA secret generation failed"); return NULL; }
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    char *secret = sb_xcalloc(33, 1);
    unsigned accumulator = 0, bits = 0;
    size_t written = 0;
    for (size_t i = 0; i < sizeof raw; ++i) {
        accumulator = (accumulator << 8) | raw[i]; bits += 8;
        while (bits >= 5) { bits -= 5; secret[written++] = alphabet[(accumulator >> bits) & 31U]; }
    }
    OPENSSL_cleanse(raw, sizeof raw); return secret;
}

static char *mfa_purpose(const char *user_id) { return sb_asprintf("totp:%s", user_id ? user_id : ""); }
static char *recovery_hash(sb_auth_security *s, const char *user_id, const char *code) {
    char *purpose = sb_asprintf("recovery:%s", user_id ? user_id : "");
    char *hash = sb_auth_sec_hash(s, purpose, code); free(purpose); return hash;
}

static int mfa_failed_locked(sb_auth_security *s, const char *user_id, int64_t now, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "UPDATE auth_mfa SET failed_attempts=CASE WHEN failed_attempts>=4 THEN 0 ELSE failed_attempts+1 END,locked_until=CASE WHEN failed_attempts>=4 THEN ? ELSE 0 END WHERE user_id=?", err);
    if (q.rc != 0) return -1;
    sbq_bind_int(q.st, 1, now + MFA_LOCK_SECONDS); sbq_bind_text(q.st, 2, user_id);
    int result = sbq_step_done(q.st, err);
    if (!result) sb_fail(err, SB_ERR_AUTH, "Invalid or already used verification code");
    return -1;
}

/* Caller holds the shared database mutex and may wrap this in a transaction.
 * A rejected code still writes the rate-limit counters; do not roll those back. */
static bool mfa_verify_locked(sb_auth_security *s, const char *user_id, const char *code,
                               bool pending, int64_t *accepted_step, sb_err *err) {
    if (!sb_auth_sec_token(user_id, 256)) {
        sb_fail(err, SB_ERR_AUTH, "Invalid user"); return false;
    }
    int64_t now = sb_unix_now(), last_step = -1, pending_until = 0, locked_until = 0;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "SELECT secret_enc,pending_enc,pending_until,last_step,locked_until FROM auth_mfa WHERE user_id=?", err);
    if (!st) return false;
    sbq_bind_text(st, 1, user_id);
    int row = sbq_step_row(st, err);
    char *encrypted = NULL;
    if (row == 1) {
        encrypted = sbq_opt_text(st, pending ? 1 : 0); pending_until = sbq_int(st, 2);
        last_step = sbq_int(st, 3); locked_until = sbq_int(st, 4);
    }
    sqlite3_finalize(st);
    if (row < 0) return false;
    if (row != 1 || !encrypted || (pending && pending_until <= now)) {
        free(encrypted); sb_fail(err, SB_ERR_AUTH, pending ? "MFA setup has expired" : "MFA is not enabled"); return false;
    }
    if (locked_until > now) {
        free(encrypted); sb_fail(err, SB_ERR_AUTH, "Verification temporarily locked; try again later"); return false;
    }
    if (!sb_auth_sec_token(code, 128)) {
        free(encrypted); mfa_failed_locked(s, user_id, now, err); return false;
    }
    char *purpose = mfa_purpose(user_id);
    char *secret = sb_auth_sec_decrypt(s, purpose, encrypted, err);
    free(purpose); free(encrypted);
    if (!secret) return false;
    int64_t matched = -1;
    if (strlen(code) == 6) {
        for (int delta = -1; delta <= 1; ++delta) {
            int64_t step = now / 30 + delta;
            char expected[9] = {0};
            if (step >= 0 && (pending || step > last_step) &&
                !sb_auth_totp_code(secret, step * 30, 6, expected, NULL) &&
                sb_consttime_streq(expected, code)) matched = step;
            OPENSSL_cleanse(expected, sizeof expected);
        }
    }
    sb_auth_sec_secret_free(secret);
    bool recovery = false;
    if (matched < 0 && !pending) {
        char *hash = recovery_hash(s, user_id, code);
        st = sbq_prepare(SB_AUTH_DB(s), "UPDATE auth_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL", err);
        if (!st) { free(hash); return false; }
        sbq_bind_int(st, 1, now); sbq_bind_text(st, 2, user_id); sbq_bind_text(st, 3, hash);
        int result = sbq_step_done(st, err); sqlite3_finalize(st); free(hash);
        if (result) return false;
        recovery = sqlite3_changes(SB_AUTH_DB(s)) == 1;
    }
    if (matched < 0 && !recovery) { mfa_failed_locked(s, user_id, now, err); return false; }
    st = sbq_prepare(SB_AUTH_DB(s), "UPDATE auth_mfa SET last_step=?,failed_attempts=0,locked_until=0 WHERE user_id=?", err);
    if (!st) return false;
    sbq_bind_int(st, 1, pending ? last_step : (recovery ? last_step : matched)); sbq_bind_text(st, 2, user_id);
    int result = sbq_step_done(st, err); sqlite3_finalize(st);
    if (!result && accepted_step) *accepted_step = matched;
    return !result;
}

sbj *sb_auth_mfa_status(sb_auth_security *s, const char *user_id, sb_err *err) {
    if (!s) return NULL;
    sb_database_lock(s->database);
    sbj *result = NULL;
    if (!required_user_locked(s, user_id, err)) {
        {
            SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT secret_enc IS NOT NULL,pending_enc IS NOT NULL AND pending_until>? FROM auth_mfa WHERE user_id=?", err);
            if (q.rc == 0) {
                sbq_bind_int(q.st, 1, sb_unix_now()); sbq_bind_text(q.st, 2, user_id);
                int row = sbq_step_row(q.st, err);
                if (row >= 0) {
                    result = sbj_object(); sbj_set_bool(result, "enabled", row == 1 && sbq_int(q.st, 0));
                    sbj_set_bool(result, "pending", row == 1 && sbq_int(q.st, 1));
                }
            }
        }
        if (result) {
            int row = -1;
            {
                SBQ_AUTO c = sbq_stmt_open(SB_AUTH_DB(s), "SELECT count(*) FROM auth_recovery_codes WHERE user_id=? AND used_at IS NULL", err);
                if (c.rc == 0) {
                    sbq_bind_text(c.st, 1, user_id); row = sbq_step_row(c.st, err);
                    if (row == 1) sbj_set_int(result, "recovery_codes_remaining", sbq_int(c.st, 0));
                }
            }
            if (row != 1) { sbj_free(result); result = NULL; }
        }
    }
    sb_database_unlock(s->database); return result;
}

sbj *sb_auth_mfa_begin(sb_auth_security *s, const char *user_id, sb_err *err) {
    if (!s || !sb_auth_sec_token(user_id, 256)) { sb_fail(err, SB_ERR_VALIDATION, "Invalid user"); return NULL; }
    char *secret = totp_secret_new(err);
    if (!secret) return NULL;
    char *purpose = mfa_purpose(user_id), *encrypted = sb_auth_sec_encrypt(s, purpose, secret, err);
    free(purpose);
    if (!encrypted) { sb_auth_sec_secret_free(secret); return NULL; }
    sb_database_lock(s->database);
    sbj *result = NULL;
    if (!required_user_locked(s, user_id, err)) {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "INSERT INTO auth_mfa(user_id,pending_enc,pending_until) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET pending_enc=excluded.pending_enc,pending_until=excluded.pending_until", err);
        if (q.rc == 0) {
            int64_t until = sb_unix_now() + MFA_PENDING_SECONDS;
            sbq_bind_text(q.st, 1, user_id); sbq_bind_text(q.st, 2, encrypted); sbq_bind_int(q.st, 3, until);
            if (!sbq_step_done(q.st, err)) {
                char *label = sb_url_encode(user_id);
                char *uri = sb_asprintf("otpauth://totp/sb-easy:%s?secret=%s&issuer=sb-easy&algorithm=SHA1&digits=6&period=30", label, secret);
                result = sbj_object(); sbj_set_str(result, "secret", secret); sbj_set_str(result, "otpauth_uri", uri);
                sbj_set_int(result, "expires_at", until); free(label); sb_auth_sec_secret_free(uri);
            }
        }
    }
    sb_database_unlock(s->database); free(encrypted); sb_auth_sec_secret_free(secret);
    return result;
}

static int clear_challenges_locked(sb_auth_security *s, const char *user_id, sb_err *err) {
    SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "DELETE FROM auth_login_challenges WHERE user_id=?", err);
    if (q.rc != 0) return -1;
    sbq_bind_text(q.st, 1, user_id);
    return sbq_step_done(q.st, err);
}

sbj *sb_auth_mfa_confirm(sb_auth_security *s, const char *user_id, const char *code,
                          const char *keep_token, sb_err *err) {
    if (!s) return NULL;
    sb_database_lock(s->database); sbj *result = NULL;
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    int64_t step = -1;
    if (!mfa_verify_locked(s, user_id, code, true, &step, err)) {
        /* Persist rejected-attempt counters, including on setup confirmation. */
        if (sbq_commit(SB_AUTH_DB(s), NULL)) sbq_rollback(SB_AUTH_DB(s));
        goto done;
    }
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "UPDATE auth_mfa SET secret_enc=pending_enc,pending_enc=NULL,pending_until=0,last_step=? WHERE user_id=?", err);
    if (!st) goto rollback;
    sbq_bind_int(st, 1, step); sbq_bind_text(st, 2, user_id);
    int rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    st = sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_recovery_codes WHERE user_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    result = sbj_object(); sbj *codes = sbj_array(); sbj_set(result, "recovery_codes", codes);
    sbj_set_bool(result, "enabled", true);
    for (unsigned i = 0; i < 10; ++i) {
        char *recovery = sb_auth_sec_random(16, err);
        if (!recovery) goto rollback;
        char *hash = recovery_hash(s, user_id, recovery);
        st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_recovery_codes(user_id,code_hash) VALUES(?,?)", err);
        if (!st) { free(hash); sb_auth_sec_secret_free(recovery); goto rollback; }
        sbq_bind_text(st, 1, user_id); sbq_bind_text(st, 2, hash);
        rc = sbq_step_done(st, err); sqlite3_finalize(st); free(hash);
        if (rc) { sb_auth_sec_secret_free(recovery); goto rollback; }
        sbj_arr_push(codes, sbj_str(recovery)); sb_auth_sec_secret_free(recovery);
    }
    if (revoke_locked(s, user_id, NULL, keep_token, err) || clear_challenges_locked(s, user_id, err) ||
        sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s)); sbj_free(result); result = NULL;
done:
    sb_database_unlock(s->database); return result;
}

bool sb_auth_mfa_verify(sb_auth_security *s, const char *user_id, const char *code, sb_err *err) {
    if (!s) return false;
    sb_database_lock(s->database);
    bool valid = false;
    if (!sbq_begin(SB_AUTH_DB(s), err)) {
        valid = mfa_verify_locked(s, user_id, code, false, NULL, err);
        if (sbq_commit(SB_AUTH_DB(s), valid ? err : NULL)) { sbq_rollback(SB_AUTH_DB(s)); valid = false; }
    }
    sb_database_unlock(s->database); return valid;
}

int sb_auth_mfa_disable(sb_auth_security *s, const char *user_id, const char *keep_token, sb_err *err) {
    if (!s) return -1;
    sb_database_lock(s->database); int result = -1;
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    if (required_user_locked(s, user_id, err)) goto rollback;
    const char *queries[] = {"DELETE FROM auth_mfa WHERE user_id=?", "DELETE FROM auth_recovery_codes WHERE user_id=?"};
    for (unsigned i = 0; i < 2; ++i) {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), queries[i], err);
        if (q.rc != 0) goto rollback;
        sbq_bind_text(q.st, 1, user_id);
        if (sbq_step_done(q.st, err)) goto rollback;
    }
    if (revoke_locked(s, user_id, NULL, keep_token, err) || clear_challenges_locked(s, user_id, err) || sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    result = 0; goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s));
done:
    sb_database_unlock(s->database); return result;
}

char *sb_auth_security_challenge_bound(sb_auth_security *s, const char *user_id, const char *method,
                                        const char *browser_binding, sb_err *err) {
    if (!s || !sb_auth_sec_token(method, 32) ||
        (browser_binding && !sb_auth_sec_token(browser_binding, 256))) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid login challenge"); return NULL;
    }
    char *challenge = sb_auth_sec_random(32, err);
    if (!challenge) return NULL;
    char *hash = sb_auth_sec_hash(s, "login-challenge", challenge);
    char *binding = browser_binding ? sb_auth_sec_hash(s, "login-binding", browser_binding) : NULL;
    sb_database_lock(s->database);
    int result = -1;
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "SELECT 1 FROM auth_mfa WHERE user_id=? AND secret_enc IS NOT NULL", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); int row = sbq_step_row(st, err); sqlite3_finalize(st);
    if (row != 1) {
        if (!row) sb_fail(err, SB_ERR_AUTH, "MFA is not enabled");
        goto rollback;
    }
    st = sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_login_challenges WHERE expires_at<=? OR (user_id=? AND challenge_hash NOT IN (SELECT challenge_hash FROM auth_login_challenges WHERE user_id=? ORDER BY rowid DESC LIMIT 9))", err);
    if (!st) goto rollback;
    sbq_bind_int(st, 1, sb_unix_now()); sbq_bind_text(st, 2, user_id); sbq_bind_text(st, 3, user_id);
    int rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    st = sbq_prepare(SB_AUTH_DB(s), "INSERT INTO auth_login_challenges(challenge_hash,binding_hash,user_id,method,expires_at) VALUES(?,?,?,?,?)", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, hash); sbq_bind_text(st, 2, binding); sbq_bind_text(st, 3, user_id);
    sbq_bind_text(st, 4, method); sbq_bind_int(st, 5, sb_unix_now() + CHALLENGE_SECONDS);
    rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc || sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    result = 0; goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s));
done:
    sb_database_unlock(s->database); free(hash); free(binding);
    if (result) { sb_auth_sec_secret_free(challenge); return NULL; }
    return challenge;
}

char *sb_auth_security_challenge(sb_auth_security *s, const char *user_id, const char *method, sb_err *err) {
    return sb_auth_security_challenge_bound(s, user_id, method, NULL, err);
}

char *sb_auth_security_complete_bound(sb_auth_security *s, const char *challenge, const char *code,
                                       const char *client_label, const char *browser_binding, sb_err *err) {
    if (!s || !sb_auth_sec_token(challenge, 128) || !label_valid(client_label) ||
        (browser_binding && !sb_auth_sec_token(browser_binding, 256))) {
        sb_fail(err, SB_ERR_AUTH, "Invalid or expired login challenge"); return NULL;
    }
    char *hash = sb_auth_sec_hash(s, "login-challenge", challenge);
    char *binding = browser_binding ? sb_auth_sec_hash(s, "login-binding", browser_binding) : NULL;
    char *user_id = NULL, *method = NULL, *token = NULL;
    sb_database_lock(s->database);
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    sqlite3_stmt *st = sbq_prepare(SB_AUTH_DB(s), "SELECT user_id,method,binding_hash FROM auth_login_challenges WHERE challenge_hash=? AND expires_at>?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, hash); sbq_bind_int(st, 2, sb_unix_now());
    int row = sbq_step_row(st, err);
    if (row == 1) {
        const char *expected = (const char *)sqlite3_column_text(st, 2);
        bool matches = (!expected && !binding) || (expected && binding && sb_consttime_streq(expected, binding));
        if (matches) { user_id = sbq_text(st, 0); method = sbq_text(st, 1); }
    }
    sqlite3_finalize(st);
    if (!user_id) {
        if (row >= 0) sb_fail(err, SB_ERR_AUTH, "Invalid or expired login challenge");
        goto rollback;
    }
    if (!mfa_verify_locked(s, user_id, code, false, NULL, err)) {
        /* Failed OTP attempts count even when the challenge remains reusable. */
        if (sbq_commit(SB_AUTH_DB(s), NULL)) sbq_rollback(SB_AUTH_DB(s));
        goto done;
    }
    st = sbq_prepare(SB_AUTH_DB(s), "DELETE FROM auth_login_challenges WHERE challenge_hash=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, hash); int rc = sbq_step_done(st, err); sqlite3_finalize(st);
    if (rc) goto rollback;
    char *full_method = sb_asprintf("%s+mfa", method);
    token = issue_locked(s, user_id, full_method, client_label, true, err); free(full_method);
    if (!token || sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s)); sb_auth_sec_secret_free(token); token = NULL;
done:
    sb_database_unlock(s->database); free(hash); free(binding); free(user_id); free(method);
    return token;
}

char *sb_auth_security_complete(sb_auth_security *s, const char *challenge, const char *code,
                                 const char *client_label, sb_err *err) {
    return sb_auth_security_complete_bound(s, challenge, code, client_label, NULL, err);
}

int sb_auth_security_change_role(sb_auth_security *s, const char *user_id, const char *role, sb_err *err) {
    if (!s || (!sb_streq(role, "admin") && !sb_streq(role, "operator") && !sb_streq(role, "viewer")))
        return sb_fail(err, SB_ERR_VALIDATION, "Role must be admin, operator or viewer");
    sb_database_lock(s->database); int result = -1;
    if (sbq_begin(SB_AUTH_DB(s), err)) goto done;
    int row = -1;
    bool prohibited = false;
    {
        SBQ_AUTO q = sbq_stmt_open(SB_AUTH_DB(s), "SELECT role,(SELECT count(*) FROM users WHERE role='admin') FROM users WHERE id=?", err);
        if (q.rc != 0) goto rollback;
        sbq_bind_text(q.st, 1, user_id); row = sbq_step_row(q.st, err);
        prohibited = row == 1 && sb_streq((const char *)sqlite3_column_text(q.st, 0), "admin") &&
                     !sb_streq(role, "admin") && sbq_int(q.st, 1) <= 1;
    }
    if (row != 1 || prohibited) {
        if (!row) sb_fail(err, SB_ERR_NOT_FOUND, "User not found");
        if (prohibited) sb_fail(err, SB_ERR_VALIDATION, "Cannot demote the last admin");
        goto rollback;
    }
    int rc;
    {
        SBQ_AUTO u = sbq_stmt_open(SB_AUTH_DB(s), "UPDATE users SET role=? WHERE id=?", err);
        if (u.rc != 0) goto rollback;
        sbq_bind_text(u.st, 1, role); sbq_bind_text(u.st, 2, user_id);
        rc = sbq_step_done(u.st, err);
    }
    if (rc || revoke_locked(s, user_id, NULL, NULL, err) || clear_challenges_locked(s, user_id, err) ||
        sbq_commit(SB_AUTH_DB(s), err)) goto rollback;
    result = 0; goto done;
rollback:
    sbq_rollback(SB_AUTH_DB(s));
done:
    sb_database_unlock(s->database); return result;
}
