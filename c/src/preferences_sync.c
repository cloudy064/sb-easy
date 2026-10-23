#include "sb/preferences_sync.h"
#include "sqlite_internal.h"
#include <openssl/evp.h>
#include <time.h>

#define ENVELOPE_LIMIT (1024u * 1024u)
#define USER_BYTES_LIMIT (8u * 1024u * 1024u)
#define USER_SLOTS_LIMIT 16

static bool exact_text(const sbj *value, const char *text) {
    size_t n = strlen(text);
    return sbj_is_string(value) && value->v.str.len == n && memcmp(value->v.str.ptr, text, n) == 0;
}
static bool canonical_base64(const sbj *value, size_t exact_length, size_t minimum) {
    if (!sbj_is_string(value)) return false;
    size_t n = value->v.str.len;
    const char *text = value->v.str.ptr;
    if (!n || n > ENVELOPE_LIMIT || n % 4) return false;
    size_t pad = (text[n - 1] == '=') + (text[n - 2] == '=');
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)text[i];
        bool alphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (!alphabet && !(i >= n - pad && c == '=')) return false;
    }
    size_t bytes = n / 4 * 3 - pad;
    if ((exact_length && bytes != exact_length) || bytes < minimum) return false;
    unsigned char *decoded = sb_xmalloc(n / 4 * 3 + 1);
    char *encoded = sb_xmalloc(n + 1);
    int got = EVP_DecodeBlock(decoded, (const unsigned char *)text, (int)n);
    bool valid = got >= 0 && EVP_EncodeBlock((unsigned char *)encoded, decoded, (int)bytes) == (int)n &&
        memcmp(encoded, text, n) == 0;
    free(decoded); free(encoded); return valid;
}
int sb_preferences_validate_envelope(const sbj *envelope, sb_err *err) {
    const sbj *version = sbj_get(envelope, "version"), *iterations = sbj_get(envelope, "iterations");
    if (!sbj_is_object(envelope) || sbj_obj_len(envelope) != 7 ||
        !exact_text(sbj_get(envelope, "format"), "sb-easy.preferences") ||
        !sbj_is_integer(version) || sbj_get_int(envelope, "version", 0) != 1 ||
        !exact_text(sbj_get(envelope, "kdf"), "pbkdf2-sha256") ||
        !sbj_is_integer(iterations) || sbj_get_int(envelope, "iterations", 0) != 600000 ||
        !canonical_base64(sbj_get(envelope, "salt"), 16, 16) ||
        !canonical_base64(sbj_get(envelope, "nonce"), 12, 12) ||
        !canonical_base64(sbj_get(envelope, "ciphertext"), 0, 17))
        return sb_fail(err, SB_ERR_VALIDATION, "Invalid encrypted preferences envelope");
    char *encoded = sbj_dump(envelope, -1);
    bool bounded = strlen(encoded) <= ENVELOPE_LIMIT; free(encoded);
    return bounded ? 0 : sb_fail(err, SB_ERR_VALIDATION, "Encrypted preferences exceed 1 MiB");
}
static bool identifier(const char *text, size_t limit) {
    if (!text || !*text || strlen(text) > limit) return false;
    for (const char *p = text; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) return false;
    return true;
}
static int arguments(sb_database *database, const char *user_id, const char *slot, sb_err *err) {
    return database && identifier(user_id, 128) && identifier(slot, 64) ? 0 :
        sb_fail(err, SB_ERR_VALIDATION, "Invalid preference slot");
}
/* Caller holds the shared database lock. */
static sbj *read_locked(sqlite3 *db, const char *user_id, const char *slot, sb_err *err) {
    sqlite3_stmt *st = sbq_prepare(db, "SELECT revision,updated_at,envelope FROM auth_preferences WHERE user_id=? AND slot=?", err);
    if (!st) return NULL;
    sbq_bind_text(st, 1, user_id); sbq_bind_text(st, 2, slot);
    int row = sbq_step_row(st, err); sbj *result = NULL;
    if (row == 1) {
        const char *text = (const char *)sqlite3_column_text(st, 2);
        bool deleted = sqlite3_column_type(st, 2) == SQLITE_NULL;
        sbj *envelope = deleted ? sbj_null() : sbj_parse(text, (size_t)sqlite3_column_bytes(st, 2), NULL, 0);
        if (envelope) {
            result = sbj_object(); sbj_set_int(result, "revision", sbq_int(st, 0));
            sbj_set_int(result, "updated_at", sbq_int(st, 1)); sbj_set(result, "envelope", envelope);
            if (deleted) sbj_set_bool(result, "deleted", true);
        } else sb_fail(err, SB_ERR_GENERIC, "Stored encrypted preferences are invalid");
    } else if (!row) sb_fail(err, SB_ERR_NOT_FOUND, "Preference slot not found");
    sqlite3_finalize(st); return result;
}
sbj *sb_preferences_get(sb_database *database, const char *user_id, const char *slot, sb_err *err) {
    if (arguments(database, user_id, slot, err) != 0) return NULL;
    sb_database_lock(database); sbj *out = read_locked(sb_database_handle(database), user_id, slot, err);
    sb_database_unlock(database); return out;
}
sbj *sb_preferences_put(sb_database *database, const char *user_id, const char *slot,
                        int64_t expected_revision, const sbj *envelope, sb_err *err) {
    if (arguments(database, user_id, slot, err) != 0 || sb_preferences_validate_envelope(envelope, err) != 0) return NULL;
    if (expected_revision < 0 || expected_revision >= INT64_MAX) {
        sb_fail(err, SB_ERR_VALIDATION, "Invalid preference revision"); return NULL;
    }
    char *encoded = sbj_dump(envelope, -1); size_t length = strlen(encoded);
    sbj *result = NULL; sqlite3 *db = sb_database_handle(database);
    sb_database_lock(database);
    if (sbq_begin(db, err) != 0) goto done;
    sqlite3_stmt *st = sbq_prepare(db, "SELECT revision,length(CAST(envelope AS BLOB)) FROM auth_preferences WHERE user_id=? AND slot=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); sbq_bind_text(st, 2, slot);
    int row = sbq_step_row(st, err);
    int64_t revision = row == 1 ? sbq_int(st, 0) : 0, previous_length = row == 1 ? sbq_int(st, 1) : 0;
    sqlite3_finalize(st); if (row < 0) goto rollback;
    if (revision != expected_revision) { sb_fail(err, SB_ERR_CONFLICT, "Preferences changed on another device; fetch and review before saving"); goto rollback; }
    st = sbq_prepare(db, "SELECT COUNT(*),COALESCE(SUM(length(CAST(envelope AS BLOB))),0) FROM auth_preferences WHERE user_id=?", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); row = sbq_step_row(st, err);
    bool room = row == 1 && (revision || sbq_int(st, 0) < USER_SLOTS_LIMIT) &&
        sbq_int(st, 1) - previous_length + (int64_t)length <= USER_BYTES_LIMIT;
    sqlite3_finalize(st); if (row < 0) goto rollback;
    if (!room) { sb_fail(err, SB_ERR_CONFLICT, "Preference storage limit reached (16 slots / 8 MiB)"); goto rollback; }
    st = sbq_prepare(db, "INSERT INTO auth_preferences(user_id,slot,revision,updated_at,envelope) VALUES(?,?,?,?,?) ON CONFLICT(user_id,slot) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at,envelope=excluded.envelope", err);
    if (!st) goto rollback;
    sbq_bind_text(st, 1, user_id); sbq_bind_text(st, 2, slot); sbq_bind_int(st, 3, revision + 1);
    sbq_bind_int(st, 4, (int64_t)time(NULL)); sbq_bind_text(st, 5, encoded);
    int rc = sbq_step_done(st, err); sqlite3_finalize(st); if (rc != 0) goto rollback;
    result = read_locked(db, user_id, slot, err);
    if (!result || sbq_commit(db, err) != 0) { sbj_free(result); result = NULL; goto rollback; }
    goto done;
rollback: sbq_rollback(db);
done: sb_database_unlock(database); free(encoded); return result;
}
int sb_preferences_delete(sb_database *database, const char *user_id, const char *slot,
                           int64_t expected_revision, sb_err *err) {
    if (arguments(database, user_id, slot, err) != 0) return -1;
    if (expected_revision <= 0 || expected_revision >= INT64_MAX) return sb_fail(err, SB_ERR_VALIDATION, "A positive preference revision is required");
    sqlite3 *db = sb_database_handle(database); int result = -1;
    sb_database_lock(database);
    sqlite3_stmt *st = sbq_prepare(db, "UPDATE auth_preferences SET revision=revision+1,updated_at=?,envelope=NULL WHERE user_id=? AND slot=? AND revision=?", err);
    if (st) {
        sbq_bind_int(st, 1, (int64_t)time(NULL)); sbq_bind_text(st, 2, user_id);
        sbq_bind_text(st, 3, slot); sbq_bind_int(st, 4, expected_revision);
        result = sbq_step_done(st, err); sqlite3_finalize(st);
        if (!result && sqlite3_changes(db) != 1) result = sb_fail(err, SB_ERR_CONFLICT, "Preferences changed or no longer exist; fetch before deleting");
    }
    sb_database_unlock(database); return result;
}
