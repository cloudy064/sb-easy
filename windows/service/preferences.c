#include "preferences.h"
#include "health.h"
#include "subscriptions.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENVELOPE (900U * 1024U)
#define MAX_PLAINTEXT (640U * 1024U)
#define ITERATIONS 600000U
static const unsigned char aad[] = "sb-easy/preferences/v1";
static int fail(sbw_error *error, const char *code) {
    return sbw_fail(error, code, !strcmp(code, "ARCHIVE_PASSWORD") ? "Use an archive password containing 12–1024 UTF-8 bytes." :
        !strcmp(code, "ARCHIVE_DECRYPT_FAILED") ? "The archive password is incorrect or the archive was modified." :
        !strcmp(code, "ARCHIVE_PLATFORM") ? "This archive belongs to another platform; Windows imports Windows preferences only." :
        "The encrypted preferences archive is invalid or exceeds the supported size.");
}
static bool password_valid(const char *password) {
    size_t size = password ? strlen(password) : 0;
    return size >= 12 && size <= 1024 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, password, (int)size, NULL, 0) > 0;
}
static char *base64(const unsigned char *data, DWORD size) {
    DWORD length = 0;
    if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &length)) return NULL;
    char *out = sb_xcalloc(length, 1);
    if (!CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &length)) { free(out); return NULL; }
    return out;
}
static unsigned char *decode(const sbj *value, DWORD minimum, DWORD maximum, DWORD *size) {
    if (!sbw_json_string(value, MAX_ENVELOPE, false)) return NULL;
    const char *text = sbj_as_str(value, ""); size_t length = strlen(text);
    if (length % 4 || strspn(text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != length) return NULL;
    DWORD decoded = 0;
    if (!CryptStringToBinaryA(text, (DWORD)length, CRYPT_STRING_BASE64, NULL, &decoded, NULL, NULL) || decoded < minimum || decoded > maximum) return NULL;
    unsigned char *bytes = sb_xcalloc((size_t)decoded + 1, 1);
    if (!CryptStringToBinaryA(text, (DWORD)length, CRYPT_STRING_BASE64, bytes, &decoded, NULL, NULL)) { free(bytes); return NULL; }
    char *canonical = base64(bytes, decoded); bool valid = canonical && !strcmp(text, canonical); free(canonical);
    if (!valid) { SecureZeroMemory(bytes, decoded); free(bytes); return NULL; }
    *size = decoded; return bytes;
}
bool sbw_preferences_envelope_valid(const sbj *envelope) {
    if (!sbj_is_object(envelope) || sbj_obj_len(envelope) != 7 ||
        !sbj_string_is(sbj_get(envelope, "format"), "sb-easy.preferences") ||
        !sbj_is_integer(sbj_get(envelope, "version")) || sbj_get_int(envelope, "version", 0) != 1 ||
        !sbj_string_is(sbj_get(envelope, "kdf"), "pbkdf2-sha256") ||
        !sbj_is_integer(sbj_get(envelope, "iterations")) || sbj_get_int(envelope, "iterations", 0) != ITERATIONS) return false;
    char *serialized = sbj_dump(envelope, -1); bool size_ok = strlen(serialized) <= MAX_ENVELOPE; free(serialized);
    if (!size_ok) return false;
    DWORD n = 0; unsigned char *salt = decode(sbj_get(envelope, "salt"), 16, 16, &n);
    unsigned char *nonce = decode(sbj_get(envelope, "nonce"), 12, 12, &n);
    unsigned char *cipher = decode(sbj_get(envelope, "ciphertext"), 17, MAX_PLAINTEXT + 16, &n);
    bool valid = salt && nonce && cipher; free(salt); free(nonce); free(cipher); return valid;
}
static int crypt(bool encrypt, const char *password, const unsigned char salt[16], const unsigned char nonce[12],
    const unsigned char *input, DWORD size, unsigned char *output, unsigned char tag[16]) {
    BCRYPT_ALG_HANDLE sha = NULL, aes = NULL; BCRYPT_KEY_HANDLE key = NULL;
    unsigned char derived[32] = {0}; unsigned char *key_object = NULL;
    DWORD object_size = 0, returned = 0, written = 0; int result = -1;
    if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0 ||
        BCryptDeriveKeyPBKDF2(sha, (PUCHAR)password, (ULONG)strlen(password), (PUCHAR)salt, 16, ITERATIONS, derived, sizeof derived, 0) < 0 ||
        BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, NULL, 0) < 0 ||
        BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof BCRYPT_CHAIN_MODE_GCM, 0) < 0 ||
        BCryptGetProperty(aes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_size, sizeof object_size, &returned, 0) < 0 || !object_size || object_size > 65536) goto done;
    key_object = sb_xcalloc(object_size, 1);
    if (BCryptGenerateSymmetricKey(aes, &key, key_object, object_size, derived, sizeof derived, 0) < 0) goto done;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info; BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce; info.cbNonce = 12; info.pbAuthData = (PUCHAR)aad; info.cbAuthData = sizeof aad - 1;
    info.pbTag = tag; info.cbTag = 16;
    NTSTATUS status = encrypt ? BCryptEncrypt(key, (PUCHAR)input, size, &info, NULL, 0, output, size, &written, 0) :
        BCryptDecrypt(key, (PUCHAR)input, size, &info, NULL, 0, output, size, &written, 0);
    if (status >= 0 && written == size) result = 0;
done:
    if (key) BCryptDestroyKey(key);
    if (aes) BCryptCloseAlgorithmProvider(aes, 0);
    if (sha) BCryptCloseAlgorithmProvider(sha, 0);
    SecureZeroMemory(derived, sizeof derived);
    if (key_object) { SecureZeroMemory(key_object, object_size); free(key_object); }
    return result;
}
sbj *sbw_preferences_encrypt(const sbj *payload, const char *password, sbw_error *error) {
    if (!password_valid(password)) { fail(error, "ARCHIVE_PASSWORD"); return NULL; }
    if (!sbj_is_object(payload)) { fail(error, "ARCHIVE_INVALID"); return NULL; }
    char *plaintext = sbj_dump(payload, -1); size_t length = strlen(plaintext); sbj *out = NULL;
    unsigned char salt[16], nonce[12]; unsigned char *cipher = NULL;
    if (!length || length > MAX_PLAINTEXT) goto done;
    cipher = sb_xcalloc(length + 16, 1);
    if (BCryptGenRandom(NULL, salt, sizeof salt, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        BCryptGenRandom(NULL, nonce, sizeof nonce, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        crypt(true, password, salt, nonce, (const unsigned char *)plaintext, (DWORD)length, cipher, cipher + length)) goto done;
    char *salt64 = base64(salt, sizeof salt), *nonce64 = base64(nonce, sizeof nonce), *cipher64 = base64(cipher, (DWORD)length + 16);
    if (salt64 && nonce64 && cipher64) {
        out = sbj_object(); sbj_set_str(out, "format", "sb-easy.preferences"); sbj_set_int(out, "version", 1);
        sbj_set_str(out, "kdf", "pbkdf2-sha256"); sbj_set_int(out, "iterations", ITERATIONS);
        sbj_set_str(out, "salt", salt64); sbj_set_str(out, "nonce", nonce64); sbj_set_str(out, "ciphertext", cipher64);
    }
    free(salt64); free(nonce64); free(cipher64);
done:
    sbw_secret_free(plaintext); free(cipher);
    if (!out) fail(error, "ARCHIVE_INVALID");
    return out;
}
sbj *sbw_preferences_decrypt(const sbj *envelope, const char *password, sbw_error *error) {
    if (!password_valid(password)) { fail(error, "ARCHIVE_PASSWORD"); return NULL; }
    if (!sbw_preferences_envelope_valid(envelope)) { fail(error, "ARCHIVE_INVALID"); return NULL; }
    DWORD salt_size = 0, nonce_size = 0, cipher_size = 0;
    unsigned char *salt = decode(sbj_get(envelope, "salt"), 16, 16, &salt_size);
    unsigned char *nonce = decode(sbj_get(envelope, "nonce"), 12, 12, &nonce_size);
    unsigned char *cipher = decode(sbj_get(envelope, "ciphertext"), 17, MAX_PLAINTEXT + 16, &cipher_size);
    unsigned char *plain = sb_xcalloc(cipher_size, 1); sbj *out = NULL;
    if (salt && nonce && cipher && !crypt(false, password, salt, nonce, cipher, cipher_size - 16, plain, cipher + cipher_size - 16))
        out = sbw_json_parse((const char *)plain, cipher_size - 16, 32, NULL);
    SecureZeroMemory(plain, cipher_size); free(plain); free(salt); free(nonce); free(cipher);
    if (!sbj_is_object(out)) { sbj_free(out); fail(error, "ARCHIVE_DECRYPT_FAILED"); return NULL; }
    return out;
}

static bool group_id(const char *id) {
    size_t n = strlen(id); return n && n <= 64 && strspn(id, "abcdefghijklmnopqrstuvwxyz0123456789-") == n && strncmp(id, "custom-", 7);
}
static bool route_preference(const sbj *value, bool is_default) {
    const char *mode = sbj_get_str(value, "mode", "");
    if (!sbj_is_object(value)) return false;
    if (!strcmp(mode, "server") || (!is_default && !strcmp(mode, "default"))) return sbj_obj_len(value) == 1;
    if (!strcmp(mode, "node")) return sbj_obj_len(value) == 2 && sbw_json_string(sbj_get(value, "node"), 512, false);
    const sbj *candidates = sbj_get(value, "automatic_candidates");
    if (strcmp(mode, "automatic") || sbj_obj_len(value) != 2 || !sbj_is_array(candidates) || !sbj_arr_len(candidates) || sbj_arr_len(candidates) > 32) return false;
    for (size_t i = 0; i < sbj_arr_len(candidates); ++i) {
        if (!sbw_json_string(sbj_arr_at(candidates, i), 512, false)) return false;
        for (size_t j = 0; j < i; ++j) if (sbj_equal(sbj_arr_at(candidates, i), sbj_arr_at(candidates, j))) return false;
    }
    return true;
}
static sbj *copy_subscriptions(const sbj *list, sbw_error *error) {
    if (list && (!sbj_is_array(list) || sbj_arr_len(list) > 16)) { fail(error, "ARCHIVE_INVALID"); return NULL; }
    sbj *out = sbj_array(); const char *keys[] = {"id", "name", "url", "nodes", "refresh_interval_minutes"};
    for (size_t i = 0; i < sbj_arr_len(list); ++i) {
        const sbj *sub = sbj_arr_at(list, i); sbj *copy = sbj_object();
        for (size_t j = 0; j < sizeof keys / sizeof *keys; ++j) if (sbj_has(sub, keys[j])) sbj_set(copy, keys[j], sbj_clone(sbj_get(sub, keys[j])));
        if (!sbj_has(copy, "url")) sbj_set_str(copy, "url", "");
        if (!sbj_has(copy, "refresh_interval_minutes")) sbj_set_int(copy, "refresh_interval_minutes", 0);
        sbj_arr_push(out, copy);
    }
    return out;
}
sbj *sbw_preferences_payload(const sbj *identity, sbw_error *error) {
    if (!sbj_is_object(identity)) { fail(error, "ARCHIVE_INVALID"); return NULL; }
    sbj *subs = copy_subscriptions(sbj_get(identity, "local_subscriptions"), error); if (!subs) return NULL;
    sbj *out = sbj_object(), *preferences = sbj_object(), *routing = sbj_object();
    const sbj *saved = sbj_get(identity, "windows_routing");
    for (size_t i = 0; i < sbj_obj_len(saved); ++i) {
        const char *id = sbj_obj_key(saved, i);
        if (group_id(id)) sbj_set(routing, id, sbj_clone(sbj_obj_val(saved, i)));
    }
    if (!sbj_has(routing, "gpt") && (sbj_has(identity, "windows_gpt_outbound") || sbj_has(identity, "windows_gpt_use_default"))) {
        const char *node = sbj_get_str(identity, "windows_gpt_outbound", "");
        sbj *legacy = sbj_object(); sbj_set_str(legacy, "mode", *node ? "node" : sbj_get_bool(identity, "windows_gpt_use_default", false) ? "default" : "server");
        if (*node) sbj_set_str(legacy, "node", node);
        sbj_set(routing, "gpt", legacy);
    }
    sbj_set(preferences, "local_subscriptions", subs); sbj_set(preferences, "routing", routing);
    sbj_set(preferences, "health", sbw_health_policy(identity));
    sbj_set_str(out, "format", "sb-easy.preferences.payload"); sbj_set_int(out, "version", 1);
    sbj_set_str(out, "platform", "windows"); sbj_set(out, "preferences", preferences); return out;
}
sbj *sbw_preferences_merge(const sbj *identity, const sbj *payload, sbw_error *error) {
    if (sbj_is_object(payload) && !sbj_string_is(sbj_get(payload, "platform"), "windows")) { fail(error, "ARCHIVE_PLATFORM"); return NULL; }
    const sbj *prefs = sbj_get(payload, "preferences"), *subs = sbj_get(prefs, "local_subscriptions"), *routing = sbj_get(prefs, "routing"), *health = sbj_get(prefs, "health");
    if (!sbj_is_object(identity) || !sbj_is_object(payload) || sbj_obj_len(payload) != 4 ||
        !sbj_string_is(sbj_get(payload, "format"), "sb-easy.preferences.payload") || !sbj_is_integer(sbj_get(payload, "version")) || sbj_get_int(payload, "version", 0) != 1 ||
        !sbj_is_object(prefs) || sbj_obj_len(prefs) != 3 || !sbj_is_array(subs) || sbj_arr_len(subs) > 16 ||
        !sbj_is_object(routing) || sbj_obj_len(routing) > 64 || !sbw_health_policy_valid(health)) goto invalid;
    sbj *result = sbj_clone(identity), *clean = sbj_array();
    /* Validate each imported source via the same subscription validator while
     * retaining stable IDs that general routing preferences reference. */
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        const sbj *sub = sbj_arr_at(subs, i); const char *id = sbj_get_str(sub, "id", "");
        if (!sbj_is_object(sub) || sbj_obj_len(sub) != 5 || strlen(id) != 36 || strspn(id, "0123456789abcdef-") != 36) goto invalid_result;
        for (size_t j = 0; j < i; ++j) if (sbj_string_is(sbj_get(sbj_arr_at(subs, j), "id"), id)) goto invalid_result;
        sbj *seed = sbj_object(), *old = sbj_array(); sbj_arr_push(old, sbj_clone(sub)); sbj_set(seed, "local_subscriptions", old);
        sbj *checked = sbw_subscriptions_change(seed, sub, false, error); sbj_free(seed);
        if (!checked) goto invalid_result;
        sbj *entry = sbj_clone(sbj_arr_at(sbj_get(checked, "local_subscriptions"), 0)); sbj_set_int(entry, "next_refresh_at", 0);
        sbj_arr_push(clean, entry); sbj_free(checked);
    }
    sbj *overrides = sbj_object(); const sbj *old_overrides = sbj_get(identity, "windows_routing");
    for (size_t i = 0; i < sbj_obj_len(old_overrides); ++i)
        if (!strncmp(sbj_obj_key(old_overrides, i), "custom-", 7)) sbj_set(overrides, sbj_obj_key(old_overrides, i), sbj_clone(sbj_obj_val(old_overrides, i)));
    for (size_t i = 0; i < sbj_obj_len(routing); ++i) {
        const char *id = sbj_obj_key(routing, i); const sbj *preference = sbj_obj_val(routing, i);
        if (!group_id(id) || !route_preference(preference, !strcmp(id, "default"))) { sbj_free(overrides); goto invalid_result; }
        if (sbj_string_is(sbj_get(preference, "mode"), "automatic") && !sbj_get_bool(health, "enabled", false)) { sbj_free(overrides); goto invalid_result; }
        sbj_set(overrides, id, sbj_clone(preference));
    }
    sbj_set(result, "local_subscriptions", clean); sbj_set(result, "windows_routing", overrides);
    sbj_set(result, "windows_health", sbj_clone(health)); sbj_del(result, "windows_gpt_outbound"); sbj_del(result, "windows_gpt_use_default"); return result;
invalid_result:
    sbj_free(clean); sbj_free(result);
invalid:
    fail(error, "ARCHIVE_INVALID"); return NULL;
}
sbj *sbw_preferences_preview(const sbj *identity) {
    sbj *out = sbj_object(), *names = sbj_array(); size_t nodes = 0;
    const sbj *subs = sbj_get(identity, "local_subscriptions");
    for (size_t i = 0; i < sbj_arr_len(subs); ++i) {
        const sbj *sub = sbj_arr_at(subs, i); nodes += sbj_arr_len(sbj_get(sub, "nodes")); sbj_arr_push(names, sbj_str(sbj_get_str(sub, "name", "")));
    }
    sbj_set(out, "subscription_names", names); sbj_set_int(out, "node_count", (int64_t)nodes);
    size_t groups = 0; const sbj *routing = sbj_get(identity, "windows_routing");
    for (size_t i = 0; i < sbj_obj_len(routing); ++i) if (group_id(sbj_obj_key(routing, i))) ++groups;
    sbj_set_int(out, "routing_count", (int64_t)groups); sbj_set_bool(out, "device_settings_preserved", true); return out;
}
