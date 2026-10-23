#include "desktop.h"
#include <errno.h>
#include <fcntl.h>
#include <libsecret/secret.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#define HEADER_SIZE 40u
static const unsigned char magic[8] = {'S', 'B', 'L', 'V', 1, 0, 0, 0};
static const SecretSchema schema = {
    "io.sbeasy.Desktop.Vault",
    SECRET_SCHEMA_NONE,
    {{"directory", SECRET_SCHEMA_ATTRIBUTE_STRING}, {NULL, 0}},
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL};
static int keyring(sbl_vault* v, bool existing, GCancellable* cancel, sb_err* err) {
    GError* error = NULL;
    char* encoded = secret_password_lookup_sync(&schema, cancel, &error, "directory",
                                                v->directory, NULL);
    if (error) {
        g_clear_error(&error);
        return sb_fail(
            err, SB_ERR_IO,
            "Unlock the desktop keyring, then retry. No unencrypted fallback is used.");
    }
    if (!encoded) {
        if (existing)
            return sb_fail(err, SB_ERR_IO,
                           "Vault key is unavailable. Unlock the original desktop "
                           "keyring; the vault was not changed.");
        char* generated = sbl_secret();
        if (!generated)
            return sb_fail(err, SB_ERR_IO, "Secure random generator unavailable");
        gboolean ok = secret_password_store_sync(
            &schema, SECRET_COLLECTION_DEFAULT, "sb-easy encrypted desktop vault",
            generated, cancel, &error, "directory", v->directory, NULL);
        OPENSSL_cleanse(generated, strlen(generated));
        free(generated);
        if (!ok || error) {
            g_clear_error(&error);
            return sb_fail(err, SB_ERR_IO,
                           "Cannot store the vault key. Unlock a Secret Service "
                           "compatible keyring and retry.");
        }
        encoded = secret_password_lookup_sync(&schema, cancel, &error, "directory",
                                              v->directory, NULL);
    }
    bool valid = encoded && strlen(encoded) == 64 && !error;
    for (unsigned i = 0; valid && i < 32; ++i) {
        int a = g_ascii_xdigit_value(encoded[i * 2]),
            b = g_ascii_xdigit_value(encoded[i * 2 + 1]);
        if (a < 0 || b < 0)
            valid = false;
        else
            v->key[i] = (unsigned char)((a << 4) | b);
    }
    if (encoded)
        secret_password_free(encoded);
    g_clear_error(&error);
    if (!valid) {
        OPENSSL_cleanse(v->key, sizeof v->key);
        return sb_fail(err, SB_ERR_IO, "Desktop keyring returned an invalid vault key");
    }
    return 0;
}
int sbl_vault_open_cancellable(sbl_vault* v, const char* directory,
                               const unsigned char* test_key, GCancellable* cancel,
                               sb_err* err) {
    memset(v, 0, sizeof *v);
    v->dirfd = v->lockfd = -1;
    if (sbl_private_dir(directory, geteuid(), err))
        return -1;
    v->directory = sb_strdup(directory);
    v->dirfd = open(directory, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (v->dirfd < 0)
        goto io;
    v->lockfd =
        openat(v->dirfd, "vault.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat lockst;
    if (v->lockfd < 0 || fstat(v->lockfd, &lockst) || !S_ISREG(lockst.st_mode) ||
        lockst.st_uid != geteuid() || (lockst.st_mode & 077))
        goto io;
    if (flock(v->lockfd, LOCK_EX | LOCK_NB)) {
        sbl_vault_close(v);
        return sb_fail(err, SB_ERR_CONFLICT,
                       "Another desktop instance owns this vault");
    }
    struct stat st;
    bool existing = fstatat(v->dirfd, "vault.bin", &st, AT_SYMLINK_NOFOLLOW) == 0;
    if (existing &&
        (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)))
        goto io;
    if (test_key)
        memcpy(v->key, test_key, sizeof v->key);
    else if (keyring(v, existing, cancel, err)) {
        sbl_vault_close(v);
        return -1;
    }
    return 0;
io:
    sbl_vault_close(v);
    return sb_fail(err, SB_ERR_IO, "Cannot open private vault files safely");
}
int sbl_vault_open(sbl_vault* v, const char* directory, const unsigned char* test_key,
                   sb_err* err) {
    return sbl_vault_open_cancellable(v, directory, test_key, NULL, err);
}
void sbl_vault_close(sbl_vault* v) {
    if (v->lockfd >= 0)
        close(v->lockfd);
    if (v->dirfd >= 0)
        close(v->dirfd);
    free(v->directory);
    OPENSSL_cleanse(v, sizeof *v);
    v->dirfd = v->lockfd = -1;
}
sbj* sbl_vault_load(sbl_vault* v, sb_err* err) {
    int fd = openat(v->dirfd, "vault.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        v->revision = 0;
        return sbl_new_state();
    }
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) || st.st_size < HEADER_SIZE ||
        st.st_size > SBL_MAX_STATE + HEADER_SIZE) {
        if (fd >= 0)
            close(fd);
        sb_fail(err, SB_ERR_IO, "Cannot read private vault");
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    unsigned char *input = sb_xmalloc(len), *plain = sb_xmalloc(len + 1);
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, input + done, len - done);
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    close(fd);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int out = 0, total = 0;
    bool ok = done == len && !memcmp(input, magic, 8) && ctx &&
              EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, v->key, input + 8) == 1 &&
              EVP_DecryptUpdate(ctx, NULL, &out, input, 24) == 1 &&
              EVP_DecryptUpdate(ctx, plain, &out, input + HEADER_SIZE,
                                (int)(len - HEADER_SIZE)) == 1;
    total = out;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, input + 24) == 1 &&
         EVP_DecryptFinal_ex(ctx, plain + total, &out) == 1;
    total += out;
    EVP_CIPHER_CTX_free(ctx);
    free(input);
    sbj* state = NULL;
    if (ok && total >= 0 && (size_t)total <= len && !memchr(plain, 0, (size_t)total)) {
        plain[total] = 0;
        state = sbl_parse((char*)plain, SBL_MAX_STATE, err);
        if (state && sbl_validate_state(state, err)) {
            sbj_free(state);
            state = NULL;
        }
    }
    OPENSSL_cleanse(plain, len + 1);
    free(plain);
    if (!state) {
        sb_fail(err, SB_ERR_VALIDATION,
                "Encrypted vault failed authentication or validation; no data was "
                "overwritten");
        return NULL;
    }
    v->revision = (uint64_t)sbj_get_int(state, "revision", 0);
    return state;
}
int sbl_vault_save(sbl_vault* v, sbj* state, sb_err* err) {
    if (sbl_validate_state(state, err))
        return -1;
    if ((uint64_t)sbj_get_int(state, "revision", 0) != v->revision)
        return sb_fail(err, SB_ERR_CONFLICT, "Stale vault revision");
    sbj* copy = sbj_clone(state);
    sbj_set_int(copy, "revision", (int64_t)(v->revision + 1));
    char* plain = sbj_dump(copy, -1);
    sbj_free(copy);
    size_t len = strlen(plain);
    if (len > SBL_MAX_STATE) {
        free(plain);
        return sb_fail(err, SB_ERR_VALIDATION, "Encrypted vault is full");
    }
    unsigned char* sealed = sb_xcalloc(len + HEADER_SIZE + 16, 1);
    memcpy(sealed, magic, 8);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int n = 0, total = 0;
    bool ok = ctx && RAND_bytes(sealed + 8, 12) == 1 &&
              EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
              EVP_EncryptInit_ex(ctx, NULL, NULL, v->key, sealed + 8) == 1 &&
              EVP_EncryptUpdate(ctx, NULL, &n, sealed, 24) == 1 &&
              EVP_EncryptUpdate(ctx, sealed + HEADER_SIZE, &n, (unsigned char*)plain,
                                (int)len) == 1;
    total = n;
    ok = ok && EVP_EncryptFinal_ex(ctx, sealed + HEADER_SIZE + total, &n) == 1;
    total += n;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, sealed + 24) == 1;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plain, len);
    free(plain);
    char *random = sbl_uuid(), *temp = sb_asprintf("vault.%s.tmp", random);
    free(random);
    int fd = ok ? openat(v->dirfd, temp,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)
                : -1;
    size_t written = 0, count = HEADER_SIZE + (size_t)total;
    if (fd >= 0) {
        while (written < count) {
            ssize_t bytes = write(fd, sealed + written, count - written);
            if (bytes <= 0)
                break;
            written += (size_t)bytes;
        }
        ok = written == count && fsync(fd) == 0;
        if (close(fd))
            ok = false;
    } else
        ok = false;
    if (ok)
        ok = renameat(v->dirfd, temp, v->dirfd, "vault.bin") == 0;
    if (ok)
        ok = fsync(v->dirfd) == 0;
    if (!ok)
        unlinkat(v->dirfd, temp, 0);
    free(temp);
    free(sealed);
    if (!ok)
        return sb_fail(err, SB_ERR_IO, "Encrypted vault could not be committed");
    ++v->revision;
    sbj_set_int(state, "revision", (int64_t)v->revision);
    return 0;
}
