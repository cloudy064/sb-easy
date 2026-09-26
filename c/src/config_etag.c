#include "sb/config_etag.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "sb/util.h"

static int update_digest(EVP_MD_CTX *ctx, const char *value) {
    if (!value || !*value) return 0;
    return EVP_DigestUpdate(ctx, value, strlen(value)) == 1 ? 0 : -1;
}

char *sb_config_etag(const char *host_id, const char *pretty_config, const char *seed) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        SB_ERROR("SHA-256 ETag initialization failed");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (update_digest(ctx, host_id) || update_digest(ctx, pretty_config) ||
        update_digest(ctx, seed)) {
        SB_ERROR("SHA-256 ETag update failed");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &size) != 1 || size != 32U) {
        SB_ERROR("SHA-256 ETag finalization failed");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);
    char *hex = sb_hex_encode(digest, size);
    char *out = sb_asprintf("\"%s\"", hex);
    free(hex);
    return out;
}
