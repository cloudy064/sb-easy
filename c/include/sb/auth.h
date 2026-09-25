/* Argon2id password hashes (Rust argon2 0.5 compatible PHC strings) and the
 * HS256 JWT session contract. Port of cpp/src/auth.cpp. */
#ifndef SB_AUTH_H
#define SB_AUTH_H

#include <stdbool.h>
#include <stdint.h>

#include "sb/util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *subject;
    char *username;
    char *role;
    int64_t expires_at;
    int64_t issued_at;
} sb_auth_claims;

void sb_auth_claims_free(sb_auth_claims *c);

/* Returns a malloc'd "$argon2id$v=19$m=19456,t=2,p=1$..." string or NULL. */
char *sb_hash_password(const char *password, sb_err *err);
bool sb_verify_password(const char *password, const char *encoded_hash);

/* Tokens are signed with `secret` (HS256). create returns malloc'd token. */
char *sb_auth_create_token(const char *secret, const char *user_id, const char *username,
                           const char *role);
/* Returns true and fills *out when the token is valid and unexpired. */
bool sb_auth_verify_token(const char *secret, const char *token, sb_auth_claims *out);

#ifdef __cplusplus
}
#endif

#endif
