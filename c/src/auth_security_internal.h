#ifndef SB_AUTH_SECURITY_INTERNAL_H
#define SB_AUTH_SECURITY_INTERNAL_H
#include "sb/auth_security.h"
#include "sqlite_internal.h"
struct sb_auth_security {
    sb_database *database; /* borrowed; lock via sb_database_lock/unlock */
    char *jwt_secret;
    unsigned char encryption_key[32];
    bool allow_loopback_oidc;
};
#define SB_AUTH_DB(security) sb_database_handle((security)->database)
/* All returned buffers owned; use sb_auth_sec_secret_free for plaintext secrets.
 * Encrypt binds `purpose` as GCM AAD; include row/user identity where relevant.
 * hash is domain-separated HMAC-SHA256, 64 lowercase hex characters. */
char *sb_auth_sec_random(size_t bytes, sb_err *err);
char *sb_auth_sec_hash(sb_auth_security *security, const char *purpose, const char *text);
char *sb_auth_sec_encrypt(sb_auth_security *security, const char *purpose,
                          const char *plaintext, sb_err *err);
char *sb_auth_sec_decrypt(sb_auth_security *security, const char *purpose,
                          const char *envelope, sb_err *err);
void sb_auth_sec_secret_free(char *text);
/* Returns 1 exists, 0 absent, -1 database failure. Caller holds database lock. */
int sb_auth_sec_user_exists_locked(sb_auth_security *security, const char *user_id, sb_err *err);
/* No NUL/control bytes, bounded ASCII token text. Useful for state/PKCE/kid. */
bool sb_auth_sec_token(const char *text, size_t max);
#endif
