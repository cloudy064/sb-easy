/* Stateful identity security layered over the existing HS256 session contract.
 * All SQLite work uses the borrowed database's SAME mutex as sb_store. Network
 * I/O never holds that mutex. Secrets are encrypted with a domain-separated
 * AES-256-GCM key derived from the server JWT secret; changing that secret
 * invalidates sessions and requires MFA/OIDC-secret recovery. */
#ifndef SB_AUTH_SECURITY_H
#define SB_AUTH_SECURITY_H
#include "sb/auth.h"
#include "sb/database.h"
#include "sb/json.h"

typedef struct sb_auth_security sb_auth_security;
sb_auth_security *sb_auth_security_new(sb_database *database, const char *jwt_secret,
                                        bool allow_loopback_oidc, sb_err *err);
void sb_auth_security_free(sb_auth_security *security);
/* New sessions have random JWT IDs and a server-side hash registry. Unregistered
 * legacy JWTs are intentionally invalid after this feature is enabled.
 * Direct issue rejects accounts with active MFA; use challenge completion. */
char *sb_auth_security_issue(sb_auth_security *security, const char *user_id,
                              const char *method, const char *client_label, sb_err *err);
bool sb_auth_security_verify(sb_auth_security *security, const char *token,
                              sb_auth_claims *out, sb_err *err);
sbj *sb_auth_security_sessions(sb_auth_security *security, const char *user_id,
                                const char *current_token, sb_err *err);
/* NULL session_id revokes all of this user's sessions and pending login
 * challenges. optional keep_token is
 * used for MFA changes after fresh password/code proof in the HTTP layer. */
int sb_auth_security_revoke(sb_auth_security *security, const char *user_id,
                            const char *session_id, const char *keep_token, sb_err *err);
int sb_auth_security_logout(sb_auth_security *security, const char *token, sb_err *err);
/* Atomic admin/operator/viewer role change; protects the last administrator,
 * revokes the target user's sessions and pending login challenges. */
int sb_auth_security_change_role(sb_auth_security *security, const char *user_id,
                                  const char *role, sb_err *err);
/* Password/OIDC primary authentication can return a short-lived opaque challenge
 * when local MFA is enabled. Completion consumes it and the OTP/recovery code. */
char *sb_auth_security_challenge(sb_auth_security *security, const char *user_id,
                                  const char *method, sb_err *err);
char *sb_auth_security_complete(sb_auth_security *security, const char *challenge,
                                 const char *code, const char *client_label, sb_err *err);
/* Browser entrypoints use the bound variants with an independent HttpOnly
 * cookie nonce; the unbound wrappers are for non-browser integrations. */
char *sb_auth_security_challenge_bound(sb_auth_security *security, const char *user_id,
                                        const char *method, const char *browser_binding, sb_err *err);
char *sb_auth_security_complete_bound(sb_auth_security *security, const char *challenge,
                                       const char *code, const char *client_label,
                                       const char *browser_binding, sb_err *err);

/* RFC6238 SHA-1, 30-second steps. This pure primitive supports 6/8 digit RFC
 * vectors; product enrollment/verification always uses 6 digits. */
int sb_auth_totp_code(const char *base32_secret, int64_t now, unsigned digits,
                      char out[9], sb_err *err);
sbj *sb_auth_mfa_status(sb_auth_security *security, const char *user_id, sb_err *err);
/* begin returns a NEW pending secret + otpauth_uri once; active secrets are
 * never returned. Existing MFA requires fresh code proof before begin/disable. */
sbj *sb_auth_mfa_begin(sb_auth_security *security, const char *user_id, sb_err *err);
sbj *sb_auth_mfa_confirm(sb_auth_security *security, const char *user_id, const char *code,
                          const char *keep_token, sb_err *err);
bool sb_auth_mfa_verify(sb_auth_security *security, const char *user_id, const char *code,
                         sb_err *err);
int sb_auth_mfa_disable(sb_auth_security *security, const char *user_id,
                         const char *keep_token, sb_err *err);

/* Admin-only HTTP integration must enforce actor authorization and recent
 * password/MFA proof before configuration or identity-link mutations. */
sbj *sb_auth_oidc_config(sb_auth_security *security, sb_err *err);
int sb_auth_oidc_configure(sb_auth_security *security, const sbj *config, sb_err *err);
typedef struct sb_auth_oidc_start { char *authorization_url, *browser_binding; } sb_auth_oidc_start;
void sb_auth_oidc_start_free(sb_auth_oidc_start *start);
/* Set browser_binding as host-only HttpOnly Secure SameSite=Lax cookie scoped
 * to the callback, NEVER serialize it into the public authorization response. */
int sb_auth_oidc_begin(sb_auth_security *security, sb_auth_oidc_start *out, sb_err *err);
/* Single-use state, browser binding, PKCE and nonce are checked. Returns owned
 * mapped LOCAL user ID, never auto-links email or grants provider roles. The
 * caller must require local MFA (challenge) before issuing an enabled user's
 * session. Only RS256 ID tokens from the configured issuer are accepted. */
char *sb_auth_oidc_finish(sb_auth_security *security, const char *state, const char *code,
                           const char *browser_binding, sb_err *err);
int sb_auth_oidc_link(sb_auth_security *security, const char *user_id,
                       const char *issuer, const char *subject, bool remove, sb_err *err);
sbj *sb_auth_oidc_links(sb_auth_security *security, const char *user_id, sb_err *err);

/* Non-admin policy is all/groups. Existing users receive all scope in migration;
 * new non-admin users without a policy are denied until assigned. Operators may
 * mutate only explicitly authorized device operations; viewers cannot mutate.
 * The HTTP layer still denies global administration to all non-admin roles. */
sbj *sb_auth_device_groups(sb_auth_security *security, sb_err *err);
int sb_auth_device_group_save(sb_auth_security *security, const sbj *group, sb_err *err);
int sb_auth_device_group_remove(sb_auth_security *security, const char *group_id, sb_err *err);
sbj *sb_auth_user_scope(sb_auth_security *security, const char *user_id, sb_err *err);
int sb_auth_user_scope_set(sb_auth_security *security, const char *user_id,
                            const sbj *policy, sb_err *err);
bool sb_auth_device_allowed(sb_auth_security *security, const char *user_id,
                             const char *host_id, bool mutate, sb_err *err);
#endif
