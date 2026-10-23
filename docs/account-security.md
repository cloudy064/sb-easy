# Account security and device access

The panel now uses registered server-side sessions. Existing stateless JWTs must
be replaced by signing in again. A session is rejected immediately after logout,
revocation, account deletion, password reset or role change. Running telemetry
WebSockets recheck the registry and device grant at least every five seconds and
close with policy code 1008 when access is withdrawn.

## Roles and device groups

Administrators manage global configuration and all devices. Viewers can inspect
only assigned devices. Operators can additionally reload/restart assigned devices,
switch their live proxy selections and close their connections when a grant permits
`operate`. `view` grants do not permit those operations. Neither role can read
server secrets, subscriptions, proxy credentials, WireGuard configs, agent tokens,
raw configuration exports, packet captures or global settings. Global system counts
require an administrator; `/api/health` remains public.

In **Users → Device groups and access**, create groups from existing hosts, then
assign each account either selected groups or explicit access to all current and
future devices. New non-admin accounts have no grants. Existing accounts receive
an explicit `all` device scope during migration, preserving their former device
visibility while removing access to global credentials. The last administrator
cannot be deleted or demoted. The device list is filtered on the server, and
WebSocket/Clash requests also require an explicit authorized host. A missing
controller never redirects a scoped user to the panel's local controller.

## MFA and session management

**Account security** manages current/other sessions, passwords and an RFC 6238
six-digit authenticator. Enrollment displays a pending secret once; confirmation
requires a valid code. It then supplies one-use recovery codes once. Keep those
codes separately; the server stores only their keyed hashes. Active and pending
TOTP secrets are encrypted using AES-256-GCM with a purpose-separated key derived
from `JWT_SECRET`. Changing that server secret invalidates sessions and requires
MFA/OIDC secret recovery from an appropriate server backup.

MFA enrollment/replacement and disable require the current password and, when
already enabled, a fresh authenticator/recovery code. MFA changes revoke other
sessions; password changes revoke all sessions. Codes have replay protection and
failed attempts are throttled. The primary-login/MFA challenge is short-lived,
one-use and bound to an independent HttpOnly browser cookie. Enabling MFA during
an in-flight password login cannot bypass verification. A login interrupted by
that change fails closed and must be retried.

## OIDC

Configure OIDC in **Users**, using an HTTPS `PUBLIC_SERVER`, the issuer URL, client
ID, optional client secret and the panel callback URL shown by the UI (`/login`).
The provider must support authorization code and S256 PKCE. Discovery and signing
keys are fetched over verified HTTPS; issuer and endpoint origins are validated.
The callback uses one-use state, browser binding, nonce and PKCE. Only RS256 ID
tokens with matching issuer, audience, time and nonce are accepted. Token-supplied
key URLs and signing-key material are ignored.

An administrator must link the exact `(issuer, subject)` to a local account before
it can sign in. Emails and external role claims never create accounts or grant
local roles automatically. Existing local MFA still applies after OIDC. Provider
and identity-link changes require current password/MFA proof. Disabling or changing
the provider during an exchange invalidates that pending flow. The callback URL
carries only the provider's one-use code and state; the UI clears it before
exchanging them, and never puts a panel JWT in a URL.

The HTTP listener is designed to sit behind HTTPS termination. Set `PUBLIC_SERVER`
to the external HTTPS origin so browser-binding cookies are Secure. OIDC start and
enable reject a non-HTTPS value. Native account clients use independent panel
sessions and must preserve the login challenge cookie; managed agent credentials
are not account credentials.
