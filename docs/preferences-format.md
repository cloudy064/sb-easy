# Encrypted archives and private preference sync

The password stays on the client. The center stores an opaque encrypted archive
owned by the authenticated panel account. Managed-agent credentials are never
accepted as panel-account authorization.

## Version 1 envelope

```json
{"format":"sb-easy.preferences","version":1,"kdf":"pbkdf2-sha256","iterations":600000,"salt":"<base64>","nonce":"<base64>","ciphertext":"<base64>"}
```

- Exactly these seven fields; unknown versions, algorithms and extra fields are rejected.
- PBKDF2-HMAC-SHA256, 600,000 iterations, a fresh random 16-byte salt, 32-byte derived key.
- The password is UTF-8, without normalization or a trailing NUL, 12–1024 bytes.
- AES-256-GCM, a fresh random 12-byte nonce, a 16-byte authentication tag.
- Additional authenticated data is the exact UTF-8 string `sb-easy/preferences/v1`.
- `ciphertext` contains encrypted bytes followed by the tag. Binary fields use canonical padded standard Base64, without whitespace.
- The entire serialized envelope must fit in 1 MiB. Clients reserve room for Base64 and metadata before encrypting. Parameters are validated before running the KDF.
- [The public interoperability vector](../testdata/preferences-v1.json) includes a Unicode password. Its fixed salt and nonce are for tests only.

The decrypted preferences document is:

```json
{"format":"sb-easy.preferences.payload","version":1,"platform":"web","preferences":{"locale":"en","theme":"dark"}}
```

Platform payloads are explicitly versioned and allowlisted. The web payload carries
only locale and theme. Native clients carry local subscription and general routing
preferences; enrollment credentials, WireGuard private keys, local app/process
rules, VPN enablement, capture/MITM state and CA material are excluded. Subscription
URLs and cached proxy credentials remain inside the encrypted payload. An import
must preview changes and preserve the destination's device-specific state.

Currently each platform imports its own payload. An archive from another platform
is rejected explicitly; an interoperable encryption envelope does not by itself
promise equivalent routing schemas.

Administrative full backups use the same algorithm with `format: "sb-easy.backup"`
and AAD `sb-easy/backup/v1`. Their plaintext is the existing backup JSON and may
contain server credentials. They are separate from preference roaming, require an
administrator, and are never stored in the preference-sync table. The web UI
performs encryption and decryption locally and previews restoration before apply.

## HTTP contract

All paths are relative to the panel origin and require a registered Bearer session.
Any role can manage its own preferences; no account can address another account's
slot. Slot names contain 1–64 ASCII letters, digits, `_` or `-`. Clients currently
use `web-personal`, `android-personal` and `windows-personal`.

- `GET /api/auth/preferences/{slot}` returns `{revision,updated_at,envelope}` and
  `ETag: "<revision>"`; an unused slot returns 404.
- `PUT` to the same path sends the envelope directly. `If-Match: "0"` creates an
  unused slot. Updates require the revision obtained from GET. Success returns
  the new snapshot, with its incremented revision.
- `DELETE` requires the same conditional header. It creates a tombstone and
  increments the revision. GET then returns `{revision,updated_at,envelope:null,
  deleted:true}`. Re-creation requires that revision, never 0.
- A stale revision returns 409 without changing stored data. Clients must fetch
  and review the remote snapshot; they must not silently retry with its revision.
- Tombstones prevent a delayed client from overwriting a deleted/re-created slot
  using an older matching revision. Revisions do not reset.
- Limits are 16 slots and 8 MiB of ciphertext JSON per account, including tombstone
  slots. Responses use `Cache-Control: no-store`. Deleting an account removes its
  snapshots through the foreign key.

Password login is `POST /api/auth/login`. If it returns `mfa_required` and a
`challenge`, retain the HttpOnly `sb_auth_flow` cookie and submit the challenge and
an authenticator/recovery code to `POST /api/auth/login/mfa`. The returned panel
session is distinct from managed enrollment tokens. Remote native sync requires
HTTPS with normal certificate verification. Logout revokes that session on the
server. Passphrases are not saved for automatic synchronization.

## Windows payload and import behavior

Windows uses `platform: "windows"` and exactly three preference fields:
`local_subscriptions` (stable ID, name, URL, cached nodes, refresh interval),
`routing` (general group preferences; no `custom-*` device groups), and `health`
(the common health policy). Destination custom domain/process rules and all
machine-specific security/connection settings are preserved. Imported references
must still compose into a valid destination configuration. A five-minute one-use
preview is required before apply, and local changes invalidate that preview.

The Windows IPC frame budget limits plaintext to 640 KiB and serialized envelopes
to 900 KiB. Native CNG encryption/decryption is checked against the shared public
Unicode vector. The sync account token is memory-only and separate from enrollment;
subsequent native requests need the random capability returned to the login window.
