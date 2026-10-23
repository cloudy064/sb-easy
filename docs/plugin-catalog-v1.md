# Signed plugin catalog v1

The catalog authenticates publisher releases independently of their download host.
It does not grant permission to install a plugin or extend its operating-system
privileges. A host build embeds a fixed allowlist of public keys from
`config/plugin-catalog-keys.json`. Catalogs cannot add or replace trust anchors.
The default list is empty: production signing credentials have not been supplied.

## Envelope and signature

```json
{"format":"sb-easy.plugin-catalog","version":1,"algorithm":"rsa-pss-sha256","key_id":"publisher-2026","payload":"BASE64_UTF8_JSON","signature":"BASE64_SIGNATURE"}
```

Both encodings are canonical RFC 4648 standard Base64 with padding, without
whitespace. Sign the exact decoded `payload` bytes with RSA-PSS, SHA-256,
MGF1-SHA256, salt length **32**, and trailer field 1. RSA moduli must be 2048–4096
bits. Do not reserialize before verification. Verify the signature before
interpreting any payload fields. The envelope is at most 1 MiB, payload at most
512 KiB. Reject duplicate JSON keys, trailing content, invalid UTF-8, unknown
fields and unsupported algorithms/versions.

Trust file:

```json
{"format":"sb-easy.plugin-catalog.keys","version":1,"keys":{"publisher-2026":"BASE64_DER_SUBJECT_PUBLIC_KEY_INFO"}}
```

There are at most 16 keys. Key IDs match `[a-zA-Z0-9_-]{1,64}`. Private keys are
external to the repository. Tests generate temporary keys; they are not accepted
by production builds. Changing a trust anchor requires a trusted host update.

## Signed payload

```json
{
  "sequence": 1,
  "issued_at": 1792732800,
  "expires_at": 1795324800,
  "releases": [{
    "id": "http-debug", "platform": "android", "version": "1.0.1", "build": 2,
    "abi": "arm64-v8a", "api": 2,
    "min_host": "1.3.4", "max_host": "2.0.0",
    "min_core": "1.14.0", "max_core": "1.15.0", "min_os": 24,
    "url": "https://downloads.example.invalid/http-debug-1.0.1-arm64-v8a.apk",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "bytes": 123456, "package": "io.sbeasy.httpdebug",
    "signer_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "permissions": ["internet", "private-files", "tls-intercept"]
  }],
  "revocations": [{"id":"http-debug","platform":"android","build":1,"reason":"Unsupported authentication protocol"}]
}
```

- All shown fields are required; unknown fields are rejected. No comments are allowed.
- `sequence` is an integer 1–9007199254740991. Times are integral Unix seconds
  1–4102444800; validity is positive and at most 90 days. New catalog acceptance
  requires `issued_at <= now + 300` and `expires_at > now`.
- `platform` is `android`, `windows`, `linux`, or `macos`. IDs/ABIs use
  `[a-zA-Z0-9_-]{1,64}`. Versions are exactly three decimal components, each
  0–999999, without leading zeros. All min ranges are inclusive; max ranges are
  exclusive. `min_os` is a platform-defined nonnegative integer (Android SDK).
- `build` is 1–2100000000; `api` is 1–65535. Current Android HTTP debug host API
  is 2; current Windows extension host API is 1. Host/core versions and ABI must
  match before downloading or launching new code.
- URLs require HTTPS with no userinfo or fragment. Downloads never send agent
  or account credentials and never follow redirects. Artifact size is 1–160 MiB,
  and SHA-256 is lowercase hexadecimal. Check actual bytes and digest before
  archive/package inspection or installation.
- Android additionally requires the exact package/versionCode/ABI and signer
  digest, a signer matching the host, no shared UID, and the supported permission
  and component allowlist. Non-Android `package` and `signer_sha256` are empty
  strings. Permissions are distinct identifiers, at most 16; each host rejects
  capabilities it does not implement.
- At most 128 releases and 256 revocations. A platform/id/ABI/build tuple is
  unique. A platform/id/build revocation covers every ABI. Reasons are 1–240
  characters, without control characters. Revocations are cumulative on clients:
  a later catalog omitting an old revocation does not reinstate that release.

## Client state and lifecycle

Persist the highest accepted sequence and payload SHA-256 together. Reject a
lower sequence and a different payload at the same sequence. Persist catalog
and revocations atomically before making newly permitted code available.
Invalid downloads/catalogs leave the last verified state intact. Known revoked
versions cannot be started, installed, updated to, or selected for rollback;
stop an active revoked plugin and restore its host routing first.

An expired catalog cannot authorize a new download/install/update. Previously
verified installed code can continue offline unless locally known to be revoked;
the UI must state that current revocation information requires a fresh catalog.
An explicit recovery to previously verified cached code is allowed offline,
provided its stored signed receipt, hash, compatibility and cumulative revocation
checks still pass. Network failures do not silently authorize unknown code.

Stage and verify a replacement before stopping the old worker. Keep the old
verified package until replacement health/handshake succeeds; retain a bounded
previous-version cache. Failed installation must not remove the working version.
On Android, installation and removal remain OS-confirmed actions. Android
[prevents versionCode downgrades](https://developer.android.com/studio/publish/versioning),
so recovery to an older cached APK requires explicit plugin removal followed by
reinstallation; this erases plugin data and ends capture. System CA removal
remains a separate user action. Never claim atomic Android rollback.

Android supplies RSA-PSS SHA-256 from API 23; implementations must still set the
exact [PSS parameters](https://developer.android.com/reference/java/security/spec/PSSParameterSpec),
rather than accepting SHA-1 defaults. See the
[Signature algorithm table](https://developer.android.com/reference/java/security/Signature).

## Publishing

Use `extensions/catalog/publish.py` to validate/sign a payload with an external
private key and an explicit trust file, and to verify the finished envelope.
Use `--artifact-root` when signing to require matching local release artifacts.
Upload only signed catalogs and verified artifacts over HTTPS. Revocation is a
new signed catalog with a higher sequence; clients cannot learn it while offline.
No production catalog/key or hosted download is created by the test suite.

Prepare a public-only configuration from a publisher's external PEM file:

```sh
python3 extensions/catalog/publish.py trust --public-key /secure/publisher-public.pem --key-id publisher-2026 --output build/publisher-trust.json
ANDROID_HOME=/path/to/sdk ./android/gradlew -p android -PsbPluginCatalogKeys=/absolute/path/build/publisher-trust.json :app:assembleRelease
python3 extensions/catalog/publish.py sign --payload release-catalog.json --keys build/publisher-trust.json --private-key /secure/publisher-private.pem --key-id publisher-2026 --artifact-root build/releases --output build/catalog.json
python3 extensions/catalog/publish.py verify --catalog build/catalog.json --keys build/publisher-trust.json
```

The host and optional APK use the same external-keystore interface through
`android/signing.gradle`: `SB_ANDROID_KEYSTORE` (absolute path),
`SB_ANDROID_KEY_ALIAS`, `SB_ANDROID_KEYSTORE_PASSWORD`, and optional
`SB_ANDROID_KEY_PASSWORD` (defaults to the store password). The path/alias may
also be supplied as `-PsbAndroidKeystore`/`-PsbAndroidKeyAlias`; passwords must
remain environment values. No external key configured means ordinary debug
signing and an unsigned release; it does not imply a trusted production release.
The plugin build script inherits the same variables. Signing both APKs with the
same identity is required for their IPC and update relationship. A changed debug
keystore cannot upgrade an APK signed with an earlier debug identity. Verify
both `apksigner verify --print-certs` results against the intended installed
release; a build or unit-test pass does not establish upgrade acceptance.

## Windows implementation and acceptance

Windows embeds `config/plugin-catalog-keys.json` (or the reviewed
`SB_EASY_PLUGIN_KEYS` CMake input). Remote catalogs cannot alter that file.
`plugin_catalog.c` uses CNG RSA-PSS with exact payload bytes, SHA-256/MGF1-SHA256
and a 32-byte salt. A DPAPI-protected store persists the highest sequence,
immutable highest build/digest, cumulative revocations and active/previous
receipts. The package cache retains only referenced versions. Legacy receipts
can refer only to digests already compiled into the host.

`plugin_storage.c` checks the fixed SBECP001 layout and `extension.json` against
the signed ID/version/build/API before publication. It journals staging and each
publication transaction, preserving recovery through process termination between
directory renames. Downloading and verification finish before the controller
stops an existing worker. A revoked or damaged installed release can be replaced
with a new trusted package; it cannot run. Explicit rollback rechecks the cached
artifact and cumulative revocations. Reinstalling the same build with a new
catalog hash is rejected. A scanner holding old files can defer cleanup after a
committed replacement without authorizing old code.

`extension_sandbox.c` follows the Windows
[AppContainer launch model](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer):
only the selected plugin code gets read/execute access; the plugin's private
profile gets write access. Host device credentials and installation directories
are not granted to the AppContainer. Child tokens are checked before execution,
and a job limits memory, CPU, child count and UI operations. Statistics and
capture receive no network capabilities. HTTP debugging receives internet/private
network capabilities and a local loopback exemption; the implementation preserves
other exemptions as required by the
[Windows configuration API](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-networkisolationsetappcontainerconfig).
Normal shutdown removes this installation's exemption. A killed host may leave
that exemption until its next normal session; it does not grant file access or
make a stopped worker run.

The PCAP worker cannot open an administrator driver. `capture_broker.c` checks
WinDivert 2.2.2-A DLL and SYS bytes against independent host pins and copies them
into a host-only, pinned directory before loading. It opens only the managed TUN
interface with SNIFF and RECV_ONLY and retains a handle so shutdown is enforced
outside the worker. A plugin cannot nominate privileged binaries, filters,
interfaces or injection flags. Upgrading that vendor dependency requires a host
update, not merely a new plugin catalog.

`windows_plugin_storage` has been run under Wine with real ephemeral signatures
and files: valid updates, all interrupted publication stages, locked directories,
modified installed bytes, revocation persistence, repair of a revoked version,
explicit rollback and downgrade/equivocation refusal. `windows_plugin_sandbox`
contains a real worker fixture for native Windows and checks private file/code,
environment, inherited-handle, parent-process and job boundaries. The sandbox
sources compile here; Wine cannot create AppContainer and the host correctly
refuses to launch. This is not a native isolation pass. Windows driver sniffing,
HTTP loopback behavior inside AppContainer and production signed artifacts remain
native acceptance requirements.
