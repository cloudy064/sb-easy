# HTTP(S) debugging plugin

This optional plugin runs **mitmproxy 12.2.3** locally on Windows and in the
unreleased Android source. It is distinct from the raw-PCAP capture plugin.
Android 1.3.4's published capture withdrawal remains in effect; restored Android
source and APK builds have not passed physical-device release acceptance.

The Android host offers explicit same-host-signed local APK installation and a
[signed catalog/update/recovery path](../../docs/plugin-catalog-v1.md). Remote
installation fails closed until a publisher public key is embedded in the host.
The catalog does not supply replacement trust anchors. Android APKs additionally
pass an actual package/version/ABI/signature check and a component/permission
allowlist: separate UID, only INTERNET permission, no shared UID or backup,
and one signature-protected control service accepting the actual host UID.
The plugin cannot access the host's enrollment or preference storage.

Android starts with capture off and requires authorization for each session.
Stopping removes its local CA key; crash remnants are removed before the next
plugin start. All exported CA fingerprints remain tracked until Android's trust
store confirms their removal. Android cannot silently remove user-installed CAs.
System-approved uninstall/reinstall is required to recover an older APK; this
ends capture and deletes plugin data. It is not an atomic downgrade.

## Usage

1. Install HTTP(S) debugging from the Windows extension store.
2. Connect the normal proxy and start the capture engine.
3. Windows: explicitly install the generated CA into **Current User → Root**.
4. Enter exact domain suffixes, then start capturing. Only ports 80/443 of those
   domains are intercepted. Windows supports TUN and local HTTP/SOCKS listeners;
   Switching starts/stops a local config reload;
   existing connections may reconnect. Managed/shared configuration is untouched.
5. Open the authenticated local mitmweb window to inspect headers, bodies, JSON,
   errors, filters, breakpoints, edits and client replay. Use **Export HAR** for
   a browser download of the currently visible sessions.
6. Stop to restore normal routing. Windows disabling/uninstalling also restores
   routing before stopping the engine. Disconnecting the VPN ends the session.
   CA removal is explicit; Windows offers a remove button while the engine runs.

## Routing and limits

Original ingress → authenticated loopback HTTP interception (17990) → loopback
HTTP inbound (17992; authenticated on Android) → original domain routing and selected proxy. Capture rules
match only original ingress tags, never the return leg. The upstream leg loses
the originating application's identity; package/process-only routing is not
preserved for captured sessions on Windows. Android gives management/WireGuard,
private destinations and application-specific routing precedence over capture,
so those connections are not intercepted. Domain routing remains available.

Selected-domain UDP/443 is rejected to encourage TCP fallback. This is **not** a
claim of HTTP/3 capture. Apps which cannot fall back may fail. Apps which reject
user CAs or pin certificates may also fail; no automatic pinning bypass is
provided. TLS verification of the upstream server remains enabled.

Bodies over 2 MiB are streamed without retention. Single-message limit: 32 MiB.
Approximately 500 completed sessions are retained; active/intercepted sessions
are not evicted. Stopping clears in-memory sessions. No automatic body upload.
The CA key stays in protected service/application storage; only its public
certificate is exported. Control uses private Windows framed IPC.
Web UI and proxy bind loopback only;
both use fresh random credentials. No arbitrary scripts, filesystem commands,
web option persistence, process enumeration or listener reconfiguration are
exposed through the service-owned mitmweb interface. This deliberately is not
every feature of standalone mitmproxy.

## Build and verification

- Windows: `windows/scripts/build-http-debug.ps1`, then the normal optional
  plugin builds, `windows/scripts/package-plugins.py --base-url <HTTPS origin> --sequence <next sequence>`, signed catalog publication and
  MSI packaging. The pinned store entry is generated from actual bytes
  (SHA-256 pinning; this is not an Authenticode signature).
- Android: `extensions/http-debug/build-android.sh` builds ARM64/x86_64 1.0.1
  APKs. Its signing configuration is shared with the host through the external
  keystore environment variables documented in the catalog specification.
- Android device evidence: [isolated acceptance driver](../../docs/android-device-acceptance.md)
  covers the engine, actual VPN overlay/HAR/stop/CA rotation and a separately
  built test-only same-certificate/different-UID adversary. Native tests are
  compiled but have not run in the current environment; no system CA is installed.
- `tests/test_engine.py`: real TLS fixture, decryption, response body, editing,
  replay, HAR, unauthenticated rejection and restricted web settings.
- `tests/worker_smoke.py <exe>`: frozen worker IPC, Web UI, certificate and stop.
- `windows_http_debug_test`: route overlay and recursion protection.
- `windows/scripts/extensions-smoke.ps1 -HttpDebug`: real store installation,
  parsed HTTP through the existing core/upstream, disable, restore and uninstall.

Windows collects
installed dependency notices into `licenses/http-debug.txt`. The mitmproxy
engine and corresponding upstream sources are available at
<https://github.com/mitmproxy/mitmproxy/tree/v12.2.3>.
