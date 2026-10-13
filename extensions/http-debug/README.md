# HTTP(S) debugging plugin

This optional plugin runs **mitmproxy 12.2.3** locally on Windows.
It is distinct from the original raw-PCAP capture plugin. Android HTTP(S)
debugging is temporarily withdrawn; its host integration and APK build are removed.

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
HTTP inbound (17992) → original domain routing and selected proxy. Capture rules
match only original ingress tags, never the return leg. The upstream leg loses
the originating application's identity; package/process-only routing is not
preserved for captured sessions. Domain routing remains available.

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
  plugin builds, `windows/scripts/package-plugins.py`, base-service rebuild and
  MSI packaging. The pinned store entry is generated from actual bytes
  (SHA-256 pinning; this is not an Authenticode signature).
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
