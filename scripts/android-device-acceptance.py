#!/usr/bin/env python3
"""Run isolated Android capture fixtures, with optional explicitly selected adb instrumentation.

Host-only verification (no device, VPN, routes, firewall, or certificate changes):
  python3 scripts/android-device-acceptance.py --self-check \
    --server build/c-proxy-users/sb-easy-c-server

On a disposable device with VPN permission already granted manually:
  python3 scripts/android-device-acceptance.py --device SERIAL --isolated-device \
    --device-host 192.168.1.20 --server build/c-proxy-users/sb-easy-c-server

Use the --*-apk options only to request installation explicitly.
Existing app data is never cleared. The driver never grants VPN permission, changes
system certificates, or uses adb reverse. For an emulator, an explicit mapping
such as --device-host 10.0.2.2 --bind-address 127.0.0.1 is supported. HTTP-debug
instrumentation additionally needs the matching signed plugin and outbound HTTPS
to www.example.com. Without adb/device execution, native acceptance is NOT RUN.
The separate --tests http-debug-vpn mode routes all IPv4 for the test app only;
it is excluded from --tests all and still does not install a system CA.
Reports/logs are retained in a new private directory. Raw PCAPs and the temporary
database are removed unless --keep-private-data is explicitly supplied.
"""
import argparse
import contextlib
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
APP = "io.sbeasy.android"
PLUGIN = "io.sbeasy.httpdebug"
SANDBOX_PROBE = "io.sbeasy.sandboxprobe"
RUNNER = APP + ".test/androidx.test.runner.AndroidJUnitRunner"
CLASSES = {"capture": APP + ".PacketCaptureIntegrationTest", "http-debug": APP + ".HttpDebugEngineTest",
           "sandbox": APP + ".PluginSandboxTest", "http-debug-vpn": APP + ".HttpDebugVpnIntegrationTest"}
DEFAULT_TESTS = ("capture", "http-debug", "sandbox")
PLUGIN_TESTS = {"http-debug", "http-debug-vpn", "sandbox"}
REQUIRED_MARKERS = {"DOMAIN-POSITIVE-12345", "APP-POSITIVE-24680", "UDP-APP-POSITIVE-13579", "BPF-ONLY-TCP-24680"}
FORBIDDEN_MARKERS = {"DOMAIN-NEGATIVE-12345", "HOST-NEGATIVE-67890", "BPF-EXCLUDED-TCP-13579"}
ECHO_MARKERS = REQUIRED_MARKERS | FORBIDDEN_MARKERS | {
    "HOST-POSITIVE-67890", "BPF-INCLUDED-UDP-13579"}
PRIVATE_V4 = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class NotRun(RuntimeError):
    """An explicit native prerequisite is missing; never report acceptance success."""


def private_address(value, allow_loopback=False):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("Fixture addresses must be literal IPv4 addresses") from error
    if not any(address in network for network in PRIVATE_V4) and not (allow_loopback and address.is_loopback):
        raise ValueError("Use an explicit RFC1918 fixture address; wildcard/public addresses are not allowed")
    if address in ipaddress.ip_network("172.19.0.0/30"):
        raise ValueError("The fixture address overlaps the isolated Android TUN subnet")
    return str(address)


def checksum(data):
    data += b"\0" if len(data) % 2 else b""
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def sample_pcap(address):
    """Synthetic raw-IP fixture for API transport checks; not a claim of TUN capture."""
    source, destination = socket.inet_aton("172.19.0.2"), socket.inet_aton(address)
    payload = b"SB-EASY-HOST-FIXTURE-ONLY"
    udp = struct.pack("!HHHH", 41000, 41001, 8 + len(payload), 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    packet = ip + udp
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101) + \
        struct.pack("<IIII", int(time.time()), 0, len(packet), len(packet)) + packet


def validate_pcap(data):
    if len(data) < 40 or struct.unpack_from("<IHH", data) != (0xA1B2C3D4, 2, 4) or \
            struct.unpack_from("<II", data, 16) != (65535, 101):
        raise AssertionError("Capture is not a complete little-endian raw-IP PCAP")
    offset, packets = 24, 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise AssertionError("Truncated PCAP record header")
        _, micros, captured, original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        if not 20 <= captured <= 65535 or captured != original or micros >= 1000000 or offset + captured > len(data):
            raise AssertionError("Invalid PCAP record boundary")
        if data[offset] >> 4 not in (4, 6):
            raise AssertionError("Capture payload is not a raw IP packet")
        offset += captured
        packets += 1
    if not packets:
        raise AssertionError("PCAP has no packet records")
    return packets


def profile(address):
    # Inline rule sets prevent the managed overlay from downloading geographic
    # rules. The only routed address belongs to this fixture, for this app only.
    return {"name": "Isolated Android acceptance", "mode": "full", "template": {
        "log": {"level": "error"},
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"],
                      "auto_route": True, "strict_route": True, "stack": "gvisor", "mtu": 1500,
                      "route_address": [address + "/32"], "include_package": [APP]}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"},
        "route": {"auto_detect_interface": True, "final": "direct", "rules": [{"action": "sniff"}],
                  "rule_set": [{"type": "inline", "tag": tag,
                                "rules": [{"domain": ["unused-fixture-rule.invalid"]}]}
                               for tag in ("geosite-private", "geosite-cn", "geoip-cn")]}}}


class EchoState:
    def __init__(self):
        self.lock = threading.Lock()
        self.http_requests, self.udp_datagrams, self.markers = 0, 0, set()

    def record(self, transport, content):
        with self.lock:
            if transport == "http":
                self.http_requests += 1
            else:
                self.udp_datagrams += 1
            self.markers.update(marker for marker in ECHO_MARKERS if marker.encode() in content)

    def snapshot(self):
        with self.lock:
            return {"http_requests": self.http_requests, "udp_datagrams": self.udp_datagrams,
                    "markers": sorted(self.markers)}


class EchoHttp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if len(self.path) > 1024:
            self.send_error(414)
            return
        content = ("sb-easy isolated HTTP echo\n" + self.path + "\n").encode()
        self.server.fixture_state.record("http", content)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


class EchoUdp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        self.server.fixture_state.record("udp", data)
        sock.sendto(data, self.client_address)


class UdpServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    max_packet_size = 8192
    block_on_close = False


class Fixture:
    def __init__(self, binary, output, address, public_address):
        self.binary, self.output, self.address, self.public_address = binary, output, address, public_address
        self.token, self.process, self.log = None, None, None
        self.echo = EchoState()
        self.listeners, self.threads = [], []
        self.redactions = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __enter__(self):
        try:
            self.http = http.server.ThreadingHTTPServer((self.address, 0), EchoHttp)
            self.http.daemon_threads = True
            self.http.block_on_close = False
            self.listeners.append(self.http)
            self.udp = UdpServer((self.address, 0), EchoUdp)
            self.listeners.append(self.udp)
            for server in self.listeners:
                server.fixture_state = self.echo
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
            with socket.socket() as reservation:
                reservation.bind((self.address, 0))
                self.panel_port = reservation.getsockname()[1]
            self.base = f"http://{self.address}:{self.panel_port}"
            self.public_base = f"http://{self.public_address}:{self.panel_port}"
            password, jwt, legacy = (secrets.token_hex(32) for _ in range(3))
            self.redactions.extend((password, jwt, legacy))
            env = {key: os.environ[key] for key in ("PATH", "ASAN_OPTIONS", "UBSAN_OPTIONS") if key in os.environ}
            env.update(HOME=str(self.output), BIND_ADDR=f"{self.address}:{self.panel_port}",
                       DATABASE_URL="sqlite:" + str(self.output / "panel.db"),
                       MIGRATIONS_DIR=str(ROOT / "migrations"), JWT_SECRET=jwt,
                       ADMIN_PASSWORD=password, AGENT_TOKEN=legacy, PUBLIC_SERVER=self.public_base,
                       EXTERNAL_HOSTNAME=self.public_address, STATIC_DIR=str(self.output / "static"),
                       WG_ENABLED="false", SINGBOX_MANAGED="false", SUBSCRIPTION_AUTO_REFRESH="false",
                       SINGBOX_API_URL=f"http://{self.address}:{self.http.server_port}", LOG_LEVEL="warn")
            self.log = (self.output / "panel.log").open("w")
            self.process = subprocess.Popen([str(self.binary)], cwd=self.output, env=env,
                                            stdout=self.log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 20
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError("Isolated C server exited; see private panel.log")
                try:
                    if self.request("/api/health", authenticated=False)[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Isolated C server did not become healthy")
                time.sleep(0.1)
            self.token = self.api("/api/auth/login", {"password": password}, authenticated=False)["token"]
            self.redactions.append(self.token)
            self.saved_profile = self.api("/api/hosts/profiles", profile(self.public_address))
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *_args):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()
        for index, listener in enumerate(self.listeners):
            if index < len(self.threads):
                listener.shutdown()
            listener.server_close()
        for thread in self.threads:
            thread.join(timeout=3)

    def redact(self, text):
        for secret in sorted(self.redactions, key=len, reverse=True):
            if secret:
                text = text.replace(secret, "[fixture credential]")
        return text

    def request(self, path, body=None, method=None, token=None, authenticated=True, content_type=None):
        headers = {}
        credential = token if token is not None else self.token if authenticated else None
        if credential:
            headers["Authorization"] = "Bearer " + credential
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base + path, body, headers, method=method)
        try:
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("Fixture API response exceeded 2 MiB")
            if "json" in response.headers.get("Content-Type", ""):
                data = json.loads(data)
            return response.status, data

    def api(self, path, body=None, method=None, **kwargs):
        status, data = self.request(path, body, method, **kwargs)
        if status != 200:
            raise AssertionError(f"Fixture API returned HTTP {status}: {path.split('?')[0]}")
        return data

    def create_device(self, name, profile_id=None):
        # The center auto-provisions a managed WireGuard identity for Android
        # hosts without an address. Predeclare only this test's TUN address and
        # leave membership false: no peer is created and the config stays direct.
        host = self.api("/api/hosts", {"name": name, "profile_id": profile_id or self.saved_profile["id"], "clash_api": "",
                        "wg_address": "172.19.0.2/32",
                        "capabilities": {"platform": "android", "runs_singbox": True,
                                         "is_wg_member": False, "is_wg_hub": False}})
        enrollment = self.api(f'/api/devices/{host["id"]}/enrollment-codes', method="POST")
        self.redactions.extend((enrollment["code"], enrollment["enrollment_uri"]))
        return host, enrollment

    def self_check(self):
        marker = "HOST-SELF-CHECK-" + secrets.token_hex(8)
        req = urllib.request.Request(f"http://{self.address}:{self.http.server_port}/{marker}",
                                     headers={"Host": "api.capture.test"})
        with self.opener.open(req, timeout=3) as response:
            if response.status != 200 or marker.encode() not in response.read(4096):
                raise AssertionError("HTTP echo fixture failed")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(marker.encode(), (self.address, self.udp.server_address[1]))
            if sock.recvfrom(4096)[0] != marker.encode():
                raise AssertionError("UDP echo fixture failed")
        host, code = self.create_device("Host-only transport fixture")
        enrolled = self.api("/api/devices/enroll", {"code": code["code"], "device": {
            "platform": "android", "agent_version": "host-fixture", "hostname": "isolated-fixture"}}, authenticated=False)
        agent = enrolled["agent_token"]
        self.redactions.append(agent)
        if enrolled["host_id"] != host["id"] or enrolled["server"] != self.public_base:
            raise AssertionError("Enrollment identity/server mismatch")
        status, _ = self.request("/api/devices/enroll", {"code": code["code"], "device": {}}, authenticated=False)
        if status == 200:
            raise AssertionError("Single-use enrollment code was accepted twice")
        config = self.api("/api/agent/config", token=agent)
        tun = next(item for item in config["inbounds"] if item["type"] == "tun")
        if tun.get("route_address") != [self.public_address + "/32"] or tun.get("include_package") != [APP]:
            raise AssertionError("Rendered profile lost fixture address/application restrictions")
        if config["route"]["final"] != "direct" or config.get("endpoints") or \
                any(item.get("type") != "direct" for item in config["outbounds"]):
            raise AssertionError("Fixture profile contains an unexpected network endpoint")
        (self.output / "rendered-fixture-profile.json").write_text(json.dumps(config, indent=2) + "\n")
        packet = sample_pcap(self.public_address)
        validate_pcap(packet)
        digest = hashlib.sha256(packet).hexdigest()
        path = "/api/agent/captures/" + digest
        for _ in range(2):
            self.api(path, packet, "POST", token=agent, content_type="application/vnd.tcpdump.pcap")
        listing = self.api(f'/api/hosts/{host["id"]}/captures')
        if len(listing) != 1 or listing[0]["digest"] != digest:
            raise AssertionError("Capture upload was not idempotent")
        download = f'/api/hosts/{host["id"]}/captures/{digest}'
        if self.api(download) != packet:
            raise AssertionError("Uploaded capture did not roundtrip byte-for-byte")
        if self.request(download, token=agent)[0] != 401 or self.request(path, packet, "POST", token="invalid-fixture-agent")[0] != 401:
            raise AssertionError("Capture authentication boundary failed")
        if self.request(path, packet[:-1], "POST", token=agent)[0] != 400:
            raise AssertionError("Truncated capture was accepted")
        self.api(download, method="DELETE")
        self.api("/api/hosts/" + host["id"], method="DELETE")
        return {"status": "passed", "checks": ["HTTP echo", "UDP echo", "single-use enrollment",
                "restricted Android profile", "PCAP upload/download/idempotency", "capture authentication", "truncated capture rejection"],
                "capture_source": "synthetic API transport fixture; Android TUN was not exercised"}

    def verify_device_captures(self, host_id, keep_private_data=False):
        entries = self.api(f"/api/hosts/{host_id}/captures")
        if not entries:
            raise AssertionError("Instrumentation did not upload a capture to the isolated center")
        directory = self.output / "device-captures"
        if keep_private_data:
            directory.mkdir(mode=0o700)
        seen, files = set(), []
        for entry in entries:
            digest = entry["digest"]
            if not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise AssertionError("Center returned an invalid capture identity")
            data = self.api(f"/api/hosts/{host_id}/captures/{digest}")
            if len(data) > 768 * 1024 or hashlib.sha256(data).hexdigest() != digest:
                raise AssertionError("Uploaded capture digest/size mismatch")
            count = validate_pcap(data)
            if any(marker.encode() in data for marker in FORBIDDEN_MARKERS):
                raise AssertionError("A forbidden marker appeared in an uploaded capture")
            seen.update(marker for marker in REQUIRED_MARKERS if marker.encode() in data)
            if keep_private_data:
                (directory / (digest + ".pcap")).write_bytes(data)
            files.append({"sha256": digest, "bytes": len(data), "packets": count})
        if seen != REQUIRED_MARKERS:
            raise AssertionError("Uploaded PCAPs did not contain every expected capture stage")
        observed = self.echo.snapshot()["markers"]
        if not ECHO_MARKERS.issubset(observed):
            raise AssertionError("Device did not exercise every expected positive/negative HTTP and UDP request")
        return files


def instrumentation_results(output, expected):
    current, passed, skipped, failed = {}, [], False, False
    for line in output.splitlines():
        if line.startswith("INSTRUMENTATION_STATUS: ") and "=" in line:
            key, value = line.removeprefix("INSTRUMENTATION_STATUS: ").split("=", 1)
            current[key] = value
        match = re.fullmatch(r"INSTRUMENTATION_STATUS_CODE:\s*(-?\d+)", line.strip())
        if match:
            code = int(match[1])
            if code == 0 and current.get("class") and current.get("test"):
                passed.append({"class": current["class"], "test": current["test"]})
            skipped |= code in (-3, -4)
            failed |= code < 0 and code not in (-3, -4)
            current = {}
    if skipped:
        raise NotRun("Instrumentation skipped an opt-in test or lacked a required prerequisite")
    if failed or "FAILURES!!!" in output or "INSTRUMENTATION_FAILED" in output or \
            not re.search(r"^INSTRUMENTATION_CODE:\s*-1\s*$", output, re.MULTILINE):
        raise AssertionError("Android instrumentation failed; see redacted instrumentation.log")
    if not set(expected).issubset({item["class"] for item in passed}):
        raise NotRun("Instrumentation did not report a successful test for every selected class")
    return passed


def run_device(args, fixture):
    adb = shutil.which(args.adb)
    if not adb:
        raise NotRun("adb is unavailable; Android native acceptance was not run")
    prefix = [adb, "-s", args.device]

    def command(arguments, timeout=20, required=True):
        result = subprocess.run(prefix + arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=timeout)
        if required and result.returncode:
            raise NotRun("Selected device or adb command is unavailable: " + arguments[0])
        return result

    if command(["get-state"]).stdout.strip() != "device":
        raise NotRun("The explicitly selected device is not ready")
    if int(command(["shell", "getprop ro.build.version.sdk"]).stdout.strip()) < 24:
        raise NotRun("Android API 24 or newer is required")
    for path in (args.app_apk, args.test_apk, args.plugin_apk, args.sandbox_probe_apk):
        if path:
            result = command(["install", "-r", "-t", str(path.resolve())], timeout=120)
            if "Success" not in result.stdout:
                raise NotRun("The explicitly supplied APK could not be installed")
    command(["shell", "run-as " + APP + " id"])
    if RUNNER not in command(["shell", "pm list instrumentation"]).stdout:
        raise NotRun("Install the matching debug instrumentation APK first")
    versions = json.loads((ROOT / "config/client-releases.json").read_text())["development"]["android"]
    package = command(["shell", "dumpsys package " + APP]).stdout
    if not re.search(r"\bversionName=" + re.escape(versions["version"]) + r"(?:\s|$)", package) or \
            not re.search(r"\bversionCode=" + str(versions["version_code"]) + r"(?:\s|$)", package):
        raise NotRun("Installed application identity does not match the current development manifest")
    tests = DEFAULT_TESTS if args.tests == "all" else (args.tests,)
    if set(tests) & PLUGIN_TESTS and not command(["shell", "pm path " + PLUGIN]).stdout.startswith("package:"):
        raise NotRun("The matching HTTP-debug plugin must be installed explicitly")
    if "sandbox" in tests and not command(["shell", "pm path " + SANDBOX_PROBE]).stdout.startswith("package:"):
        raise NotRun("Sandbox acceptance requires the explicitly installed probe APK")
    profile_id = None
    if "http-debug-vpn" in tests:
        vpn_profile = profile(fixture.public_address)
        vpn_profile["name"] = "Explicit isolated HTTP-debug VPN acceptance"
        vpn_profile["template"]["inbounds"][0]["route_address"] = ["0.0.0.0/0"]
        profile_id = fixture.api("/api/hosts/profiles", vpn_profile)["id"]
    host, enrollment = fixture.create_device("Disposable Android instrumentation", profile_id)
    classes = [CLASSES[test] for test in tests]
    arguments = ["am", "instrument", "-w", "-r", "-e", "class", ",".join(classes),
                 "-e", "captureIsolatedDevice", "true", "-e", "captureAllowInsecureLocalHttp", "true",
                 "-e", "captureEnrollment", enrollment["enrollment_uri"],
                 "-e", "captureAddress", fixture.public_address,
                 "-e", "capturePort", str(fixture.http.server_port),
                 "-e", "captureUdpPort", str(fixture.udp.server_address[1]),
                 "-e", "httpDebugIsolatedDevice", "true", "-e", "pluginSandboxIsolatedDevice", "true",
                 "-e", "httpDebugVpnIsolatedDevice", "true" if "http-debug-vpn" in tests else "false",
                 "-e", "httpDebugEnrollment", enrollment["enrollment_uri"] if "http-debug-vpn" in tests else "",
                 "-e", "httpDebugAllowInsecureLocalHttp", "true", RUNNER]
    try:
        result = command(["shell", " ".join(shlex.quote(value) for value in arguments)], timeout=args.timeout,
                         required=False)
        output = fixture.redact(result.stdout)
        (fixture.output / "instrumentation.log").write_text(output)
        if result.returncode:
            raise AssertionError("adb instrumentation failed; see redacted instrumentation.log")
        passed = instrumentation_results(output, classes)
        captures = fixture.verify_device_captures(host["id"], args.keep_private_data) if "capture" in tests else []
        return {"status": "passed", "serial": args.device, "tests": passed, "captures": captures}
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        (fixture.output / "instrumentation.log").write_text(fixture.redact(output))
        raise AssertionError("Instrumentation exceeded its deadline; test apps were stopped") from error
    finally:
        # Stop only the explicitly selected fixture apps, including on timeout;
        # do not leave a test-owned VPN/plugin alive after the host fixture exits.
        packages = [APP + ".test", APP]
        if set(tests) & PLUGIN_TESTS:
            packages.append(PLUGIN)
        if "sandbox" in tests:
            packages.append(SANDBOX_PROBE)
        for package_name in packages:
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                command(["shell", "am force-stop " + package_name], timeout=5, required=False)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-check", action="store_true", help="Verify host fixtures only; report native acceptance NOT RUN")
    mode.add_argument("--device", metavar="SERIAL", help="Explicit adb serial; no device is auto-selected")
    parser.add_argument("--server", type=Path, required=True, help="Built C server executable")
    parser.add_argument("--isolated-device", action="store_true", help="Confirm the selected device contains only disposable test data")
    parser.add_argument("--device-host", help="RFC1918 IPv4 address used by the device to reach this fixture")
    parser.add_argument("--bind-address", help="Explicit local bind address; defaults to --device-host, or loopback for self-check")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--tests", choices=(*CLASSES, "all"), default="capture")
    parser.add_argument("--app-apk", type=Path, help="Explicitly install this debug application APK")
    parser.add_argument("--test-apk", type=Path, help="Explicitly install this matching instrumentation APK")
    parser.add_argument("--plugin-apk", type=Path, help="Explicitly install this matching signed HTTP-debug plugin APK")
    parser.add_argument("--sandbox-probe-apk", type=Path, help="Explicitly install the matching test-only sandbox probe APK")
    parser.add_argument("--timeout", type=int, default=300, help="Instrumentation deadline, 30..900 seconds")
    parser.add_argument("--output-dir", type=Path, help="New private artifact directory; must not already exist")
    parser.add_argument("--keep-private-data", action="store_true", help="Retain the isolated database and raw device PCAPs in the private output directory")
    args = parser.parse_args(argv)
    try:
        if not args.server.is_file() or not os.access(args.server, os.X_OK):
            raise ValueError("--server must be a built executable C server")
        if not 30 <= args.timeout <= 900:
            raise ValueError("--timeout must be between 30 and 900 seconds")
        if args.device:
            if not args.isolated_device or not args.device_host:
                raise ValueError("Device mode requires --isolated-device and --device-host")
            if not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]{1,128}", args.device):
                raise ValueError("Invalid explicit adb serial")
            args.device_host = private_address(args.device_host)
            args.bind_address = private_address(args.bind_address or args.device_host, allow_loopback=True)
        else:
            if args.device_host or args.bind_address or args.isolated_device or args.tests != "capture" or \
                    any((args.app_apk, args.test_apk, args.plugin_apk, args.sandbox_probe_apk)):
                raise ValueError("Host self-check only uses loopback and does not accept device/install options")
            args.device_host = args.bind_address = "127.0.0.1"
        if args.sandbox_probe_apk and args.tests not in ("sandbox", "all"):
            raise ValueError("--sandbox-probe-apk requires --tests sandbox or all")
        if args.plugin_apk and args.tests == "capture":
            raise ValueError("--plugin-apk requires a plugin test selection")
        for path in (args.app_apk, args.test_apk, args.plugin_apk, args.sandbox_probe_apk):
            if path and (not path.is_file() or path.suffix.lower() != ".apk"):
                raise ValueError("Explicit APK inputs must be existing .apk files")
    except ValueError as error:
        parser.error(str(error))
    args.server = args.server.resolve()
    return args


def main(argv=None):
    args = parse_args(argv)
    os.umask(0o077)
    if args.output_dir:
        args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        output = args.output_dir.resolve()
    else:
        output = Path(tempfile.mkdtemp(prefix="sb-easy-android-acceptance-"))
    report = {"schema": 1, "fixture": {"status": "failed"}, "native": {"status": "not_run"},
              "server_sha256": hashlib.sha256(args.server.read_bytes()).hexdigest(),
              "private_data_retained": args.keep_private_data}
    exit_code = 0
    try:
        with Fixture(args.server, output, args.bind_address, args.device_host) as fixture:
            report["fixture"] = fixture.self_check()
            report["addresses"] = {"bind": fixture.address, "device": fixture.public_address,
                                   "panel_port": fixture.panel_port, "http_port": fixture.http.server_port,
                                   "udp_port": fixture.udp.server_address[1]}
            print("Host fixtures verified: real C enrollment/config/capture API and HTTP/UDP echo.", flush=True)
            if args.device:
                try:
                    report["native"] = run_device(args, fixture)
                except NotRun as error:
                    report["native"] = {"status": "not_run", "reason": fixture.redact(str(error))}
                    exit_code = 2
                except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
                    report["native"] = {"status": "failed", "reason": fixture.redact(str(error))}
                    exit_code = 1
            else:
                report["native"]["reason"] = "Host self-check selected; no adb, device, Android VPN, or plugin was exercised"
            report["echo"] = fixture.echo.snapshot()
    except (AssertionError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["fixture"] = {"status": "failed", "reason": str(error)}
        exit_code = 1
    if not args.keep_private_data:
        for name in ("panel.db", "panel.db-wal", "panel.db-shm", "panel.db-journal"):
            (output / name).unlink(missing_ok=True)
    (output / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print("Android native acceptance: " + report["native"]["status"].upper().replace("_", " "), flush=True)
    if "reason" in report["native"]:
        print(report["native"]["reason"], flush=True)
    if report["fixture"]["status"] == "failed":
        print("Host fixture failed: " + report["fixture"].get("reason", "unknown error"), flush=True)
    print("Private artifacts: " + str(output), flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
