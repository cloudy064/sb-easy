"""Bounded, isolated sing-box node exit-IP probe (Python standard library only).

This prototype does not change the running client's configuration. Every echo
request uses an authenticated HTTP CONNECT tunnel to one temporary sing-box
instance whose final route is the selected concrete node. A failed proxy is a
failed measurement: there is deliberately no direct echo-request fallback.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from provider import MAX_RESPONSE_BYTES, Response, ResponseTooLarge, public_ip
from offline_provider import OfflineProvider, PROVIDER


NON_NODES = {"selector", "urltest", "direct", "block", "dns"}
SUPPORTED_NODES = {
    "http", "socks", "shadowsocks", "vmess", "trojan", "vless", "hysteria",
    "hysteria2", "tuic", "anytls", "shadowtls", "ssh", "naive",
}
MAX_CONFIG_BYTES = 8 * 1024 * 1024
MAX_NODES = 100


class ProbeError(Exception):
    """A deliberately non-secret diagnostic code, suitable for result JSON."""


class ProbeCancelled(ProbeError):
    def __init__(self):
        super().__init__("cancelled")


class ProbeControl:
    """Cancel only this measurement's child; never touch an existing proxy."""

    def __init__(self):
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.process = None

    def check(self):
        if self.event.is_set():
            raise ProbeCancelled()

    def attach(self, process):
        with self.lock:
            self.process = process
            if self.event.is_set() and process.poll() is None:
                process.terminate()
        self.check()

    def detach(self, process):
        with self.lock:
            if self.process is process:
                self.process = None

    def cancel(self):
        self.event.set()
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                try:
                    self.process.terminate()
                except OSError:
                    pass


class PrivateDirectory:
    """Create the credential directory with a private ACL before writing files.

    The extension normally runs as SYSTEM. Windows' shared system TEMP must
    therefore not supply the default inherited ACL for proxy credentials.
    On a crash the random directory remains readable only by its owner,
    administrators and SYSTEM; normal completion/EOF/cancel removes it.
    """

    def __init__(self):
        self.name = None
        if os.name != "nt":
            self.name = tempfile.mkdtemp(prefix="sb-easy-ip-check-")
            os.chmod(self.name, 0o700)
            return
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        class Attributes(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                        ("inherit", wintypes.BOOL)]
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(Attributes)]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        token, sid, descriptor = wintypes.HANDLE(), wintypes.LPWSTR(), ctypes.c_void_p()
        try:
            if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
                raise OSError("private_directory_unavailable")
            size = wintypes.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not size.value:
                raise OSError("private_directory_unavailable")
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, buffer, size.value, ctypes.byref(size)):
                raise OSError("private_directory_unavailable")
            user_sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            if not advapi.ConvertSidToStringSidW(user_sid, ctypes.byref(sid)):
                raise OSError("private_directory_unavailable")
            sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid.value})"
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
                raise OSError("private_directory_unavailable")
            attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
            path = str(Path(tempfile.gettempdir()) / ("sb-easy-ip-check-" + secrets.token_hex(16)))
            if not kernel.CreateDirectoryW(path, ctypes.byref(attributes)):
                raise OSError("private_directory_unavailable")
            self.name = path
        finally:
            if descriptor:
                kernel.LocalFree(descriptor)
            if sid:
                kernel.LocalFree(ctypes.cast(sid, ctypes.c_void_p))
            if token:
                kernel.CloseHandle(token)

    def cleanup(self):
        # The directory is freshly generated and only owned by this instance.
        # It never accepts an external cleanup path.
        if self.name:
            import shutil
            shutil.rmtree(self.name)
            self.name = None


def _outbound_map(source: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values = source.get("outbounds", [])
    if not isinstance(values, list):
        raise ProbeError("invalid_outbounds")
    result = {}
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("tag"), str) or not item["tag"]:
            raise ProbeError("invalid_outbound_tag")
        if item["tag"] in result:
            raise ProbeError("duplicate_outbound_tag")
        result[item["tag"]] = item
    return result


def select_tags(source: dict[str, Any], tags: list[str], all_nodes: bool, limit: int) -> list[str]:
    if not 1 <= limit <= MAX_NODES:
        raise ProbeError("node_limit_must_be_1_to_100")
    outbounds = _outbound_map(source)
    if all_nodes:
        selected = [tag for tag, node in outbounds.items() if node.get("type") not in NON_NODES][:limit]
        if not selected:
            raise ProbeError("select_at_least_one_node")
        return selected
    selected = list(dict.fromkeys(tags))
    if not selected:
        raise ProbeError("select_at_least_one_node")
    if len(selected) > limit:
        raise ProbeError("selected_nodes_exceed_limit")
    for tag in selected:
        if tag not in outbounds:
            raise ProbeError("selected_node_missing")
        if outbounds[tag].get("type") in NON_NODES:
            raise ProbeError("select_concrete_proxy_nodes_only")
    return selected


def make_probe_config(source: dict[str, Any], tag: str, port: int, username: str,
                      password: str, interface: str, bootstrap_dns: str | None = None) -> dict[str, Any]:
    """Retain the selected node and DNS/detour dependencies, never client routes.

    DNS server definitions and the default resolver are retained. Client DNS
    routing rules/fake-IP answers are not suitable for this new HTTP ingress and
    are omitted. Selector dependencies are pinned to their configured default;
    a URL-test dependency is rejected because its runtime choice is unknown.
    Unsupported endpoint-based nodes fail explicitly instead of measuring some
    other node. Only a caller-selected physical interface may be used.
    """
    if not interface.strip():
        raise ProbeError("physical_interface_required")
    outbounds = _outbound_map(source)
    if tag not in outbounds or outbounds[tag].get("type") not in SUPPORTED_NODES:
        raise ProbeError("unsupported_proxy_type")
    if not 1 <= port <= 65535 or not username or not password:
        raise ProbeError("invalid_probe_listener")
    dns = copy.deepcopy(source.get("dns", {}))
    if bootstrap_dns:
        try:
            bootstrap_dns = str(ipaddress.ip_address(bootstrap_dns))
        except ValueError:
            raise ProbeError("bootstrap_dns_must_be_ip") from None
        dns = {"servers": [{"type": "udp", "tag": "probe-bootstrap", "server": bootstrap_dns}], "final": "probe-bootstrap"}
    if not isinstance(dns, dict) or not isinstance(dns.get("servers", []), list):
        raise ProbeError("invalid_dns_config")
    servers = dns.get("servers", [])
    if any(not isinstance(server, dict) for server in servers):
        raise ProbeError("invalid_dns_server")
    servers = [s for s in servers if s.get("type") != "fakeip" and s.get("address") != "fakeip"]
    dns.pop("rules", None)
    dns.pop("fakeip", None)
    if servers:
        dns["servers"] = servers
        if dns.get("final") and dns["final"] not in {s.get("tag") for s in servers}:
            raise ProbeError("unsupported_fakeip_default_dns")
    elif dns.get("final"):
        raise ProbeError("missing_dns_server")
    else:
        dns = {}

    kept: dict[str, dict[str, Any]] = {}
    visiting: set[str] = set()

    def bind_dialer(item: dict[str, Any]) -> None:
        # An existing per-dialer binding would override route.default_interface.
        for key in ("inet4_bind_address", "inet6_bind_address", "routing_mark", "netns", "network_namespace"):
            item.pop(key, None)
        item["bind_interface"] = interface

    def retain(dependency: str) -> None:
        if dependency in visiting:
            raise ProbeError("cyclic_outbound_dependencies")
        if dependency in kept:
            return
        if dependency not in outbounds:
            raise ProbeError("missing_outbound_dependency")
        node = copy.deepcopy(outbounds[dependency])
        kind = node.get("type")
        if kind == "urltest":
            raise ProbeError("unsupported_urltest_dependency")
        if kind not in SUPPORTED_NODES | {"selector", "direct"}:
            raise ProbeError("unsupported_outbound_dependency")
        visiting.add(dependency)
        if kind == "selector":
            choices = node.get("outbounds", [])
            chosen = node.get("default") or (choices[0] if choices else None)
            if not isinstance(chosen, str) or chosen not in choices:
                raise ProbeError("invalid_selector_dependency")
            node = {"type": "selector", "tag": dependency, "outbounds": [chosen], "default": chosen}
            retain(chosen)
        else:
            bind_dialer(node)
            if bootstrap_dns:
                node["domain_resolver"] = "probe-bootstrap"
            if node.get("detour"):
                retain(node["detour"])
        visiting.remove(dependency)
        kept[dependency] = node

    retain(tag)
    for server in servers:
        if server.get("detour"):
            retain(server["detour"])
        if server.get("type") in {"udp", "tcp", "tls", "https", "quic", "h3"}:
            bind_dialer(server)

    old_route = source.get("route", {})
    if not isinstance(old_route, dict):
        raise ProbeError("invalid_route_config")
    route: dict[str, Any] = {"final": tag, "default_interface": interface, "rules": []}
    if old_route.get("default_domain_resolver"):
        route["default_domain_resolver"] = copy.deepcopy(old_route["default_domain_resolver"])
    if bootstrap_dns:
        route["default_domain_resolver"] = "probe-bootstrap"
    config = {
        "log": {"disabled": True},
        "inbounds": [{"type": "http", "tag": "sb-easy-ip-check", "listen": "127.0.0.1",
                      "listen_port": port, "users": [{"username": username, "password": password}]}],
        "outbounds": list(kept.values()),
        "route": route,
    }
    if dns:
        config["dns"] = dns
    return config


def hidden_process_options() -> dict[str, Any]:
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


class ProbeCore:
    def __init__(self, executable: str, source: dict[str, Any], tag: str, interface: str,
                 startup_timeout: float = 12, bootstrap_dns: str | None = None,
                 control: ProbeControl | None = None, routing_mark: int | None = None):
        self.executable = str(Path(executable).resolve())
        self.source, self.tag, self.interface = source, tag, interface
        self.startup_timeout = startup_timeout
        self.bootstrap_dns = bootstrap_dns
        if routing_mark is not None and (type(routing_mark) is not int or not 0 < routing_mark <= 0xffffffff):
            raise ProbeError("invalid_routing_mark")
        self.routing_mark = routing_mark
        self.username = "probe"
        self.password = secrets.token_urlsafe(32)
        self.port = 0
        self.process = None
        self.directory = None
        self.control = control

    def __enter__(self) -> "ProbeCore":
        try:
            if self.control:
                self.control.check()
            # The kernel chooses a port; a bind race fails startup, never attaches
            # to another service successfully because authentication is random.
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                self.port = listener.getsockname()[1]
            config = make_probe_config(self.source, self.tag, self.port, self.username, self.password, self.interface, self.bootstrap_dns)
            if self.routing_mark is not None:
                # Center administrator override only; never inherited from a
                # node or a public request. No host routing rules are modified.
                config['route']['default_mark'] = self.routing_mark
            self.directory = PrivateDirectory()
            config_path = Path(self.directory.name) / "config.json"
            with config_path.open("x", encoding="utf-8") as handle:
                os.chmod(config_path, 0o600)
                json.dump(config, handle, ensure_ascii=False)
            self.process = subprocess.Popen(
                [self.executable, "run", "-c", str(config_path)], cwd=self.directory.name,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                **hidden_process_options(),
            )
            if self.control:
                self.control.attach(self.process)
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if self.control:
                    self.control.check()
                if self.process.poll() is not None:
                    raise ProbeError("probe_core_start_failed")
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.15):
                        return self
                except OSError:
                    time.sleep(0.05)
            raise ProbeError("probe_core_start_timeout")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.process is not None:
            if self.control:
                self.control.detach(self.process)
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1)
            self.process = None
        if self.directory is not None:
            self.directory.cleanup()
            self.directory = None
        self.password = ""

    def __exit__(self, *_: Any) -> None:
        self.close()


def proxy_request(core: ProbeCore, url: str, timeout: float = 15,
                  maximum: int = MAX_RESPONSE_BYTES) -> Response:
    """Allowlisted HTTPS CONNECT; no redirects, ambient proxies or fallback."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in {"api.ipify.org", "api6.ipify.org"} or parsed.fragment:
        raise OSError("unsupported_probe_destination")
    if parsed.path != "/" or parsed.query != "format=json":
        raise OSError("unsupported_echo_request")
    credentials = base64.b64encode(f"{core.username}:{core.password}".encode()).decode("ascii")
    connection = http.client.HTTPSConnection("127.0.0.1", core.port, timeout=timeout)
    connection.set_tunnel(parsed.hostname, 443, headers={"Proxy-Authorization": f"Basic {credentials}"})
    expired = threading.Event()

    def expire_request():
        # Socket timeouts alone reset on each read and permit a slow-drip
        # response forever. A total deadline also interrupts header/body reads.
        expired.set()
        active_socket = connection.sock
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            active_socket.close()

    deadline = threading.Timer(timeout, expire_request)
    deadline.daemon = True
    deadline.start()
    try:
        connection.request("GET", parsed.path + "?" + parsed.query, headers={"Accept": "application/json", "User-Agent": "sb-easy-ip-check/0.1"})
        response = connection.getresponse()
        body = response.read(maximum + 1)
        if expired.is_set():
            raise TimeoutError("probe_request_timeout")
        if len(body) > maximum:
            raise ResponseTooLarge("Probe response exceeds the size limit")
        return Response(response.status, body, dict(response.getheaders()))
    except (OSError, http.client.HTTPException):
        if expired.is_set():
            raise TimeoutError("probe_request_timeout") from None
        raise OSError("probe_http_connection_failed") from None
    finally:
        deadline.cancel()
        connection.close()


def echo_ip(core: ProbeCore, family: int, timeout: float = 15) -> str:
    """Environment proxy/NO_PROXY cannot bypass the explicitly selected node."""
    if family not in (4, 6):
        raise ProbeError("invalid_ip_family")
    host = "api.ipify.org" if family == 4 else "api6.ipify.org"
    try:
        response = proxy_request(core, f"https://{host}/?format=json", timeout, 4096)
        if response.status != 200:
            raise ProbeError("echo_http_error")
        payload = json.loads(response.body)
        if not isinstance(payload, dict) or not isinstance(payload.get("ip"), str):
            raise ProbeError("echo_invalid_response")
        address = ipaddress.ip_address(public_ip(payload["ip"]))
        if address.version != family:
            raise ProbeError("echo_not_public_expected_ip_family")
        return str(address)
    except ProbeError:
        raise
    except ResponseTooLarge:
        raise ProbeError("echo_response_too_large") from None
    except (ValueError, TypeError, UnicodeError):
        raise ProbeError("echo_invalid_response") from None
    except (OSError, http.client.HTTPException):
        raise ProbeError("echo_connection_failed") from None


def probe_node(executable: str, source: dict[str, Any], tag: str, interface: str,
               provider: Any, cache: dict[str, Any], ipv6: bool = False, timeout: float = 15,
               bootstrap_dns: str | None = None, control: ProbeControl | None = None,
               routing_mark: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"node": tag, "checked_at": datetime.now(timezone.utc).isoformat(), "ipv6_requested": ipv6}
    try:
        with ProbeCore(executable, source, tag, interface, bootstrap_dns=bootstrap_dns, control=control,
                       routing_mark=routing_mark) as core:
            for family in ([4, 6] if ipv6 else [4]):
                if control:
                    control.check()
                key = f"ipv{family}"
                try:
                    exit_ip = echo_ip(core, family, timeout)
                    result[key] = {"status": "ok", "ip": exit_ip}
                except ProbeError as error:
                    result[key] = {"status": "unknown", "reason": str(error)}
            # Metadata is local only. The batch owns one read-only database;
            # no external metadata requests or direct-network fallback exist.
            active_provider = provider
            for key in ("ipv4", "ipv6"):
                if control:
                    control.check()
                measurement = result.get(key, {})
                if measurement.get("status") != "ok":
                    continue
                exit_ip = measurement["ip"]
                if exit_ip in cache:
                    measurement["ip_info"] = copy.deepcopy(cache[exit_ip])
                    measurement["ip_info_cached"] = True
                    continue
                try:
                    if active_provider is None:
                        with OfflineProvider() as local_provider:
                            info = local_provider.lookup(exit_ip)
                    else:
                        info = active_provider.lookup(exit_ip)
                except Exception:
                    info = {"status": "unknown", "reason": "provider_lookup_failed"}
                if info.get("status") == "ok":
                    cache[exit_ip] = copy.deepcopy(info)
                measurement["ip_info"] = info
                measurement["ip_info_cached"] = False
    except ProbeCancelled:
        raise
    except ProbeError as error:
        result["status"] = "unknown"
        result["reason"] = str(error)
    except OSError:
        result["status"] = "unknown"
        result["reason"] = "probe_runtime_io_failed"
    if control:
        control.check()
    return result


def summarize(results: list[dict[str, Any]], node_count: int, ipv6: bool = False) -> dict[str, Any]:
    """An IP echo alone is partial success when its requested metadata failed."""
    measured = sum(item.get("ipv4", {}).get("status") == "ok" for item in results)
    info = sum(item.get("ipv4", {}).get("status") == "ok"
               and item["ipv4"].get("ip_info", {}).get("status") == "ok" for item in results)
    complete = sum(all(item.get(key, {}).get("status") == "ok"
                       and item[key].get("ip_info", {}).get("status") == "ok"
                       and not item[key].get("ip_info", {}).get("partial", False)
                       for key in (["ipv4", "ipv6"] if ipv6 else ["ipv4"])) for item in results)
    status = "failed" if not measured else "complete" if node_count > 0 and complete == node_count else "partial"
    return {"status": status, "node_count": node_count, "processed_count": len(results),
            "measured_count": measured, "info_count": info, "complete_count": complete}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch node exit-IP check using isolated sing-box and local open datasets.")
    parser.add_argument("--config", required=True, type=Path, help="Local sing-box JSON file (credentials remain local)")
    parser.add_argument("--sing-box", required=True, help="Path to sing-box executable")
    choose = parser.add_mutually_exclusive_group(required=True)
    choose.add_argument("--tag", action="append", default=[], help="Concrete node tag; repeat to select several")
    choose.add_argument("--all", action="store_true", dest="all_nodes", help="First --limit concrete nodes, in config order")
    parser.add_argument("--limit", type=int, default=10, help="Maximum nodes, default 10; hard cap 100")
    parser.add_argument("--interface", required=True, help="Physical uplink interface; do not select the running VPN/TUN")
    parser.add_argument("--bootstrap-dns", help="Optional DNS server IP queried on that interface; avoids the active client's fake-IP DNS")
    parser.add_argument("--ipv6", action="store_true", help="Also attempt an IPv6-only echo; failure is inconclusive")
    parser.add_argument("--timeout", type=float, default=15, help="Per-request socket timeout in seconds")
    parser.add_argument("--output", type=Path, help="Write incremental JSON results to this file")
    parser.add_argument("--data-dir", type=Path, help="Offline dataset directory (diagnostic CLI only)")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    try:
        if args.config.stat().st_size > MAX_CONFIG_BYTES:
            raise ProbeError("config_too_large")
        source = json.loads(args.config.read_text(encoding="utf-8-sig"))
        if not isinstance(source, dict):
            raise ProbeError("config_must_be_object")
        tags = select_tags(source, args.tag, args.all_nodes, args.limit)
        output: dict[str, Any] = {"schema_version": 2, "provider": PROVIDER, "interface": args.interface, "results": []}
        cache: dict[str, Any] = {}
        with OfflineProvider(args.data_dir) as provider:
            for tag in tags:
                output["results"].append(probe_node(args.sing_box, source, tag, args.interface, provider, cache, args.ipv6, args.timeout, args.bootstrap_dns))
                output["summary"] = summarize(output["results"], len(tags), args.ipv6)
                if args.output:
                    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return {"complete": 0, "partial": 3, "failed": 1}[output["summary"]["status"]]
    except KeyboardInterrupt:
        print("Cancelled; temporary probe core stopped.", file=sys.stderr)
        return 130
    except ProbeError as error:
        print(f"IP check failed: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, ImportError):
        print("IP check failed: input_or_runtime_unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
