"""Private framed IPC for isolated node checks; no public listener/control API."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import struct
import sys
import threading
from typing import Any

from probe import MAX_CONFIG_BYTES, MAX_NODES, ProbeCancelled, ProbeControl, ProbeError, probe_node, select_tags, summarize
from offline_provider import OfflineProvider

MAX_FRAME_BYTES = MAX_CONFIG_BYTES + 64 * 1024


class Worker:
    def __init__(self, data_dir=None, routing_mark=None):
        self.data_dir = data_dir
        self.routing_mark = routing_mark
        self.lock = threading.Lock()
        self.thread = None
        self.control = None
        self.phase = "idle"
        self.results = []
        self.node_count = 0
        self.ipv6 = False
        self.error = ""

    def _snapshot_locked(self):
        return {"phase": self.phase, "results": copy.deepcopy(self.results),
                "summary": summarize(self.results, self.node_count, self.ipv6),
                "error": self.error,
                "cancel_requested": bool(self.control and self.control.event.is_set())}

    def snapshot(self):
        with self.lock:
            return self._snapshot_locked()

    def start(self, params):
        if not isinstance(params, dict):
            raise ProbeError("invalid_start_parameters")
        source = params.get("config")
        tags = params.get("tags")
        executable = params.get("sing_box")
        interface = params.get("interface")
        ipv6 = params.get("ipv6", False)
        dns = params.get("bootstrap_dns", "223.5.5.5")
        if not isinstance(source, dict):
            raise ProbeError("config_must_be_object")
        if len(json.dumps(source, ensure_ascii=False).encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ProbeError("config_too_large")
        if (not isinstance(tags, list) or not 1 <= len(tags) <= MAX_NODES
                or any(not isinstance(tag, str) or not tag or len(tag.encode("utf-8")) > 256
                       or any(ord(char) < 32 or ord(char) == 127 for char in tag) for tag in tags)):
            raise ProbeError("invalid_node_selection")
        tags = select_tags(source, tags, False, MAX_NODES)
        if (not isinstance(executable, str) or not executable
                or not Path(executable).is_absolute() or not Path(executable).is_file()):
            raise ProbeError("probe_core_unavailable")
        if (not isinstance(interface, str) or not interface.strip() or len(interface.encode("utf-8")) > 256
                or any(ord(char) < 32 or ord(char) == 127 for char in interface)):
            raise ProbeError("physical_interface_required")
        if type(ipv6) is not bool:
            raise ProbeError("invalid_ipv6_option")
        # This private worker deliberately exposes no arbitrary DNS/server URL.
        if dns != "223.5.5.5":
            raise ProbeError("unsupported_bootstrap_dns")
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise ProbeError("check_already_running")
            self.control = ProbeControl()
            self.phase, self.results, self.error = "running", [], ""
            self.node_count, self.ipv6 = len(tags), ipv6
            self.thread = threading.Thread(target=self._run,
                args=(str(Path(executable).resolve()), copy.deepcopy(source), tags,
                      interface, ipv6, dns, self.control), name="node-ip-check", daemon=True)
            self.thread.start()
            return self._snapshot_locked()

    def _run(self, executable, source, tags, interface, ipv6, dns, control):
        cache = {}
        provider = None
        try:
            # Construct in the worker thread: sqlite connections stay on their
            # owning thread. Integrity verification and load happen once/batch.
            provider = OfflineProvider(self.data_dir) if self.data_dir is not None else OfflineProvider()
            for tag in tags:
                control.check()
                result = probe_node(executable, source, tag, interface, provider, cache,
                                    ipv6=ipv6, timeout=12, bootstrap_dns=dns, control=control,
                                    routing_mark=self.routing_mark)
                control.check()
                # Keep 100 results below the host's 1 MiB public pipe frame.
                # Still oversized intelligence is unknown, never a truncated
                # clean verdict. Echo IPs are always retained.
                if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 7 * 1024:
                    for family in ("ipv4", "ipv6"):
                        if "ip_info" in result.get(family, {}):
                            result[family]["ip_info"] = {"status": "unknown", "reason": "response_too_large"}
                with self.lock:
                    self.results.append(result)
            with self.lock:
                self.phase = "cancelled" if control.event.is_set() else summarize(self.results, len(tags), ipv6)["status"]
        except ProbeCancelled:
            with self.lock:
                self.phase = "cancelled"
        except Exception:
            # Never send traceback, subprocess paths or source credentials.
            with self.lock:
                self.phase = "cancelled" if control.event.is_set() else "failed"
                self.error = "" if control.event.is_set() else "probe_runtime_failed"
        finally:
            if provider is not None:
                provider.close()
            source.clear()
            cache.clear()

    def cancel(self):
        with self.lock:
            if self.phase == "running" and self.control:
                self.control.cancel()
            return self._snapshot_locked()

    def close(self):
        self.cancel()
        if self.thread:
            # Closing the sole child breaks any active HTTP tunnel. Socket and
            # startup timeouts remain bounded in case it died before cancel.
            self.thread.join(timeout=15)

    def dispatch(self, method, params):
        if method == "snapshot":
            return self.snapshot()
        if method == "start":
            return self.start(params)
        if method == "cancel":
            return self.cancel()
        raise ProbeError("unsupported_method")


def read_exact(reader, length):
    result = bytearray()
    while len(result) < length:
        part = reader.read(length - len(result))
        if not part:
            raise EOFError
        result.extend(part)
    return result


def serve(reader, writer, worker=None):
    worker = worker or Worker()
    try:
        while True:
            try:
                length, = struct.unpack("<I", read_exact(reader, 4))
                if not 0 < length <= MAX_FRAME_BYTES:
                    break
                try:
                    request = json.loads(read_exact(reader, length))
                    if not isinstance(request, dict) or not isinstance(request.get("method"), str):
                        raise ProbeError("invalid_request")
                    response = {"ok": True, "result": worker.dispatch(request["method"], request.get("params", {}))}
                except EOFError:
                    raise
                except ProbeError as error:
                    response = {"ok": False, "code": "IP_CHECK_ERROR", "message": str(error)}
                except (ValueError, TypeError, RecursionError):
                    response = {"ok": False, "code": "IP_CHECK_ERROR", "message": "invalid_request"}
                except Exception:
                    response = {"ok": False, "code": "IP_CHECK_ERROR", "message": "probe_runtime_failed"}
                content = json.dumps(response, ensure_ascii=False).encode("utf-8")
                writer.write(struct.pack("<I", len(content)) + content)
                writer.flush()
            except (EOFError, BrokenPipeError, OSError):
                break
    finally:
        worker.close()


def main():
    if len(sys.argv) > 1:
        # Diagnostic CLI is local-only and uses the exact same fixed packaged
        # dataset. IPC callers cannot override paths or submit arbitrary URLs.
        import argparse
        parser = argparse.ArgumentParser(description="Inspect bundled offline IP data without network traffic")
        parser.add_argument("--lookup-ip", required=True)
        args = parser.parse_args()
        try:
            with OfflineProvider() as provider:
                result = provider.lookup(args.lookup_ip)
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result["status"] == "ok" else 3
        except ValueError:
            parser.error("--lookup-ip requires a public literal IP address")
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    reader, writer = sys.stdin.buffer, sys.stdout.buffer
    # Core diagnostics and arbitrary library prints must not enter this pipe.
    sys.stdout = sys.stderr = open(os.devnull, "w")
    serve(reader, writer)


if __name__ == "__main__":
    raise SystemExit(main())
