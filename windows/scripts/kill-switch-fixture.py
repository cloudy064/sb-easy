#!/usr/bin/env python3
"""Controlled remote TCP/UDP/DNS echo target for kill-switch-acceptance.ps1.

Run on a separate disposable host reachable over both IPv4 and IPv6. DNS port
53 is needed for the Windows system resolver checks. Restrict access using the
host firewall to the acceptance machine; this fixture serves only .sbeasy.test.
It prints a JSON endpoint manifest, then receipt logs for packet correlation.
No proxy, routing, or firewall settings are changed by this fixture.
"""

import argparse
import datetime
import json
import socket
import struct
import threading

output_lock = threading.Lock()


def emit(value):
    with output_lock:
        print(json.dumps(value), flush=True)


def receipt(kind, peer, payload):
    emit({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "kind": kind, "peer": peer[0], "marker": payload.decode("ascii", "replace")[:256]})


def dns_response(packet, kind, peer):
    if len(packet) < 12 or len(packet) > 2048:
        return None
    identifier, flags, questions, _, _, _ = struct.unpack("!6H", packet[:12])
    if flags & 0x8000 or questions != 1:
        return None
    offset, labels = 12, []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            return None
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 != len(packet):
        return None
    query_type, query_class = struct.unpack("!2H", packet[offset:offset + 4])
    name = ".".join(labels).lower()
    if not name.endswith(".sbeasy.test") or query_type != 1 or query_class != 1:
        return None
    receipt(kind, peer, name.encode("ascii", "replace"))
    answer = b"\xc0\x0c" + struct.pack("!2HIH", 1, 1, 0, 4) + bytes([198, 18, 0, 1])
    return struct.pack("!6H", identifier, 0x8180, 1, 1, 0, 0) + packet[12:] + answer


def exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def handle_tcp(stream, peer, kind, dns):
    with stream:
        stream.settimeout(120)
        try:
            while True:
                if dns:
                    prefix = exact(stream, 2)
                    if not prefix:
                        return
                    length = struct.unpack("!H", prefix)[0]
                    if length > 2048:
                        return
                    packet = exact(stream, length)
                    if packet is None:
                        return
                    response = dns_response(packet, kind, peer)
                    if response:
                        stream.sendall(struct.pack("!H", len(response)) + response)
                else:
                    packet = stream.recv(2048)
                    if not packet:
                        return
                    receipt(kind, peer, packet)
                    stream.sendall(packet)
        except (OSError, TimeoutError):
            return


def serve_tcp(listener, kind, dns=False):
    while True:
        stream, peer = listener.accept()
        threading.Thread(target=handle_tcp, args=(stream, peer, kind, dns), daemon=True).start()


def serve_udp(listener, kind, dns=False):
    while True:
        packet, peer = listener.recvfrom(2048)
        response = dns_response(packet, kind, peer) if dns else packet
        if not dns:
            receipt(kind, peer, packet)
        if response:
            listener.sendto(response, peer)


def bind_socket(family, address, port, udp):
    listener = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((address, port))
    if not udp:
        listener.listen(32)
    return listener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipv4", required=True, help="Owned IPv4 address on this fixture host")
    parser.add_argument("--ipv6", required=True, help="Owned globally reachable IPv6 address on this fixture host")
    parser.add_argument("--tcp-port", type=int, default=34001)
    parser.add_argument("--udp-port", type=int, default=34002)
    parser.add_argument("--dns-port", type=int, default=53)
    args = parser.parse_args()
    endpoints, listeners = {}, []
    for label, family, address in (("ipv4", socket.AF_INET, args.ipv4),
                                   ("ipv6", socket.AF_INET6, args.ipv6)):
        tcp = bind_socket(family, address, args.tcp_port, False)
        udp = bind_socket(family, address, args.udp_port, True)
        dns_udp = bind_socket(family, address, args.dns_port, True)
        dns_tcp = bind_socket(family, address, dns_udp.getsockname()[1], False)
        endpoints[label] = {"address": address, "tcp_port": tcp.getsockname()[1],
                            "udp_port": udp.getsockname()[1], "dns_port": dns_udp.getsockname()[1]}
        listeners.extend([(serve_tcp, tcp, label + "-tcp", False),
                          (serve_udp, udp, label + "-udp", False),
                          (serve_udp, dns_udp, label + "-dns-udp", True),
                          (serve_tcp, dns_tcp, label + "-dns-tcp", True)])
    emit({"endpoints": endpoints})
    for target, listener, kind, dns in listeners:
        threading.Thread(target=target, args=(listener, kind, dns), daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for _, listener, _, _ in listeners:
            listener.close()


if __name__ == "__main__":
    main()
