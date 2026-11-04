#!/usr/bin/env python3
"""Catch-all for TCP and UDP traffic that is not HTTP(S): record the attempt, then close
(docs/ARCHITECTURE.md 6.5). Packets arrive here through iptables REDIRECT, so the original
destination port comes from SO_ORIGINAL_DST (TCP) or IP_ORIGDSTADDR (UDP)."""

import argparse
import asyncio
import json
import socket
import struct
import threading
import time

SO_ORIGINAL_DST = 80  # linux/netfilter_ipv4.h
IP_RECVORIGDSTADDR = 20  # linux/in.h; the control message type IP_ORIGDSTADDR has the same value
FIRST_BYTES = 256
READ_LIMIT = 4096
READ_TIMEOUT = 2.0
MAX_RECORDS = 2000


class Recorder:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.count = 0

    def write(self, record):
        with self.lock:
            self.count += 1
            if self.count > MAX_RECORDS:
                return
            record["ts_ms"] = int(time.time() * 1000)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def parse_sockaddr_in(raw):
    """Return (ip, port) from a struct sockaddr_in, or (None, None)."""
    if len(raw) < 8:
        return None, None
    port = struct.unpack_from("!H", raw, 2)[0]
    return socket.inet_ntoa(raw[4:8]), port


def tls_sni(data):
    """Best-effort SNI from a TLS ClientHello; every length is bounds-checked."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, client version, random
        pos += 1 + data[pos]  # session id
        pos += 2 + struct.unpack_from("!H", data, pos)[0]  # cipher suites
        pos += 1 + data[pos]  # compression methods
        end = pos + 2 + struct.unpack_from("!H", data, pos)[0]
        pos += 2
        while pos + 4 <= min(end, len(data)):
            ext_type, ext_len = struct.unpack_from("!HH", data, pos)
            pos += 4
            if ext_type == 0 and pos + 5 <= len(data):  # server_name: list len, type, name len, name
                name_len = struct.unpack_from("!H", data, pos + 3)[0]
                name = data[pos + 5:pos + 5 + name_len]
                return name.decode("ascii", "replace") if len(name) == name_len else None
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None


async def handle_tcp(reader, writer, recorder):
    sock = writer.get_extra_info("socket")
    peer = writer.get_extra_info("peername") or (None, None)
    try:
        orig_ip, orig_port = parse_sockaddr_in(sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16))
    except OSError:
        orig_ip, orig_port = None, None
    try:
        data = await asyncio.wait_for(reader.read(READ_LIMIT), READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError):
        data = b""
    looks_like_tls = len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03
    record = {
        "kind": "tcp.connect",
        "src_port": peer[1],
        "orig_dst_ip": orig_ip,
        "orig_dst_port": orig_port,
        "bytes_in": len(data),
        "first_bytes_hex": data[:FIRST_BYTES].hex(),
        "looks_like_tls": looks_like_tls,
    }
    if looks_like_tls:
        record["sni"] = tls_sni(data)
    recorder.write(record)
    writer.close()


def serve_udp(port, recorder):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
    sock.bind(("0.0.0.0", port))
    while True:
        data, ancdata, _flags, addr = sock.recvmsg(READ_LIMIT, socket.CMSG_SPACE(16))
        orig_port = None
        for level, kind, payload in ancdata:
            if level == socket.SOL_IP and kind == IP_RECVORIGDSTADDR:
                _, orig_port = parse_sockaddr_in(payload)
        recorder.write({
            "kind": "udp.datagram",
            "src_port": addr[1],
            "orig_dst_port": orig_port,
            "len": len(data),
            "first_bytes_hex": data[:FIRST_BYTES].hex(),
        })


async def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--port", type=int, default=9009)
    args = parser.parse_args()

    recorder = Recorder(args.out)
    threading.Thread(target=serve_udp, args=(args.port, recorder), daemon=True).start()
    server = await asyncio.start_server(lambda r, w: handle_tcp(r, w, recorder), "0.0.0.0", args.port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
