#!/usr/bin/env python3
"""A stdlib TLS client that speaks the relay protocol, for testing by hand.

    python3 tests/fakeclient.py --host relay.example.com --token XXXX --ping
    python3 tests/fakeclient.py --host relay.example.com --token XXXX --dc 2
    python3 tests/fakeclient.py --host relay.example.com --garbage

Prints what came back: a decoded status frame, the cover site's response, or
nothing at all.
"""

import argparse
import os
import socket
import ssl
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import wire


def connect(host, port, sni=None, insecure=True, timeout=10):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=sni or host)


def hello(sock, args):
    if args.garbage:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        return
    if args.v1:
        sock.sendall(wire.build_v1_header(args.dc or 2))
        return
    token = wire.token_from_str(args.token)
    device = bytes.fromhex(args.device) if args.device else os.urandom(wire.DEVICE_LEN)
    ext = {}
    if args.tunnel:
        mode = wire.MODE_TUNNEL
        ext[wire.TLV_CONNECT_HOST] = args.tunnel.encode("ascii")
    elif args.ping:
        mode = wire.MODE_PING
    else:
        mode = args.dc or 2
    sock.sendall(wire.build_v2_header(mode, token, device, ext))


def read_reply(sock, limit=4096):
    sock.settimeout(6)
    try:
        return sock.recv(limit)
    except Exception:
        return b""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--sni", default=None)
    p.add_argument("--token", default=None)
    p.add_argument("--device", default=None, help="hex, 16 bytes")
    p.add_argument("--dc", type=int, default=None)
    p.add_argument("--tunnel", default=None, help="host to CONNECT to")
    p.add_argument("--ping", action="store_true")
    p.add_argument("--v1", action="store_true")
    p.add_argument("--garbage", action="store_true")
    args = p.parse_args()

    if not (args.garbage or args.v1) and not args.token:
        p.error("--token is required unless --v1 or --garbage")

    sock = connect(args.host, args.port, args.sni)
    hello(sock, args)
    data = read_reply(sock)
    if not data:
        print("(no reply - connection was masked or dropped)")
        return
    if data[:4] == wire.STATUS_MAGIC:
        code, ttl, payload = wire.parse_status(data)
        print("status %s (0x%02x) ttl_days=%s payload=%s"
              % (wire.STATUS_NAMES.get(code, "?"), code, ttl, payload))
    else:
        print("non-status reply, %d bytes: %r" % (len(data), data[:200]))


if __name__ == "__main__":
    main()
