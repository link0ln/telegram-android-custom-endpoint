#!/usr/bin/env python3
"""
Real-TLS relay for the custom Telegram Android client.

The custom client opens a GENUINE TLS connection to this relay (so on the wire it
is indistinguishable from ordinary HTTPS to your domain), then sends a 5-byte
routing header  b"TGR1" + <dcId>  right after the TLS handshake. This relay
terminates TLS, reads that header and forwards the (still end-to-end encrypted)
MTProto stream to the matching real Telegram datacenter.

Any connection that does NOT start with the magic header (a browser, a DPI active
probe, ...) is transparently forwarded to MASK_HOST:MASK_PORT when configured
(e.g. a real website you host), so the endpoint looks like a normal HTTPS site.
If masking is not configured, such connections are simply closed.

Config via environment variables (see .env.example):
  RELAY_LISTEN_HOST   default 0.0.0.0
  RELAY_LISTEN_PORT   default 443
  RELAY_CERT          default /certs/fullchain.pem   (valid TLS cert for your domain)
  RELAY_KEY           default /certs/privkey.pem
  MASK_HOST/MASK_PORT optional cover site for non-proxy traffic (e.g. 127.0.0.1 / 80)
  DC1..DC5, DC_PORT   optional overrides for Telegram DC addresses

NOTE: the relay must be able to reach the Telegram DCs. If your host itself is
blocked from Telegram, add host-level routing/VPN for the DC ranges (see README).
"""
import asyncio
import os
import ssl

LISTEN_HOST = os.environ.get("RELAY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("RELAY_LISTEN_PORT", "443"))
CERT = os.environ.get("RELAY_CERT", "/certs/fullchain.pem")
KEY = os.environ.get("RELAY_KEY", "/certs/privkey.pem")
MASK_HOST = os.environ.get("MASK_HOST", "")
MASK_PORT = int(os.environ.get("MASK_PORT", "0") or "0")

MAGIC = b"TGR1"
# Telegram production datacenter IPs (public). Override per-DC via env if needed.
DC = {
    1: os.environ.get("DC1", "149.154.175.50"),
    2: os.environ.get("DC2", "149.154.167.51"),
    3: os.environ.get("DC3", "149.154.175.100"),
    4: os.environ.get("DC4", "149.154.167.91"),
    5: os.environ.get("DC5", "149.154.171.5"),
}
DC_PORT = int(os.environ.get("DC_PORT", "443"))


async def splice(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(client_reader, client_writer):
    try:
        head = await asyncio.wait_for(client_reader.readexactly(5), timeout=20)
    except Exception:
        _close(client_writer)
        return

    if head[:4] == MAGIC:
        dc = head[4]
        ip = DC.get(dc if 1 <= dc <= 5 else 2, DC[2])
        try:
            up_reader, up_writer = await asyncio.open_connection(ip, DC_PORT)
        except Exception as exc:
            print("dc dial failed dc=%d: %s" % (dc, exc), flush=True)
            _close(client_writer)
            return
        print("PROXY dc=%d -> %s:%d" % (dc, ip, DC_PORT), flush=True)
        # header stripped; forward the rest of the client stream to the DC
    elif MASK_HOST and MASK_PORT:
        try:
            up_reader, up_writer = await asyncio.open_connection(MASK_HOST, MASK_PORT)
        except Exception:
            _close(client_writer)
            return
        up_writer.write(head)  # replay the peeked bytes to the cover site
        await up_writer.drain()
        print("mask -> %s:%d" % (MASK_HOST, MASK_PORT), flush=True)
    else:
        _close(client_writer)
        return

    await asyncio.gather(splice(client_reader, up_writer),
                         splice(up_reader, client_writer))


def _close(writer):
    try:
        writer.close()
    except Exception:
        pass


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT, ssl=ctx)
    print("mtrelay listening on %s:%d (cert=%s)" % (LISTEN_HOST, LISTEN_PORT, CERT), flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
