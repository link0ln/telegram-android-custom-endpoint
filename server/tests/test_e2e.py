"""End-to-end tests: a real relay, a fake datacenter and a fake cover site.

Everything runs in one process on loopback with a throwaway self-signed cert,
so `python3 -m unittest discover server/tests` needs no phone, no Telegram and
no network.

The masking assertions are the important ones. If a test here ever has to be
relaxed, the relay has become distinguishable from the site it fronts, which is
the whole security property.
"""

import asyncio
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import authcache            # noqa: E402
import mtrelay              # noqa: E402
import store                # noqa: E402
import wire                 # noqa: E402

COVER_BANNER = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world\n"


def make_cert(dirpath):
    """Self-signed cert via the openssl binary; skip the suite without one."""
    if shutil.which("openssl") is None:
        raise unittest.SkipTest("openssl not available")
    cert = os.path.join(dirpath, "cert.pem")
    key = os.path.join(dirpath, "key.pem")
    subprocess.check_call(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=relay.test"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


class Harness(object):
    """Relay + fake DC + fake cover site on one background event loop."""

    def __init__(self, tmp, **env):
        self.tmp = tmp
        self.env = env
        self.dc_conns = 0
        self.dc_bytes = bytearray()
        self.cover_seen = bytearray()
        self.loop = None
        self.thread = None
        self.port = None

    # -- fake upstreams --
    async def _dc(self, r, w):
        self.dc_conns += 1
        try:
            while True:
                data = await r.read(4096)
                if not data:
                    break
                self.dc_bytes += data
                w.write(b"ECHO:" + data)      # so the client can see it round-trip
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def _cover(self, r, w):
        try:
            data = await asyncio.wait_for(r.read(4096), 5)
            self.cover_seen += data
            w.write(COVER_BANNER)
            await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def _run(self, ready):
        dc = await asyncio.start_server(self._dc, "127.0.0.1", 0)
        cover = await asyncio.start_server(self._cover, "127.0.0.1", 0)
        dc_port = dc.sockets[0].getsockname()[1]
        cover_port = cover.sockets[0].getsockname()[1]

        cert, key = make_cert(self.tmp)
        os.environ.update({
            "RELAY_LISTEN_HOST": "127.0.0.1", "RELAY_LISTEN_PORT": "0",
            "RELAY_CERT": cert, "RELAY_KEY": key,
            "RELAY_DB": os.path.join(self.tmp, "relay.db"),
            "RELAY_PIDFILE": os.path.join(self.tmp, "relay.pid"),
            "MASK_HOST": "127.0.0.1", "MASK_PORT": str(cover_port),
            "DC1": "127.0.0.1", "DC2": "127.0.0.1", "DC3": "127.0.0.1",
            "DC4": "127.0.0.1", "DC5": "127.0.0.1", "DC_PORT": str(dc_port),
            "AUTH_RELOAD_SEC": "1", "METER_FLUSH_SEC": "1", "SWEEP_SEC": "1",
            "LOG_IP": "off",
        })
        os.environ.update(self.env)
        fut = asyncio.get_running_loop().create_future()
        serving = asyncio.ensure_future(mtrelay.serve(ready=fut))
        self.port = await fut
        ready.set()
        await serving

    def start(self):
        started = threading.Event()

        def runner():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_until_complete(self._run(started))
            except RuntimeError:
                pass                      # loop stopped during teardown
            except Exception:
                started.set()
                raise

        self.thread = threading.Thread(target=runner, daemon=True)
        self.thread.start()
        if not started.wait(30):
            raise RuntimeError("relay did not start")
        return self.port

    def stop(self):
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self.loop.stop)

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(20)


def tls_connect(port, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s = ctx.wrap_socket(raw, server_hostname="relay.test")
    s.settimeout(timeout)
    return s


def read_ack(sock):
    """Every v2 connection starts with a 10-byte TGS2 acknowledgement."""
    buf = b""
    while len(buf) < 10:
        chunk = sock.recv(10 - len(buf))
        if not chunk:
            break
        buf += chunk
    code, ttl, plen = wire.parse_status_header(buf)
    assert plen == 0, "an OK ack must carry no payload"
    return code


def recv_some(sock, n=4096):
    try:
        return sock.recv(n)
    except Exception:
        return b""


class RelayE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mtrelay-test-")
        cls.db = os.path.join(cls.tmp, "relay.db")
        conn = store.init_db(cls.db)
        now = int(time.time())
        cls.raw_ok = wire.new_token()
        cls.raw_exp = wire.new_token()
        cls.raw_rev = wire.new_token()
        # Device presence survives a test (that is the whole anti-flap point),
        # so tests that exercise device limits get their own tokens instead of
        # inheriting devices from the ones before them.
        cls.raw_dev = wire.new_token()
        cls.raw_tun = wire.new_token()
        cls.id_ok = store.create_token(conn, wire.token_hash(cls.raw_ok),
                                       wire.token_prefix(cls.raw_ok),
                                       now + 86400, label="ok", device_limit=2)
        store.create_token(conn, wire.token_hash(cls.raw_dev),
                           wire.token_prefix(cls.raw_dev), now + 86400,
                           label="device-limit", device_limit=2)
        store.create_token(conn, wire.token_hash(cls.raw_tun),
                           wire.token_prefix(cls.raw_tun), now + 86400,
                           label="tunnel", device_limit=8)
        store.create_token(conn, wire.token_hash(cls.raw_exp),
                           wire.token_prefix(cls.raw_exp), now - 60, label="expired")
        rid = store.create_token(conn, wire.token_hash(cls.raw_rev),
                                 wire.token_prefix(cls.raw_rev), now + 86400,
                                 label="revoked")
        store.update_token(conn, rid, status="revoked", revoked_at=now)
        conn.close()

        cls.h = Harness(cls.tmp)
        cls.port = cls.h.start()

    @classmethod
    def tearDownClass(cls):
        cls.h.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- happy path ----

    def test_01_valid_token_reaches_dc(self):
        before = self.h.dc_conns
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(2, self.raw_ok, b"\x01" * 16))
        self.assertEqual(read_ack(s), wire.ST_OK)
        s.sendall(b"payload-1")
        self.assertEqual(recv_some(s), b"ECHO:payload-1")
        s.close()
        self.assertEqual(self.h.dc_conns, before + 1)

    def test_02_ping_returns_status(self):
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(wire.MODE_PING, self.raw_ok, b"\x01" * 16))
        code, ttl, payload = wire.parse_status(recv_some(s))
        s.close()
        self.assertEqual(code, wire.ST_OK)
        self.assertEqual(payload["code"], "ok")
        self.assertGreaterEqual(ttl, 0)

    # ---- enforcement ----

    def test_03_expired_token_is_told_and_never_dialled(self):
        before = self.h.dc_conns
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(2, self.raw_exp, b"\x02" * 16))
        code, ttl, payload = wire.parse_status(recv_some(s))
        s.close()
        self.assertEqual(code, wire.ST_EXPIRED)
        self.assertEqual(payload["code"], "expired")
        # the whole point: an expired subscription costs the DC nothing
        self.assertEqual(self.h.dc_conns, before, "expired token still reached the DC")

    def test_04_revoked_token_gets_an_explanation(self):
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(2, self.raw_rev, b"\x03" * 16))
        code, _, payload = wire.parse_status(recv_some(s))
        s.close()
        self.assertEqual(code, wire.ST_SUSPENDED)
        self.assertEqual(payload["code"], "revoked")

    def test_05_device_limit(self):
        socks = []
        # 20 sockets from ONE device must all be admitted
        for i in range(20):
            s = tls_connect(self.port)
            s.sendall(wire.build_v2_header(2, self.raw_dev, b"\xaa" * 16))
            self.assertEqual(read_ack(s), wire.ST_OK, "socket %d rejected" % i)
            s.sendall(b"x")
            self.assertEqual(recv_some(s), b"ECHO:x", "socket %d rejected" % i)
            socks.append(s)
        # a second device still fits the limit of 2
        s2 = tls_connect(self.port)
        s2.sendall(wire.build_v2_header(2, self.raw_dev, b"\xbb" * 16))
        self.assertEqual(read_ack(s2), wire.ST_OK)
        s2.sendall(b"y")
        self.assertEqual(recv_some(s2), b"ECHO:y")
        socks.append(s2)
        # the third does not
        s3 = tls_connect(self.port)
        s3.sendall(wire.build_v2_header(2, self.raw_dev, b"\xcc" * 16))
        code, _, payload = wire.parse_status(recv_some(s3))
        s3.close()
        for s in socks:
            s.close()
        self.assertEqual(code, wire.ST_DEVICE_LIMIT)
        self.assertEqual(payload["limit"], 2)

    # ---- masking: the security-critical part ----

    def test_06_plain_http_gets_the_cover_site(self):
        probe = b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n"
        mark = len(self.h.cover_seen)
        s = tls_connect(self.port)
        s.sendall(probe)
        got = recv_some(s)
        s.close()
        self.assertEqual(got, COVER_BANNER)
        self.assertEqual(bytes(self.h.cover_seen[mark:mark + len(probe)]), probe,
                         "cover site did not receive a byte-exact replay")

    def test_07_unknown_token_is_indistinguishable_from_a_probe(self):
        hdr = wire.build_v2_header(2, wire.new_token(), b"\xee" * 16)
        mark = len(self.h.cover_seen)
        s = tls_connect(self.port)
        s.sendall(hdr)
        got = recv_some(s)
        s.close()
        self.assertEqual(got, COVER_BANNER, "unknown token got something other "
                                            "than the cover site's response")
        self.assertEqual(bytes(self.h.cover_seen[mark:mark + len(hdr)]), hdr,
                         "peeked bytes were not replayed verbatim")

    def test_08_short_header_then_fin_is_masked(self):
        mark = len(self.h.cover_seen)
        s = tls_connect(self.port)
        s.sendall(b"TG")          # fewer bytes than the prologue, then go away
        s.close()
        deadline = time.time() + 10
        while len(self.h.cover_seen) <= mark and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(bytes(self.h.cover_seen[mark:mark + 2]), b"TG",
                         "a truncated probe was dropped instead of masked")

    def test_09_legacy_v1_still_works(self):
        before = self.h.dc_conns
        s = tls_connect(self.port)
        s.sendall(wire.build_v1_header(2))
        s.sendall(b"legacy")
        self.assertEqual(recv_some(s), b"ECHO:legacy")
        s.close()
        self.assertEqual(self.h.dc_conns, before + 1)

    # ---- tunnel guards ----

    def test_10_tunnel_rejects_a_host_off_the_whitelist(self):
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(
            wire.MODE_TUNNEL, self.raw_tun, b"\x0f" * 16,
            {wire.TLV_CONNECT_HOST: b"evil.example.com"}))
        code, _, payload = wire.parse_status(recv_some(s))
        s.close()
        self.assertEqual(code, wire.ST_FORBIDDEN_HOST)
        self.assertEqual(payload["code"], "forbidden_host")

    # ---- metering ----

    def test_11_traffic_is_metered(self):
        s = tls_connect(self.port)
        s.sendall(wire.build_v2_header(2, self.raw_ok, b"\x01" * 16))
        self.assertEqual(read_ack(s), wire.ST_OK)
        s.sendall(b"z" * 5000)
        recv_some(s)
        s.close()
        self.h.call(mtrelay.flush_meter())
        conn = store.connect(self.db)
        try:
            rows = store.usage(conn, self.id_ok)
        finally:
            conn.close()
        self.assertTrue(rows, "no usage rows were written")
        self.assertGreaterEqual(sum(r["bytes_up"] for r in rows), 5000)


if __name__ == "__main__":
    unittest.main()
